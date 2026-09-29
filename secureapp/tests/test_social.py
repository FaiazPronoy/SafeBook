"""Friends, and the keys that go with them.

A friends-only post is readable by a friend because that friend was handed
a copy of its key, locked with their own public key. These tests check the
copies: who gets one, when, and that they go away with the friendship.
"""

from django.test import TestCase
from django.utils import timezone

from secureapp import keys
from secureapp.keyring import AAD_PRIVKEY
from secureapp.crypto import aead_decrypt
from secureapp.models import Comment, FriendRequest, Like, Post, PostShare
from secureapp.rsa_utils import load_private_key_from_der

from .test_confidentiality import full_account, sign_in


def befriend(a, b):
    FriendRequest.objects.create(from_user=a, to_user=b, accepted_at=timezone.now())


class FriendsPostTests(TestCase):
    def setUp(self):
        self.alice, self.alice_dek, _ = full_account("alice")
        self.bob, self.bob_dek, _ = full_account("bob")
        self.carol, _, _ = full_account("carol")
        befriend(self.alice, self.bob)
        self.author = sign_in("alice")
        self.author.post("/posts/new/", {"body": "party at mine on friday", "audience": "friends"})
        self.post = Post.objects.get()

    def test_each_friend_gets_a_copy_and_nobody_else_does(self):
        self.assertEqual(list(self.post.shares.values_list("reader__username", flat=True)), ["bob"])

    def test_the_server_holds_no_key_it_can_open(self):
        self.assertIsNone(self.post.key_public)

    def test_the_friend_s_copy_opens_with_the_friend_s_private_key(self):
        der = aead_decrypt(self.bob_dek, self.bob.privkey_nonce, self.bob.privkey_ct, AAD_PRIVKEY)
        share = self.post.shares.get()
        self.assertEqual(
            keys.unwrap_post_key_as_friend(share.wrapped_key, load_private_key_from_der(der)),
            keys.unwrap_post_key_for_owner(self.post.key_owner, self.alice_dek))

    def test_a_friend_reads_it_and_a_stranger_does_not(self):
        self.assertContains(sign_in("bob").get("/"), "party at mine on friday")
        carol = sign_in("carol")
        self.assertNotContains(carol.get("/"), "party at mine on friday")
        self.assertNotContains(carol.get(f"/posts/{self.post.id}/", follow=True), "party at mine")
        self.assertNotContains(carol.get("/u/alice/"), "party at mine on friday")

    def test_friends_can_comment_and_the_comment_is_ciphertext(self):
        sign_in("bob").post(f"/posts/{self.post.id}/comments/", {"body": "bringing samosas"})
        comment = Comment.objects.get()
        self.assertNotIn(b"samosas", bytes(comment.body_ct))
        self.assertContains(self.author.get(f"/posts/{self.post.id}/"), "bringing samosas")

    def test_a_stranger_cannot_comment(self):
        response = sign_in("carol").post(f"/posts/{self.post.id}/comments/", {"body": "hi"})
        self.assertEqual(response.status_code, 404)
        self.assertFalse(Comment.objects.exists())

    def test_the_author_can_delete_a_friend_s_comment_and_a_stranger_cannot(self):
        sign_in("bob").post(f"/posts/{self.post.id}/comments/", {"body": "first!"})
        comment = Comment.objects.get()
        self.assertEqual(sign_in("carol").post(f"/comments/{comment.id}/delete/").status_code, 404)
        self.author.post(f"/comments/{comment.id}/delete/")
        self.assertFalse(Comment.objects.exists())

    def test_unfriending_takes_the_copies_back(self):
        sign_in("bob").post("/friends/alice/remove/")
        self.assertFalse(PostShare.objects.exists())
        self.assertNotContains(sign_in("bob").get("/"), "party at mine on friday")

    def test_moving_it_to_only_me_takes_the_copies_back_and_keeps_the_text(self):
        before = bytes(self.post.body_ct)
        self.author.post(f"/posts/{self.post.id}/audience/", {"audience": "me"})
        self.post.refresh_from_db()
        self.assertFalse(self.post.shares.exists())
        self.assertEqual(bytes(self.post.body_ct), before)

    def test_deleting_the_post_deletes_every_copy_of_its_key(self):
        self.author.post(f"/posts/{self.post.id}/delete/")
        self.assertFalse(PostShare.objects.exists())


class NewFriendTests(TestCase):
    """A friend made after the post was written gets a key from the author,
    and only the author can give it, so it waits for them to sign in."""

    def setUp(self):
        self.alice, _, _ = full_account("alice")
        self.carol, _, _ = full_account("carol")
        alice = sign_in("alice")
        alice.post("/posts/new/", {"body": "written before carol", "audience": "friends"})
        alice.post("/friends/carol/add/")
        self.carol_client = sign_in("carol")
        self.carol_client.post("/posts/new/", {"body": "news from carol", "audience": "friends"})
        self.carol_client.post("/friends/alice/accept/")

    def test_the_old_post_waits_for_its_author(self):
        page = self.carol_client.get("/")
        self.assertContains(page, "Waiting for a key")
        self.assertNotContains(page, "written before carol")

    def test_the_author_signing_in_hands_the_key_over(self):
        sign_in("alice").get("/")
        self.assertContains(self.carol_client.get("/"), "written before carol")

    def test_the_accepter_s_own_posts_go_across_at_once(self):
        """Carol was signed in when she accepted, so her keys went straight away."""
        self.assertTrue(PostShare.objects.filter(post__user=self.carol, reader=self.alice).exists())
        self.assertFalse(PostShare.objects.filter(post__user=self.alice, reader=self.carol).exists())


class FriendRequestTests(TestCase):
    def setUp(self):
        full_account("alice")
        full_account("bob")
        full_account("carol")
        self.alice = sign_in("alice")
        self.alice.post("/friends/bob/add/")

    def test_a_request_is_pending_until_accepted(self):
        request = FriendRequest.objects.get()
        self.assertIsNone(request.accepted_at)
        self.assertEqual(sign_in("bob").get("/").context["request_count"], 1)

    def test_only_the_person_asked_can_accept(self):
        self.alice.post("/friends/bob/accept/")
        sign_in("carol").post("/friends/bob/accept/")
        self.assertIsNone(FriendRequest.objects.get().accepted_at)
        sign_in("bob").post("/friends/alice/accept/")
        self.assertIsNotNone(FriendRequest.objects.get().accepted_at)

    def test_asking_twice_makes_one_request(self):
        self.alice.post("/friends/bob/add/")
        sign_in("bob").post("/friends/alice/add/")
        self.assertEqual(FriendRequest.objects.count(), 1)

    def test_declining_removes_it(self):
        sign_in("bob").post("/friends/alice/decline/")
        self.assertFalse(FriendRequest.objects.exists())

    def test_nobody_can_befriend_themselves(self):
        self.assertEqual(self.alice.post("/friends/alice/add/").status_code, 404)

    def test_friend_actions_need_a_post(self):
        self.assertEqual(self.alice.get("/friends/carol/add/").status_code, 405)


class LikeTests(TestCase):
    def setUp(self):
        full_account("alice")
        self.client = sign_in("alice")
        self.client.post("/posts/new/", {"body": "like me", "audience": "public"})
        self.post = Post.objects.get()

    def test_liking_twice_is_unliking(self):
        self.client.post(f"/posts/{self.post.id}/like/")
        self.assertEqual(Like.objects.count(), 1)
        self.client.post(f"/posts/{self.post.id}/like/")
        self.assertEqual(Like.objects.count(), 0)

    def test_the_page_script_gets_json_back(self):
        response = self.client.post(f"/posts/{self.post.id}/like/", HTTP_X_REQUESTED_WITH="fetch")
        self.assertEqual(response.json(), {"liked": True, "count": 1})


class RedirectTests(TestCase):
    """The next field comes from the page, so it is not trusted."""

    def setUp(self):
        full_account("alice")

    def test_sign_in_does_not_follow_next_off_the_site(self):
        from .test_auth import PASSWORD
        response = self.client.post("/login/", {"username": "alice", "password": PASSWORD,
                                                "next": "https://evil.example/"})
        self.assertEqual(response["Location"], "/")

    def test_a_like_does_not_follow_next_off_the_site(self):
        client = sign_in("alice")
        client.post("/posts/new/", {"body": "x", "audience": "public"})
        post = Post.objects.get()
        response = client.post(f"/posts/{post.id}/like/", {"next": "https://evil.example/"})
        self.assertEqual(response["Location"], "/")
