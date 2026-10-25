from django.test import TestCase

from secureapp.models import Comment, Message, Post

from .test_confidentiality import full_account, sign_in


def flip(row, field):
    raw = bytearray(getattr(row, field))
    raw[0] ^= 0x01
    setattr(row, field, bytes(raw))
    row.save()


class TamperedPostTests(TestCase):
    def setUp(self):
        full_account("alice")
        self.client = sign_in("alice")
        self.client.post("/posts/new/", {"body": "salary is 90000", "audience": "public"})
        self.post = Post.objects.get(user__username="alice")

    def test_a_flipped_body_is_not_shown_to_the_owner(self):
        flip(self.post, "body_ct")
        response = self.client.get(f"/posts/{self.post.id}/", follow=True)
        self.assertNotContains(response, "salary is 90000")
        self.assertContains(response, "could not be opened")

    def test_a_flipped_body_is_dropped_from_the_feed_and_counted(self):
        flip(self.post, "body_ct")
        response = self.client.get("/")
        self.assertNotContains(response, "salary is 90000")
        self.assertEqual(response.context["unreadable"], 1)

    def test_a_wrecked_mac_is_not_shown(self):
        self.post.mac = b"\x00" * 32
        self.post.save()
        response = self.client.get(f"/posts/{self.post.id}/", follow=True)
        self.assertNotContains(response, "salary is 90000")

    def test_a_missing_mac_is_not_treated_as_no_mac_required(self):
        self.post.mac = None
        self.post.save()
        self.assertNotContains(self.client.get(f"/posts/{self.post.id}/", follow=True),
                               "salary is 90000")

    def test_a_row_swapped_onto_another_owner_does_not_verify(self):
        bob, _, _ = full_account("bob")
        self.post.user = bob
        self.post.save()
        self.assertNotContains(sign_in("bob").get("/feed/"), "salary is 90000")


class TamperedCommentTests(TestCase):
    def setUp(self):
        full_account("alice")
        self.client = sign_in("alice")
        self.client.post("/posts/new/", {"body": "a public post", "audience": "public"})
        self.post = Post.objects.get()
        self.client.post(f"/posts/{self.post.id}/comments/", {"body": "meet at gate 3"})
        self.comment = Comment.objects.get()

    def test_a_comment_arrives_intact(self):
        self.assertContains(self.client.get(f"/posts/{self.post.id}/"), "meet at gate 3")

    def test_a_flipped_comment_is_hidden(self):
        flip(self.comment, "body_ct")
        response = self.client.get(f"/posts/{self.post.id}/")
        self.assertNotContains(response, "meet at gate 3")
        self.assertContains(response, "failed its check")

    def test_a_comment_moved_under_another_post_does_not_verify(self):
        self.client.post("/posts/new/", {"body": "another post", "audience": "public"})
        other = Post.objects.exclude(id=self.post.id).get()
        self.comment.post = other
        self.comment.save()
        self.assertNotContains(self.client.get(f"/posts/{other.id}/"), "meet at gate 3")


class TamperedMessageTests(TestCase):
    def setUp(self):
        full_account("alice")
        full_account("bob")
        sign_in("alice").post("/messages/bob/", {"body": "the door code is 8890"})
        self.message = Message.objects.get()
        self.reader = sign_in("bob")

    def test_a_message_arrives_intact(self):
        self.assertContains(self.reader.get("/messages/alice/"), "the door code is 8890")

    def test_a_flipped_body_is_not_shown(self):
        flip(self.message, "body_ct")
        response = self.reader.get("/messages/alice/")
        self.assertNotContains(response, "the door code is 8890")
        self.assertContains(response, "could not be opened")

    def test_a_message_cannot_be_read_by_anyone_else(self):
        full_account("carol")
        carol = sign_in("carol")
        self.assertNotContains(carol.get("/messages/alice/"), "the door code is 8890")
        self.assertNotContains(carol.get("/messages/bob/"), "the door code is 8890")

    def test_the_sender_keeps_a_readable_copy(self):
        self.assertContains(sign_in("alice").get("/messages/bob/"), "the door code is 8890")

    def test_the_two_copies_of_the_key_are_different_blobs(self):
        self.assertNotEqual(bytes(self.message.key_for_recipient), bytes(self.message.key_for_sender))
        self.assertNotIn(b"8890", bytes(self.message.body_ct))

    def test_reading_marks_it_read(self):
        self.assertIsNone(self.message.read_at)
        self.reader.get("/messages/alice/")
        self.message.refresh_from_db()
        self.assertIsNotNone(self.message.read_at)
