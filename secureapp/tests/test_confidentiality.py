"""What the server can and cannot read, and what it refuses to show.

These are the tests that decide whether the design does what the front page
of this project claims it does.
"""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from secureapp import keys
from secureapp.crypto import aead_decrypt, new_key
from secureapp.models import Message, Post
from secureapp.rsa_utils import generate_rsa_keypair
from secureapp.keyring import AAD_EMAIL, AAD_PRIVKEY

from .test_auth import PASSWORD, make_account

Account = get_user_model()


def full_account(username):
    """An account with everything registration gives you."""
    user, dek, code = make_account(username)
    from secureapp.crypto import aead_encrypt
    user.email_nonce, user.email_ct = aead_encrypt(dek, b"private@example.com", AAD_EMAIL)
    pub, priv = generate_rsa_keypair()
    user.public_key_pem = pub.decode()
    user.privkey_nonce, user.privkey_ct = aead_encrypt(dek, priv, AAD_PRIVKEY)
    user.save()
    return user, dek, code


def sign_in(username=None):
    client = Client()
    client.post("/login/", {"username": username, "password": PASSWORD})
    return client


class ServerCannotReadTests(TestCase):
    """The database and the KEK together must not be enough."""

    def setUp(self):
        self.alice, self.dek, _ = full_account("alice")
        client = sign_in("alice")
        client.post("/posts/new/", {"body": "the vault code is 4417", "audience": "me"})
        self.post = Post.objects.get(user=self.alice)

    def test_a_private_post_has_no_key_the_server_can_open(self):
        self.assertIsNone(self.post.key_public)

    def test_the_server_kek_does_not_open_a_private_post(self):
        with self.assertRaises(Exception):
            keys.unwrap_post_key_for_public(self.post.key_owner)

    def test_the_plaintext_is_not_in_the_row(self):
        blob = bytes(self.post.body_ct)
        self.assertNotIn(b"4417", blob)
        self.assertNotIn(b"vault", blob)

    def test_the_envelope_needs_the_password(self):
        with self.assertRaises(Exception):
            keys.open_private_dek(self.alice.pdek_wrapped, self.alice.pdek_salt, "wrong")

    def test_the_right_password_does_open_it(self):
        recovered = keys.open_private_dek(
            self.alice.pdek_wrapped, self.alice.pdek_salt, PASSWORD)
        self.assertEqual(recovered, self.dek)

    def test_pii_is_ciphertext_in_the_database(self):
        self.assertNotIn(b"private@example.com", bytes(self.alice.email_ct))

    def test_the_private_key_is_ciphertext_in_the_database(self):
        self.assertNotIn(b"PRIVATE KEY", bytes(self.alice.privkey_ct))
        self.assertEqual(
            aead_decrypt(self.dek, self.alice.privkey_nonce,
                         self.alice.privkey_ct, AAD_PRIVKEY)[:2], b"0\x82")


class PublishingTests(TestCase):
    def setUp(self):
        self.alice, self.dek, _ = full_account("alice")
        self.client = sign_in("alice")
        self.client.post("/posts/new/", {"body": "an open letter, printable", "audience": "me"})
        self.post = Post.objects.get(user=self.alice)

    def _audience(self, audience):
        self.client.post(f"/posts/{self.post.id}/audience/", {"audience": audience})
        self.post.refresh_from_db()

    def test_publishing_does_not_re_encrypt_the_post(self):
        """Only a wrapped key is added. That is the point of an envelope."""
        before = bytes(self.post.body_ct)
        self._audience("public")
        self.assertTrue(self.post.is_public)
        self.assertEqual(bytes(self.post.body_ct), before)
        self.assertIsNotNone(self.post.key_public)

    def test_the_two_wrappings_hold_the_same_key(self):
        self._audience("public")
        self.assertEqual(keys.unwrap_post_key_for_owner(self.post.key_owner, self.dek),
                         keys.unwrap_post_key_for_public(self.post.key_public))

    def test_unpublishing_drops_the_server_key(self):
        self._audience("public")
        self._audience("me")
        self.assertFalse(self.post.is_public)
        self.assertIsNone(self.post.key_public)

    def test_an_unknown_audience_changes_nothing(self):
        self._audience("everyone-please")
        self.assertEqual(self.post.audience, "me")

    def test_the_feed_of_a_stranger_only_carries_public_posts(self):
        full_account("bob")
        bob = sign_in("bob")
        self.assertNotContains(bob.get("/feed/"), "printable")
        self._audience("public")
        self.assertContains(bob.get("/feed/"), "printable")


class AccessControlTests(TestCase):
    def setUp(self):
        full_account("alice")
        full_account("bob")
        alice = sign_in("alice")
        alice.post("/posts/new/", {"body": "not for bob", "audience": "me"})
        self.post = Post.objects.get(user__username="alice")

    def test_another_user_cannot_open_a_private_post_by_its_id(self):
        response = sign_in("bob").get(f"/posts/{self.post.id}/", follow=True)
        self.assertNotContains(response, "not for bob")

    def test_another_user_cannot_delete_it(self):
        self.assertEqual(sign_in("bob").post(f"/posts/{self.post.id}/delete/").status_code, 404)

    def test_another_user_cannot_publish_it(self):
        response = sign_in("bob").post(f"/posts/{self.post.id}/audience/", {"audience": "public"})
        self.assertEqual(response.status_code, 404)
        self.post.refresh_from_db()
        self.assertFalse(self.post.is_public)

    def test_another_user_cannot_comment_on_it(self):
        response = sign_in("bob").post(f"/posts/{self.post.id}/comments/", {"body": "hi"})
        self.assertEqual(response.status_code, 404)

    def test_another_user_cannot_like_it(self):
        self.assertEqual(sign_in("bob").post(f"/posts/{self.post.id}/like/").status_code, 404)

    def test_signed_out_visitors_are_sent_to_the_login_page(self):
        for url in ("/feed/", "/messages/", "/account/", "/lab/", "/friends/", "/u/alice/"):
            self.assertRedirects(Client().get(url), f"/login/?next={url}",
                                 fetch_redirect_response=False)

    def test_the_front_page_is_public_and_shows_nobody_s_posts(self):
        """Visitors get the front page; none of anyone's posts are on it."""
        response = Client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "landing.html")
        self.assertNotContains(response, "not for bob")
