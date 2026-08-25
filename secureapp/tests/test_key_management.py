"""Changing a password, using a recovery code, rotating the server key.

All three are the same idea: rewrite an envelope, leave the data alone.
"""

import base64
import os
from io import StringIO

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase, override_settings

from secureapp import keys
from secureapp.models import Post

from .test_auth import PASSWORD
from .test_confidentiality import full_account, sign_in

Account = get_user_model()
NEW_PASSWORD = "Second#Password2026"


def signed_in_as(username, password):
    client = Client()
    client.post("/login/", {"username": username, "password": password})
    return client


class PasswordChangeTests(TestCase):
    def setUp(self):
        self.alice, self.dek, _ = full_account("alice")
        self.client = sign_in("alice")
        self.client.post("/posts/new/", {"title": "Keep me", "body": "still readable after"})
        self.post = Post.objects.get(user=self.alice)

    def _change(self, current=PASSWORD):
        return self.client.post("/account/password/", {
            "current": current, "new1": NEW_PASSWORD, "new2": NEW_PASSWORD})

    def test_changing_the_password_does_not_re_encrypt_anything(self):
        before_body = bytes(self.post.body_ct)
        before_key = bytes(self.post.key_owner)
        self._change()
        self.post.refresh_from_db()
        self.assertEqual(bytes(self.post.body_ct), before_body)
        self.assertEqual(bytes(self.post.key_owner), before_key)

    def test_the_envelope_is_the_only_thing_rewritten(self):
        before = bytes(self.alice.pdek_wrapped)
        self._change()
        self.alice.refresh_from_db()
        self.assertNotEqual(bytes(self.alice.pdek_wrapped), before)
        self.assertEqual(
            keys.open_private_dek(self.alice.pdek_wrapped, self.alice.pdek_salt, NEW_PASSWORD),
            self.dek)

    def test_the_old_password_stops_working(self):
        self._change()
        stale = signed_in_as("alice", PASSWORD)
        self.assertRedirects(stale.get("/"), "/login/?next=/", fetch_redirect_response=False)

    def test_the_posts_are_still_readable_afterwards(self):
        self._change()
        after = signed_in_as("alice", NEW_PASSWORD)
        self.assertContains(after.get("/posts/%d/" % self.post.id), "still readable after")

    def test_the_wrong_current_password_changes_nothing(self):
        before = bytes(self.alice.pdek_wrapped)
        self._change(current="not-it")
        self.alice.refresh_from_db()
        self.assertEqual(bytes(self.alice.pdek_wrapped), before)


class RecoveryTests(TestCase):
    def setUp(self):
        self.alice, self.dek, self.code = full_account("alice")
        client = sign_in("alice")
        client.post("/posts/new/", {"title": "Before", "body": "survives the reset"})
        self.post = Post.objects.get(user=self.alice)
        self.visitor = Client()

    def _recover(self, code=None, new=NEW_PASSWORD, username="alice"):
        return self.visitor.post("/recover/", {
            "username": username, "code": code or self.code, "new1": new, "new2": new})

    def test_the_code_opens_the_account_and_sets_a_new_password(self):
        self._recover()
        after = signed_in_as("alice", NEW_PASSWORD)
        self.assertContains(after.get("/posts/%d/" % self.post.id), "survives the reset")

    def test_the_data_key_is_unchanged_by_a_recovery(self):
        self._recover()
        self.alice.refresh_from_db()
        self.assertEqual(
            keys.open_private_dek(self.alice.pdek_wrapped, self.alice.pdek_salt, NEW_PASSWORD),
            self.dek)

    def test_a_used_code_does_not_work_twice(self):
        self._recover()
        response = self._recover(new="Third#Password2026")
        self.assertContains(response, "do not match")

    def test_a_wrong_code_changes_nothing(self):
        before = bytes(self.alice.pdek_wrapped)
        self._recover(code="AAAAA-BBBBB-CCCCC-DDDDD")
        self.alice.refresh_from_db()
        self.assertEqual(bytes(self.alice.pdek_wrapped), before)

    def test_a_username_that_does_not_exist_says_the_same_thing(self):
        self.assertContains(self._recover(username="ghost"), "do not match")


class KekRotationTests(TestCase):
    def setUp(self):
        self.alice, self.dek, _ = full_account("alice")
        client = sign_in("alice")
        client.post("/posts/new/",
                    {"title": "Published", "body": "readable by the feed", "is_public": "on"})
        self.post = Post.objects.get(user=self.alice)
        self.new_kek = base64.b64encode(os.urandom(32)).decode()

    def _rotate(self, **extra):
        out = StringIO()
        call_command("rotate_kek", new_kek_b64=self.new_kek, new_kek_id=2, stdout=out, **extra)
        return out.getvalue()

    def test_rotation_rewraps_the_key_and_leaves_the_post_alone(self):
        before = bytes(self.post.body_ct)
        wrapped_before = bytes(self.post.key_public)
        self._rotate()
        self.post.refresh_from_db()
        self.assertEqual(bytes(self.post.body_ct), before)
        self.assertNotEqual(bytes(self.post.key_public), wrapped_before)
        self.assertEqual(self.post.key_public_kek_id, 2)

    def test_the_new_kek_opens_what_the_old_one_did(self):
        original = keys.unwrap_post_key_for_public(self.post.key_public)
        self._rotate()
        self.post.refresh_from_db()
        with override_settings(APP_KEK_BASE64=self.new_kek):
            self.assertEqual(keys.unwrap_post_key_for_public(self.post.key_public), original)

    def test_a_dry_run_writes_nothing(self):
        before = bytes(self.post.key_public)
        output = self._rotate(dry_run=True)
        self.post.refresh_from_db()
        self.assertEqual(bytes(self.post.key_public), before)
        self.assertIn("would re-wrap", output)

    def test_rotating_to_the_same_key_is_refused(self):
        with self.assertRaises(CommandError):
            call_command("rotate_kek", new_kek_b64=settings.APP_KEK_BASE64,
                         new_kek_id=2, stdout=StringIO())

    def test_a_key_of_the_wrong_size_is_refused(self):
        with self.assertRaises(CommandError):
            call_command("rotate_kek", new_kek_b64=base64.b64encode(os.urandom(7)).decode(),
                         new_kek_id=2, stdout=StringIO())

    def test_private_posts_have_nothing_for_the_server_to_rotate(self):
        client = sign_in("alice")
        client.post("/posts/new/", {"title": "Kept back", "body": "no server key"})
        private = Post.objects.get(is_public=False)
        self.assertIsNone(private.key_public)
        self._rotate()
        private.refresh_from_db()
        self.assertIsNone(private.key_public)
