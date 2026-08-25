"""A row that has been altered must not be shown. Not shown with a warning
beside it - not shown."""

from django.test import TestCase

from secureapp.models import Message, Post

from .test_auth import PASSWORD
from .test_confidentiality import full_account, sign_in


class TamperedPostTests(TestCase):
    def setUp(self):
        full_account("alice")
        self.client = sign_in("alice")
        self.client.post("/posts/new/",
                         {"title": "Payroll", "body": "salary is 90000", "is_public": "on"})
        self.post = Post.objects.get(user__username="alice")

    def _flip(self, field):
        raw = bytearray(getattr(self.post, field))
        raw[0] ^= 0x01
        setattr(self.post, field, bytes(raw))
        self.post.save()

    def test_a_flipped_body_is_not_shown_to_the_owner(self):
        self._flip("body_ct")
        response = self.client.get(f"/posts/{self.post.id}/", follow=True)
        self.assertNotContains(response, "salary is 90000")
        self.assertContains(response, "could not be opened")

    def test_a_flipped_body_is_dropped_from_the_feed(self):
        self._flip("body_ct")
        self.assertNotContains(sign_in("alice").get("/feed/"), "Payroll")

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

    def test_the_dashboard_counts_the_rows_it_could_not_verify(self):
        self._flip("title_ct")
        response = self.client.get("/")
        self.assertEqual(response.context["unreadable"], 1)

    def test_a_row_swapped_onto_another_owner_does_not_verify(self):
        """The MAC covers the owner id, so a row cannot be re-homed."""
        bob, _, _ = full_account("bob")
        self.post.user = bob
        self.post.save()
        self.assertNotContains(sign_in("bob").get("/feed/"), "Payroll")


class TamperedMessageTests(TestCase):
    def setUp(self):
        full_account("alice")
        full_account("bob")
        sender = sign_in("alice")
        sender.post("/messages/new/",
                    {"to": "bob", "title": "Handover", "body": "the door code is 8890"})
        self.message = Message.objects.get()
        self.reader = sign_in("bob")

    def test_a_message_arrives_intact(self):
        self.assertContains(self.reader.get(f"/messages/{self.message.id}/"),
                            "the door code is 8890")

    def test_a_flipped_body_is_not_shown(self):
        raw = bytearray(self.message.body_ct)
        raw[0] ^= 0x01
        self.message.body_ct = bytes(raw)
        self.message.save()
        response = self.reader.get(f"/messages/{self.message.id}/", follow=True)
        self.assertNotContains(response, "the door code is 8890")
        self.assertContains(response, "could not be opened")

    def test_a_message_cannot_be_read_by_anyone_else(self):
        full_account("carol")
        response = sign_in("carol").get(f"/messages/{self.message.id}/", follow=True)
        self.assertNotContains(response, "the door code is 8890")

    def test_the_sender_keeps_a_readable_copy(self):
        self.assertContains(sign_in("alice").get("/messages/sent/"), "Handover")

    def test_an_anonymous_message_keeps_no_sender_copy(self):
        alice = sign_in("alice")
        alice.post("/messages/new/", {"to": "bob", "title": "Tip off",
                                      "body": "look at the ledger", "anonymous": "on"})
        anonymous = Message.objects.get(is_anonymous=True)
        self.assertIsNone(anonymous.key_for_sender)
        self.assertIsNone(anonymous.sender)
        self.assertNotContains(alice.get("/messages/sent/"), "Tip off")

    def test_the_recipient_is_not_told_who_sent_it(self):
        alice = sign_in("alice")
        alice.post("/messages/new/", {"to": "bob", "title": "Tip off",
                                      "body": "look at the ledger", "anonymous": "on"})
        rows = self.reader.get("/messages/").context["inbox"]
        anonymous = next(row for row in rows if row["title"] == "Tip off")
        named = next(row for row in rows if row["title"] == "Handover")
        self.assertEqual(anonymous["sender"], "Anonymous")
        self.assertEqual(named["sender"], "alice")
