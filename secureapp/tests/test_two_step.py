import re

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client, TestCase

from secureapp import two_step
from secureapp.crypto import aead_encrypt
from secureapp.keyring import AAD_EMAIL
from secureapp.tests.test_auth import PASSWORD, make_account

Account = get_user_model()


def code_in(message) -> str:
    return re.search(r"\b(\d{6})\b", message.subject).group(1)


class TwoStepTests(TestCase):
    def setUp(self):
        self.user, dek, _ = make_account("alice")
        self.user.email_nonce, self.user.email_ct = aead_encrypt(dek, b"alice@example.com", AAD_EMAIL)
        self.user.save()
        self.client = Client()

    def sign_in(self, client=None):
        return (client or self.client).post("/login/", {"username": "alice", "password": PASSWORD})

    def turn_on(self):
        self.sign_in()
        self.client.post("/account/two-step/start/")
        self.client.post("/account/two-step/confirm/", {"code": code_in(mail.outbox[-1])})
        self.client.post("/logout/")
        self.user.refresh_from_db()

    def test_it_is_off_by_default_and_sign_in_needs_no_code(self):
        response = self.sign_in()
        self.assertRedirects(response, "/", fetch_redirect_response=False)
        self.assertEqual(len(mail.outbox), 0)

    def test_turning_it_on_needs_the_emailed_code(self):
        self.sign_in()
        self.client.post("/account/two-step/start/")
        self.assertEqual(mail.outbox[-1].to, ["alice@example.com"])
        self.client.post("/account/two-step/confirm/", {"code": "000000"})
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_step)
        self.client.post("/account/two-step/confirm/", {"code": code_in(mail.outbox[-1])})
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_step)

    def test_the_password_alone_no_longer_signs_in(self):
        self.turn_on()
        response = self.sign_in()
        self.assertRedirects(response, "/login/verify/", fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(self.client.get("/account/").status_code, 302)

    def test_the_right_code_finishes_signing_in_and_unlocks_the_key(self):
        self.turn_on()
        self.sign_in()
        response = self.client.post("/login/verify/", {"code": code_in(mail.outbox[-1])})
        self.assertRedirects(response, "/", fetch_redirect_response=False)
        self.assertEqual(self.client.get("/account/").status_code, 200)

    def test_a_code_works_only_once(self):
        self.turn_on()
        self.sign_in()
        code = code_in(mail.outbox[-1])
        self.client.post("/login/verify/", {"code": code})
        self.client.post("/logout/")
        other = Client()
        self.sign_in(other)
        response = other.post("/login/verify/", {"code": code})
        self.assertNotIn("_auth_user_id", other.session)
        self.assertEqual(response.status_code, 200)

    def test_too_many_wrong_codes_send_you_back_to_the_start(self):
        self.turn_on()
        self.sign_in()
        right = code_in(mail.outbox[-1])
        wrong = "111111" if right != "111111" else "222222"
        for _ in range(two_step.MAX_TRIES - 1):
            self.assertEqual(self.client.post("/login/verify/", {"code": wrong}).status_code, 200)
        response = self.client.post("/login/verify/", {"code": wrong})
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
        response = self.client.post("/login/verify/", {"code": right})
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_an_expired_code_is_refused(self):
        self.turn_on()
        self.sign_in()
        code = code_in(mail.outbox[-1])
        session = self.client.session
        session[two_step.LOGIN_SLOT] = {**session[two_step.LOGIN_SLOT], "expires": 0}
        session.save()
        response = self.client.post("/login/verify/", {"code": code})
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_the_code_page_without_a_password_first_goes_back_to_sign_in(self):
        response = self.client.get("/login/verify/")
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)

    def test_a_new_code_has_to_wait_a_minute(self):
        self.turn_on()
        self.sign_in()
        sent = len(mail.outbox)
        self.client.post("/login/verify/", {"action": "resend"})
        self.assertEqual(len(mail.outbox), sent)

    def test_turning_it_off_needs_the_password(self):
        self.turn_on()
        self.sign_in()
        self.client.post("/login/verify/", {"code": code_in(mail.outbox[-1])})
        self.client.post("/account/two-step/off/", {"password": "Wrong#Password2026"})
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_step)
        self.client.post("/account/two-step/off/", {"password": PASSWORD})
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_step)

    def test_the_stored_code_is_not_the_code_itself(self):
        self.sign_in()
        self.client.post("/account/two-step/start/")
        stored = self.client.session[two_step.SETUP_SLOT]
        self.assertNotIn(code_in(mail.outbox[-1]), str(stored))

    def test_demo_accounts_cannot_turn_it_on(self):
        demo, dek, _ = make_account("nusrat")
        demo.email_nonce, demo.email_ct = aead_encrypt(dek, b"nusrat@safebook.test", AAD_EMAIL)
        demo.save()
        self.client.post("/login/", {"username": "nusrat", "password": PASSWORD})
        self.client.post("/account/two-step/start/")
        self.assertEqual(len(mail.outbox), 0)
        demo.refresh_from_db()
        self.assertFalse(demo.two_step)
