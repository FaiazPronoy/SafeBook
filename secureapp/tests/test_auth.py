import time

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from secureapp import keys
from secureapp.auth_utils import MAX_FAILURES, check_credentials, is_locked_out
from secureapp.crypto import new_key
from secureapp.models import LoginAttempt
from secureapp.recovery import new_recovery_code, normalise

Account = get_user_model()
PASSWORD = "Right#Password2026"


def make_account(username="alice", password=PASSWORD):
    user = Account.objects.create_user(username=username, password=password)
    dek = new_key()
    user.pdek_salt, user.pdek_wrapped = keys.seal_private_dek(dek, password)
    code = new_recovery_code()
    user.rec_salt, user.rec_wrapped = keys.seal_recovery_dek(dek, normalise(code))
    user.save()
    return user, dek, code


class CredentialTests(TestCase):
    def setUp(self):
        self.user, _, _ = make_account()

    def test_the_right_password_returns_the_user(self):
        self.assertEqual(check_credentials("alice", PASSWORD), self.user)

    def test_the_wrong_password_returns_nothing(self):
        self.assertIsNone(check_credentials("alice", "Wrong#Password2026"))

    def test_an_unknown_username_returns_nothing(self):
        self.assertIsNone(check_credentials("nobody", PASSWORD))

    def test_an_unknown_username_costs_the_same_as_a_wrong_password(self):
        def fastest_ms(username):
            samples = []
            for _ in range(7):
                start = time.perf_counter()
                check_credentials(username, "Wrong#Password2026")
                samples.append((time.perf_counter() - start) * 1000)
            return min(samples)

        known = fastest_ms("alice")
        unknown = fastest_ms("no_such_account_here")
        ratio = max(known, unknown) / min(known, unknown)
        self.assertLess(ratio, 2.5, f"known {known:.1f}ms vs unknown {unknown:.1f}ms")


class LockoutTests(TestCase):
    def setUp(self):
        make_account()
        self.client = Client()

    def test_five_failures_lock_the_account(self):
        for _ in range(MAX_FAILURES):
            self.client.post("/login/", {"username": "alice", "password": "nope"})
        self.assertTrue(is_locked_out("alice"))

    def test_a_locked_account_rejects_the_right_password_too(self):
        for _ in range(MAX_FAILURES):
            self.client.post("/login/", {"username": "alice", "password": "nope"})
        response = self.client.post("/login/", {"username": "alice", "password": PASSWORD})
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_a_username_that_does_not_exist_is_throttled_the_same_way(self):
        for _ in range(MAX_FAILURES):
            self.client.post("/login/", {"username": "ghost", "password": "nope"})
        self.assertTrue(is_locked_out("ghost"))

    def test_signing_in_clears_the_count(self):
        for _ in range(MAX_FAILURES - 1):
            self.client.post("/login/", {"username": "alice", "password": "nope"})
        self.client.post("/login/", {"username": "alice", "password": PASSWORD})
        self.assertFalse(is_locked_out("alice"))

    def test_the_wording_is_the_same_for_a_real_and_a_made_up_username(self):
        def message_for(username):
            response = self.client.post(
                "/login/", {"username": username, "password": "Wrong#Password2026"})
            return [str(m) for m in response.context["messages"]]

        self.assertEqual(message_for("alice"), message_for("not_a_real_user"))

    def test_attempts_are_recorded_for_the_owner_to_see(self):
        self.client.post("/login/", {"username": "alice", "password": "nope"})
        self.client.post("/login/", {"username": "alice", "password": PASSWORD})
        rows = LoginAttempt.objects.filter(username="alice")
        self.assertEqual(rows.filter(successful=True).count(), 1)


class LogoutTests(TestCase):
    def setUp(self):
        make_account()
        self.client = Client()
        self.client.post("/login/", {"username": "alice", "password": PASSWORD})

    def test_logout_needs_a_post(self):
        self.assertEqual(self.client.get("/logout/").status_code, 405)

    def test_logout_clears_the_key_from_the_session(self):
        from secureapp.session_keys import SESSION_FIELD
        self.client.post("/logout/")
        self.assertNotIn(SESSION_FIELD, self.client.session)

    def test_an_idle_lock_says_why_it_happened(self):
        page = self.client.post("/logout/", {"reason": "idle"}, follow=True)
        self.assertContains(page, "Locked after 15 minutes")
        self.assertNotIn("_auth_user_id", self.client.session)


class DemoFileTests(TestCase):
    def test_no_demo_files_on_an_empty_database(self):
        self.assertEqual(Client().get("/login/").context["demo"], [])

    def test_a_demo_file_signs_in_as_that_person(self):
        from secureapp.demo import PEOPLE
        username, password = PEOPLE[0][0], PEOPLE[0][1]
        make_account(username, password)
        demo = Client().get("/login/").context["demo"]
        self.assertEqual([d["username"] for d in demo], [username])
        client = Client()
        client.post("/login/", {"username": username, "password": password})
        self.assertEqual(client.get("/").status_code, 200)
        self.assertIn("_auth_user_id", client.session)
