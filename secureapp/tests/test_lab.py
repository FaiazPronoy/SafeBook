"""The lab pages make claims with numbers on them. These check the claims."""

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.test import TestCase

from secureapp.lab import _bmp, _padlock, _repeated_blocks, _xor

from .test_confidentiality import full_account, sign_in


class BlockModeTests(TestCase):
    def setUp(self):
        full_account("alice")
        self.client = sign_in("alice")

    def test_ecb_keeps_the_repeated_blocks_and_the_others_do_not(self):
        """This is the whole lesson of the page, so it is worth asserting."""
        plain = _padlock()
        key = os.urandom(32)

        ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        ecb_ct = ecb.update(plain) + ecb.finalize()
        cbc = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16))).encryptor()
        cbc_ct = cbc.update(plain) + cbc.finalize()

        plain_repeats = _repeated_blocks(plain)
        self.assertGreater(plain_repeats, 100)
        self.assertEqual(_repeated_blocks(ecb_ct), plain_repeats)
        self.assertLess(_repeated_blocks(cbc_ct), 5)

    def test_the_generated_bitmap_is_a_valid_bmp(self):
        data = _bmp(_padlock())
        self.assertEqual(data[:2], b"BM")
        self.assertEqual(int.from_bytes(data[2:6], "little"), len(data))

    def test_the_page_reports_what_it_measured(self):
        response = self.client.get("/lab/modes/")
        panels = {p["name"]: p for p in response.context["panels"]}
        self.assertEqual(panels["AES-ECB"]["repeats"], panels["Plaintext"]["repeats"])
        self.assertEqual(panels["AES-GCM"]["repeats"], 0)


class NonceReuseTests(TestCase):
    def setUp(self):
        full_account("alice")
        self.client = sign_in("alice")

    def test_a_repeated_nonce_gives_the_plaintext_away(self):
        response = self.client.post("/lab/nonce/", {
            "secret": "meet me at the north gate", "known": "the weather is quite mild!!"})
        self.assertTrue(response.context["recovered_exactly"])
        self.assertEqual(response.context["recovered"], response.context["secret"])

    def test_fresh_nonces_give_nothing_away(self):
        response = self.client.post("/lab/nonce/", {
            "secret": "meet me at the north gate", "known": "the weather is quite mild!!"})
        self.assertNotEqual(response.context["junk"], response.context["secret"])

    def test_xor_is_its_own_inverse(self):
        a, b = os.urandom(24), os.urandom(24)
        self.assertEqual(_xor(_xor(a, b), b), a)


class TamperLabTests(TestCase):
    def setUp(self):
        full_account("alice")
        self.client = sign_in("alice")

    def test_a_flipped_byte_fails_both_checks(self):
        response = self.client.post("/lab/tamper/", {"text": "the vault code is 4417", "byte": "3"})
        steps = response.context["steps"]
        self.assertFalse(steps[0]["ok"])          # the row MAC
        self.assertFalse(steps[1]["ok"])          # the GCM tag
        self.assertTrue(steps[2]["ok"])           # the untouched row still verifies

    def test_a_byte_index_past_the_end_wraps_instead_of_crashing(self):
        self.assertEqual(self.client.post("/lab/tamper/", {"byte": "99999"}).status_code, 200)

    def test_nonsense_in_the_byte_field_is_not_an_error_page(self):
        self.assertEqual(self.client.post("/lab/tamper/", {"byte": "abc"}).status_code, 200)


class KdfLabTests(TestCase):
    def setUp(self):
        full_account("alice")
        self.client = sign_in("alice")

    def test_the_slow_hashes_are_measurably_slower(self):
        rows = {r["name"]: r for r in self.client.get("/lab/kdf/").context["rows"]}
        self.assertGreater(rows["scrypt N=2^16"]["ms"], rows["MD5"]["ms"] * 1000)
        self.assertGreater(rows["Argon2id"]["ms"], rows["SHA-256"]["ms"] * 1000)


class TimingLabTests(TestCase):
    def setUp(self):
        full_account("alice")
        self.client = sign_in("alice")

    def test_the_hand_written_loop_leaks_and_compare_digest_does_not(self):
        rows = self.client.get("/lab/timing/").context["rows"]
        first, last = rows[0], rows[-1]
        self.assertGreater(last["loop"], first["loop"] * 1.5)
        self.assertLess(max(r["safe"] for r in rows), min(r["safe"] for r in rows) * 1.5)


class LabIsolationTests(TestCase):
    def test_the_lab_is_behind_the_login(self):
        from django.test import Client
        for url in ("/lab/", "/lab/modes/", "/lab/nonce/", "/lab/timing/",
                    "/lab/kdf/", "/lab/tamper/"):
            self.assertRedirects(Client().get(url), "/login/?next=" + url,
                                 fetch_redirect_response=False)

    def test_the_lab_writes_nothing_to_the_database(self):
        from secureapp.models import Message, Post
        full_account("alice")
        client = sign_in("alice")
        before = (Post.objects.count(), Message.objects.count())
        for url in ("/lab/modes/", "/lab/nonce/", "/lab/timing/", "/lab/kdf/", "/lab/tamper/"):
            client.get(url)
        self.assertEqual((Post.objects.count(), Message.objects.count()), before)
