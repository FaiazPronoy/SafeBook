"""The crypto layer on its own, with no database and no views."""

import os

from django.test import SimpleTestCase

from secureapp.crypto import aead_decrypt, aead_encrypt, new_key, unwrap_key, wrap_key
from secureapp.mac import CTX_MESSAGE, CTX_POST, mac_ok, row_mac
from secureapp.pwdwrap import SCRYPT_N, derive_wrapping_key, new_salt
from secureapp.recovery import ALPHABET, entropy_bits, new_recovery_code, normalise


class AeadTests(SimpleTestCase):
    def test_round_trip(self):
        key = new_key()
        nonce, ct = aead_encrypt(key, b"hello", b"col.a")
        self.assertEqual(aead_decrypt(key, nonce, ct, b"col.a"), b"hello")

    def test_a_different_column_will_not_open_it(self):
        """A ciphertext moved from one column to another must stop decrypting."""
        key = new_key()
        nonce, ct = aead_encrypt(key, b"hello", b"post.body")
        with self.assertRaises(Exception):
            aead_decrypt(key, nonce, ct, b"message.body")

    def test_every_encryption_draws_a_fresh_nonce(self):
        key = new_key()
        nonces = {aead_encrypt(key, b"same text", b"x")[0] for _ in range(200)}
        self.assertEqual(len(nonces), 200)

    def test_a_flipped_bit_is_rejected(self):
        key = new_key()
        nonce, ct = aead_encrypt(key, b"the vault code is 4417", b"x")
        broken = bytearray(ct)
        broken[3] ^= 0x01
        with self.assertRaises(Exception):
            aead_decrypt(key, nonce, bytes(broken), b"x")

    def test_wrapping_a_key_in_another(self):
        inner, outer = new_key(), new_key()
        self.assertEqual(unwrap_key(wrap_key(inner, outer), outer), inner)

    def test_the_wrong_wrapping_key_does_not_open_it(self):
        inner = new_key()
        blob = wrap_key(inner, new_key())
        with self.assertRaises(Exception):
            unwrap_key(blob, new_key())


class MacTests(SimpleTestCase):
    def setUp(self):
        self.key = new_key()

    def test_it_verifies_what_it_signed(self):
        tag = row_mac(self.key, CTX_POST, b"7", b"nonce", b"ct")
        self.assertTrue(mac_ok(tag, self.key, CTX_POST, b"7", b"nonce", b"ct"))

    def test_a_post_mac_does_not_verify_as_a_message_mac(self):
        """The HKDF context keeps the two tables from sharing a key."""
        tag = row_mac(self.key, CTX_POST, b"7", b"nonce", b"ct")
        self.assertFalse(mac_ok(tag, self.key, CTX_MESSAGE, b"7", b"nonce", b"ct"))

    def test_a_row_cannot_be_moved_to_another_owner(self):
        tag = row_mac(self.key, CTX_POST, b"7", b"nonce", b"ct")
        self.assertFalse(mac_ok(tag, self.key, CTX_POST, b"8", b"nonce", b"ct"))

    def test_fields_cannot_be_regrouped(self):
        """Length prefixing stops ("ab","c") colliding with ("a","bc")."""
        tag = row_mac(self.key, CTX_POST, b"ab", b"c")
        self.assertFalse(mac_ok(tag, self.key, CTX_POST, b"a", b"bc"))

    def test_a_missing_mac_is_a_failure_not_a_pass(self):
        self.assertFalse(mac_ok(None, self.key, CTX_POST, b"x"))

    def test_the_mac_key_is_not_the_row_key(self):
        from secureapp.mac import derive_mac_key
        self.assertNotEqual(derive_mac_key(self.key, CTX_POST), self.key)


class PasswordKeyTests(SimpleTestCase):
    def test_same_password_and_salt_gives_the_same_key(self):
        salt = new_salt()
        self.assertEqual(derive_wrapping_key("hunter2", salt),
                         derive_wrapping_key("hunter2", salt))

    def test_a_different_salt_gives_a_different_key(self):
        """Two people with the same password must not share a key."""
        self.assertNotEqual(derive_wrapping_key("hunter2", new_salt()),
                            derive_wrapping_key("hunter2", new_salt()))

    def test_the_cost_parameter_is_the_one_we_think_it_is(self):
        self.assertEqual(SCRYPT_N, 2 ** 16)


class RecoveryCodeTests(SimpleTestCase):
    def test_the_alphabet_has_no_lookalike_characters(self):
        for ch in "01OIL8B":
            if ch in "01OIL":
                self.assertNotIn(ch, ALPHABET)

    def test_it_is_worth_about_99_bits(self):
        self.assertGreater(entropy_bits(), 95)

    def test_codes_do_not_repeat(self):
        self.assertEqual(len({new_recovery_code() for _ in range(500)}), 500)

    def test_it_can_be_typed_back_carelessly(self):
        code = new_recovery_code()
        self.assertEqual(normalise(code.lower().replace("-", " ")), normalise(code))
