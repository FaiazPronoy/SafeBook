"""Turning a password (or a recovery code) into a key-wrapping key.

scrypt, not a plain hash. The point of the memory cost is that an attacker
who steals the database cannot try billions of candidate passwords a second
on a graphics card the way they could against SHA-256.

These parameters are not the same job as the Argon2 hash Django keeps in
`password`. That one answers "is this the right password". This one produces
32 bytes that unlock the user's data, and it is never stored anywhere.
"""

import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16
KEY_LEN = 32

# N is the knob that costs an attacker the most, so it is written out here
# rather than buried in a call. At 2**16 this needs 64 MB and takes about
# 280 ms per guess on my laptop - slow enough to matter to someone working
# through a wordlist, short enough that a login still feels immediate.
SCRYPT_N = 2 ** 16
SCRYPT_R = 8
SCRYPT_P = 1


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_wrapping_key(secret: str, salt: bytes) -> bytes:
    """The key that wraps a user's private DEK. Never stored, only derived."""
    kdf = Scrypt(salt=bytes(salt), length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(secret.encode("utf-8"))
