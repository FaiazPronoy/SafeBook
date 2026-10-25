import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16
KEY_LEN = 32

SCRYPT_N = 2 ** 16
SCRYPT_R = 8
SCRYPT_P = 1


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_wrapping_key(secret: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=bytes(salt), length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(secret.encode("utf-8"))
