import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
KEY_LEN = 32

AAD_DEK_WRAP = b"dek-wrap"


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_LEN)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(bytes(nonce), bytes(ct), aad)


def wrap_key(inner: bytes, wrapping_key: bytes, aad: bytes = AAD_DEK_WRAP) -> bytes:
    nonce, ct = aead_encrypt(wrapping_key, inner, aad)
    return nonce + ct


def unwrap_key(blob: bytes, wrapping_key: bytes, aad: bytes = AAD_DEK_WRAP) -> bytes:
    blob = bytes(blob)
    return aead_decrypt(wrapping_key, blob[:NONCE_LEN], blob[NONCE_LEN:], aad)


def new_key() -> bytes:
    return os.urandom(KEY_LEN)
