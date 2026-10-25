"""AES-GCM, and the two ways this app wraps a key.

Everything encrypted here is AEAD: the nonce and the ciphertext travel
together and every call passes an `aad` string naming the column it belongs
to, so a ciphertext lifted out of one column and dropped into another will
not decrypt.
"""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12          # 96 bits, the size AES-GCM is defined for
KEY_LEN = 32            # AES-256

AAD_DEK_WRAP = b"dek-wrap"


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_LEN)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(bytes(nonce), bytes(ct), aad)


def wrap_key(inner: bytes, wrapping_key: bytes, aad: bytes = AAD_DEK_WRAP) -> bytes:
    """Encrypt one key under another and return nonce||ciphertext as one blob."""
    nonce, ct = aead_encrypt(wrapping_key, inner, aad)
    return nonce + ct


def unwrap_key(blob: bytes, wrapping_key: bytes, aad: bytes = AAD_DEK_WRAP) -> bytes:
    blob = bytes(blob)
    return aead_decrypt(wrapping_key, blob[:NONCE_LEN], blob[NONCE_LEN:], aad)


def new_key() -> bytes:
    return os.urandom(KEY_LEN)
