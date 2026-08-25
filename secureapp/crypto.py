import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD_DEK_WRAP = b"dek-wrap"

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    aes = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aead_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, aad)

def wrap_dek_with_kek(dek: bytes, kek: bytes) -> bytes:
    # Use AES-GCM as a simple key wrapper
    n, ct = aead_encrypt(kek, dek, AAD_DEK_WRAP)
    return n + ct

def unwrap_dek_with_kek(wrapped: bytes, kek: bytes) -> bytes:
    n, ct = wrapped[:12], wrapped[12:]
    return aead_decrypt(kek, n, ct, AAD_DEK_WRAP)



