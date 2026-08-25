import hmac, hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_mac_key_from_dek(dek: bytes) -> bytes:
    # Derive a distinct MAC key from DEK (context separates use)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"post-row-mac")
    return hkdf.derive(dek)

def row_mac(dek: bytes, payload: bytes) -> bytes:
    mac_key = derive_mac_key_from_dek(dek)
    return hmac.new(mac_key, payload, hashlib.sha256).digest()
