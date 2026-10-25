import hmac
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CTX_POST = b"safebook/post-row-mac/v1"
CTX_MESSAGE = b"safebook/message-row-mac/v2"
CTX_COMMENT = b"safebook/comment-row-mac/v1"


def derive_mac_key(row_key: bytes, context: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=context).derive(bytes(row_key))


def _canonical(parts) -> bytes:
    out = bytearray()
    for part in parts:
        part = b"" if part is None else bytes(part)
        out += len(part).to_bytes(4, "big") + part
    return bytes(out)


def row_mac(row_key: bytes, context: bytes, *parts) -> bytes:
    return hmac.new(derive_mac_key(row_key, context), _canonical(parts),
                    hashlib.sha256).digest()


def mac_ok(expected, row_key: bytes, context: bytes, *parts) -> bool:
    if expected is None:
        return False
    return hmac.compare_digest(bytes(expected), row_mac(row_key, context, *parts))
