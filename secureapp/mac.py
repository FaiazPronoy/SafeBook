"""HMAC-SHA256 over a stored row.

AES-GCM already authenticates each field on its own. What it cannot do is
say that these particular fields belong together, in this row, owned by this
user. Without that, a row's ciphertext columns can be swapped for another
row's and every individual GCM tag still verifies.

So the MAC covers a canonical encoding of the whole tuple, keyed by a
subkey derived from the row key with an HKDF context that names the table.
"""
import hmac
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CTX_POST = b"safebook/post-row-mac/v1"
CTX_MESSAGE = b"safebook/message-row-mac/v2"
CTX_COMMENT = b"safebook/comment-row-mac/v1"


def derive_mac_key(row_key: bytes, context: bytes) -> bytes:
    """A MAC subkey that cannot be used to decrypt, and does not cross tables."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=context).derive(bytes(row_key))


def _canonical(parts) -> bytes:
    """Length-prefix every field so ("ab","c") cannot collide with ("a","bc")."""
    out = bytearray()
    for part in parts:
        part = b"" if part is None else bytes(part)
        out += len(part).to_bytes(4, "big") + part
    return bytes(out)


def row_mac(row_key: bytes, context: bytes, *parts) -> bytes:
    return hmac.new(derive_mac_key(row_key, context), _canonical(parts),
                    hashlib.sha256).digest()


def mac_ok(expected, row_key: bytes, context: bytes, *parts) -> bool:
    """Constant time, so a wrong MAC cannot be guessed one byte at a time."""
    if expected is None:
        return False
    return hmac.compare_digest(bytes(expected), row_mac(row_key, context, *parts))
