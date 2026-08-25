"""Which key protects what.

SafeBook keeps two data keys per user, because two different things are
being defended against.

    private DEK   unwrapped only by the user's password (scrypt) or their
                  recovery code. Protects the things the server has no
                  business reading: email, phone, the RSA private key, the
                  contents of private posts and of messages. Nobody holding
                  the database and the .env file can read any of it.

    public DEK    wrapped by the server KEK from .env, so the server can use
                  it without the user present. Protects public posts, which
                  have to be rendered for other people. The threat here is
                  someone walking off with the database file, not the server
                  operator.

Every post gets its own random content key. That key is wrapped once for the
author under the private DEK, and a second time under the server KEK when
the post is public. Making a post public or private adds or removes a 60
byte wrapped key and never re-encrypts the post itself - which is the whole
reason for wrapping keys inside keys.
"""

import base64

from django.conf import settings

from .crypto import new_key, unwrap_key, wrap_key
from .pwdwrap import derive_wrapping_key, new_salt

AAD_PRIVATE_DEK = b"envelope/private-dek"
AAD_RECOVERY_DEK = b"envelope/recovery-dek"
AAD_POST_KEY_OWNER = b"envelope/post-key/owner"
AAD_POST_KEY_PUBLIC = b"envelope/post-key/public"


def server_kek() -> bytes:
    kek = base64.b64decode(settings.APP_KEK_BASE64)
    if len(kek) not in (16, 24, 32):
        raise RuntimeError(
            f"APP_KEK_BASE64 decodes to {len(kek)} bytes; it must be 16, 24 or 32."
        )
    return kek


# --- the private DEK, held by the password -----------------------------

def seal_private_dek(dek: bytes, password: str) -> tuple[bytes, bytes]:
    salt = new_salt()
    return salt, wrap_key(dek, derive_wrapping_key(password, salt), AAD_PRIVATE_DEK)


def open_private_dek(wrapped: bytes, salt: bytes, password: str) -> bytes:
    return unwrap_key(wrapped, derive_wrapping_key(password, salt), AAD_PRIVATE_DEK)


def seal_recovery_dek(dek: bytes, code: str) -> tuple[bytes, bytes]:
    salt = new_salt()
    return salt, wrap_key(dek, derive_wrapping_key(code, salt), AAD_RECOVERY_DEK)


def open_recovery_dek(wrapped: bytes, salt: bytes, code: str) -> bytes:
    return unwrap_key(wrapped, derive_wrapping_key(code, salt), AAD_RECOVERY_DEK)


# --- per-post content keys ---------------------------------------------

def new_post_key() -> bytes:
    return new_key()


def wrap_post_key_for_owner(post_key: bytes, private_dek: bytes) -> bytes:
    return wrap_key(post_key, private_dek, AAD_POST_KEY_OWNER)


def unwrap_post_key_for_owner(wrapped: bytes, private_dek: bytes) -> bytes:
    return unwrap_key(wrapped, private_dek, AAD_POST_KEY_OWNER)


def wrap_post_key_for_public(post_key: bytes) -> bytes:
    return wrap_key(post_key, server_kek(), AAD_POST_KEY_PUBLIC)


def unwrap_post_key_for_public(wrapped: bytes) -> bytes:
    return unwrap_key(wrapped, server_kek(), AAD_POST_KEY_PUBLIC)
