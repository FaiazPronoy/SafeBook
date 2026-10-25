from keymgmt.services import get_active_kek

from .crypto import new_key, unwrap_key, wrap_key
from .pwdwrap import derive_wrapping_key, new_salt
from .rsa_utils import load_public_key_from_pem, rsa_unwrap_session_key, rsa_wrap_session_key

AAD_PRIVATE_DEK = b"envelope/private-dek"
AAD_RECOVERY_DEK = b"envelope/recovery-dek"
AAD_POST_KEY_OWNER = b"envelope/post-key/owner"
AAD_POST_KEY_PUBLIC = b"envelope/post-key/public"


def server_kek() -> bytes:
    return get_active_kek()[0]


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


def wrap_post_key_for_friend(post_key: bytes, friend) -> bytes:
    return rsa_wrap_session_key(load_public_key_from_pem(friend.public_key_pem.encode()), post_key)


def unwrap_post_key_as_friend(wrapped: bytes, private_key) -> bytes:
    return rsa_unwrap_session_key(private_key, bytes(wrapped))
