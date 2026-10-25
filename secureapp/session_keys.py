import base64

from .crypto import aead_decrypt, aead_encrypt, new_key

COOKIE_NAME = "sb_skey"
SESSION_FIELD = "wrapped_private_dek"
AAD = b"session.private_dek"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def arm_session(request, response, dek: bytes, field: str = SESSION_FIELD, cookie: str = COOKIE_NAME) -> None:
    session_key = new_key()
    nonce, ct = aead_encrypt(session_key, dek, AAD)
    request.session[field] = _b64(nonce + ct)
    response.set_cookie(
        cookie,
        _b64(session_key),
        httponly=True,
        samesite="Lax",
        secure=not request.get_host().startswith(("127.0.0.1", "localhost")),
        max_age=request.session.get_expiry_age(),
    )


def read_private_dek(request, field: str = SESSION_FIELD, cookie: str = COOKIE_NAME) -> bytes | None:
    blob = request.session.get(field)
    key = request.COOKIES.get(cookie)
    if not blob or not key:
        return None
    try:
        session_key = base64.b64decode(key)
        raw = base64.b64decode(blob)
        return aead_decrypt(session_key, raw[:12], raw[12:], AAD)
    except Exception:
        return None


def disarm_session(request, response, field: str = SESSION_FIELD, cookie: str = COOKIE_NAME) -> None:
    request.session.pop(field, None)
    response.delete_cookie(cookie)
