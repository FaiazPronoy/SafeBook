import base64

from .crypto import aead_decrypt, aead_encrypt, new_key

COOKIE_NAME = "sb_skey"
SESSION_FIELD = "wrapped_private_dek"
AAD = b"session.private_dek"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def arm_session(request, response, dek: bytes) -> None:
    session_key = new_key()
    nonce, ct = aead_encrypt(session_key, dek, AAD)
    request.session[SESSION_FIELD] = _b64(nonce + ct)
    response.set_cookie(
        COOKIE_NAME,
        _b64(session_key),
        httponly=True,
        samesite="Lax",
        secure=not request.get_host().startswith(("127.0.0.1", "localhost")),
        max_age=request.session.get_expiry_age(),
    )


def read_private_dek(request) -> bytes | None:
    blob = request.session.get(SESSION_FIELD)
    cookie = request.COOKIES.get(COOKIE_NAME)
    if not blob or not cookie:
        return None
    try:
        session_key = base64.b64decode(cookie)
        raw = base64.b64decode(blob)
        return aead_decrypt(session_key, raw[:12], raw[12:], AAD)
    except Exception:
        return None


def disarm_session(request, response) -> None:
    request.session.pop(SESSION_FIELD, None)
    response.delete_cookie(COOKIE_NAME)
