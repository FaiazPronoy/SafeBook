"""Holding the user's private DEK for the length of a login, without ever
writing it down anywhere one theft can reach.

The DEK is unwrapped from the password at login and is needed on every
request after that, so it has to live somewhere. Django's session table is
in the database, and the database is exactly what an attacker is assumed to
have taken. So it is split:

    the browser cookie holds a random 32 byte session wrapping key
    the session row holds the DEK encrypted under that key

Neither half is worth anything alone. A stolen database gives ciphertext
with no key; a stolen cookie gives a key with no ciphertext. Both together
compromise that one user, for as long as that one session lives.
"""
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
        httponly=True,          # javascript on the page must not be able to read it
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
        # a tampered cookie or a session from a previous key - treat it as
        # simply not being logged in rather than as an error to explain
        return None


def disarm_session(request, response, field: str = SESSION_FIELD, cookie: str = COOKIE_NAME) -> None:
    request.session.pop(field, None)
    response.delete_cookie(cookie)
