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


def arm_session(request, response, dek: bytes) -> None:
    """Called once, at login. Puts half the secret in each place."""
    session_key = new_key()
    nonce, ct = aead_encrypt(session_key, dek, AAD)
    request.session[SESSION_FIELD] = _b64(nonce + ct)
    response.set_cookie(
        COOKIE_NAME,
        _b64(session_key),
        httponly=True,          # javascript on the page must not be able to read it
        samesite="Lax",
        secure=not request.get_host().startswith(("127.0.0.1", "localhost")),
        max_age=request.session.get_expiry_age(),
    )


def read_private_dek(request) -> bytes | None:
    """The DEK for this request, or None if either half is missing."""
    blob = request.session.get(SESSION_FIELD)
    cookie = request.COOKIES.get(COOKIE_NAME)
    if not blob or not cookie:
        return None
    try:
        session_key = base64.b64decode(cookie)
        raw = base64.b64decode(blob)
        return aead_decrypt(session_key, raw[:12], raw[12:], AAD)
    except Exception:
        # a tampered cookie or a session from a previous key - treat it as
        # simply not being logged in rather than as an error to explain
        return None


def disarm_session(request, response) -> None:
    request.session.pop(SESSION_FIELD, None)
    response.delete_cookie(COOKIE_NAME)
