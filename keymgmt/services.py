"""Reading and checking the server KEK.

The KEK never leaves this process and never touches the database. It comes
from the environment, wraps the content key of every public post, and can be
replaced without re-encrypting a single post - see `rotate_kek`.
"""
import base64

from django.conf import settings

VALID_KEY_SIZES = (16, 24, 32)


def get_active_kek() -> tuple[bytes, int]:
    """The KEK in use right now, and the id recorded alongside what it wraps."""
    b64 = getattr(settings, "APP_KEK_BASE64", None)
    if not b64:
        raise RuntimeError(
            "APP_KEK_BASE64 is not set. Copy .env.example to .env and put a "
            "fresh key in it - `python manage.py new_kek` prints one."
        )
    try:
        kek = base64.b64decode(b64, validate=True)
    except Exception as exc:
        raise RuntimeError("APP_KEK_BASE64 is not valid base64.") from exc

    if len(kek) not in VALID_KEY_SIZES:
        raise RuntimeError(
            f"APP_KEK_BASE64 decodes to {len(kek)} bytes; AES needs 16, 24 or 32."
        )
    return kek, int(getattr(settings, "KEYMGMT_ACTIVE_KEK_ID", 1))
