from .models import KeyEnvelope
from secureapp.keymgmt import generate_dek, wrap_dek, unwrap_dek
import base64
from django.conf import settings
from secureapp.crypto import wrap_dek_with_kek, unwrap_dek_with_kek  # AES-GCM helpers


def create_key_envelope_for_user(user, *, kek_id=1, force=False):

    if not force:
        try:
            return user.key_envelope
        except KeyEnvelope.DoesNotExist:
            pass

    dek = generate_dek()
    wrapped = wrap_dek(dek)
    env, _ = KeyEnvelope.objects.update_or_create(
        user=user,
        defaults={"wrapped_dek": wrapped, "kek_id": kek_id},
    )
    return env

def get_user_dek(user):

    try:
        env = user.key_envelope
    except KeyEnvelope.DoesNotExist:
        env = create_key_envelope_for_user(user)
    return unwrap_dek(env.wrapped_dek)


def get_active_kek():

    b64 = getattr(settings, "APP_KEK_BASE64", None)
    if not b64:
        raise RuntimeError("APP_KEK_BASE64 is not set. Configure it in your env/.env.")

    try:
        kek = base64.b64decode(b64)
    except Exception as e:
        raise RuntimeError("APP_KEK_BASE64 is not valid base64.") from e

    if len(kek) not in (16, 24, 32):
        # We prefer 32 bytes for AES-256
        raise RuntimeError(f"APP_KEK_BASE64 decoded to {len(kek)} bytes; expected 16/24/32 (32 recommended).")

    kek_id = getattr(settings, "KEYMGMT_ACTIVE_KEK_ID", "default")
    return kek, str(kek_id)

def wrap_dek(dek: bytes, kek: bytes | None = None) -> bytes:
    """
    Wrap (encrypt) a DEK using the provided KEK; falls back to active KEK.
    """
    if kek is None:
        kek, _ = get_active_kek()
    return wrap_dek_with_kek(dek, kek)

def unwrap_dek(wrapped: bytes, kek: bytes | None = None) -> bytes:
    """
    Unwrap (decrypt) a DEK using the provided KEK; falls back to active KEK.
    """
    if kek is None:
        kek, _ = get_active_kek()
    return unwrap_dek_with_kek(wrapped, kek)

