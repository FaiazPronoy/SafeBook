import hashlib
import hmac
import secrets
import time

from django.conf import settings
from django.core.mail import send_mail

CODE_TTL = 10 * 60
RESEND_AFTER = 60
MAX_TRIES = 5

LOGIN_SLOT = "two_step_login"
SETUP_SLOT = "two_step_setup"
PENDING_FIELD = "pending_private_dek"
PENDING_COOKIE = "sb_pkey"


def _digest(code: str) -> str:
    return hmac.new(settings.SECRET_KEY.encode(), code.encode(), hashlib.sha256).hexdigest()


def mask_email(email: str) -> str:
    name, _, domain = email.partition("@")
    return (name[:2] + "•" * max(len(name) - 2, 1) + "@" + domain) if domain else email


def send_code(request, slot: str, email: str, reason: str, **extra) -> None:
    code = f"{secrets.randbelow(10 ** 6):06d}"
    now = time.time()
    request.session[slot] = {**request.session.get(slot, {}), **extra,
                             "digest": _digest(code), "expires": now + CODE_TTL, "sent": now, "tries": 0}
    send_mail(
        f"{code} is your SafeBook code",
        f"Your SafeBook code is {code}.\n\nUse it to {reason}. It expires in 10 minutes.\n\n"
        "If this was not you, change your password.",
        None,
        [email],
    )


def can_resend(request, slot: str) -> bool:
    pending = request.session.get(slot)
    return bool(pending) and time.time() - pending["sent"] >= RESEND_AFTER


def check_code(request, slot: str, code: str) -> str:
    pending = request.session.get(slot)
    if not pending:
        return "missing"
    if time.time() > pending["expires"]:
        request.session.pop(slot, None)
        return "expired"
    if hmac.compare_digest(pending["digest"], _digest(code.strip())):
        request.session.pop(slot, None)
        return "ok"
    pending["tries"] += 1
    if pending["tries"] >= MAX_TRIES:
        request.session.pop(slot, None)
        return "locked"
    request.session[slot] = pending
    return "wrong"
