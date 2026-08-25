"""Checking a password without saying more than yes or no.

Two things leak from a naive login check, and neither of them is the
password:

  * how long it took. Returning early for a username that does not exist
    skips the Argon2 hash entirely, and the gap between "no such user" and
    "wrong password" is large enough to read from a browser. So a miss
    hashes against a throwaway record anyway.

  * how often you may ask. Without a limit, an offline wordlist becomes an
    online one.
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone

from .models import LoginAttempt

User = get_user_model()

MAX_FAILURES = 5
LOCKOUT_WINDOW = timedelta(minutes=15)

# Hashed once at import: a real Argon2 hash to check misses against, so the
# work done for an unknown username matches the work done for a known one.
_DECOY_HASH = make_password("decoy-password-nobody-uses")


def check_credentials(username: str, password: str):
    """The user, or None. Takes the same time either way."""
    user = User.objects.filter(username=username).first()

    if user is None or not user.is_active:
        check_password(password, _DECOY_HASH)
        return None

    return user if check_password(password, user.password) else None


def recent_failures(username: str) -> int:
    since = timezone.now() - LOCKOUT_WINDOW
    return LoginAttempt.objects.filter(
        username=username, successful=False, at__gte=since
    ).count()


def is_locked_out(username: str) -> bool:
    return recent_failures(username) >= MAX_FAILURES


def record_attempt(request, username: str, successful: bool) -> None:
    LoginAttempt.objects.create(
        username=username[:150],
        successful=successful,
        ip=_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:200],
    )


def clear_failures(username: str) -> None:
    """A correct password ends the lockout; the successful row is kept."""
    LoginAttempt.objects.filter(username=username, successful=False).delete()


def _client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")
