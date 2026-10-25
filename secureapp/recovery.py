"""The one time recovery code.

Wrapping the DEK with the password alone means a forgotten password is a
destroyed account, which is not a trade most people would knowingly make.
So the same DEK is wrapped a second time under a code the user is shown once
and told to write down.

The code is base32 in five character groups: no 0/1/8/O/I/L to be misread,
and twenty characters of it is about 99 bits, which is not worth guessing.
"""
import secrets

ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"   # no O, I, L, 0, 1
GROUPS = 4
GROUP_LEN = 5


def new_recovery_code() -> str:
    body = "".join(secrets.choice(ALPHABET) for _ in range(GROUPS * GROUP_LEN))
    return "-".join(body[i:i + GROUP_LEN] for i in range(0, len(body), GROUP_LEN))


def normalise(code: str) -> str:
    """Accept it typed in lower case, with spaces, or without the dashes."""
    return "".join(ch for ch in code.upper() if ch in ALPHABET)


def entropy_bits() -> float:
    import math
    return GROUPS * GROUP_LEN * math.log2(len(ALPHABET))
