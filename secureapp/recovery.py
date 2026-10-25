import secrets

ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
GROUPS = 4
GROUP_LEN = 5


def new_recovery_code() -> str:
    body = "".join(secrets.choice(ALPHABET) for _ in range(GROUPS * GROUP_LEN))
    return "-".join(body[i:i + GROUP_LEN] for i in range(0, len(body), GROUP_LEN))


def normalise(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch in ALPHABET)


def entropy_bits() -> float:
    import math
    return GROUPS * GROUP_LEN * math.log2(len(ALPHABET))
