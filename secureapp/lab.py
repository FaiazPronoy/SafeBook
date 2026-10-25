"""The Security Lab.

Five claims this app makes, each with the experiment that checks it, run
live rather than described. Nothing on these pages touches a real account:
every key and every message here is generated on the spot and thrown away.
"""
import base64
import hashlib
import hmac
import os
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import Argon2PasswordHasher
from django.shortcuts import render

IMG = 96          # the demo picture is IMG x IMG, one byte per pixel


def _padlock() -> bytes:
    """A padlock in greyscale, drawn rather than loaded, so the repository
    carries no binary assets. The large flat areas are the whole point."""
    pixels = bytearray()
    cx = IMG / 2
    for y in range(IMG):
        for x in range(IMG):
            body = 34 <= y <= 82 and 22 <= x <= IMG - 22
            shackle = 18 <= y < 34 and 16 <= ((x - cx) ** 2 + (y - 34) ** 2) ** 0.5 <= 26
            keyhole = (((x - cx) ** 2 + (y - 52) ** 2) ** 0.5 <= 6
                       or (52 <= y <= 68 and abs(x - cx) <= 3))
            if body and keyhole:
                pixels.append(0x20)
            elif body or shackle:
                pixels.append(0xE8)
            else:
                pixels.append(0x11)
    return bytes(pixels)


def _bmp(gray: bytes, width: int = IMG, height: int = IMG) -> bytes:
    """An 8 bit greyscale BMP, assembled by hand. Rows are padded to four
    bytes and stored bottom up, which is simply how the format works."""
    palette = b"".join(bytes((i, i, i, 0)) for i in range(256))
    pad = (-width) % 4
    rows = b"".join(gray[y * width:(y + 1) * width] + b"\x00" * pad
                    for y in range(height - 1, -1, -1))
    offset = 14 + 40 + len(palette)
    header = b"BM" + struct.pack("<IHHI", offset + len(rows), 0, 0, offset)
    info = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 8, 0,
                       len(rows), 2835, 2835, 256, 256)
    return header + info + palette + rows


def _data_uri(gray: bytes) -> str:
    return "data:image/bmp;base64," + base64.b64encode(_bmp(gray)).decode()


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _repeated_blocks(data: bytes) -> int:
    blocks = [data[i:i + 16] for i in range(0, len(data) - 15, 16)]
    return len(blocks) - len(set(blocks))


@login_required
def lab_index(request):
    return render(request, "lab/index.html")


@login_required
def modes_view(request):
    """The same picture through ECB, CBC and GCM."""
    plain = _padlock()
    key = os.urandom(32)

    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ecb_ct = ecb.update(plain) + ecb.finalize()

    cbc = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16))).encryptor()
    cbc_ct = cbc.update(plain) + cbc.finalize()

    gcm_ct = AESGCM(key).encrypt(os.urandom(12), plain, b"")[:len(plain)]

    return render(request, "lab/modes.html", {
        "panels": [
            {"name": "Plaintext", "img": _data_uri(plain),
             "repeats": _repeated_blocks(plain),
             "note": "96 by 96 pixels, one byte each"},
            {"name": "AES-ECB", "img": _data_uri(ecb_ct),
             "repeats": _repeated_blocks(ecb_ct),
             "note": "every identical block encrypts to the same thing"},
            {"name": "AES-CBC", "img": _data_uri(cbc_ct),
             "repeats": _repeated_blocks(cbc_ct),
             "note": "each block is chained into the next"},
            {"name": "AES-GCM", "img": _data_uri(gcm_ct),
             "repeats": _repeated_blocks(gcm_ct),
             "note": "counter mode, and what SafeBook actually uses"},
        ],
        "blocks": len(plain) // 16,
    })


@login_required
def nonce_view(request):
    """What one repeated nonce costs you."""
    secret = (request.POST.get("secret") or "meet me at the north gate at nine").strip()
    known = (request.POST.get("known") or "the weather today is really quite mild").strip()

    n = min(len(secret), len(known))
    secret, known = secret[:n], known[:n]
    key, nonce = os.urandom(32), os.urandom(12)

    def keystream(data):
        # AES-GCM runs AES-CTR underneath, so this is the same keystream the
        # real thing would produce for that key and nonce
        enc = Cipher(algorithms.AES(key),
                     modes.CTR(nonce + b"\x00\x00\x00\x02")).encryptor()
        return enc.update(data) + enc.finalize()

    c1, c2 = keystream(secret.encode()), keystream(known.encode())

    # an eavesdropper holds c1 and c2 and knows one of the two plaintexts
    recovered = _xor(_xor(c1, c2), known.encode())

    # the same pair, with a fresh nonce each time
    g1 = AESGCM(key).encrypt(os.urandom(12), secret.encode(), b"")[:n]
    g2 = AESGCM(key).encrypt(os.urandom(12), known.encode(), b"")[:n]
    junk = _xor(_xor(g1, g2), known.encode())

    return render(request, "lab/nonce.html", {
        "secret": secret,
        "known": known,
        "c1": c1.hex(),
        "c2": c2.hex(),
        "xor_ct": _xor(c1, c2).hex(),
        "recovered": recovered.decode("utf-8", "replace"),
        "recovered_exactly": recovered == secret.encode(),
        "junk": junk.decode("utf-8", "replace"),
        "junk_hex": junk.hex(),
    })


@login_required
def timing_view(request):
    """Which ways of comparing a MAC leak where the first wrong byte is.

    Three comparisons of the same 32 bytes. The hand written loop is the one
    people write when they have not thought about it, and it is the one that
    gives the answer away.
    """
    secret = os.urandom(32)
    rounds = 3000

    def hand_written(a, b):
        if len(a) != len(b):
            return False
        for x, y in zip(a, b):
            if x != y:
                return False
        return True

    def fastest_ns(compare, guess):
        """The quickest of thirteen runs, not the average of them.

        Anything else happening on the machine can only add time to a run,
        never take it away, so the smallest number is the closest thing to
        the cost of the comparison by itself. Averaging would fold the
        machine being busy into the answer, and on a laptop that noise is
        larger than the effect being measured.
        """
        samples = []
        for _ in range(13):
            start = time.perf_counter_ns()
            for _ in range(rounds):
                compare(guess, secret)
            samples.append((time.perf_counter_ns() - start) / rounds)
        return min(samples)

    rows = []
    for prefix in (0, 8, 16, 24, 31):
        guess = secret[:prefix] + bytes(32 - prefix)
        rows.append({
            "prefix": prefix,
            "loop": fastest_ns(hand_written, guess),
            "eq": fastest_ns(lambda a, b: a == b, guess),
            "safe": fastest_ns(hmac.compare_digest, guess),
        })

    scale = max(r["loop"] for r in rows) or 1
    for row in rows:
        for column in ("loop", "eq", "safe"):
            row[column + "_pct"] = row[column] / scale * 100

    def spread(column):
        values = [r[column] for r in rows]
        return max(values) - min(values), (max(values) / min(values) if min(values) else 0)

    loop_spread, loop_ratio = spread("loop")
    eq_spread, eq_ratio = spread("eq")
    safe_spread, safe_ratio = spread("safe")

    return render(request, "lab/timing.html", {
        "rows": rows,
        "rounds": rounds,
        "loop_spread": loop_spread, "loop_ratio": loop_ratio,
        "eq_spread": eq_spread, "eq_ratio": eq_ratio,
        "safe_spread": safe_spread, "safe_ratio": safe_ratio,
    })


@login_required
def kdf_view(request):
    """How many password guesses a second each way of storing one allows.

    MD5 and SHA-256 finish faster than the clock can resolve a single call, so
    those two are timed over a batch and divided. The slow ones are timed one
    call at a time, because a batch of them would keep the page waiting.
    """
    password = b"correct-horse-battery"
    salt = os.urandom(16)

    def per_call(fn, batch=1, reps=5):
        best = None
        for _ in range(reps):
            start = time.perf_counter()
            for _ in range(batch):
                fn()
            elapsed = (time.perf_counter() - start) / batch
            best = elapsed if best is None else min(best, elapsed)
        return best

    measurements = [
        ("MD5", per_call(lambda: hashlib.md5(password).digest(), batch=200_000),
         "one pass over the input and nothing else"),
        ("SHA-256", per_call(lambda: hashlib.sha256(password).digest(), batch=200_000),
         "fast by design, which is exactly the problem here"),
        ("scrypt N=2^16", per_call(
            lambda: Scrypt(salt=salt, length=32, n=2 ** 16, r=8, p=1).derive(password), reps=3),
         "what SafeBook derives your data key with"),
        ("Argon2id", per_call(
            lambda: Argon2PasswordHasher().encode("correct-horse-battery", "abcdefghijklmnop"),
            reps=3),
         "what Django stores your password with"),
    ]

    rows = [{"name": name, "ms": seconds * 1000, "per_second": 1 / seconds, "note": note}
            for name, seconds, note in measurements]
    fastest = max(r["per_second"] for r in rows)
    slowest_ms = max(r["ms"] for r in rows)
    for row in rows:
        row["slowdown"] = fastest / row["per_second"]
        row["bar"] = max(0.5, 100 * row["ms"] / slowest_ms)

    # a six character lowercase password, at each of these speeds
    space = 26 ** 6
    for row in rows:
        row["crack_days"] = space / row["per_second"] / 86400

    return render(request, "lab/kdf.html", {"rows": rows, "space": space})


@login_required
def tamper_view(request):
    """Flip one bit in a stored row and watch it stop being readable."""
    from .crypto import aead_decrypt, aead_encrypt, new_key
    from .mac import CTX_POST, mac_ok, row_mac

    text = (request.POST.get("text") or "the vault code is 4417").strip()
    key = new_key()
    nonce, ct = aead_encrypt(key, text.encode(), b"post.body")
    mac = row_mac(key, CTX_POST, b"7", nonce, ct)

    try:
        which = int(request.POST.get("byte", 0)) % len(ct)
    except (TypeError, ValueError):
        which = 0

    tampered = bytearray(ct)
    tampered[which] ^= 0x01
    tampered = bytes(tampered)

    try:
        aead_decrypt(key, nonce, tampered, b"post.body")
        gcm_ok, gcm_detail = True, "the tag verified"
    except Exception as exc:
        gcm_ok, gcm_detail = False, f"AES-GCM raised {type(exc).__name__}"

    steps = [
        {"step": "Row MAC, on the flipped bytes",
         "ok": mac_ok(mac, key, CTX_POST, b"7", nonce, tampered),
         "detail": "HMAC-SHA256 over a length prefixed encoding of the row"},
        {"step": "AES-GCM tag, on the flipped bytes",
         "ok": gcm_ok, "detail": gcm_detail},
        {"step": "Row MAC, on the bytes as written",
         "ok": mac_ok(mac, key, CTX_POST, b"7", nonce, ct),
         "detail": "the same check against what was actually stored"},
    ]

    return render(request, "lab/tamper.html", {
        "text": text,
        "byte": which,
        "ct_hex": ct.hex(),
        "tampered_hex": tampered.hex(),
        "ct_len": len(ct),
        "steps": steps,
    })
