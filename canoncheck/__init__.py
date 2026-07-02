"""canoncheck: cross-language canonicalization + hash conformance for JSON records.

The property that matters for any hash-based integrity check on JSON is that two
independent implementations, in different languages, produce byte-identical canonical
bytes and therefore the same digest. This package implements RFC 8785 (JCS)
canonicalization and pairs it with a Node implementation and a harness that diffs the
two against shared test vectors, including the adversarial cases (duplicate keys,
numerically-equivalent values, non-ASCII fields) that break naive canonicalizers.

Numeric policy: integers within the IEEE-754 safe range and finite non-integer numbers
are serialized per the ECMAScript Number-to-String algorithm (RFC 8785 section 3.2.2.3),
which is what a JS String(n) produces. NaN and Infinity are rejected. Integers beyond
2**53-1 are not safely representable as JSON numbers across languages and are rejected in
strict mode; represent them as strings.
"""

from __future__ import annotations

import decimal
import hashlib
import json

__version__ = "0.1.0"

SAFE_INT = 2 ** 53 - 1
SUPPORTED_ALGORITHMS = ("sha256", "keccak256")


class CanonError(ValueError):
    """Raised when input cannot be canonicalized deterministically."""


# ---------------------------------------------------------------------------
# Number serialization: ECMAScript Number::toString (RFC 8785 section 3.2.2.3)
# ---------------------------------------------------------------------------

def _es6_number(x: float) -> str:
    """Serialize a finite float exactly as ECMAScript String(Number) would."""
    if x != x or x in (float("inf"), float("-inf")):
        raise CanonError("NaN and Infinity are not valid JSON numbers")
    if x == 0:
        return "0"  # also normalizes -0.0 to "0"
    sign = "-" if x < 0 else ""
    d = decimal.Decimal(repr(abs(x)))
    _, digits, exp = d.as_tuple()
    digs = list(digits)
    while len(digs) > 1 and digs[-1] == 0:  # drop trailing zeros
        digs.pop()
        exp += 1
    s = "".join(str(v) for v in digs)
    k = len(s)
    n = exp + k  # decimal point sits after n digits from the left
    if k <= n <= 21:
        return sign + s + "0" * (n - k)
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + s
    # exponential form
    exp_part = n - 1
    mantissa = s[0] + ("." + s[1:] if k > 1 else "")
    esign = "+" if exp_part >= 0 else "-"
    return sign + mantissa + "e" + esign + str(abs(exp_part))


def _number(x, strict: bool) -> str:
    if isinstance(x, bool):  # bool is a subclass of int; handled by caller
        raise CanonError("bool routed to _number")
    if isinstance(x, int):
        if abs(x) > SAFE_INT:
            if strict:
                raise CanonError(
                    "integer %d exceeds the IEEE-754 safe range; represent it as a "
                    "string for cross-language stability" % x
                )
            return _es6_number(float(x))
        return str(x)
    if isinstance(x, float):
        return _es6_number(x)
    raise CanonError("unsupported number type: %r" % type(x))


# ---------------------------------------------------------------------------
# String serialization: JCS minimal escaping (RFC 8785 section 3.2.2.2)
# ---------------------------------------------------------------------------

_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)  # all other chars, including non-ASCII, stay literal
    out.append('"')
    return "".join(out)


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------

def _canon(value, strict: bool) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (int, float)):
        return _number(value, strict)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canon(v, strict) for v in value) + "]"
    if isinstance(value, dict):
        # sort keys by UTF-16 code units (RFC 8785); utf-16-be bytes preserve that order
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_string(k) + ":" + _canon(v, strict) for k, v in items) + "}"
    raise CanonError("unsupported type: %r" % type(value))


def _utf16_key(k) -> bytes:
    if not isinstance(k, str):
        raise CanonError("object keys must be strings, got %r" % type(k))
    return k.encode("utf-16-be")


def canonicalize(value, *, strict: bool = True) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes for a JSON-compatible value."""
    return _canon(value, strict).encode("utf-8")


# ---------------------------------------------------------------------------
# Strict parsing: reject duplicate object member names (RFC 8259 hygiene)
# ---------------------------------------------------------------------------

def _no_dupes(pairs):
    seen = {}
    for key, val in pairs:
        if key in seen:
            raise CanonError("duplicate object member name: %r" % key)
        seen[key] = val
    return seen


def parse_strict(text: str):
    """Parse JSON, rejecting duplicate keys and NaN/Infinity."""
    return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_reject_const)


def _reject_const(name):
    raise CanonError("non-finite constant not allowed: %s" % name)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def check_algorithm(name: str) -> str:
    if name not in SUPPORTED_ALGORITHMS:
        raise CanonError(
            "unsupported hash algorithm %r; supported: %s"
            % (name, ", ".join(SUPPORTED_ALGORITHMS))
        )
    return name


def digest(value, algorithm: str = "sha256", *, strict: bool = True) -> str:
    """Canonicalize value and return its hex digest under the named algorithm."""
    check_algorithm(algorithm)
    data = canonicalize(value, strict=strict)
    if algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    return keccak256(data).hex()


def digest_bytes(data: bytes, algorithm: str = "sha256") -> str:
    check_algorithm(algorithm)
    if algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    return keccak256(data).hex()


# ---------------------------------------------------------------------------
# Self-contained Keccak-256 (Ethereum's pre-NIST SHA-3), no dependencies.
# Verified against the known-answer vector in the test suite.
# ---------------------------------------------------------------------------

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(state):
    for rc in _KECCAK_RC:
        # theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        # rho and pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(state[x][y], _KECCAK_ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        # iota
        state[0][0] ^= rc
    return state


def keccak256(data: bytes) -> bytes:
    rate = 136  # bytes, for 256-bit output (1600 - 2*256)/8
    state = [[0] * 5 for _ in range(5)]
    # pad: Keccak (0x01 domain) with 0x80 final bit
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f(state)
    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out += state[i % 5][i // 5].to_bytes(8, "little")
            if len(out) >= 32:
                break
        if len(out) < 32:
            _keccak_f(state)
    return bytes(out[:32])
