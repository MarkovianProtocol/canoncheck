import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import canoncheck as cc


# --- Keccak-256 known-answer tests (a from-scratch primitive must be pinned) ---
@pytest.mark.parametrize("msg,want", [
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    (b"The quick brown fox jumps over the lazy dog",
     "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"),
])
def test_keccak_kat(msg, want):
    assert cc.keccak256(msg).hex() == want


# --- ES6 number serialization (RFC 8785 section 3.2.2.3) ---
@pytest.mark.parametrize("x,want", [
    (0.0, "0"), (-0.0, "0"), (1.0, "1"), (1.5, "1.5"), (100.0, "100"),
    (0.001, "0.001"), (1e21, "1e+21"), (1e-7, "1e-7"), (1e20, "100000000000000000000"),
    (1e-6, "0.000001"), (-2.5, "-2.5"), (3.141592653589793, "3.141592653589793"),
])
def test_es6_number(x, want):
    assert cc._es6_number(x) == want


def test_canonicalize_sorts_and_escapes():
    obj = {"b": 1, "a": 2, "z": [3, True, None, "x"]}
    assert cc.canonicalize(obj) == b'{"a":2,"b":1,"z":[3,true,null,"x"]}'


def test_non_bmp_key_sort():
    # non-BMP key sorts after BMP keys by UTF-16 code unit
    assert cc.canonicalize({"\U0001F600": 1, "b": 2}) == '{"b":2,"😀":1}'.encode()


def test_numeric_equivalence_collapses():
    assert cc.canonicalize(cc.parse_strict('{"a":1.0,"b":1e2,"c":100}')) == b'{"a":1,"b":100,"c":100}'


def test_duplicate_key_rejected():
    with pytest.raises(cc.CanonError):
        cc.parse_strict('{"a":1,"a":2}')


def test_unknown_algorithm_rejected():
    with pytest.raises(cc.CanonError):
        cc.check_algorithm("md5")


def test_unsafe_integer_rejected_in_strict():
    with pytest.raises(cc.CanonError):
        cc.canonicalize(2 ** 53 + 1, strict=True)


def test_cross_language_harness():
    """The whole point: Python and Node must agree on every vector."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if subprocess.run(["node", "--version"], capture_output=True).returncode != 0:
        pytest.skip("node not available")
    result = subprocess.run([sys.executable, os.path.join(root, "harness.py")],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
