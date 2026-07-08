#!/usr/bin/env python3
"""Verify a receipt by hashing the bytes you were GIVEN, never a re-serialized object.

This is the leg 0rkz asked to see closed on real bytes rather than a promise
(OpenBB-finance/OpenBB#7455): a verifier must hash the exact wire bytes it received.
The failure it guards against is subtle because the LENGTH does not change: a verifier
that parses then re-serializes "to canonicalize" (e.g. sorts keys, re-escapes, reprs a
float its own way) mints a different hash for byte-for-byte the same information. The
2067-byte payload stays 2067 bytes; the commitment still fails to verify.

No dependencies. `python3 verify_received_bytes.py` runs the demonstration.
"""
import hashlib, json


def sha256_hex(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def verify(received_bytes: bytes, committed_hash: str) -> bool:
    """The whole rule in one function: hash the bytes received, compare. No parse in the path."""
    return sha256_hex(received_bytes) == committed_hash


def demo():
    # A signed response exactly as it came off the wire. Keys are in the provider's
    # emission order (ticker, price, note, ts), compact separators. The signer committed
    # to a hash over THESE bytes.
    wire = b'{"ticker":"NVDA","price":183.5,"note":"beat guidance","ts":1751932800}'
    committed = sha256_hex(wire)

    print("received bytes :", wire.decode())
    print("committed hash :", committed)
    print("verify(received bytes)          ->", verify(wire, committed), " <- hash the bytes you were given")
    print()

    # A well-meaning verifier that parses, then re-serializes with sort_keys=True because
    # "canonical means sorted." Same data, SAME length (sorting only reorders characters),
    # different bytes -> different hash. This is the 2067 -> 2067, hash-changes failure.
    reserialized = json.dumps(json.loads(wire), separators=(",", ":"), sort_keys=True).encode("utf-8")
    print("reserialized   :", reserialized.decode(), " <- verifier 'canonicalized' by sorting keys")
    print(f"len received   : {len(wire)}      len reserialized: {len(reserialized)}   (identical length)")
    print("verify(reserialized)            ->", verify(reserialized, committed), " <- same info, FAILS")
    print()
    print("Rule: hold the bytes you were given and hash exactly those. Do not verify")
    print("sha256(canonicalize(parse(bytes))) on the verifier side. Canonicalization")
    print("(RFC 8785) belongs to the SIGNER, so two honest producers emit identical")
    print("bytes; the VERIFIER hashes what it received and never re-serializes.")


if __name__ == "__main__":
    demo()
