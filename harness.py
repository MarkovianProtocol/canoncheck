#!/usr/bin/env python3
"""Cross-language conformance harness.

For every vector in vectors/, canonicalize and hash it in Python and in Node, then assert
the two agree byte-for-byte and digest-for-digest. Vectors named reject_*.json must be
rejected by BOTH implementations. Exit code is non-zero if any implementation disagrees,
which is the property that matters: determinism is only real if two independent stacks
produce the same bytes.

Usage:  python3 harness.py            # run all vectors, print a table
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors")
JS = os.path.join(HERE, "js", "canoncheck.mjs")

sys.path.insert(0, HERE)
import canoncheck as cc  # noqa: E402


def py_run(raw):
    try:
        value = cc.parse_strict(raw)
        data = cc.canonicalize(value)
        return {
            "canonical": data.decode("utf-8"),
            "canonical_hex": data.hex(),
            "sha256": cc.digest_bytes(data, "sha256"),
            "keccak256": cc.digest_bytes(data, "keccak256"),
        }
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def js_run(path):
    out = subprocess.run(["node", JS, path], capture_output=True, text=True)
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return {"error": "js crash: " + (out.stderr or out.stdout)[:200]}


def main():
    files = sorted(f for f in os.listdir(VECTORS) if f.endswith(".json"))
    rows, ok = [], True
    for f in files:
        path = os.path.join(VECTORS, f)
        raw = open(path).read()
        py, js = py_run(raw), js_run(path)
        must_reject = f.startswith("reject_")

        if must_reject:
            passed = "error" in py and "error" in js
            detail = "both reject" if passed else "SHOULD REJECT: py=%s js=%s" % (
                "error" in py, "error" in js)
        elif "error" in py or "error" in js:
            passed = False
            detail = "unexpected error py=%r js=%r" % (py.get("error"), js.get("error"))
        else:
            same = (py["canonical_hex"] == js["canonical_hex"]
                    and py["sha256"] == js["sha256"]
                    and py["keccak256"] == js["keccak256"])
            passed = same
            detail = py["canonical"] if same else "MISMATCH\n  py=%s\n  js=%s" % (
                py["canonical"], js["canonical"])
        ok = ok and passed
        rows.append((f, passed, detail))

    width = max(len(f) for f, _, _ in rows)
    print("cross-language conformance (Python vs Node)\n")
    for f, passed, detail in rows:
        mark = "PASS" if passed else "FAIL"
        print("  [%s] %-*s  %s" % (mark, width, f, detail))
    print("\n%d/%d vectors conformant" % (sum(1 for _, p, _ in rows if p), len(rows)))
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
