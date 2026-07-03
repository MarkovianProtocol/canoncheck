# canoncheck

A cross-language canonicalization and hash conformance harness for JSON records.

Any hash-based integrity check on JSON rests on one property: two independent
implementations, in different languages, must produce **byte-identical** canonical bytes and
therefore the same digest. If they don't, a record that verifies in one runtime fails in
another, and "recomputable" stops meaning anything. `canoncheck` implements
[RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785) canonicalization in **both Python and
Node**, pins both to self-contained SHA-256 and Keccak-256, and ships a harness that diffs the
two against shared test vectors, including the adversarial cases that break naive
canonicalizers.

```
pip install git+https://github.com/MarkovianProtocol/canoncheck
# PyPI release coming soon: pip install canoncheck
```

## Why this exists

Most "canonical JSON" bugs are not in the happy path. They are in three places, and they only
surface once a second language or SDK consumes your data:

1. **Number serialization.** Two conformant JSON libraries serialize the same number
   differently (trailing zeros, exponent form, integer vs float, negative zero) and produce
   different bytes. `canoncheck` uses the ECMAScript Number-to-String algorithm (RFC 8785
   section 3.2.2.3), which is exactly what a JavaScript `String(n)` produces, so `1.0`, `1e2`,
   and `100` all canonicalize to the same bytes across both languages.
2. **Unicode handling.** Strings are kept as-is (no NFC/NFD normalization), with minimal
   escaping and UTF-8 output, and object keys are sorted by UTF-16 code units, so a non-ASCII
   field name or value canonicalizes identically across clients.
3. **Duplicate keys.** RFC 8259 says member names "SHOULD" be unique; many parsers silently
   keep the last value. `canoncheck` rejects duplicate keys on parse, in both languages, rather
   than letting two parsers pick different values and hash to different roots.

## Use it

```python
import canoncheck as cc

record = {"agent": "resolver-01", "block_height": 800000, "result": "MATCH"}
cc.canonicalize(record)          # -> b'{"agent":"resolver-01","block_height":800000,"result":"MATCH"}'
cc.digest(record, "sha256")      # -> hex digest over the canonical bytes
cc.digest(record, "keccak256")   # -> Ethereum keccak-256 over the same bytes

cc.parse_strict('{"a":1,"a":2}') # -> raises CanonError (duplicate key)
cc.check_algorithm("md5")        # -> raises CanonError (unsupported algorithm)
```

```js
import { canonicalize, digestBytes, parseStrict } from "./js/canoncheck.mjs";
const c = canonicalize(parseStrict(raw));
digestBytes(c, "sha256");
digestBytes(c, "keccak256");
```

## Prove it (the whole point)

```
python3 harness.py
```

Canonicalizes and hashes every vector in `vectors/` in Python and in Node and asserts they
agree byte-for-byte and digest-for-digest. Vectors named `reject_*.json` must be rejected by
both. Exit code is non-zero on any disagreement.

```
cross-language conformance (Python vs Node)

  [PASS] numbers.json               {"big":100000000000000000000,"frac":3.141592653589793,...}
  [PASS] numeric_equivalence.json   {"a":1,"b":100,"c":100,"d":10,"e":10}
  [PASS] record_agent_output.json   {"agent":"resolver-01","block_height":800000,...}
  [PASS] record_nested.json         {"a":[{"x":null,"y":true},{"n":-2.5}],"m":"","z":{"a":1,"b":2}}
  [PASS] reject_duplicate_key.json  both reject
  [PASS] reject_nan.json            both reject
  [PASS] unicode.json               {"a":"plain","emoji":"😀","greek":"Ωμέγα","é":"café"}

7/7 vectors conformant
```

## Pinned conformance vectors

Published digests, reproducible from the vector files above in either language:

| vector | canonical form | sha256 | keccak256 |
|---|---|---|---|
| `record_agent_output` | `{"agent":"resolver-01","block_height":800000,"claim":"tx_count==3721","result":"MATCH","tags":["bitcoin","deterministic"]}` | `d9d95374…eff393f` | `35ee5191…cee1172` |
| `numbers` | `{"big":100000000000000000000,"frac":3.141592653589793,"half":1.5,"int":123456789,"neg":-42,"tiny":0.000001,"zero":0}` | `b175a680…a20badbf` | `f1ddcb33…5c63ca46` |

## Numeric policy (honest scope)

Integers within the IEEE-754 safe range (`|n| <= 2**53-1`) and finite non-integer numbers are
serialized per RFC 8785. `NaN` and `Infinity` are rejected. Integers beyond the safe range are
not portably representable as JSON numbers across languages, so in strict mode they are
rejected; represent them as strings. This is the same guidance the JCS number rules are built
around: pin the number format, or keep numbers where cross-language agreement is guaranteed.

The Keccak-256 implementation is self-contained (no native dependency) and pinned against the
standard Ethereum known-answer vectors in `tests/`.

## Where this fits

`canoncheck` is the determinism substrate under provenance and resolution: a receipt or a
verdict is only recomputable by a third party if everyone canonicalizes the record the same way
first. It is part of the [Markovian Protocol](https://markovianprotocol.com) stack, alongside
[`evalproof`](https://github.com/MarkovianProtocol/evalproof) (tamper-evident receipts) and
[`replayverdict`](https://github.com/MarkovianProtocol/replayverdict) (recomputable verdicts),
and it stands alone for anyone who needs cross-language canonical-JSON hashing they can trust.

Apache-2.0.
