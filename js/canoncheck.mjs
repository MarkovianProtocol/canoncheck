// canoncheck (JS): RFC 8785 canonicalization + sha256/keccak256, matching the Python
// implementation byte-for-byte. Run as a CLI it reads a JSON file and prints the canonical
// form and digests, or an {error} object for inputs that must be rejected. The harness
// diffs this output against the Python side.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const SAFE_INT = 2n ** 53n - 1n;
export const SUPPORTED_ALGORITHMS = ["sha256", "keccak256"];

export class CanonError extends Error {}

// --- number: ECMAScript String(Number) is exactly RFC 8785 section 3.2.2.3 ---
function numberToken(n) {
  if (!Number.isFinite(n)) throw new CanonError("NaN and Infinity are not valid JSON numbers");
  if (n === 0) return "0"; // normalizes -0
  return String(n);
}

// --- string: JCS minimal escaping (RFC 8785 section 3.2.2.2) ---
const ESC = { 8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r", 34: '\\"', 92: "\\\\" };
function stringToken(s) {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (ESC[cp] !== undefined) out += ESC[cp];
    else if (cp < 0x20) out += "\\u" + cp.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

export function canonicalize(value) {
  return Buffer.from(canon(value), "utf8");
}

function canon(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  const t = typeof value;
  if (t === "string") return stringToken(value);
  if (t === "number") return numberToken(value);
  if (t === "bigint") {
    if (value > SAFE_INT || value < -SAFE_INT)
      throw new CanonError("integer exceeds the IEEE-754 safe range; use a string");
    return value.toString();
  }
  if (Array.isArray(value)) return "[" + value.map(canon).join(",") + "]";
  if (t === "object") {
    // sort keys by UTF-16 code units: default JS string comparison
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => stringToken(k) + ":" + canon(value[k])).join(",") + "}";
  }
  throw new CanonError("unsupported type: " + t);
}

// --- strict JSON parse: reject duplicate object member names ---
// Minimal recursive-descent parser; JSON.parse silently drops duplicate keys, so we cannot
// use it for the duplicate-key rule. Numbers are parsed as JS numbers (IEEE-754 doubles),
// matching the canonicalization contract.
export function parseStrict(text) {
  let i = 0;
  const err = (m) => { throw new CanonError(m + " at position " + i); };
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  function value() {
    ws();
    const c = text[i];
    if (c === "{") return object();
    if (c === "[") return array();
    if (c === '"') return string();
    if (c === "-" || (c >= "0" && c <= "9")) return number();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    err("unexpected token");
  }
  function object() {
    i++; const obj = {}; const seen = new Set(); ws();
    if (text[i] === "}") { i++; return obj; }
    for (;;) {
      ws(); if (text[i] !== '"') err("expected string key");
      const k = string();
      if (seen.has(k)) err("duplicate object member name: " + JSON.stringify(k));
      seen.add(k); ws(); if (text[i] !== ":") err("expected colon"); i++;
      obj[k] = value(); ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "}") { i++; return obj; }
      err("expected comma or end of object");
    }
  }
  function array() {
    i++; const arr = []; ws();
    if (text[i] === "]") { i++; return arr; }
    for (;;) {
      arr.push(value()); ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "]") { i++; return arr; }
      err("expected comma or end of array");
    }
  }
  function string() {
    i++; let s = "";
    for (;;) {
      const c = text[i++];
      if (c === undefined) err("unterminated string");
      if (c === '"') return s;
      if (c === "\\") {
        const e = text[i++];
        if (e === "u") { s += String.fromCharCode(parseInt(text.slice(i, i + 4), 16)); i += 4; }
        else s += { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[e];
      } else s += c;
    }
  }
  function number() {
    const start = i;
    if (text[i] === "-") i++;
    while (i < text.length && "0123456789.eE+-".includes(text[i])) i++;
    const raw = text.slice(start, i);
    if (!/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(raw)) err("invalid number");
    return Number(raw);
  }
  const v = value(); ws();
  if (i !== text.length) err("trailing content");
  return v;
}

// --- keccak-256 (Ethereum), self-contained via BigInt lanes ---
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808An, 0x8000000080008000n,
  0x000000000000808Bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008An, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000An,
  0x000000008000808Bn, 0x800000000000008Bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800An, 0x800000008000000An,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [
  [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
];
const M = (1n << 64n) - 1n;
const rotl = (x, n) => ((x << n) | (x >> (64n - n))) & M;

function keccakF(s) {
  for (const rc of RC) {
    const c = [];
    for (let x = 0; x < 5; x++) c[x] = s[x][0] ^ s[x][1] ^ s[x][2] ^ s[x][3] ^ s[x][4];
    const d = [];
    for (let x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1n);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) s[x][y] ^= d[x];
    const b = [[], [], [], [], []];
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++)
      b[y][(2 * x + 3 * y) % 5] = rotl(s[x][y], BigInt(ROT[x][y]));
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++)
      s[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & M) & b[(x + 2) % 5][y]);
    s[0][0] ^= rc;
  }
  return s;
}

export function keccak256(data) {
  const rate = 136;
  const s = [[0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n],
             [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n]];
  const padded = Buffer.concat([Buffer.from(data), Buffer.from([0x01])]);
  const padLen = rate - (padded.length % rate || rate) + padded.length;
  const buf = Buffer.alloc(Math.ceil((padded.length + 1) / rate) * rate);
  padded.copy(buf);
  buf[buf.length - 1] ^= 0x80;
  for (let off = 0; off < buf.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      const lane = buf.readBigUInt64LE(off + i * 8);
      s[i % 5][Math.floor(i / 5)] ^= lane;
    }
    keccakF(s);
  }
  const out = Buffer.alloc(32);
  let filled = 0;
  while (filled < 32) {
    for (let i = 0; i < rate / 8 && filled < 32; i++) {
      const tmp = Buffer.alloc(8);
      tmp.writeBigUInt64LE(s[i % 5][Math.floor(i / 5)] & M);
      const n = Math.min(8, 32 - filled);
      tmp.copy(out, filled, 0, n);
      filled += n;
    }
    if (filled < 32) keccakF(s);
  }
  return out;
}

export function digestBytes(data, algorithm = "sha256") {
  if (!SUPPORTED_ALGORITHMS.includes(algorithm)) throw new CanonError("unsupported algorithm: " + algorithm);
  if (algorithm === "sha256") return createHash("sha256").update(data).digest("hex");
  return keccak256(data).toString("hex");
}

// --- CLI: node canoncheck.mjs <file.json> ---
if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const raw = readFileSync(process.argv[2], "utf8");
    const value = parseStrict(raw);
    const c = canonicalize(value);
    process.stdout.write(JSON.stringify({
      canonical: c.toString("utf8"),
      canonical_hex: c.toString("hex"),
      sha256: digestBytes(c, "sha256"),
      keccak256: digestBytes(c, "keccak256"),
    }));
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: String(e.message || e) }));
  }
}
