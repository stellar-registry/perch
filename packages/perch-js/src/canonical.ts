// Canonical JSON (RFC 8785 / JCS subset) and doc_hash — byte-identical to
// perch-ir's `canon.rs`. This is the whole point of the TS surface: the hash a
// reviewer approves off-chain must match what the Rust compiler and on-chain
// state commit to.
//
// Parity notes (verified against testdata/ci-publish.*):
//  - Object keys are sorted by UTF-16 code units; JS `Array#sort` on strings
//    already does exactly this, matching Rust's `encode_utf16().cmp`.
//  - String escaping: `JSON.stringify` of a string emits precisely the JCS
//    escaping serde_json produces — minimal escapes, short forms \b\t\n\f\r,
//    lowercase \u00xx for other control chars, literal UTF-8 beyond ASCII,
//    forward slash NOT escaped.
//  - Numbers: every number in a PolicyDoc is a u32, so plain decimal (`String`)
//    matches; a non-integer is a bug and throws rather than emit an exponent.
//  - `undefined` fields are omitted; the canonical form never contains `null`.

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

function write(v: unknown): string {
  if (v === null) {
    // A PolicyDoc never carries null (absent optionals are omitted). Reaching
    // here means malformed input; fail closed rather than emit `null`.
    throw new Error('canonical form must not contain null');
  }
  switch (typeof v) {
    case 'string':
      return JSON.stringify(v);
    case 'number':
      if (!Number.isInteger(v)) throw new Error(`non-integer number in canonical form: ${v}`);
      return String(v);
    case 'boolean':
      return v ? 'true' : 'false';
    case 'object': {
      if (Array.isArray(v)) return `[${v.map(write).join(',')}]`;
      const obj = v as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${write(obj[k])}`).join(',')}}`;
    }
    default:
      throw new Error(`unserializable value in canonical form: ${typeof v}`);
  }
}

/** Serialize a policy document to its canonical JSON form. */
export function canonicalJson(doc: unknown): string {
  return write(doc);
}

/** Lowercase-hex SHA-256 of the canonical JSON bytes — the document's identity. */
export function docHash(doc: unknown): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonicalJson(doc))));
}
