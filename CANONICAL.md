# Perch canonical form (CANON v1)

`doc_hash = SHA-256(canonical_bytes(doc))` is the identity of a policy document:
what a reviewer approves off-chain, what the compiler lowers, and what on-chain
state commits to. For that identity to be trustworthy, **every implementation
must produce the same bytes for the same document** — in Rust
(`perch-ir/src/canon.rs`), in TypeScript (`perch-js/src/canonical.ts`), and in
anything written later.

This document is the authoritative definition of those bytes. It is normative;
the code implements it, not the other way around. Implementations **must not**
delegate canonicalization to a language JSON serializer whose output could drift
between versions (`serde_json`, `JSON.stringify`, …). They implement the rules
below directly, and the shared conformance vector pins the result.

> Why not "just use the serializer's output"? Because serializer output is not a
> stable contract. Biscuit shipped its signed format over protobuf and
> discovered protobuf encoding is not deterministic; it had to move to an
> explicit, versioned byte layout. Perch avoids that trap by defining the bytes
> here and never depending on a serializer being canonical.

## Version

`CANON_VERSION = 1`.

The version is a **format identifier**, exported as a constant in each
implementation (`perch_ir::CANON_VERSION`, `perch-js` `CANON_VERSION`). It is
**not** part of the hash preimage — the bytes below contain no version marker,
so `doc_hash` is exactly `SHA-256` of the canonical serialization and nothing
else. The constant exists so that any change to the rules in this document is an
explicit, greppable, reviewable event: **any change here is a breaking change**
that must bump `CANON_VERSION`, re-freeze the conformance vectors, and be treated
as a new format — never a silent hash drift.

## Codec decision: JSON (JCS), not CBOR

The canonical form is JSON per **RFC 8785 (JSON Canonicalization Scheme)**,
restricted to the subset a `PolicyDoc` can produce (below). DAG-CBOR was
considered (it is what UCAN uses, precisely because CBOR defines deterministic
map-key ordering) and rejected for v1:

- A `PolicyDoc` is a **human-authored, human-reviewed** artifact. JSON stays
  diffable in a PR and readable in a wallet prompt; a binary codec does not.
- The parity guarantee CBOR would buy — byte-identical output across languages —
  is **already met**: `perch-ir` (Rust) and `perch-js` (TypeScript) reproduce
  the same canonical bytes and `doc_hash` for the shared `ci-publish` fixture,
  proven in CI on both sides.

Revisit only if a future value type makes JSON canonicalization genuinely
painful (e.g. arbitrary-precision or binary fields) — and if so, that is a
`CANON_VERSION` bump, per above.

## The bytes

The canonical serialization of a document value is defined recursively. There is
**no insignificant whitespace** anywhere: no spaces, no newlines, no
indentation.

### Objects

`{` then each member `key:value` joined by `,` then `}`. Members are sorted in
**ascending order by the UTF-16 code units of the (unescaped) key**. Keys in the
model are fixed ASCII field names, so this coincides with byte order; the
ordering is still specified over UTF-16 code units so it remains well-defined if
a non-ASCII key ever enters the model. The key is serialized with the **string**
rules below; `value` recurses.

```
{"alpha":[1,2],"beta":{"x":2,"y":1},"zeta":1}
```

### Arrays

`[` then elements joined by `,` then `]`. **Element order is preserved** (arrays
are ordered; only object members are sorted).

### Numbers

Every number a `PolicyDoc` can hold is a `u32`. It is serialized as **plain
decimal ASCII digits**: no sign, no exponent, no decimal point, no leading zero
(except the value `0`, which is `0`). A non-integer or out-of-range number is a
bug, not input — implementations fail closed rather than emit an exponent form.

### Strings

A string is `"` … `"` with the contents UTF-8, escaping **only** what RFC 8785
§3.2.2.2 requires:

| character | escape |
|-----------|--------|
| `"` (U+0022) | `\"` |
| `\` (U+005C) | `\\` |
| backspace (U+0008) | `\b` |
| tab (U+0009) | `\t` |
| line feed (U+000A) | `\n` |
| form feed (U+000C) | `\f` |
| carriage return (U+000D) | `\r` |
| any other control char U+0000–U+001F | `\u00xx` (lowercase hex) |
| everything else | emitted literally |

Consequences worth stating explicitly, because they are where naive
implementations differ:

- **Forward slash `/` is not escaped.**
- **Non-ASCII is not escaped** — it is emitted as literal UTF-8, never `\uXXXX`.
- **`\uXXXX` escapes are lowercase** and only ever used for control characters
  U+0000–U+001F that lack a short form.
- **DEL (U+007F) is not a control character for this purpose** (it is ≥ U+0020)
  and is emitted literally.

### Booleans and null

`true` / `false` are defined for completeness but are unreachable from the
current model. **`null` never appears**: an absent optional field is omitted
from its object entirely, not serialized as `null`. Encountering `null` while
canonicalizing is malformed input and fails closed.

## Conformance

The shared vector lives in `testdata/`:

- `ci-publish.json` — a real policy document (the flagship CI-publish policy).
- `ci-publish.canonical.json` — its canonical bytes, exactly as defined above.
- `ci-publish.doc-hash` — `38c7ae56e602adbd318d08b92c664106fde77f3f08b7457ed8203f0d2d27ab0d`.

Both suites assert, against these files, that canonicalization is byte-identical
and the hash matches:

- Rust: `crates/perch-ir/tests/fixture.rs`
- TypeScript: `packages/perch-js/test/parity.test.ts`

A change to any byte of `ci-publish.canonical.json` or `ci-publish.doc-hash` is,
by definition, a canonical-form break — see **Version** above.
