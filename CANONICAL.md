# Perch canonical form (CANON v1)

`doc_hash = SHA-256(canonical_bytes(doc))` is the identity of a policy document:
what a reviewer approves off-chain, what the compiler lowers, and what on-chain
state commits to. For that identity to be trustworthy, **every implementation
must produce the same bytes for the same document**, in Rust
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

The version is a format identifier, exported as a constant in each
implementation (`perch_ir::CANON_VERSION`, `perch-js` `CANON_VERSION`). It is
**not** part of the hash preimage. The bytes below contain no version marker,
so `doc_hash` is exactly `SHA-256` of the canonical serialization and nothing
else. The constant exists so that any change to the rules in this document is an
explicit, greppable, reviewable event. **Any change here is a breaking change** that must
bump `CANON_VERSION`, re-freeze the conformance vectors, and be treated as a new
format, never a silent hash drift.

## Codec decision: JSON (JCS), not CBOR

The canonical form is JSON per RFC 8785 (JSON Canonicalization Scheme),
restricted to the subset a `PolicyDoc` can produce (below). DAG-CBOR was
considered (it is what UCAN uses, because CBOR defines deterministic
map-key ordering) and rejected for v1:

- A `PolicyDoc` is a human-authored, human-reviewed artifact. JSON stays
  diffable in a PR and readable in a wallet prompt; a binary codec does not.
- The parity guarantee CBOR would buy, byte-identical output across languages,
  is already met. `perch-ir` (Rust) and `perch-js` (TypeScript) reproduce
  the same canonical bytes and `doc_hash` for the shared `ci-publish` fixture,
  proven in CI on both sides.

Revisit only if a future value type makes JSON canonicalization painful
(e.g. arbitrary-precision or binary fields). If so, that is a
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
bug, not input. Implementations fail closed rather than emit an exponent form.

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
- **Non-ASCII is not escaped.** It is emitted as literal UTF-8, never `\uXXXX`.
- **`\uXXXX` escapes are lowercase** and only ever used for control characters
  U+0000–U+001F that lack a short form.
- **DEL (U+007F) is not a control character for this purpose** (it is ≥ U+0020)
  and is emitted literally.

### Booleans and null

`true` / `false` are defined for completeness but are unreachable from the
current model. **`null` never appears.** An absent optional field is omitted
from its object entirely, not serialized as `null`. Encountering `null` while
canonicalizing is malformed input and fails closed.

## Fragment hashes

`doc_hash` identifies a whole document. Two other hashes identify one
**fragment** of it: the exact bytes that member contributes to the
document's canonical serialization above, cut out unchanged and hashed
under a domain tag of its own.

| Hash | Fragment `F` | Preimage | Used by |
| --- | --- | --- | --- |
| `rule_hash` | one element of the top-level `rules` array, without the separating commas | `"perch/rule" ‖ F` | interpreter program provenance: the hash an installed program carries in place of the whole document's `doc_hash`. Also how a delta `apply_doc` tells which rules changed. |
| `config_hash` | the value of the top-level `recovery` member | `"perch/recovery/config" ‖ F` | recovery configuration identity (`docs/recovery/spec.md` §3.2) |

Both are `SHA-256` of the preimage. The tags are ASCII and are part of the
preimage. `doc_hash` is unchanged: still untagged `SHA-256` of the whole
canonical document.

**Domain separation.**

- A canonical document starts with `{`, and every tag starts with `perch/`,
  so no fragment preimage equals a document preimage.
- Neither tag is a prefix of the other, and neither is a prefix of the
  recovery statement's tags (`perch/recovery/statement`, …;
  `docs/recovery/statement.md`). Different fragment kinds therefore never
  share a preimage.

The Lean model (`formal/`) proves both preimages injective and the
separations between document, `rule_hash`, and `config_hash` preimages
(`rulePreimage_injective`, `configPreimage_injective`,
`rulePreimage_ne_emitDoc`, `configPreimage_ne_emitDoc`,
`rulePreimage_ne_configPreimage`). It does not model the statement tags.

**What a rule hash covers.** A `rule_hash` covers the rule's own text,
signer *ids* included. It does not cover the signers' credentials, which
live in the document's `signers` member. The same rule text in two
documents therefore has the same `rule_hash` (see the `admin` rule across
the vectors below). A program's `rule_hash` says which rule text it was
compiled from; it does not identify the document. Only `doc_hash` does.

Fragment hashes are definitions over the bytes above, not new
canonicalization rules, so they do not change `CANON_VERSION`. Changing a
tag or the fragment boundaries is a breaking change to every recorded
value, and must be treated like one.

Code:

- Rust: `perch_recovery_interface::fragment::rule_hash` and
  `perch_recovery_interface::config::config_hash`.
- The doc compiler computes both from the canonical bytes it already
  emits.

## Conformance

The shared vector lives in `testdata/`:

- `ci-publish.json`: a real policy document (the CI-publish policy).
- `ci-publish.canonical.json`: its canonical bytes, exactly as defined above.
- `ci-publish.doc-hash`: `27cb38ef07bd8e4f86f07bef4d9272c070c2d9f05063d4c1ad1d4769b1d74a98`.

Fragment hashes have their own vector, `testdata/rule-hashes.json`. An
independent script (`scripts/rule-hash-vectors.py`) generates it by cutting
each rule's bytes out of the committed `ci-publish{,-delegated,-threshold}`
canonical files. `crates/perch-recovery-interface/tests/vectors.rs` asserts
that those bytes are exactly each fixture's `rules` array and that every
`rule_hash` matches. For `ci-publish`:

- `admin` rule: `a23e499eb6906e76a489ae7b901d11245b18119bf9f7299c42932016a02e4ecf`
- `ci-publish` rule: `fbd758674683fdbafa01f927b76cef5f79c86448b440177296709b3073f7751e`

Both suites assert, against these files, that canonicalization is byte-identical
and the hash matches:

- Rust: `crates/perch-ir/tests/fixture.rs`
- TypeScript: `packages/perch-js/test/parity.test.ts`

The Lean model (`formal/`) parses and re-emits it, and the other
`testdata/*.canonical.json` fixtures, byte-identically with a verified inverse
of its own canonical emitter (`just drt`), and proves that emitter injective.

A change to any byte of `ci-publish.canonical.json` or `ci-publish.doc-hash` is,
by definition, a canonical-form break; see **Version** above.
