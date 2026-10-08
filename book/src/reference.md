# Language reference and glossary

This is a compact map of document format 1. Examples in the earlier chapters explain how the pieces work together.

## Document fields

| Field | Meaning |
|---|---|
| `version` | Required; currently `1` |
| `network` | Optional string in the schema; matching network passphrase required by the on-chain doc compiler |
| `signers` | Signer declarations, each with a unique local `id` |
| `rules` | Named authorization rules, with unique names |

## Rule fields

| Field | Meaning |
|---|---|
| `name` | Local name for review and tooling |
| `scope` | `{"type":"self-admin"}` or `{"type":"contract","address":"…"}` |
| `principals` | `all`, `threshold`, or schema-only `self-authenticating` |
| `functions` | Optional nonempty function allowlist; omission is unrestricted within scope |
| `args` | Optional nonempty list of `{index, pred}`; indices must be unique |
| `not-after-ledger` | Optional nonzero U32 exclusive cutoff |
| `cap` | Optional positive decimal-string `limit`, nonzero `period-ledgers`, optional matching `token` |

An external signer has `id`, `verifier`, and `key`. A delegated signer has `id` and `address`. The forms cannot be mixed. External key material decodes to 1–256 bytes and is interpreted by its verifier.

Argument predicate payloads are `is-self` (no additional fields), `address-eq` (`address`), `string-in` (`values`), `string-prefix` (`prefix`), and `u32-eq` (`value`). Strings and addresses retain their types; no automatic string-to-number conversion is implied.

## Glossary

| Term | Meaning in this book |
|---|---|
| Authentication | Establishing which identities authorized a call |
| Authorization | Deciding whether a call is permitted |
| Canonicalization | Deterministically encoding a document value |
| Conformance vector | A shared input and expected result |
| Declarative | Describing permitted behavior rather than an execution procedure |
| Differential test | Comparing implementations on the same inputs |
| Fail closed | Requiring a definite successful verdict before allowing |
| Formal model | Precise data and functions used to state and prove properties |
| Injective | Different inputs cannot produce the same output |
| Invariant | A property required to hold throughout the relevant operations |
| Lowering | Translating a document into execution-oriented rules and programs |
| Predicate | A check about an input |
| Principals | The identities required by a rule |
| RPN | A notation placing combining operations after their operands |
| Semantics | The meaning assigned to a document or program |
| SMT solver | A tool for deciding logical constraints in supported theories |
| Trusted base | Components and assumptions a claim still depends on |

## Where to go next

Read [CANONICAL.md](https://github.com/stellar-registry/perch/blob/main/CANONICAL.md) for byte-level rules, [the IR types](https://github.com/stellar-registry/perch/blob/main/crates/perch-ir/src/doc.rs) for the document model, and [the compiler](https://github.com/stellar-registry/perch/blob/main/crates/perch-compile/src/lib.rs) for lowering decisions. The [formal README](https://github.com/stellar-registry/perch/blob/main/formal/README.md) maps proof files, while the [slide deck](../slides/) offers a shorter presentation.
