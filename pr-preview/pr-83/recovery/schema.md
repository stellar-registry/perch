# Recovery configuration: schema design

This documents the `recovery` field added to `PolicyDoc`
(`crates/perch-ir/src/doc.rs`), why it is shaped the way it is, and how it
was fit into `CANONICAL.md` without disturbing the canonical form of any
document that doesn't use it. See the authoritative decision record's §5.5
("Reviewable configuration without circular hashes") for the requirements
this design answers.

## What's in scope here, and what isn't

`RecoveryConfig` is **enrollment configuration** — who may recover this
account and how. It is not a recovery attempt. An attempt's target document
and evidence are supplied when recovery starts, against a separate
controller contract (see [`controller-governance.md`](controller-governance.md));
none of that is, or should be, predeclared in the document. Putting only the
configuration in the document — never dynamic pending state — is what keeps
`doc_hash` a stable, reviewable identity: two enrollments with the same
configuration hash the same, regardless of how many attempts have come and
gone.

## Field-by-field rationale

```
recovery: Option<RecoveryConfig>
```

Omitted entirely when `None` (see "CANONICAL.md treatment" below) — this is
the single fact that keeps every pre-existing document's hash unchanged.

```
RecoveryConfig {
  profile: RecoveryProfile,            // Loss | Protected           — §2.1
  mode: RecoveryMode,                  // GuardianOnly | ZkOnly | Combined
  controller: String,                  // adopted controller instance's address
  baseline: Option<BaselineCommitment>,// required to enroll compromise recovery
  replaceable: Vec<String>,            // signer ids recovery may replace — §4.1
  delay_ledgers: u32,                  // timelock window
  expiry_ledgers: u32,                 // authorized-attempt lapse window
  max_cancels: u32,                    // lifetime cancellation cap (griefing bound)
  pending_activity: PendingActivityPolicy, // Freeze | Continue, NO default — §7
}
```

- **`profile` and `mode` are orthogonal fields**, exactly per §2.1 ("Either
  profile can use any of the three authentication modes"). Keeping them as
  two independent fields rather than a combined enum avoids a 6-way
  cross-product type for no benefit.
- **`mode` is a per-variant enum, not a flattened struct with optional ZK
  fields.** The validated experiment this stage generalizes stored mode as
  one struct with `guardians: Vec<Address>` and `verifier: Option<Address>`
  side by side (`RecoveryConfig` in that codebase's `types.rs`), because its
  target SDK's `#[contracttype]` derive doesn't support `Option<CustomStruct>`
  on a flattened struct field cleanly. Perch's document model has no such
  constraint (`perch-ir` is plain Rust, not itself a `#[contracttype]`), so
  `RecoveryMode::GuardianOnly(GuardianSet)` simply **cannot** carry a
  `verifier`/`circuit-id`/`pool` field at all — "guardian-only requires no ZK
  machinery" is enforced by the type, not by a runtime check that a ZK field
  happens to be `None`. The wire (`perch-doc-compiler`) and JSON
  (`perch-js`) encodings flatten the tagged variant's fields into one object
  at the wire level (`{"type":"guardian-only","guardians":[...],"quorum":N}`)
  for a compact document, but the *source of truth* — the Rust and TS types
  — stay per-variant.
- **`delay_ledgers`/`expiry_ledgers` are ledger-sequence deltas, not
  durations in seconds.** This matches perch's own existing convention
  (`Rule::not_after_ledger`) rather than the validated experiment's
  timestamp-based fields — the account, interpreter, and every other
  ledger-relative quantity in this schema already speaks ledger sequence,
  and mixing units within one document would be a real (if subtle) foot-gun
  for anyone reading it.
- **`replaceable` is required non-empty**, per §4.1: "Enrollment records...
  identifies which signer entries or roles recovery may replace." An empty
  list would enroll recovery that can never restore access — rejected at
  validation, not left as a silent no-op. In the document it names
  document-local signer **ids** (human-reviewable, e.g. `"admin"`); the
  compiler resolves each to a `sha256` fingerprint of that signer's actual
  credential (verifier+key, or the delegated address) for the wire form the
  controller stores — not the id string, which a later document could
  legitimately reuse for a different physical key. This is what lets
  revocation (property 10: an old baseline must not restore a revoked
  credential) survive id reuse across documents.
- **`baseline` is optional, and its presence is what gates suspected-compromise
  recovery**, per §4.2: lost-key recovery needs no predetermined baseline
  (it targets "current approved document with designated credentials
  replaced"); compromise recovery needs one to restore to. `None` therefore
  means "lost-key recovery only," not "recovery is half-configured."
- **`pending_activity` has no default and no third "unspecified" variant.**
  See [`section-7-gate.md`](section-7-gate.md) — this is the schema-level
  half of keeping §7 an explicit parameter rather than a library default.

## Non-circular baseline commitment (§5.5)

`BaselineCommitment { doc_hash: String }` names a **different, earlier**
document's canonical hash — never the enclosing document's own hash. There
is no field anywhere that could make a document's `recovery.baseline`
recursively depend on that same document's own `doc_hash`, because the
baseline is always a value chosen *before* the enclosing document is
authored (whatever the previously-approved document was), and `doc_hash` is
computed *after* the whole document — including `recovery` — is fixed. The
`ci-publish-recovery` conformance fixture demonstrates this concretely: its
`recovery.baseline.doc-hash` is literally the pinned `doc_hash` of the
plain `ci-publish` fixture, a genuinely different, independently-hashed
document (see `testdata/ci-publish-recovery.json` and
`crates/perch-ir/tests/recovery.rs`).

This is intentionally **not** verified against on-chain history at compile
time — `perch-smart-account` only stores the *current* `applied_doc_hash`,
not a history of prior ones (see
[`account-mutation-paths.md`](account-mutation-paths.md)), so there is
nothing on-chain to check a baseline against even if perch wanted to.
Reviewing that a declared baseline hash genuinely names a real,
previously-approved document is part of enrollment review, the same way
reviewing that a `Scope::Contract` address is the intended contract is part
of ordinary rule review.

## CANONICAL.md treatment

`recovery` slots into the existing "omit `None`, don't emit `null`"
convention (`CANONICAL.md`, "Booleans and null") that every other optional
field in the schema already uses (`network`, `not-after-ledger`, `cap`,
...). No new canonicalization *rule* was needed — `crates/perch-ir/src/canon.rs`
adds a `recovery_to_cv` builder that's only invoked `if let Some(r) =
&doc.recovery`, exactly mirroring `rule_to_cv`'s treatment of `cap`. Because
`CANON_VERSION` is a format identifier covering the *serialization rules*,
not the document's field set, adding a new optional field does not bump it
— the rules in `CANONICAL.md` (object key sorting, JCS string escaping,
plain-decimal `u32`s, no `null`) are unchanged; only the set of fields a
`PolicyDoc` can carry grew, which every implementation must still agree on
byte-for-byte (verified below).

**Testable compatibility condition, and its proof:** the follow-up review's
§5.5 asks whether an additive field can preserve the existing canonical
format — a testable condition, not a blanket claim. It's tested directly:
`crates/perch-ir/tests/recovery.rs::recovery_absent_documents_hash_exactly_as_before_this_field_existed`
asserts the canonical form of a recovery-absent document contains no
`"recovery"` substring at all, and every pre-existing fixture
(`ci-publish{,-delegated,-threshold}`) and its pinned hash is **unchanged**
by this stage (not regenerated) — their tests in `crates/perch-ir/tests/fixture.rs`
and `packages/perch-js/test/parity.test.ts` still pass against the same
committed bytes. That is the condition being claimed, made byte-for-byte
verifiable rather than asserted.

## Cross-language conformance

Two new fixture triples extend `testdata/` in lockstep with the existing
`ci-publish*` ones: `ci-publish-recovery` (guardian-only, `protected`
profile, with a baseline) and `ci-publish-recovery-combined` (combined
guardian+ZK, `loss` profile, no baseline — demonstrating lost-key-only
enrollment). Both are asserted byte-identical and hash-identical on the
Rust side (`crates/perch-ir/tests/recovery.rs`) and the TypeScript side
(`packages/perch-js/test/parity.test.ts`), and `packages/perch-js/src/builder.ts`'s
new `.recovery(...)` builder method is proven to reproduce both fixtures'
exact `doc_hash` from a fluent call
(`packages/perch-js/test/builder.test.ts`) — the same "does the ergonomic
builder actually produce the reviewed bytes" property already established
for every other rule shape.

perch-ir's semantic validation (`crates/perch-ir/src/validate.rs`) is
extended with recovery-specific checks (non-empty/non-duplicate
`replaceable` referencing declared signers, non-zero delay/expiry/max-cancels,
address-shape checks on `controller`/guardian addresses/verifier/pool,
hex-format checks on `circuit-id` and the baseline `doc-hash`, and
`1 <= quorum <= guardians.len()` mirroring `Principals::Threshold`'s
existing `InvalidThreshold` rationale). `packages/perch-js/src/schema.ts`
mirrors the *shape* of these rules (strict per-variant objects, required
`pending-activity` with no default) but not yet the full semantic pass —
consistent with, and tracked under, the same pre-existing gap noted at the
top of `schema.ts` for the rest of the schema (issue #8: perch-js does not
yet mirror `perch-ir`'s full `validate()`).

## Lean / formal-verification impact

See [`formal-verification-impact.md`](formal-verification-impact.md).
