# Deferred until after the audit

Work listed here is outside the audited commit ([`audit-scope.md`](audit-scope.md)).
Each entry states what the audited code does today, the residual risk of
leaving the change for later, what ends the deferral, and the review the
change will need then. The audit reviews the current behaviour each entry
describes.

These are implemented and in scope, not deferred: the account's consumer
views (`revision`, `configuration`, `document`, `capabilities`), the
two-digest recovery target binding, and `apply_doc`'s optional
`expected_revision` check.

**Decision status.** The entries that cite RFC
[#109](https://github.com/stellar-registry/perch/issues/109) are scope
declarations for this audit. RFC #109 is an open discussion, and none of
these entries is an accepted design for the later work.

**Packaging rule.** Moving a consumer from a source or submodule dependency
to a published package (an npm release, a registry Wasm release) is
packaging work only when the consumed code and artifacts are shown equal to
the audited source: for example, by rebuilding the package from the audited
commit and comparing bytes, or by comparing a published Wasm hash with the
hash a reproducible build of the audited commit gives
([`audit-scope.md`](audit-scope.md#deployment-provenance)). A version bump
is not that proof. Without it, the move is a code change and needs review
as one.

## CANON v2 structured document identity

**Deferred:** a structured document identity (CANON v2), such as a
Merkle-style hash over document members, in place of the hash of the whole
canonical document.

**Current behaviour:** CANON v1 ([`CANONICAL.md`](../CANONICAL.md)) is the
identity: `doc_hash = SHA-256(canonical bytes)`, plus two tagged fragment
hashes, `rule_hash` (`"perch/rule" ‖ rule bytes`) and `config_hash`
(`"perch/recovery/config" ‖ recovery member bytes`). A recovery attempt
records two digests of its derived target ([spec](recovery/spec.md) §6.3,
T1): `target_bytes_hash`, which the controller's `rcv_complete` compares with
`sha256` of the completing `apply_doc` bytes, and `target_doc_hash`, which
`rcv_sync` compares with the identity the account's compiler computed. Under
CANON v1 the two are equal (`canonical_bytes_identity`,
[`formal/README.md`](../formal/README.md)). Baselines are enrolled by their
CANON v1 `doc_hash` (spec §3.5).

**Why it is safe to defer:** CANON v1 identifies a document completely: T7
proves the canonical form injective over every `PolicyDoc` shape, so
`doc_hash` names one document up to a SHA-256 collision. What v1 lacks is a
proof that one member belongs to a document without the whole document, and
no audited check needs one. Because the controller keeps the two digests
apart, a later identity scheme needs a new compiler and account build, not a
new controller.

**Exit criterion and follow-up review:** a CANON v2 definition with frozen
vectors and a `CANON_VERSION` bump. An account pins its compiler at build
time, so adopting v2 needs a new compiler and account build, an account
upgrade (owner authorization and the 120,960-ledger delay; under
`Protected`, the condition's evidence over the upgrade, spec §12),
re-application of each document, and re-approval of every enrolled baseline
under the new identity (a reconfiguration, which under `Protected` needs the
condition). Review the new identity and its proofs, every compiler, account,
and controller path that computes or compares an identity, the statement
fields that carry document hashes, and the migration of existing accounts.

**Owner:** Perch.

**Tracking:** RFC [#109](https://github.com/stellar-registry/perch/issues/109)
(CANON v2 identity);
[#105](https://github.com/stellar-registry/perch/issues/105) (Merkle-style
document hash).

## Canonical value spellings

**Deferred:** enforcing one canonical spelling for every value a CANON v1
document carries, so that two logically equal documents always share a
`doc_hash`.

**Current behaviour:** CANON v1 ([`CANONICAL.md`](../CANONICAL.md)) fixes
byte-level serialization but not every value-level spelling, and `perch-ir`
and `perch-js` disagree on a few. A cap `limit` with a leading `+` or leading
zeros (`+1000`, `01000`) is accepted as distinct bytes from `1000`; signer key
hex is accepted in either case; and perch-js's `canonicalJson` accepts or emits
number forms (`1.0`, `1e0`, `-0`, exponent output) that `perch-ir` refuses or
spells differently. So two documents that mean the same thing can compile to
different `doc_hash`es.

**Why it is safe to defer:** the wallet's Rust and TypeScript builders emit the
canonical spelling, so documents produced through the supported path already
agree. The residual is a hand-written or third-party document whose
non-canonical spelling hashes differently from its canonical twin; it still
authorizes exactly what it says, and the account enforces the document it
received. Enforcing canonical spellings changes the `doc_hash` of existing
non-canonical inputs, so it is a versioned change, not a silent one.

**Exit criterion and follow-up review:** define the one valid spelling per
field (lowercase hex, a decimal `limit` with no sign or leading zeros, integer
number forms), enforce it in `perch-ir::validate` and `perch-js`, add
cross-language parity vectors, and bump `CANON_VERSION` with the rest of
CANON v2.

**Owner:** Perch.

**Tracking:** CANON v2, RFC [#109](https://github.com/stellar-registry/perch/issues/109).

## PolicyDoc JSON Schema: strict profile and out-of-schema checks

**Deferred:** a strict *canonical* profile of the versioned PolicyDoc JSON
Schema ([`schema.md`](schema.md)) that rejects the non-canonical value spellings
its v1 profile accepts; schema rules for the two value checks it can express
but does not yet encode (Soroban `Symbol` function names and the
`string-prefix` byte bound); and any schema expression of the document checks
JSON Schema structurally cannot state.

**Current behaviour:** the generated schema,
[`packages/perch-js/schemas/policy.schema.json`](../packages/perch-js/schemas/policy.schema.json)
(generator `crates/perch-schema`, drift-checked by `cargo test`), describes
document `version: 1`. `@stellar-registry/perch` lists `schemas/` in its
published files; npm releases from 0.4.0 contain it, and 0.3.2 and earlier
predate it. By design the schema accepts what `perch-ir`'s parser accepts,
so that schema validation and the parser agree (a schema that rejected a
document the parser accepts would mislead an offline editor). It therefore
accepts the same non-canonical spellings the "Canonical value spellings" entry
above lists: a `cap.limit` with a leading `+` or leading zeros, and signer-key
hex in either case. It *does* pin the 64-lowercase-hex digest fields
(`doc-hash`, `circuit-id`, `enrollment-id`, `commitment`) because the parser
already requires that form. These checks stay outside the schema, each
with its authority unchanged:

- `perch-ir`'s parser: duplicate raw JSON keys, which a validator of
  already-parsed JSON cannot see;
- `perch-ir::validate`: uniqueness of signer ids and of rule names, compared
  by key across siblings;
- `perch-ir::validate`: reference resolution (a principal/`replaceable` id
  resolving to a declared signer; a cap `token` matching the rule's contract
  scope);
- `perch-ir::validate`: the CRC16 checksum of every address strkey (the
  schema pins only the shape);
- `perch-ir::validate`: each `functions` entry being a Soroban `Symbol`
  (1–32 characters from `[a-zA-Z0-9_]`), and a `string-prefix` prefix of at
  most `MAX_STRING_PRED_LEN` (256) bytes. Both are expressible in JSON
  Schema; the generator does not emit them yet;
- the compiler (`perch-doc-compiler`), mirrored client-side by perch-js
  `checkLimits`: the canonical-byte budget (`max_canonical_bytes`), a
  property of the canonically-encoded bytes rather than the parsed tree;
- `perch-ir::validate`: the BN254 field-element range on a recovery
  `commitment`, and the exact `i128` upper bound on a `cap.limit`;
- `perch-ir::validate`: guardian `quorum <= count` for guardian sets larger
  than the schema's enumerated depth (guardians have no dedicated cap
  constant);
- `__check_auth` and OZ policy enforcement: signatures and authorization.

**Why it is safe to defer:** the parser, compiler, and account remain the
authority for every check the schema leaves out, so no check is lost, only
not yet mirrored into the schema. `compile_doc` refuses a schema-valid
document that fails one of them with a typed error (`DocParse`,
`DocInvalid`, or `DocTooLarge`), so the gap fails closed: an editor can
accept a document the chain will refuse, never the reverse. Tightening the
schema to a canonical profile before the parser enforces one spelling would
make it reject documents the chain still accepts.

**Exit criterion and follow-up review:** add the `Symbol` pattern for
`functions` entries and a `string-prefix` bound to the generator (the byte
bound needs the same ASCII-or-stricter treatment as rule names, because
`maxLength` counts code points), regenerate the committed artifact, and extend
the conformance cases so schema and validator reject them together. Once
"Canonical value spellings" lands (one valid spelling enforced in
`perch-ir::validate` and `perch-js`), add the matching strict profile
(lowercase-only signer-key hex, a `cap.limit` with no sign and no leading
zeros, and the settled integer number-form spelling) and extend the
drift/parity/conformance suites so the strict schema and the parser still agree
in both directions. A dedicated guardian-count cap would let the schema encode
`quorum <= count` fully. Review the regenerated schema against the parser's
rules and the cross-language parity vectors.

**Owner:** Perch.

**Tracking:** CANON v2, RFC [#109](https://github.com/stellar-registry/perch/issues/109).

## Versioned policy backend and larger limits

**Deferred:** explicit policy-backend versioning and document
limits above the current caps.

**Current behaviour:** the account's rule-eval backend and delta reconciliation
are described in [the recovery spec §7.5](recovery/spec.md#75-bounded-completion-cost).
The doc compiler refuses with `DocTooLarge`, on every `compile_doc` and
`derive_target`, a document with more than 8 declared signers
(`MAX_DOC_SIGNERS`), more than 10 rules (`MAX_DOC_RULES`), more than 8,192
canonical bytes (`MAX_DOC_CANONICAL_BYTES`), or a rule name over 20 bytes
(`MAX_RULE_NAME_BYTES`, the account's `MAX_NAME_SIZE`). The recovery rule the account
generates is additional to the 10 document rules. The caps are sized so that
a worst-case completion, compromise restore, or `Protected` reconfiguration
stays within 75% of every *measured* per-transaction limit: instructions,
memory, write bytes, and write entries
([`budgets.md`](recovery/budgets.md), "Document caps"; the `worst_case_*`
tests in `crates/integration-tests/tests/release_stack.rs`). Disk read bytes
are not yet measured for any row (budgets.md: "Required before launch"), so
this within-budget guarantee is conditional on completing that measurement
before mainnet.

**Why it is safe to defer:** the caps exist so that a thief holding the
owner key cannot make a recovery too expensive to complete (spec §7.5). A
document over a cap is refused whole and changes nothing. The account's
records are the audited backend (the Perch OZ materialization unit).
The residual limit is product capacity: a document that needs more signers,
rules, or bytes cannot be applied. The caps apply per document; app grants
can be spread over any number of grant documents (spec §7.6), each under
the same caps.

**Exit criterion and follow-up review:** a backend change is a new account
build that existing accounts adopt only by upgrade. Review it as a
separately scoped change with regression evidence across authorization,
recovery, and migration, and re-measure the caps against the new
completion cost. Before rollout, decide whether existing funded accounts
move to it and how. The two Perch review units are a boundary for that
review, not a guarantee that the new backend needs no integration review.

**Owner:** Perch and Nido.

**Tracking:** RFC [#109](https://github.com/stellar-registry/perch/issues/109).

## Revision-bound ordinary signatures

**Deferred:** binding ordinary (non-`apply_doc`) signatures to a
configuration revision.

**Current behaviour:** the account's configuration revision is 0 after the
constructor and advances by one on every successful `apply_doc` (a re-apply
of the same document included) and every executed upgrade, and on nothing
else. `apply_doc(doc_json, approval_valid_until, expected_revision)` refuses
with `StaleRevision` when `expected_revision` is set and the account is at
another revision. An ordinary signature binds the invocation and the
selected rule ids (OZ's `sha256(signature_payload || xdr(context_rule_ids))`),
not a revision. Between signing and inclusion, a selected rule that was
removed or replaced fails closed (`ContextRuleNotFound`), and a selected
rule that was edited in place keeps its id and the transaction is evaluated
under the rule's content at inclusion (spec §15, "Revision binding";
`crates/integration-tests/tests/revision.rs`).

**Why it is safe to defer:** a signature still authorizes only the
invocation it signed. What can change before inclusion is which signers and
policies the selected rule requires. Document writes, where acting on a
stale view does the most harm, are revision-bound. Residual risk: a signer
approves an invocation expecting one rule content, and it executes under an
in-place edit made between signing and inclusion. Consumers bound that
window with short signature expirations
([`packages/perch-js/README.md`](../packages/perch-js/README.md#selecting-rules-by-name-and-scope)).

**Exit criterion and follow-up review:** new signing semantics (what each
signer signs and how `__check_auth` checks it), capability discovery so a
wallet can tell which semantics an account implements, and updated wallet,
dApp, and session signers. Review the digest change, the account's
authorization path, and every signer implementation. Until then, no
document may claim that the document-write revision check covers every
transaction.

**Owner:** Perch and its consumers (Nido's wallet, dApp, and session
signers).

**Tracking:** RFC [#109](https://github.com/stellar-registry/perch/issues/109)
(signing semantics).

## Stable numeric rule IDs

**Deferred:** a promise that a rule keeps one numeric id across document
changes.

**Current behaviour:** rule ids come from the account's counter, as OZ's
context-rule registry gave them for the same documents. An in-place edit
keeps a rule's id. A new id comes with a changed scope, a rename, a
removal and re-addition, or a recovery rule reconfigured at the same
controller (spec §7.5). No id is given twice, so A → B → A restores the `doc_hash` but
not the ids (`a_b_a_restores_the_doc_hash_but_not_the_selection` in
`revision.rs`). Consumers select rules by name and scope from
`configuration()` at one revision (perch-js `selectRules`) and do not keep
ids across revisions.

**Why it is safe to defer:** a stale id fails closed with
`ContextRuleNotFound`, so instability costs a new signature, not a wrong
authorization. No audited contract depends on id stability.

**Exit criterion and follow-up review:** define id behaviour under rename,
recreation, and restoration (a compromise recovery to a baseline), and
whether a signature stays valid across each, before anything promises
stability. Review that definition and the account change that implements
it. The current audit contract makes no id-stability promise.

**Owner:** Perch.

**Tracking:** [#108](https://github.com/stellar-registry/perch/issues/108)
(consumer interface, rule selection).

## Persistent spending budgets across replacements

**Deferred:** a spending budget that survives rule replacement and policy
reinstallation.

**Current behaviour:** the account keeps one spending record per capped
rule, keyed by its rule id, which rule-eval charges in `__check_auth`.
When `apply_doc` or `apply_grant` keeps a rule's id and its cap, the record
is kept: a signer change or a change to the rule's other text keeps it.
Changing the cap's own parameters, renaming or rescoping the rule, or
removing it starts an empty record (spec §7.5). A compromise recovery that
restores a baseline whose capped rule the thief renamed, rescoped or
recapped therefore gives the baseline's retained signers a fresh window.

**Why it is safe to defer:** every reset needs the authority to change the
document, and that authority could remove the cap outright, so a reset
grants nothing its holder lacked. The cap still holds within each window.
Residual risk: a user or wallet that treats the cap as a budget across
document changes is wrong, and a compromise restore can give retained
baseline signers up to one further window's limit. Nido's threat model and
user-facing cap explanation must state this.

**Exit criterion and follow-up review:** new schema, policy, and state
semantics for a persistent budget, with their own audit: the policy, how
existing windows migrate, and the delta reconcile that installs it.

**Owner:** Perch and Nido.

**Tracking:** RFC [#109](https://github.com/stellar-registry/perch/issues/109)
(spending budgets).

## Additional formal models

**Deferred:** formal models and proofs beyond the existing Lean model.

**Current behaviour:** the Lean model ([`formal/README.md`](../formal/README.md))
proves T1–T8: the per-invocation evaluator and its lowering, and the CANON
v1 canonical form and fragment hashes. Its link to the Rust code is
empirical (shared vectors, round-trips, fuzzing), not deductive. There is no
formal model of the recovery controller's state machine, account
authorization (`__check_auth`, rule selection, the delta `apply_doc`, the
revision), the ZK circuit, verifier, adapter, and pool, the doc compiler
beyond canonical bytes and `config_hash` (validation, `derive_target`), or
the recovery statement encoding. Tests cover these instead
([`verification/PLAN.md`](verification/PLAN.md#coverage-today)).

**Why it is safe to defer:** the audit reviews these runtime paths
directly. A formal model adds assurance; it does not replace that review,
and no current claim rests on a model that does not exist.

**Exit criterion and follow-up review:** each new model with its proof
obligations, an axiom audit, and a stated link to the Rust code. Review the
model's assumptions and its correspondence to the implemented paths. Open
items include T9 (attenuation monotonicity), a deductive model-to-Rust tie,
and wasm-level properties beyond Komet's three.

**Owner:** Perch.

**Tracking:** none yet.

## OZ quiet-events fork pull requests

**Deferred:** merging theahaco/stellar-contracts-OZ
[#4](https://github.com/theahaco/stellar-contracts-OZ/pull/4) (`_no_events`
variants of every context-rule, signer, and policy mutation) and
[#5](https://github.com/theahaco/stellar-contracts-OZ/pull/5)
(`reconcile_signers`), re-basing the CAP-0071 delegation change they stack
on ([#3](https://github.com/theahaco/stellar-contracts-OZ/pull/3)) onto
upstream OpenZeppelin, and re-pinning to the merged code.

**Current behaviour:** the account calls none of the `_no_events` mutators,
`reconcile_signers` or `do_check_auth`. The spending limit's quiet install
and uninstall come from #4. `Cargo.toml` pins `stellar-accounts` 0.7.1 to
git rev `42089fc90684fdab33a85eac3e8311259b69a61b` of
bitswell-hq/theahaco__stellar-contracts-OZ. That rev is theahaco/stellar-contracts-OZ
`33726766a1fd5e7e3d2977d79f64ee29e1ea3ca9` (the head of #5, which is stacked
on #4, which is stacked on #3, CAP-0071 delegated authentication) moved to
soroban-sdk 29.0.1
([bitswell-hq #1](https://github.com/bitswell-hq/theahaco__stellar-contracts-OZ/pull/1)).
`33726766` is upstream OpenZeppelin `fbfde38` (the fork's `main`) plus one
commit per pull request. All three theahaco pull requests are open. Cargo
builds the pinned commit whatever their state (`Cargo.lock` records it), so
the audited code is that rev, and the fork's changes are reviewed as the
diff from upstream `fbfde38` to `42089fc9`
([`audit-scope.md`](audit-scope.md#explicit-dependency-review)).

**Why it is safe to defer:** the state of a pull request does not change the
pinned bytes. The residual risk is that the code that eventually merges
differs from the pinned rev, through review changes or a rebase onto newer
upstream code.

**Exit criterion and follow-up review:** the pull requests merge, into the
fork or upstream into OpenZeppelin/stellar-contracts (the CAP-0071 change
re-based onto upstream), and Perch re-pins.
Review the diff from `42089fc9` to the new pin. If the source differs, every
contract that links `stellar-accounts` gets a new Wasm: new builds, a new
deployment and manifest, and an account upgrade for deployed accounts.

**Owner:** Perch.

**Tracking:** [theahaco/stellar-contracts-OZ#4](https://github.com/theahaco/stellar-contracts-OZ/pull/4)
and [#5](https://github.com/theahaco/stellar-contracts-OZ/pull/5), stacked
on [#3](https://github.com/theahaco/stellar-contracts-OZ/pull/3).

## Completion input-byte binding

**Deferred:** requiring a recovery completion's `apply_doc` to carry the
*exact* authorized target bytes, not merely a document that compiles to the
authorized canonical identity.

**Current behaviour:** at T5 the controller's `rcv_complete` checks
`sha256(target_bytes) = A.target_bytes_hash` for the context it authorizes and
writes a completion marker holding the canonical identity
`(attempt_id, A.target_doc_hash, L)`. The account's `apply_doc` body runs
`rcv_sync` with the identity it compiled; `rcv_sync` consumes a marker when the
identity, ledger, and authorized attempt match, and does not re-check the
consuming invocation's input bytes against `A.target_bytes_hash`. Because
an account can ask `rcv_complete` about a context in an authorization tree
that never executes, a marker can be left behind (a perch account asks only
about a completion's one `apply_doc` context, the invocation being
authorized; the controller serves any account), and within
the same ledger and authorized window an `apply_doc` under ordinary owner
authorization that carries a differently formatted spelling of the same
canonical target can consume it and be classified as a completion rather than
refused as an ordinary write (recovery [`spec.md`](recovery/spec.md) §10 T5).

**Why it is safe to defer:** the completed document is still the authorized
canonical target, so the identity is bound. This neither installs a different
policy nor bypasses the `Protected` freeze. The effect is a misclassification:
an owner-authorized ordinary write over the authorized target, in the same
ledger as a leftover marker, runs the completion's revocation,
nullifier-spending, and epoch effects, rather than a loss of the target
binding.

**Exit criterion and follow-up review:** `rcv_sync` receives the completing
invocation's input-byte hash from the account (`sha256` of the `apply_doc`
input bytes) and requires it to equal the authorized attempt's
`target_bytes_hash` before consuming a completion marker; the leftover-marker
regression gains an active attempt and a second owner-authorized, differently
formatted target in the same ledger, which must be refused. This changes the
account↔controller `rcv_sync` ABI, so it reaches only newly-built accounts
(infra is pinned by wasm hash). It is a coordinated redeploy, not a live upgrade.

**Owner:** Perch.

**Tracking:** none yet.

## Contract-admin governance behind a multisig and timelock

**Deferred:** moving the mutable contract-admin surfaces (the publishing
registry's admin and the Nido factory's upgrade) behind a 2-of-3
Perch-account multisig and an admin timelock (a visible, cancelable delay on
admin actions).

**Current behaviour:** the publishing registry's `admin`/`manager` is a single
human-held key, backed up encrypted in 1Password. The same key
(`GAMPJROH…`) is the registry's `admin` and `manager` in both
[`deployments/testnet.json`](../deployments/testnet.json) and
[`deployments/mainnet.json`](../deployments/mainnet.json) (mainnet deployed
2026-10-26, ledger 65138427). The registry's
`upgrade`/`set_admin`/`set_manager`/`remove_manager` take effect the moment
that key authorizes them.

**Why it is safe to defer:** the admin key is human-held and backed up
encrypted in 1Password. The deferred change hardens
key custody and adds a delay; it does not alter any audited on-chain
authorization path.

**Exit criterion and follow-up review:** adopt the multisig + timelock before
any mainnet deployment, and review the timelock contract, the multisig policy
document, and the admin cutover. Driving the multisig on-chain also
needs multi-sig signing tooling (noted in the tracked PR).

**Owner:** Perch and Nido.

**Tracking:** [stellar-registry/perch#123](https://github.com/stellar-registry/perch/pull/123).
