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
T1): `target_bytes_hash`, which the controller's `enforce` compares with
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
published files; npm release 0.3.2 predates the schema and does not contain
it. By design the schema accepts what `perch-ir`'s parser accepts,
so that schema validation and the parser agree (a schema that rejected a
document the parser accepts would mislead an offline editor). It therefore
accepts the same non-canonical spellings the "Canonical value spellings" entry
above lists: a `cap.limit` with a leading `+` or leading zeros, and signer-key
hex in either case. It *does* pin the 64-lowercase-hex digest fields
(`doc-hash`, `circuit-id`, `enrollment-id`, `commitment`) because the parser
already requires that form. These checks stay outside the schema, with the
authority unchanged:

- duplicate raw JSON keys, which a validator of already-parsed JSON cannot
  see — `perch-ir`'s parser;
- uniqueness of signer ids and of rule names, compared by key across siblings —
  `perch-ir::validate`;
- reference resolution (a principal/`replaceable` id resolving to a declared
  signer; a cap `token` matching the rule's contract scope) — `perch-ir::validate`;
- the CRC16 checksum of every address strkey (the schema pins only the shape) —
  `perch-ir::validate`;
- each `functions` entry being a Soroban `Symbol` (1–32 characters from
  `[a-zA-Z0-9_]`), and a `string-prefix` prefix of at most
  `MAX_STRING_PRED_LEN` (256) bytes — `perch-ir::validate`. Both are
  expressible in JSON Schema; the generator does not emit them yet;
- the canonical-byte budget (`max_canonical_bytes`), a property of the
  canonically-encoded bytes rather than the parsed tree — the compiler
  (`perch-doc-compiler`), mirrored client-side by perch-js `checkLimits`;
- the BN254 field-element range on a recovery `commitment`, and the exact
  `i128` upper bound on a `cap.limit` — `perch-ir::validate`;
- guardian `quorum <= count` for guardian sets larger than the schema's
  enumerated depth (guardians have no dedicated cap constant today) —
  `perch-ir::validate`;
- signatures and authorization — `__check_auth` / OZ policy enforcement.

**Why it is safe to defer:** the parser, compiler, and account remain the
authority for every check the schema leaves out, so no check is lost — only
not yet mirrored into the schema. A schema-valid document that fails one of
them is refused by `compile_doc` with a typed error (`DocParse`,
`DocInvalid`, or `DocTooLarge`), so the gap fails closed: an editor can
accept a document the chain will refuse, never the reverse. Tightening the schema to a canonical profile before the parser
enforces one spelling would make it reject documents the chain still accepts.

**Exit criterion and follow-up review:** add the `Symbol` pattern for
`functions` entries and a `string-prefix` bound to the generator (the byte
bound needs the same ASCII-or-stricter treatment as rule names, because
`maxLength` counts code points), regenerate the committed artifact, and extend
the conformance cases so schema and validator reject them together. Once
"Canonical value spellings" lands (one valid spelling enforced in
`perch-ir::validate` and `perch-js`), add the matching strict profile —
lowercase-only signer-key hex, a `cap.limit` with no sign and no leading zeros,
and the settled integer number-form spelling — and extend the
drift/parity/conformance suites so the strict schema and the parser still agree
in both directions. A dedicated guardian-count cap would let the schema encode
`quorum <= count` fully. Review the regenerated schema against the parser's
rules and the cross-language parity vectors.

**Owner:** Perch.

**Tracking:** CANON v2, RFC [#109](https://github.com/stellar-registry/perch/issues/109).

## Versioned policy backend and larger limits

**Deferred:** a policy backend other than the OpenZeppelin context-rule
materialization, selected by version, and document limits above the current
caps.

**Current behaviour:** the account materializes each document rule as one OZ
`stellar-accounts` context rule (the pinned fork,
[`audit-scope.md`](audit-scope.md#explicit-dependency-review)): policy-free,
or with the Perch interpreter, plus OZ `spending_limit` for a rule with a
`cap`. `apply_doc` reconciles the installed rules as a delta (spec §7.5).
The doc compiler refuses with `DocTooLarge`, on every `compile_doc` and
`derive_target`, a document with more than 8 declared signers
(`MAX_DOC_SIGNERS`), more than 11 rules (`MAX_DOC_RULES`), more than 8,192
canonical bytes (`MAX_DOC_CANONICAL_BYTES`), or a rule name over 20 bytes
(`MAX_RULE_NAME_BYTES`, OZ's `MAX_NAME_SIZE`). The recovery rule the account
generates is additional to the 11 document rules. The caps are sized so that
a worst-case completion, compromise restore, or `Protected` reconfiguration
stays within 75% of every *measured* per-transaction limit — instructions,
memory, write bytes, and write entries
([`budgets.md`](recovery/budgets.md), "Document caps"; the `worst_case_*`
tests in `crates/integration-tests/tests/release_stack.rs`). Disk read bytes
are not yet measured for any row (budgets.md: "Required before launch"), so
this within-budget guarantee is conditional on completing that measurement
before mainnet.

**Why it is safe to defer:** the caps exist so that a thief holding the
owner key cannot make a recovery too expensive to complete (spec §7.5). A
document over a cap is refused whole and changes nothing. The OZ
materialization is the audited backend (the Perch OZ materialization unit).
The residual limit is product capacity: a document that needs more signers,
rules, or bytes cannot be applied.

**Exit criterion and follow-up review:** a backend change is a new account
build that existing accounts adopt only by upgrade. Review it as a
separately scoped change with regression evidence across authorization,
recovery, and migration, and re-measure the caps against the new
completion cost. Before mainnet, decide whether existing funded accounts
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

**Current behaviour:** rule ids are OZ context-rule ids. An in-place edit
keeps a rule's id. A replacement gives it a new one: a changed scope, a
rename, a removal and re-addition, or the cost model choosing replacement
(spec §7.5). OZ never reuses an id, so A → B → A restores the `doc_hash` but
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

**Current behaviour:** a rule with a `cap` carries OZ `spending_limit`
(deployed as `perch-spending-limit`), which keys its rolling window by
`(account, context rule id)` and starts an empty window on `install`. When
`apply_doc` edits a rule in place, every policy whose install parameters are
unchanged keeps its state: a signer change or a change to the rule's other
text keeps the window. Changing the cap's own parameters reinstalls the
spending limit, and replacing the rule reinstalls every policy; both start
an empty window. Whether a changed rule is edited or replaced is the cost
model's choice (spec §7.5), so a document change that touches a capped rule
can reset its window. A compromise recovery that restores a baseline can
therefore give the baseline's retained signers a fresh window.

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
authorization (`__check_auth`, OZ rule selection, the delta `apply_doc`, the
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

**Current behaviour:** `Cargo.toml` pins `stellar-accounts` 0.7.1 to git rev
`33726766a1fd5e7e3d2977d79f64ee29e1ea3ca9` of theahaco/stellar-contracts-OZ,
the head of #5, which is stacked on #4, which is stacked on #3 (CAP-0071
delegated authentication). The pinned commit is upstream OpenZeppelin
`fbfde38` (the fork's `main`) plus three commits, one per pull request. All
three pull requests are open. Cargo builds the pinned commit
whatever their state (`Cargo.lock` records it), so the audited code is that
rev: the fork's changes are reviewed as the diff from upstream `fbfde38` to
`33726766` ([`audit-scope.md`](audit-scope.md#explicit-dependency-review)).

**Why it is safe to defer:** the state of a pull request does not change the
pinned bytes. The residual risk is that the code that eventually merges
differs from the pinned rev, through review changes or a rebase onto newer
upstream code.

**Exit criterion and follow-up review:** the pull requests merge, into the
fork or upstream into OpenZeppelin/stellar-contracts (the CAP-0071 change
re-based onto upstream), and Perch re-pins.
Review the diff from `33726766` to the new pin. If the source differs, every
contract that links `stellar-accounts` gets a new Wasm: new builds, a new
deployment and manifest, and an account upgrade for deployed accounts.

**Owner:** Perch.

**Tracking:** [theahaco/stellar-contracts-OZ#4](https://github.com/theahaco/stellar-contracts-OZ/pull/4)
and [#5](https://github.com/theahaco/stellar-contracts-OZ/pull/5), stacked
on [#3](https://github.com/theahaco/stellar-contracts-OZ/pull/3).

## npm publishing of perch-zk and the contract clients

**Deferred:** publishing `@stellar-registry/perch-zk` and the contract
clients, `@stellar-registry/perch-contracts`, to npm.

**Current behaviour:** both packages are built, tested, and pack-checked in
CI (`scripts/check-packages.sh`), and neither is in `release.yml`'s
`NPM_PACKAGES`, so neither is published. Consumers use them from the
repository at the audited commit (Nido consumes `perch-zk` as an npm
workspace from its `vendor/perch` submodule). Each `perch-contracts` module
exports `WASM_SHA256`, and the package's tests fail if it, or the bundled
`testnet` manifest, differs from `deployments/testnet.json`.
`@stellar-registry/perch-relay` is unpublished on the same terms. The
published packages are listed in
[`audit-scope.md`](audit-scope.md#packages).

**Why it is safe to defer:** consumers run the audited source, and no
published artifact is trusted in its place.

**Exit criterion and follow-up review:** listing a package in
`NPM_PACKAGES` publishes it, with npm provenance, from the next merge at
which its manifest version has no release tag. Before a consumer switches from the repository to a published version, show
that the tarball's code and artifacts equal the audited source's (the
packaging rule above): for `perch-zk`, its circuit artifacts match
`circuits/manifest.json`; for `perch-contracts`, every `WASM_SHA256` equals
the deployment manifest. Review any difference as a code change.

**Owner:** Perch (publishing) and each consumer (switching).

**Tracking:** none yet.

## Completion input-byte binding

**Deferred:** requiring a recovery completion's `apply_doc` to carry the
*exact* authorized target bytes, not merely a document that compiles to the
authorized canonical identity.

**Current behaviour:** at T5 the controller's `enforce` checks
`sha256(target_bytes) = A.target_bytes_hash` for the context it authorizes and
writes a completion marker holding the canonical identity
`(attempt_id, A.target_doc_hash, L)`. The account's `apply_doc` body runs
`rcv_sync` with the identity it compiled; `rcv_sync` consumes a marker when the
identity, ledger, and authorized attempt match, and does not re-check the
consuming invocation's input bytes against `A.target_bytes_hash`. Because
`enforce` runs for every context in an authorization tree — including a
sub-invocation that never executes — a marker can be left behind, and within
the same ledger and authorized window an `apply_doc` under ordinary owner
authorization that carries a differently formatted spelling of the same
canonical target can consume it and be classified as a completion rather than
refused as an ordinary write (recovery [`spec.md`](recovery/spec.md) §10 T5).

**Why it is safe to defer:** the completed document is still the authorized
canonical target, so the identity is bound — this neither installs a different
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
(infra is pinned by wasm hash) — a coordinated redeploy, not a live upgrade.

**Owner:** Perch.

**Tracking:** none yet.

## Contract-admin governance behind a multisig and timelock

**Deferred:** moving the mutable contract-admin surfaces — the publishing
registry's admin and the Nido factory's upgrade — behind a 2-of-3
Perch-account multisig and an admin timelock (a visible, cancelable delay on
admin actions).

**Current behaviour:** the publishing registry's `admin`/`manager` is a single
human-held key, backed up encrypted in 1Password. The deployment is testnet
only; no mainnet deployment lands before the audit. The registry's
`upgrade`/`set_admin`/`set_manager`/`remove_manager` take effect the moment
that key authorizes them.

**Why it is safe to defer:** the admin key is human-held and backed up
encrypted in 1Password, and the only live deployment is on testnet, so no
mainnet value is governed by it before the audit. The deferred change hardens
key custody and adds a delay; it does not alter any audited on-chain
authorization path.

**Exit criterion and follow-up review:** adopt the multisig + timelock before
any mainnet deployment, and review the timelock contract, the multisig policy
document, and the admin cutover. Driving the multisig on-chain additionally
needs multi-sig signing tooling (noted in the tracked PR).

**Owner:** Perch and Nido.

**Tracking:** [stellar-registry/perch#123](https://github.com/stellar-registry/perch/pull/123).
