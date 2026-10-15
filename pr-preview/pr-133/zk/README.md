# ZK recovery: circuit, pool, and adapter

This is Perch's one supported zero-knowledge recovery backend: a Noir circuit
proved with UltraHonk, a membership pool that accounts enroll into, and the
adapter a recovery controller cross-calls to check a proof. It implements the
ZK half of [`docs/recovery/spec.md`](../recovery/spec.md) (§13 "ZK adapter
boundary", §14 "Membership pool") against the interfaces in
`crates/perch-recovery-interface`. Nullifier state, evidence freshness, and
attempts are not here: the recovery controller (`crates/perch-recovery`)
records each account's spent nullifiers, and a ZK proof is accepted only if
its nullifier is unspent for that account (spec §11).

| Piece | Where | What it is |
| --- | --- | --- |
| Circuit | `circuits/` | Noir workspace: `perch_zk` (the relation), `perch_zk_recovery` (release, depth 32), `perch_zk_recovery_d24` (depth-24 fallback), vendored `poseidon` |
| Primitives | `crates/perch-zk-primitives` | Host-side Poseidon2 for every formula the circuit proves |
| Pool | `crates/perch-zk-pool` | Deployable membership pool: invoker-only insertion, depth-32 trees, rollover, every historical root acceptable |
| Adapter | `crates/perch-zk-adapter` | Deployable `ZkAdapterInterface`: root check against the enrolled pool, statement binding, embedded zero-knowledge UltraHonk verifier and VK |
| Verifier library | `vendor/ultrahonk-soroban-verifier` | NethermindEth's audited (non-ZK) UltraHonk verifier, plus Perch's `UltraKeccakZKFlavor` delta |
| Native prover | `crates/perch-zk-prover` | Incremental witness index over pool leaves, circuit inputs, nargo/bb driver, and the `perch-zk-fixtures` tool |
| Browser/Node prover | `packages/perch-zk` | The same in TypeScript (`PoolWitnessIndex` for indexers), proving with bb.js |
| Fixtures | `testdata/zk/` | One real ZK proof per scenario, with the enrollment history to rebuild its pool; for `lost_key`, also a bb.js proof and a non-ZK proof the adapter must refuse |
| Manifest | `circuits/manifest.json` | Hashes of every source, artifact, VK, and fixture proof, plus the toolchain |

Further reading: [`circuit.md`](circuit.md) (the relation, its encodings,
and its fixtures), [`pool.md`](pool.md) (storage, rollover, root retention,
witnesses, renewal), and [`measurements.md`](measurements.md) (proving and
on-chain component costs, and the circuit identities). The budgets, the
results against them, and the depth decision are in
[`docs/recovery/budgets.md`](../recovery/budgets.md#results).

## Open release criteria

1. **Delta audit of the ZK verifier.** Witness hiding is provided: proofs are
   Barretenberg's zero-knowledge flavor, `UltraKeccakZKFlavor`, and the adapter
   refuses any other (see [Which verifier](#which-verifier)). The audited
   upstream verifier implements only the non-ZK flavor, so Perch added the ZK
   flavor as a delta: one new file, `vendor/ultrahonk-soroban-verifier/src/zk.rs`,
   plus visibility-only changes to four audited files. The vendored README and
   NOTICE list every change, and `crates/perch-zk-adapter/tests/vendor.rs`
   enforces that nothing else changed. **That delta is not audited.** It is
   in the audit scope ([`docs/audit-scope.md`](../audit-scope.md)), and its
   audit must close before release.
2. **Client proving on reference devices.** `budgets.md` §1 sets budgets for
   a mid-range phone and laptop. Only desktop numbers exist
   ([`measurements.md`](measurements.md#proving)); the reference-device rows
   are required before launch
   ([`budgets.md`](../recovery/budgets.md#results)).

The full-transaction measurements are substantially complete but not
finished: every recovery transaction is measured in process on the release
wasm and on testnet against the deployed wasm, and every measured row is
within budget. Rows still open before launch are disk read bytes (every row),
§3 end-to-end latency, and the §4 controller-state and `renew`-fee rows; a few
rows (completion after rule churn, promotion with many siblings) are bounded
by construction rather than measured.
[`budgets.md`](../recovery/budgets.md#results) is the authoritative release
checklist, and its status column lists each outstanding row.

## How a proof is checked

```text
controller ──verify(statement, binding, evidence)──▶ adapter
   │                                                  │ 1. binding.circuit_id == sha256(VK)
   │ statement: its own RecoveryStatement             │ 2. project statement → account, enrollment, digest
   │ binding:   enrolled pool, enrollment id,         │ 3. root, nullifier < r
   │            circuit id                            │ 4. proof is 16,224 bytes (else MalformedProof)
   │ evidence:  tree id, root, nullifier, proof       │ 5. pool.is_known_root(tree_id, root) ──▶ enrolled pool
   │                                                  │ 6. ZK UltraHonk verify(root ‖ nullifier ‖ statement_hash)
   ▼                                                  ▼
nullifier unspent for this account (§11),          Ok(()) or a ZkAdapterError; no state written
freshness, attempts
```

The checks run in that order, and the first failure is the error returned;
spec §13.2 names each check's `ZkAdapterError`. Everything before step 5 is
local, so a malformed or mismatched submission never reaches the pool.
`verify` does not compare tree depths. The adapter only exposes
`tree_depth()`, and the controller compares it with the pool's `depth()`
when a ZK factor is enrolled or changed (spec §3.4). The controller reports
any adapter error as `RecoveryError::ZkEvidenceRejected`, then refuses a
nullifier this account has spent (`NullifierSpent`).

`verify` writes no contract state, but it has one ledger effect. When step 5
matches, the pool's `is_known_root` extends that `Root` entry's TTL, so a
root a recovery relies on stays live. The submitter pays for that extension,
and a simulation of `verify` must carry the entry in its read-write
footprint. Nothing else changes; `verification_only_extends_the_matched_roots_ttl`
in the adapter's tests pins this. The adapter's `verify` doc string says it
"writes nothing", and neither it nor the pool's `is_known_root` doc string
mentions the TTL extension. Both doc strings are part of the deployed
wasm's contract spec.

The circuit's public inputs are `root`, `nullifier`, and
`statement_hash = H(DOM_AUTH, account, enrollment_id, digest)`, where `digest`
is the controller's `RecoveryStatement::digest`. Every statement field
(network, account, controller, configuration epoch and hash, timing, action,
subject) therefore binds the proof without the circuit knowing the statement's
layout. A statement-format change needs no new circuit or verification key.

## Immutability and identity

The pool and the adapter are constructorless and have no admin, owner,
upgrade, pause, or factory authority. The adapter holds no storage at all.
The pool holds only the trees that accounts fill, and every write to them is
authorized by the enrolling account. An instance's behavior is a pure
function of its wasm hash. A new version is a new wasm and a new address,
which an account adopts only through its own recovery configuration.

The adapter's `circuit_id()` is `sha256` of its compiled-in verification key.
A configuration names it in its ZK binding, and the adapter refuses any
binding that names another circuit.

**The verifier is compiled into the adapter**, not a second contract the
adapter calls. The public-input layout belongs to the VK, so a new circuit
means a new adapter anyway, and an embedded verifier leaves no address to
pin or misconfigure. The adapter also exports the raw verifier as
`verify_proof(public_inputs, proof)`, implementing
`ProofVerifierInterface` (spec §13.2). Nothing in Perch calls it: the
controller uses `verify`. It is stateless, but it is audited surface that
accepts caller-chosen public inputs.

## Which verifier

The verifier is
[NethermindEth/rs-soroban-ultrahonk](https://github.com/NethermindEth/rs-soroban-ultrahonk),
vendored at the commit recorded in `vendor/ultrahonk-soroban-verifier`
(`UPSTREAM.sha256`, the vendored README). It has had an internal review and
an OpenZeppelin audit, whose fixes include G1 point validation and
canonical encodings at parse time, constrained Gemini padding, and
public-input canonicality. The audited line targets bb 0.87.0 and nargo
1.0.0-beta.9, which is why Perch pins that toolchain, but implements only
the *non-zero-knowledge* `UltraKeccakFlavor`. A non-ZK proof carries
witness-dependent protocol messages, so it does not hide the enrolled
secret. The same secret backs cancellation, reconfiguration, and upgrade
proofs until a completion spends its nullifier, so recovery needs witness
hiding.

Perch therefore vendors the audited verifier and adds Barretenberg's
zero-knowledge flavor, `UltraKeccakZKFlavor`, as a delta on top of it.
The delta adds Libra masking of the sumcheck, the Gemini masking polynomial,
nine-evaluation round univariates, and the small-subgroup IPA consistency
check:

- **All new verification logic is in one file**,
  `vendor/ultrahonk-soroban-verifier/src/zk.rs` (`UltraHonkZkVerifier`). Every
  step the two flavors share runs the audited code itself: the Oink rounds,
  the relations, point and scalar decoding, the public-input delta, the MSM,
  and the pairing. Four audited files change only in visibility (`fn` →
  `pub(crate) fn`), and `lib.rs` gains three lines to register the module.
  The vendored README lists every function with the Barretenberg v0.87.0
  source it follows. `crates/perch-zk-adapter/tests/vendor.rs` reverses
  exactly those edits and requires upstream's bytes, as recorded in
  `UPSTREAM.sha256` and checked against the pinned GitHub commit.
- **The ZK and non-ZK flavors share one circuit and one verification key**
  (`bb write_vk` takes no `--zk`), so the circuit ids in
  [`measurements.md`](measurements.md#circuit-identities) name both. Proofs
  come from `bb prove --zk` natively and bb.js `{ keccakZK: true }` in
  browsers.
- **The adapter accepts only ZK proofs.** A valid non-ZK proof of the same
  statement is refused (`testdata/zk/lost_key/proof.non-zk`).

Consequences ([`measurements.md`](measurements.md) has the figures):

- A ZK proof is 16,224 bytes, 507 field elements; bb 0.87.0 pads every proof
  to 28 sumcheck rounds.
- `verify_proof` costs about a third of a transaction's instructions. Most
  of the ZK flavor's cost over the non-ZK one is the consistency check,
  about 2,000 field operations over a 256-element subgroup.
- Proofs are randomized: two proofs of one witness differ, and both verify.
  Proof bytes are therefore no identifier (per the upstream README); the
  nullifier is.
- A proof is checked against the embedded verification key and relation, not
  against a version number. A malformed or wrong-length proof is refused at the
  parsing and structural checks; a structurally valid but incompatible proof is
  refused at a later verification step, not necessarily the final pairing. The
  verifier reads no version.
  Separately, `scripts/zk-toolchain.sh`, the prover crate, and the TS package
  pin bb to the tested version and refuse others, so Perch's own tooling never
  produces a proof under another version.

## Reproducing the artifacts

```sh
eval "$(scripts/zk-toolchain.sh)"      # pinned nargo/bb under target/, checksummed
just zk-artifacts check                # rebuild ACIR, VKs, all fixture proofs, manifest; fail on any drift
just zk-artifacts                      # regenerate them after a circuit or statement change
just zk-bench                          # proving and on-chain measurements, both depths
```

The ACIR and the VKs are deterministic, so `check` compares their bytes, not
just hashes. ZK proofs are randomized, so `check` cannot compare a fresh proof
with the committed one. Instead, it keeps a committed proof exactly as long as
`bb verify --zk` accepts it against the freshly built VK and public inputs,
and reports drift otherwise. It also proves every scenario afresh, and checks
that bb's public inputs equal the host's and that the fresh proof verifies.
The committed bb.js proof is checked the same way. The non-ZK proof of
`lost_key` is deterministic and must reproduce exactly. The committed ACIR
artifacts drop nargo's `debug_symbols` and `file_map`, which carry absolute
source paths, so they are identical on every machine. CI's `zk` job runs the
circuit tests, the check, and the metered cost harness.

The `node` job runs `packages/perch-zk`'s tests. Those tests prove the
`lost_key` witness with bb.js and require that each proof:

- carries the committed public inputs;
- verifies under bb.js;
- differs from the next proof and from the CLI's.

They also require bb.js to accept the CLI's proof and the committed bb.js
proof, and bb.js's ZK verification key to equal the committed VK.
`PERCH_ZK_WRITE_VECTORS=1 npm test` rewrites the committed bb.js proof
(`testdata/zk/lost_key/proof.bbjs`). The adapter's tests verify that proof
on-chain, so the browser prover's output is checked against the Soroban
verifier on every CI run.

The deployable wasm's hash depends on the Rust toolchain that builds it. The
repository's `rust-toolchain.toml` tracks `stable`, so the wasm hash is
recorded per release build (`deployments/testnet.json` for the testnet
deployment) rather than in `circuits/manifest.json`.

## What is tested, and how

All proofs in the adapter's tests are real zero-knowledge proofs from the
pinned toolchain, verified by the adapter's ZK verifier against a real pool.
No verifier or pool is mocked. `rcv_insert`'s account authorization is
mocked in the adapter's tests and in most of the pool's;
`insertion_requires_the_accounts_own_authorization` checks, with targeted
mock authorizations, that only the account itself can insert. The account
side of the rule (it never signs a reserved `rcv_*` name, spec §15) is
tested under enforcing authorization in `crates/integration-tests`.

- **Every ZK action**: `LostKey`, `Compromise`, `Cancel`,
  `Reconfigure(Set)`, `Reconfigure(Remove)`, and `Upgrade` each have a
  fixture proof over a synthetic statement built by
  `crates/perch-zk-prover/src/bin/fixtures.rs` (not the controller). Each
  verifies, and none verifies as any other
  (`crates/perch-zk-adapter/src/test.rs`). End-to-end proofs over statements
  the controller actually builds are the `release_stack` tests.
- **Mismatches**: changing any statement field (network, controller, epoch,
  configuration hash, delay, expiry, validity bound, attempt, source, target,
  replacements), the account, the enrollment id, the nullifier, the tree id,
  or the pool refuses the evidence. So do a fabricated or unknown root (one the
  tree never had — roots are never evicted; every historical root stays valid,
  §14.3), a non-canonical root or nullifier, a malformed proof, a tampered
  proof, and a binding for another circuit.
- **Replay**: evidence cannot be redirected to another attempt, action,
  configuration, or epoch, because the statement binds them. A replay of
  identical evidence for the identical statement passes the adapter, which
  keeps no state by design. The controller refuses it: an attempt counts
  one initiation proof and one cancellation proof (`AlreadyCounted`); an
  authorized attempt accepts no initiation evidence
  (`AttemptNotCollecting`); a completion spends the nullifier for that
  account, so any later proof carrying it is refused (`NullifierSpent`);
  and every completion and configuration change bumps the epoch, which
  kills older statements. No nullifier is reserved or released: several
  live attempts may carry the same unspent nullifier, and only a
  completion changes its state (spec §11). `release_stack.rs`
  (`zk_lost_key_recovery_with_real_proofs_across_a_rollover`) replays real
  evidence through the real controller; `recovery.rs`
  (`nullifiers_are_never_reserved_or_released`,
  `a_zk_completion_spends_the_nullifier_and_installs_the_declared_enrollment`,
  `one_accounts_completion_never_spends_anothers_nullifier`) pins the
  nullifier rules with a statement-bound mock adapter.
- **Pool boundaries** without 2^32 inserts: the Merkle code is parameterized
  by depth and driven to fill and roll over at depth 2. The real depth-32 last
  slot (index 2^32 − 1, every path bit set) is reached by synthesizing the
  frontier one slot short of full, then filling it through `rcv_insert`, rolling
  over, and verifying a real proof for that slot afterwards (`earlier_tree`).
- **Historical roots**: a proof against an older root still verifies after
  129 further insertions, and so does a proof against the later root
  (`later_root`). Nobody can race a victim's evidence out of the pool.
- **Parity**: the Noir circuit, the Soroban host (`soroban-poseidon`), and
  bb.js agree on every formula. All three suites pin the same vectors.
- **The ZK verifier delta** (`crates/perch-zk-adapter/tests/zk_verifier.rs`):
  - every committed CLI and bb.js proof verifies, and the two `lost_key`
    proofs differ;
  - the parsed layout matches bb's;
  - a valid non-ZK proof is refused, as is one re-encoded in the ZK layout;
  - malformed ZK proofs are refused at parse time: lengths, non-canonical
    scalars, non-canonical limbs and off-curve points in every ZK-only
    commitment, and non-zero Gemini padding;
  - every ZK-only field is bound: each scalar nudged, each commitment
    replaced, and a padded round's evaluation changed are all rejected;
  - each ZK check rejects on its own with the transcript held fixed: the
    Libra-corrected sumcheck target and final value, the ninth evaluation,
    the small-subgroup IPA identity (including a padded round's challenge and
    a challenge inside the subgroup), the masking polynomial's opening, and
    each Libra commitment's opening;
  - the constants are bb's.

## Interface notes

These crates implement `perch-recovery-interface` and spec §13–§14.
`perch-zk-pool` is driven through the interface's own `MembershipPoolClient`
in its tests.

- **One leaf per `(account, enrollment_id)`** (spec §14.2,
  `EnrollmentIdTaken`), in addition to the account's own refusal (spec
  §3.4). A second leaf under an adopted id would satisfy the ZK factor with
  someone else's secret and give the credential a second nullifier. The
  record that enforces the rule, `Enrollment(account, id)`, is also the
  client's lookup of its own leaf.
- **Stored leaves** (spec §14.3). Every leaf is a persistent entry, so a
  witness for any tree, sealed ones included, can be rebuilt from contract
  storage alone (`leaves` pages) if every indexer is lost. It costs about a
  third of an insertion's rent
  ([`measurements.md`](measurements.md#on-chain-components-compiled-wasm-metered)).
- **Adapter topology** (spec §13.2). The verifier and VK are compiled into
  the adapter, which also exports `verify_proof` for
  `ProofVerifierInterface` callers: one deployable, no verifier address to
  pin.
- **Genesis insertion.** `rcv_insert` is invoker-only, so a factory cannot
  insert for a new account. Enrollment happens in the account's own
  `apply_doc` (spec §14.2).
- **Release pipeline.** `perch-zk-pool` and `perch-zk-adapter` are in both
  `release.yml` `CONTRACTS` lists with `paths_for()` scopes. The adapter's
  scope includes `vendor/ultrahonk-soroban-verifier`. Both are therefore
  tagged and version-tracked, but they are not in `publish-plan`'s `ALLOW`
  list, so `release.yml` does not publish them to the canonical registry
  (`AGENTS.md`); the testnet deployment publishes them into its own registry
  instance (`deployments/testnet.json`). `packages/perch-zk` is not published
  to npm: it has no `NPM_PACKAGES` entry
  ([`DEFERRED.md`](../DEFERRED.md#npm-publishing-of-perch-zk-and-the-contract-clients)).
- **Where the rest lives.** The controller (`crates/perch-recovery`) keeps
  per-account spent-nullifier records, checks evidence freshness, runs
  attempts, and compares the adapter's `tree_depth()` with the pool's
  `depth()` in `rcv_sync`. The account (`crates/perch-smart-account`) wires
  `rcv_insert` into `apply_doc` and refuses reserved names. A replay of
  identical evidence, which the adapter alone cannot refuse, is refused by
  the controller ([What is tested](#what-is-tested-and-how)).
