# ZK recovery: circuit, pool, and adapter

This is Perch's one supported zero-knowledge recovery backend: a Noir circuit
proved with UltraHonk, a membership pool that accounts enroll into, and the
adapter a recovery controller cross-calls to check a proof. It implements the
ZK half of [`docs/recovery/spec.md`](../recovery/spec.md) ("ZK adapter
boundary", "Membership pool") against the interfaces in
`crates/perch-recovery-interface`. The controller that reserves and spends
nullifiers, checks evidence freshness, and runs attempts is not here. It
lives in the recovery controller.

| Piece | Where | What it is |
| --- | --- | --- |
| Circuit | `circuits/` | Noir workspace: `perch_zk` (the relation), `perch_zk_recovery` (release, depth 32), `perch_zk_recovery_d24` (depth-24 fallback), vendored `poseidon` |
| Primitives | `crates/perch-zk-primitives` | Host-side Poseidon2 for every formula the circuit proves |
| Pool | `crates/perch-zk-pool` | Deployable membership pool: invoker-only insertion, depth-32 trees, rollover, every historical root acceptable |
| Adapter | `crates/perch-zk-adapter` | Deployable `ZkAdapterInterface`: root check against the enrolled pool, statement binding, embedded audited UltraHonk verifier and VK |
| Verifier library | `vendor/ultrahonk-soroban-verifier` | NethermindEth's audited UltraHonk verifier, vendored unmodified |
| Native prover | `crates/perch-zk-prover` | Witness building from pool leaves, circuit inputs, nargo/bb driver, and the `perch-zk-fixtures` tool |
| Browser/Node prover | `packages/perch-zk` | The same in TypeScript, proving with bb.js |
| Fixtures | `testdata/zk/` | One real proof per scenario, with the enrollment history to rebuild its pool |
| Manifest | `circuits/manifest.json` | Hashes of every source, artifact, VK, and fixture proof, plus the toolchain |

Further reading: [`circuit.md`](circuit.md) (the relation, its encodings, and
compatibility with Nido's circuits), [`pool.md`](pool.md) (storage, rollover,
root retention, witnesses, renewal), and
[`measurements.md`](measurements.md) (proving and on-chain costs, budgets, and
the depth decision).

## How a proof is checked

```text
controller ──verify(statement, binding, evidence)──▶ adapter
   │                                                  │ 1. binding.circuit_id == sha256(VK)
   │ statement: its own RecoveryStatement             │ 2. project statement → account, enrollment, digest
   │ binding:   enrolled pool, enrollment id,         │ 3. root, nullifier < r
   │            circuit id                            │ 4. pool.is_known_root(tree_id, root) ──▶ enrolled pool
   │ evidence:  tree id, root, nullifier, proof       │ 5. UltraHonk verify(root ‖ nullifier ‖ statement_hash)
   ▼                                                  ▼
nullifier bookkeeping, freshness, attempts         Ok(()) or a ZkAdapterError; writes nothing
```

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

**The verifier is compiled into the adapter** instead of being a second
contract the adapter calls. The public-input layout belongs to the VK, so a
new circuit means a new adapter anyway, and an embedded verifier leaves no
address to pin or misconfigure. The raw verifier is still exported as
`verify_proof(public_inputs, proof)`, `ProofVerifierInterface`, with the same
ABI and error codes as Nido's `nido-recovery-verifier`.

## Which verifier, and why the toolchain changed

Nido's working stack proves with nargo 1.0.0-beta.18 and bb
3.0.0-nightly.20260102. Its verifier is `theahaco/rs-soroban-ultrahonk`'s
`feat/bb3-nozk-verifier` branch, a port to bb 3's proof format that no one
has audited. The upstream verifier,
[NethermindEth/rs-soroban-ultrahonk](https://github.com/NethermindEth/rs-soroban-ultrahonk),
has since gone through an internal review and an OpenZeppelin audit. Its
fixes include G1 point validation and canonical encodings at parse time,
constrained Gemini padding, and public-input canonicality. The audited line
targets bb 0.87.0 (`UltraKeccakFlavor`, non-ZK) and nargo 1.0.0-beta.9.

Perch uses the audited verifier, vendored unmodified (see
`vendor/ultrahonk-soroban-verifier/NOTICE`), and pins the toolchain it
targets. The circuit itself needed no change for the older compiler. The
consequences are measured in [`measurements.md`](measurements.md):

- Proofs are 14,592 bytes, 456 field elements. bb 0.87.0 pads to 28 sumcheck
  rounds; Nido's bb 3 proofs were 6,976 bytes.
- `verify_proof` costs about 91M instructions, where Nido's verifier cost
  159M to 179M.
- Proofs from any other bb version do not verify. They fail at the pairing
  check, not at parse time. `scripts/zk-toolchain.sh`, the prover crate, and
  the TS package all refuse other versions.

## Reproducing the artifacts

```sh
eval "$(scripts/zk-toolchain.sh)"      # pinned nargo/bb under target/, checksummed
just zk-artifacts check                # rebuild ACIR, VKs, all fixture proofs, manifest; fail on any byte of drift
just zk-artifacts                      # regenerate them after a circuit or statement change
just zk-bench                          # proving and on-chain measurements, both depths
```

The ACIR, the VKs, and the proofs are deterministic, so `check` compares
bytes, not just hashes. The committed ACIR artifacts drop nargo's
`debug_symbols` and `file_map`, which carry absolute source paths, so they are
identical on every machine. CI's `zk` job runs the circuit tests, the
byte-for-byte check, and the metered cost harness. The `node` job runs
`packages/perch-zk`'s tests. Those tests prove the `lost_key` witness with
bb.js and require the result to equal the committed CLI proof byte for byte.

The deployable wasm's hash depends on the Rust toolchain that builds it. The
repository's `rust-toolchain.toml` tracks `stable`, so the wasm hash is
recorded per release build rather than in `circuits/manifest.json`.

## What is tested, and how

All proofs in the tests are real proofs from the pinned toolchain, verified
by the audited verifier against a real pool. No verifier or pool is mocked.
Only `rcv_insert`'s account authorization is mocked, and only in the adapter's
tests. The pool's own tests exercise real authorization rules.

- **Every ZK action**: `LostKey`, `Compromise`, `Cancel`,
  `Reconfigure(Set)`, `Reconfigure(Remove)`, and `Upgrade` each have a
  fixture proof over the statement the controller builds. Each verifies, and
  none verifies as any other (`crates/perch-zk-adapter/src/test.rs`).
- **Mismatches**: changing any statement field (network, controller, epoch,
  configuration hash, delay, expiry, validity bound, attempt, source, target,
  replacements), the account, the enrollment id, the nullifier, the tree id,
  or the pool refuses the evidence. So do a fabricated or evicted root, a
  non-canonical root or nullifier, a malformed proof, a tampered proof, and a
  binding for another circuit.
- **Replay**: evidence cannot be redirected to another attempt, action,
  configuration, or epoch, because the statement binds them. A replay of
  identical evidence for the identical statement passes the adapter, which is
  pure by design. The controller refuses it through nullifier reservation and
  attempt consumption, and its own tests must cover that with these fixtures.
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

## Interface notes for the rest of the epic

This crate implements `perch-recovery-interface` and spec §13–§14 as they
stand on `fm/perch-epic99-spec-p5`. A few points go beyond the spec or
differ from its prose:

- **Pool-side one leaf per `(account, enrollment_id)`.** Spec §3.4 makes the
  account refuse to reuse an enrollment id. The pool refuses a repeat as
  well (`EnrollmentIdTaken`), because a second leaf under an adopted id
  would satisfy the ZK factor with someone else's secret and give the
  credential a second nullifier. The cost is one small persistent entry per
  insertion, which doubles as the client's lookup of its own leaf.
- **On-chain leaves.** Spec §14.3 sources witnesses from `LeafInserted`
  events via a persisting indexer. The pool also stores each leaf, so a
  witness for any tree, sealed ones included, can be rebuilt from contract
  storage alone (`leaves` pages) if every indexer is lost. That is one more
  persistent entry per insertion; dropping it is a one-line change if the
  rent is not worth it (see [`measurements.md`](measurements.md)).
- **Adapter topology.** Spec §13 describes the adapter calling a separately
  deployed, build-pinned verifier. Here the verifier is compiled into the
  adapter, and the same contract also exports `verify_proof` for
  `ProofVerifierInterface` callers. Both interfaces are implemented exactly
  as specified. The difference is one deployable and no verifier address to
  pin.
- **Genesis insertion.** `rcv_insert` is invoker-only, so a factory cannot
  insert for a new account. Enrollment happens in the account's own
  `apply_doc`, as spec §14.2 describes.
- **Release pipeline.** `perch-zk-pool` and `perch-zk-adapter` are new
  deployables, and `packages/perch-zk` is a new npm package. None of them is
  registered in `release.yml` yet: the `CONTRACTS` lists, `paths_for()`, and
  `NPM_PACKAGES` need entries (`AGENTS.md`).
- **Not here.** The controller (nullifier reservation and spending, evidence
  freshness, attempts) and the account (`apply_doc` wiring of `rcv_insert`,
  the `tree_depth`/`depth` check, refusing reserved names) are the controller
  workstream's. Its tests should replay these fixtures through the real
  controller, including a replay of identical evidence, which the adapter
  alone cannot refuse.
