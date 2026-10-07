# Recovery resource budgets

**Status: stub.** This file lists what must be measured before the pool's
release depth is chosen ([`spec.md`](spec.md) §14, D15), and the rule that
chooses it. Workstream 2 fills in the measurements against the release
circuit, adapter, verifier, pool, controller, and account. Every cell
marked *TBD* is unmeasured. Do not read a number into it.

## Reference points (not release measurements)

From Nido's `docs/recovery/stage3-measurements.md`. These are a prior
circuit at depth 24 with an arity-15 `auth_hash`, measured on a high-end
desktop:

| Metric | Value |
| --- | --- |
| `verify_proof` CPU instructions (constructorless UltraHonk verifier, real Wasm metering) | 179 257 831 |
| Network per-transaction instruction limit at that time (protocol 27) | 400 000 000 |
| `bb prove` wall time, Apple M5 Max | ~68 ms |
| Proof size / VK size / public inputs | 6 976 B / 1 888 B / 96 B |

Every full-transaction cost, fee, browser number, and mobile number was
left unmeasured there.

## What to record with every measurement

- Commit, toolchain versions (nargo, bb or bb.js, soroban-sdk,
  stellar-cli), and the circuit's `circuit_id`.
- The network's resource limits at measurement time, read from the
  network's config settings. Budgets below are fractions of those limits,
  not absolute numbers, so a limit change moves the threshold with it.
- The device (model, OS, browser and version, RAM) for client-side numbers.

## 1. Proving (client)

Per depth `D ∈ {24, 32}`, for one proof of any action. All actions share one
circuit.

| Workload | Reference device | Metric | D = 24 | D = 32 | Proposed budget |
| --- | --- | --- | --- | --- | --- |
| Witness fetch (indexer to path) | — | latency p95 | TBD | TBD | ≤ 2 s |
| Witness generation | browser, mid-range phone | time p95 | TBD | TBD | ≤ 2 s |
| Proof generation, bb.js in the browser | mid-range phone (named in results) | time p95 | TBD | TBD | ≤ 30 s |
| Proof generation, bb.js in the browser | mid-range phone | peak memory | TBD | TBD | ≤ 1 GiB |
| Proof generation, bb.js in the browser | mid-range laptop | time p95 | TBD | TBD | ≤ 10 s |
| Proof generation, native `bb` | mid-range laptop | time p95 | TBD | TBD | ≤ 5 s |
| Artifacts the client downloads (circuit, CRS slice, prover Wasm) | — | bytes | TBD | TBD | ≤ 50 MiB |
| Proof size | — | bytes | TBD | TBD | fits the transaction-size budget below |

## 2. Full transactions (on-chain)

Each row is the complete transaction, simulated and then submitted against
the release Wasm on testnet under enforcing authorization (no mocked auth,
no mock verifier). Each records CPU instructions, memory bytes, ledger
read/write entries and bytes, transaction size, event bytes, resource fee,
and inclusion latency.

| Transaction | Worst case to measure | Instructions | Memory | Read/write bytes | Tx size | Fee | Latency |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Enroll ZK through `apply_doc` (compile, `rcv_sync` wiring checks, `rcv_insert`) | insertion that seals a tree and opens the next | TBD | TBD | TBD | TBD | TBD | TBD |
| `begin_lost_key` (includes `derive_target`) | largest supported document | TBD | TBD | TBD | TBD | TBD | TBD |
| `begin_compromise` (includes `derive_target` over the baseline) | largest supported document | TBD | TBD | TBD | TBD | TBD | TBD |
| `publish_baseline` | largest supported document | TBD | TBD | TBD | TBD | TBD | TBD |
| `submit_guardian` | promoting approval under `Protected` (includes `rcv_gate`) | TBD | TBD | TBD | TBD | TBD | TBD |
| `submit_zk` (adapter, verifier, root check, nullifier) | promoting proof, `Combined` | TBD | TBD | TBD | TBD | TBD | TBD |
| Completion `apply_doc` (recovery rule) | `Combined`, ZK rotation (pool insert), a pre-recovery document and a target both at the document caps with every slot differing (spec §7.5), every removed credential revoked | TBD | TBD | TBD | TBD | TBD | TBD |
| Completion after rule churn | the row above, after many prior ordinary applies of a maximum-size document; must not grow with the number of past applies (#102 review, P1) | TBD | TBD | TBD | TBD | TBD | TBD |
| Cancellation | `Combined` (both factors in the last transaction) | TBD | TBD | TBD | TBD | TBD | TBD |
| `approve_change` | one guardian, `Reconfigure` or `Upgrade` | TBD | TBD | TBD | TBD | TBD | TBD |
| `submit_zk_change` (adapter, verifier, root check) | `Reconfigure` or `Upgrade` | TBD | TBD | TBD | TBD | TBD | TBD |
| `Protected` reconfiguration `apply_doc` | `Combined`: reading the recorded quorum and proof, a new enrollment insert, documents at the caps | TBD | TBD | TBD | TBD | TBD | TBD |
| `Protected` `schedule_upgrade` | `Combined`, reading recorded approvals | TBD | TBD | TBD | TBD | TBD | TBD |
| `execute_upgrade` (includes the `rcv_upgrade` epoch bump) | — | TBD | TBD | TBD | TBD | TBD | TBD |
| `begin_*` after an attacker opened many collecting attempts | promotion with `invalidate_below` (must not grow with the number of siblings) | TBD | TBD | TBD | TBD | TBD | TBD |
| Ordinary authorization overhead | `__check_auth` reading the freeze mirror and checking reserved names, versus plain `do_check_auth` | TBD | TBD | — | — | TBD | — |

**Proposed budget for every row:** at most 75% of the network's
per-transaction limit for instructions, memory, read bytes, write bytes,
and transaction size. The headroom covers authorization growth (more
guardians) and network limit changes. Workstream 4 applies the same 75% to
the footprint entries (distinct keys, read-only plus read-write, of 400),
written entries (the read-write keys, of 200), and contract-event bytes as
well: each is a hard per-transaction limit. With OZ's per-item events,
contract events were the one the caps hit first; the release suppresses
them, and instructions and written entries bind instead. That tightens
the rule; it relaxes nothing. The document caps (spec §7.5) are then set
from the frontier where every completion and reconfiguration row stays
within budget: see "Document caps" under Results
(`perch_doc_compiler::MAX_DOC_SIGNERS` = 8, `MAX_DOC_RULES` = 11,
`MAX_DOC_CANONICAL_BYTES` = 8 192).

## 3. End-to-end latency

| Flow | Measured from → to | Proposed budget |
| --- | --- | --- |
| ZK lost-key recovery | the user starts recovery → the attempt is authorized (witness fetch, prove, begin, submit) | ≤ 2 min p95 on the mid-range phone |
| Guardian approval | a guardian opens the request → their approval is included | ≤ 1 min p95, excluding human time |
| Completion | timelock elapsed → target installed | ≤ 1 min p95 |

## 4. Storage and rent

| Item | Per | Metric |
| --- | --- | --- |
| Controller state | account | entries, bytes, rent per year at maximum TTL |
| Revoked set | account | bytes per revoked credential |
| Nullifier records | credential | bytes, rent |
| Pool frontier | active tree | bytes, rent |
| Root → tree entry | insertion | bytes, rent (paid by the inserter) |
| Recorded change approval | guardian or proof | bytes, rent |
| `renew` / `renew_tree` | call | fee |

## 5. Depth decision rule

1. Measure §1 and §2 at both `D = 32` and `D = 24`, with the release circuit
   and contracts, recording §"What to record".
2. **Choose 32** if every §1 and §2 row at `D = 32` is within its budget.
3. Otherwise **choose 24** if every row at `D = 24` is within its budget.
   Record which `D = 32` rows failed and by how much.
4. Otherwise **no depth is releasable.** Stop and revisit the circuit, the
   adapter, or the transaction shapes. Do not relax a budget to make a depth
   pass without recording the change here and having it reviewed.
5. Rollover is required at either depth (§14.2); this rule never removes it.

The proposed budgets above are proposals. Reviewers confirm or replace them
before §5 runs, and the confirmed values are recorded here.

## Results

Workstream 2's measurements and the rule's application are in
[`docs/zk/measurements.md`](../zk/measurements.md) (2026-10-06, protocol
29 limits, zero-knowledge proofs; the measured circuits' `circuit_id`s are
in its generated "Circuit identities" table). In summary:

- §1: native and single-threaded bb.js proving take 0.10 s and 0.82 s on a
  desktop at D = 32. Client artifacts are 8.9 MB and the proof is 16.2 KB.
  The reference phone and laptop are not yet measured.
- §2, ZK components only: adapter `verify` is 136.9M instructions and
  6.7 MB at D = 32 (134.7M at D = 24); `rcv_insert` sealing a tree is 43.8M
  instructions and 2.2 KB written (34.8M at D = 24). The full-transaction
  rows are the controller workstream's.
- §5: every measured row is within budget at D = 32, so **D = 32**,
  provisional on the open rows above. D = 24 stays buildable as the
  fallback.

### Document caps

The measurements below use `release_stack.rs` (`cap_sweep`, the `worst_case_*`
tests) and `scripts/cap-sweep.py`, which arrive with the release stack in
the pull request above this one (#103) and hold these caps in its CI.

Workstream 4, 2026-10-06, protocol-29 limits, the release-stack suite on the
stack built from this branch's source (`build-stack.sh --builder contract`)
with real proofs and enforcing authorization. The provisional caps (16
signers, 16 rules, 8 192 bytes) did not hold: at them, a recovery
completion exceeded two network limits outright.

**The wasm stack.** Every contract linked rustc's default 1 MiB wasm stack,
so each VM started with 17 pages (1 088 KiB) of linear memory, and the host
charges that memory on every cross-contract call. A completion at the caps
makes dozens of them (OZ canonicalizes each rule's signers through their
verifier and installs and uninstalls each policy), so it took 107 MB of
the 41.9 MB limit. Each stack contract now links a 64 KiB stack
(`build.rs`, `-zstack-size=65536`; 2 pages). The same flows take about a
quarter of the memory (the largest existing row: 17 MB to 4.5 MB), and
every flow passes with real proofs. The stack is laid out first, so an
overflow wraps below address 0 and traps instead of corrupting data. The
UltraHonk verifier is the deepest code: the ZK-flavor verifier traps at
32 KiB (the controller reports `ZkEvidenceRejected`, failing closed) and
passes at 48 KiB, so the adapter links 128 KiB (3 pages), more than twice
that, at one VM per ZK transaction. The verifier's stack use does not
depend on its input, and the compiler's only input-driven recursion (JSON
nesting) refuses cleanly at its depth limit on the 64 KiB stack.

**With OZ's events, events bound.** OZ emits an event for every rule
added, removed, or edited, for every signer registered, added to a rule, or
removed from one, and for every policy installed or uninstalled. The
controller emits one per revoked credential. `apply_doc` applies only the
delta between documents (spec §7.5): rules are matched by name and scope,
and each changed rule takes the cheaper of an in-place edit and a whole
replacement. With OZ's events, contract events bound every frontier row:

| Signers | 2 | 4 | 6 | 8 | 10 | 12 |
| --- | --- | --- | --- | --- | --- | --- |
| Most rules within budget | 11 | 10 | 8 (72.9%) | 6 | 5 | fewer than 5 |

That allowed 6 signers and 8 rules. The release removes that limit in two
steps, both from theahaco/stellar-contracts-OZ, the OZ fork this repo pins:

- **Quiet mutations (OZ fork PR #4).** `apply_doc` makes every rule,
  signer, and policy mutation through `_no_events` variants, and the
  spending-limit policy installs and uninstalls quietly. The account emits
  one `DocApplied` per application: `doc_hash` is its topic, and the
  delta's counts are its data (rules added, removed, and edited in place;
  signers and policies added and removed). `applied_doc` serves the
  document, and `CredentialRevoked` is unchanged. Events drop to at most 31%
  anywhere measured. With no events to price, the reconcile chooses each
  rule's path by ledger writes, counted per OZ operation.
- **One call per in-place signer change (OZ fork PR #5).** An in-place edit
  changes a rule's signers in one `reconcile_signers_no_events`, instead of
  a `remove_signer` per leaving signer and a `batch_add_signer`. The call
  checks the final set as a whole (size, key sizes, canonical duplicates),
  keeps the retained signers' registry ids, and writes the rule once. The
  edit no longer needs room for old and new keys side by side. The cost
  model prices it as one rule write plus each leaving and joining signer's
  registry and lookup entries.

**Worst cases.** A completion's cost depends on how its source and target
differ, so the flows are the ones with the largest difference, every way
the diff can go:

- **Compromise recovery after a thief replaced every key.** A thief holding
  the owner key under `Protected` changes every signer's key without a
  condition (no recovery text changes), and the completion revokes both key
  sets. The thief also chooses the diff:
  - keep every rule's name, so the reconcile picks each rule's path;
  - rename every rule, so every rule is removed and added;
  - keep every name but change every interpreter program and cap
    (reparam), every program (reprogram), or every cap (recap), so every
    policy is reinstalled whichever path is taken.
- **Lost-key recovery replacing every signer.**
- **A `Protected` reconfiguration replacing every key**, with recorded
  quorum and proof and a new ZK enrollment, both with every rule kept by
  name and with every rule renamed.

**Method.** `cap_sweep` (in `release_stack.rs`) runs those eight flows
(`WORST_FLOWS`) over a document shape, and `scripts/cap-sweep.py` runs it
over S,R shapes and tabulates the worst share of every limit. The shape is
the costliest the caps admit:
- every signer is a passkey (the longest key the stack's verifiers take),
  named by some rule, as many per rule as OZ allows;
- every rule but `admin` and the owner's activity rule carries both
  policies (the interpreter and a spending cap);
- the document is padded to the larger of 8 192 bytes and its own size,
  with a `string-in` argument constraint and rule names at OZ's 20-byte
  limit.

**Footprint is counted as the network counts it**: the transaction's
distinct ledger keys, read-only plus read-write, against 400. Written
entries (the read-write keys) are a separate limit of 200. Until
2026-10-07 the sweep added the two, which counted every read-write key
twice and reported the footprint as binding when it never was.
`the_metered_footprint_is_the_simulated_transactions` simulates every
`apply_doc` of the binding flows at the caps the way RPC simulation runs
it, and checks the metered footprint against the simulated read-only plus
read-write keys, and the written entries against the read-write keys.
`cap-sweep.py --simulate` does the same inside a sweep: 63 of 63 matched at
6 and 14, 8 and 11, and 10 and 9.

The sweep ran on a stack built from this source with the compiler's caps
raised (15 signers, OZ's per-rule maximum; 32 rules; 32 768 bytes). The
same 33 shapes, padding, flows, and toolchain were also run on the two
earlier designs: OZ's events, and quiet mutations with per-signer edits.
For each signer count, the most rules within budget and the first row past
it:

| Signers | Rules | Instructions | Memory | Footprint | Written entries | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 | 17 | 62.8% | 73.2% | 37.8% | 70.5% | 40.1% | 10.0% |
| 2 | 18 | 64.3% | **77.3%** | 39.2% | 73.5% | 41.1% | 10.0% |
| 4 | 16 | 69.6% | 74.3% | 39.8% | 73.5% | 43.2% | 13.3% |
| 4 | 17 | 71.6% | **78.8%** | 41.2% | **76.5%** | 44.4% | 13.3% |
| 6 | 14 | 74.5% | 70.4% | 40.2% | 73.5% | 44.3% | 16.5% |
| 6 | 15 | **77.3%** | **75.2%** | 41.8% | **76.5%** | 45.8% | 16.5% |
| **8** | **11** | **73.6%** | **60.5%** | **39.2%** | **70.5%** | **42.8%** | **19.7%** |
| 8 | 12 | **77.1%** | 65.5% | 40.8% | 73.5% | 44.5% | 19.7% |
| 10 | 9 | 72.6% | 54.4% | 39.8% | 70.5% | 41.8% | 22.9% |
| 10 | 10 | **76.8%** | 59.6% | 41.2% | 73.5% | 43.8% | 22.9% |
| 12 | 8 | 73.6% | 52.6% | 41.8% | 73.5% | 42.1% | 26.1% |
| 12 | 9 | **79.0%** | 58.3% | 43.2% | **76.5%** | 44.3% | 26.1% |
| 15 | 5 | 62.2% | 40.0% | 42.5% | 73.5% | 37.8% | 31.0% |
| 15 | 6 | 69.0% | 45.9% | 44.0% | **76.5%** | 40.3% | 31.0% |

**What binds.**
- **Instructions bind from 6 to 12 signers**, in the thief who keeps every
  name and changes every program.
- **Memory binds at 2 and 4 signers.**
- **Written entries bind at 15 signers.** Everywhere else they are close
  behind, in the renamed thief's completion: it replaces every rule whole,
  and each capped rule it replaces writes 6 entries (old and new rule,
  program, and spending window).
- **The footprint is never above 44.0%.**

**The reprogram thief costs instructions because of the cost model.** The
model prices only ledger writes. For a rule whose name is kept and whose
program changed, the in-place edit writes fewer entries than a
replacement: one `reconcile_signers` and a reinstall of the interpreter
policy, against a removal and an addition. So the reconcile edits the rule
in place. Each of those OZ calls re-reads the rule and its signers, and the
in-place path costs more instructions. With per-signer edits, the
in-place path writes more, so the same thief is replaced and instructions
never bind (8 and 12, and 10 and 10, fit there). A model that also priced
instructions would take the replacement for these rules, at the reparam
rows' cost (72.2% at 8 and 12, 71.1% at 10 and 10). That would add a rule
at 8 and at 10 signers. It is not needed at the caps and is not
implemented: it would change the reviewed cost model, which the tests
require to price exactly what runs.

**The caps are 8 signers, 11 rules, and 8 192 canonical bytes** (the
captain's choice from this frontier). Every shape up to the caps fits the
8 192-byte canonical cap. The worst share at the caps is instructions at
73.6%, in the reprogram thief's completion; written entries are at 70.5%
(the renamed thief). Other frontier points are 2 and 17, 4 and 16, 6 and
14, 10 and 9, 12 and 8, and 15 and 5. Rerun `scripts/cap-sweep.py` after a
change to the reconcile's cost model, OZ's mutations, the controller's or
the policies' storage, or a network limit.

At the caps, the worst rows are:

| Row | Instructions | Memory | Footprint | Written | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Enroll `Combined` through `apply_doc` | 197.2M (49.3%) | 14.6 MB | 91 | 63 | 51 144 | 888 |
| `begin_lost_key` / `begin_compromise` | 134.8M (33.7%) | 5.4 MB | 25 | 2 | 2 176 | 248 |
| Thief's `apply_doc` (every key swapped, every rule renamed) | 201.7M (50.4%) | 20.1 MB | 124 | 102 | 47 408 | 340 |
| Thief's `apply_doc` (names kept, every program changed) | 249.3M (62.3%) | 16.2 MB | 83 | 61 | 44 156 | 340 |
| Compromise completion, names kept, every program changed (binding) | 294.5M (73.6%) | 19.8 MB (47.1%) | 116 (29.0%) | 99 (49.5%) | 53 160 (40.2%) | 3 228 (19.7%) |
| Compromise completion, names kept, every program and cap changed | 276.2M (69.0%) | 25.4 MB (60.5%) | 155 (38.8%) | 137 (68.5%) | 56 260 | 3 228 |
| Compromise completion, names kept, every cap changed | 275.6M (68.9%) | 24.7 MB | 152 | 134 | 55 812 | 3 228 |
| Compromise completion, every rule renamed | 251.6M (62.9%) | 24.9 MB (59.3%) | 157 (39.2%) | 141 (70.5%) | 56 532 (42.8%) | 3 228 |
| Compromise completion, every rule kept by name | 259.6M (64.9%) | 13.2 MB | 99 | 85 | 44 852 | 3 228 |
| Lost-key completion (`Combined`, ZK rotation, every signer revoked) | 257.0M (64.2%) | 12.5 MB | 91 | 77 | 43 752 | 2 172 |
| `Protected` reconfiguration, every rule edited | 257.5M (64.4%) | 12.9 MB | 83 | 60 | 39 960 | 888 |
| `Protected` reconfiguration, every rule replaced | 244.3M (61.1%) | 23.1 MB | 141 | 114 | 51 592 | 888 |

The `worst_case_*` tests in `release_stack.rs` run all eight flows at the
compiled-in caps and assert each stays within budget, so lowering a limit
or growing a flow's cost fails CI's `release-stack-source` job.

**Signer transitions, in release wasm.** `signer_transitions`
(`release_stack.rs`) applies one document change per row to `pay`, a
1-of-n rule (the interpreter policy), and to the spending cap in the
capped row. It compares the release with the two earlier designs, all on
WS3's batched-addition base (4d11470), on stacks built with the caps raised
so the 15-signer rows run. In "full six-key rotation" every declared key
changes, the owner's (and so `admin`'s) too. Each cost is the whole
`apply_doc`, compiling the document included.

**CPU instructions**

| Transition | OZ's events | Quiet, per-signer edits | Release (quiet + `reconcile_signers`) |
| --- | ---: | ---: | ---: |
| single addition | 22.51M | 22.36M | 23.08M |
| several additions | 25.01M | 24.77M | 25.75M |
| full six-key rotation | 30.81M | 30.36M | 30.40M |
| one swap in a six-key rule | 28.21M | 28.03M | 28.93M |
| five swaps in a six-key rule | 28.74M | 28.38M | 31.19M |
| shared signers | 27.10M | 27.76M | 28.44M |
| full rotation with an active spending cap | 32.54M | 32.07M | 34.02M |
| one swap at OZ's 15 | 52.61M | 52.26M | 54.87M |
| seven swaps at OZ's 15 | 57.04M | 56.24M | 58.84M |

**Memory**

| Transition | OZ's events | Quiet, per-signer edits | Release (quiet + `reconcile_signers`) |
| --- | ---: | ---: | ---: |
| single addition | 2.42 MB | 2.40 MB | 2.41 MB |
| several additions | 2.50 MB | 2.46 MB | 2.48 MB |
| full six-key rotation | 3.11 MB | 3.03 MB | 3.02 MB |
| one swap in a six-key rule | 2.54 MB | 2.50 MB | 2.50 MB |
| five swaps in a six-key rule | 2.75 MB | 2.70 MB | 2.75 MB |
| shared signers | 2.49 MB | 2.48 MB | 2.48 MB |
| full rotation with an active spending cap | 3.68 MB | 3.61 MB | 3.13 MB |
| one swap at OZ's 15 | 2.88 MB | 2.81 MB | 2.82 MB |
| seven swaps at OZ's 15 | 3.45 MB | 3.34 MB | 3.30 MB |

**Footprint entries (distinct keys)**

| Transition | OZ's events | Quiet, per-signer edits | Release (quiet + `reconcile_signers`) |
| --- | ---: | ---: | ---: |
| single addition | 27 | 27 | 27 |
| several additions | 31 | 31 | 31 |
| full six-key rotation | 50 | 50 | 50 |
| one swap in a six-key rule | 33 | 33 | 33 |
| five swaps in a six-key rule | 48 | 48 | 45 |
| shared signers | 33 | 29 | 29 |
| full rotation with an active spending cap | 57 | 57 | 49 |
| one swap at OZ's 15 | 51 | 51 | 51 |
| seven swaps at OZ's 15 | 69 | 69 | 69 |

**Written entries**

| Transition | OZ's events | Quiet, per-signer edits | Release (quiet + `reconcile_signers`) |
| --- | ---: | ---: | ---: |
| single addition | 12 | 12 | 12 |
| several additions | 16 | 16 | 16 |
| full six-key rotation | 37 | 37 | 37 |
| one swap in a six-key rule | 14 | 14 | 14 |
| five swaps in a six-key rule | 33 | 33 | 30 |
| shared signers | 16 | 12 | 12 |
| full rotation with an active spending cap | 42 | 42 | 35 |
| one swap at OZ's 15 | 14 | 14 | 14 |
| seven swaps at OZ's 15 | 38 | 38 | 38 |

**Event bytes**

| Transition | OZ's events | Quiet, per-signer edits | Release (quiet + `reconcile_signers`) |
| --- | ---: | ---: | ---: |
| single addition | 1,020 | 340 | 340 |
| several additions | 1,812 | 340 | 340 |
| full six-key rotation | 3,340 | 340 | 340 |
| one swap in a six-key rule | 1,244 | 340 | 340 |
| five swaps in a six-key rule | 2,720 | 340 | 340 |
| shared signers | 844 | 340 | 340 |
| full rotation with an active spending cap | 4,020 | 340 | 340 |
| one swap at OZ's 15 | 1,244 | 340 | 340 |
| seven swaps at OZ's 15 | 4,964 | 340 | 340 |

**Path and what it preserved** (rule id, spending window)

| Transition | OZ's events | Quiet, per-signer edits | Release (quiet + `reconcile_signers`) |
| --- | --- | --- | --- |
| single addition | in place, id kept | in place, id kept | in place, id kept |
| several additions | in place, id kept | in place, id kept | in place, id kept |
| full six-key rotation | replaced, new id | replaced, new id | replaced, new id |
| one swap in a six-key rule | in place, id kept | in place, id kept | in place, id kept |
| five swaps in a six-key rule | replaced, new id | replaced, new id | in place, id kept |
| shared signers | replaced, new id | in place, id kept | in place, id kept |
| full rotation with an active spending cap | replaced, new id, window reset | replaced, new id, window reset | in place, id kept, window kept |
| one swap at OZ's 15 | in place, id kept | in place, id kept | in place, id kept |
| seven swaps at OZ's 15 | in place, id kept | in place, id kept | in place, id kept |

On all three designs the rule ends up with exactly the target signers: a
joining key acts and a leaving key cannot. Retained signers keep their
registry ids. `a_rejected_signer_transition_changes_nothing` passes. In
it, a duplicate key (one passkey under a second credential id) and a budget
running out at 25, 50, 75, and 95% of a full rotation leave every ledger
entry unchanged.

`reconcile_signers` keeps two more transitions in place than per-signer
edits do: five swaps in a six-key rule, and the full rotation under an
active spending cap. The capped rotation now keeps its rule id and its
spending window, which a replacement reset (a key rotation also reset what
the cap had counted). It costs 0.7 to 2.6M more instructions on small
applies, where both designs edit in place. OZ's call reads the current
signers back from the registry and re-checks duplicates over the whole set.
At the caps, the flows that edit every rule in place are cheaper with it,
because a rule's whole swap is one call.

The compiler also refuses a rule name longer than OZ's 20-byte context-rule
limit (`MAX_RULE_NAME_BYTES`). Before, such a document compiled and failed
only at install, so a published compromise baseline with one could never be
restored. A rule cannot name more signers than OZ's per-rule 15 because the
document cannot declare more than 8.

Assumption: signer keys are at most a passkey's (81 bytes of key data). A
custom verifier with keys up to the 256 bytes the IR admits would grow every
signer's registry entry and the write bytes, and needs its own measurement.
