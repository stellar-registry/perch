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
well: each is a hard per-transaction limit, and contract events turned out
to be the one these caps hit first. That tightens the rule; it relaxes nothing. The
document caps (spec §7.5) are then set to the largest values for which the
completion and reconfiguration rows stay within budget: see "Document caps"
under Results (`perch_doc_compiler::MAX_DOC_SIGNERS` = 6, `MAX_DOC_RULES` =
8, `MAX_DOC_CANONICAL_BYTES` = 8 192; on the quiet-events experiment branch,
where OZ's per-item events are suppressed, 6, 13, and 8 192: see
"Experiment: OZ's per-item events suppressed").

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

Workstream 4 measured the §2 full-transaction rows on testnet, against the
deployed depth-32 release wasm (`deployments/testnet.json`, built before the
ZK-flavor verifier, WS3's completion fixes, the final caps, and the small
wasm stacks; the redeploy re-measures them) under enforcing authorization
with real proofs; see
[`docs/deploy/testnet-exercise.md`](../deploy/testnet-exercise.md). Every
row is within the 75% budget. The largest are `submit_zk` at 91.2M
instructions (22.8%) and 16.5 KB of transaction (12.5%), `submit_zk_change`
at 89.3M (22.3%), enrollment at 72.8M (18.2%), and the `Combined`
completion with ZK rotation at 71.2M (17.8%). No row reaches 11% of the
footprint-entry or 15% of the written-entry limit. Memory is not reported
by the RPC; the release-stack suite meters it in-process on the same wasm,
and every row stays under 18 MB of the 41.9 MB limit. Two rows are measured
only in-process: an enrollment that seals a tree (65.7M instructions) and
`execute_upgrade` (6.7M), whose seven-day delay testnet would need. The
deployed adapter's `circuit_id()` is
`9e39c41f4f35aad43e64b255dfe3ba13f10e8c9d36d6f56fce23c2d97c0a0b4a`, the
`vk_sha256` in `circuits/manifest.json`. The open §1 rows (reference phone
and laptop) remain open.

### Release stack, in process

Workstream 4, 2026-10-06: the release-stack suite on this branch's stack
(`build-stack.sh --builder contract`), with WS2's ZK-flavor verifier, WS3's
cheaper-path delta `apply_doc`, the final caps, and the 64 KiB (adapter: 128 KiB) wasm
stacks, real proofs, and enforcing authorization. The worst row of each §2
kind, as a share of the protocol-29 limits. Footprint is the transaction's
distinct ledger keys, read-only plus read-write, which is what the network
limits (400). Written entries are the read-write keys (200). Before
2026-10-07 this table counted every read-write key twice in the footprint
column (reads plus writes): the old value was the new one plus the written
entries. `the_metered_footprint_is_the_simulated_transactions` checks the
count against an RPC-style simulation of each binding `apply_doc`.

| Row | Instructions | Memory | Footprint | Written | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Enroll `Combined` through `apply_doc`, at the caps | 185.2M (46.3%) | 12.1 MB | 76 | 50 | 42 184 | 6 876 |
| `begin_lost_key` / `begin_compromise`, at the caps | 138.9M (34.7%) | 5.2 MB | 23 | 2 | 1 888 | 248 |
| `publish_baseline`, at the caps | 101.2M (25.3%) | 2.3 MB | 10 | 1 | 7 464 | 0 |
| `submit_guardian` (promoting, sets the freeze) | 1.8M | 0.7 MB | 13 | 6 | 1 996 | 368 |
| `submit_zk` (promoting, `Combined`, sets the freeze) | 119.2M (29.8%) | 5.7 MB | 17 | 5 | 2 284 | 368 |
| Completion, at the caps (compromise, both key sets revoked, every rule renamed) | 215.5M (53.9%) | 18.3 MB (43.6%) | 125 (31.2%) | 111 (55.5%) | 46 756 (35.4%) | 11 940 (72.9%) |
| Completion, at the caps (compromise, both key sets revoked, every rule kept) | 224.3M (56.1%) | 18.4 MB (43.9%) | 123 | 107 | 46 484 | 11 428 (69.8%) |
| Completion, at the caps (compromise, every rule kept by name, every program and cap changed) | 225.1M (56.3%) | 18.4 MB (44.0%) | 123 | 107 | 46 484 | 11 428 (69.8%) |
| Completion, at the caps (lost-key, every signer revoked) | 221.1M (55.3%) | 17.5 MB | 117 | 101 | 45 840 | 10 636 (64.9%) |
| Cancellation (`Combined`, ZK last) | 118.6M (29.7%) | 5.4 MB | 16 | 5 | 2 132 | 332 |
| `approve_change` | 0.9M | 0.3 MB | 8 | 2 | 392 | 192 |
| `submit_zk_change` | 117.6M (29.4%) | 5.1 MB | 12 | 1 | 240 | 192 |
| `Protected` reconfiguration `apply_doc`, at the caps | 222.8M (55.7%) | 17.9 MB | 113 | 88 | 42 632 | 10 132 |
| `Protected` `schedule_upgrade` | 6.2M | 1.2 MB | 13 | 2 | 1 116 | 196 |
| `execute_upgrade` | 6.3M | 1.2 MB | 12 | 5 | 1 232 | 696 |
| Enrollment that seals a tree (small document) | 58.5M | 4.4 MB | 34 | 18 | 8 016 | 1 460 |

Every row is within 75% of every limit. Native proving (`nargo execute` +
`bb prove`, 15 proofs on an Apple M-series desktop): 69 ms median witness,
97 ms median and 117 ms maximum proof. The deployable adapter is 67 982
bytes (`stellar scaffold build`; 52% of the 131 072-byte contract limit) and
the pool 45 663: `docs/zk/measurements.md`'s 116 776 and 75 264 are plain
`cargo build` sizes, without the CLI's spec shaking.

### Document caps

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

**The binding limit: contract events.** OZ emits an event for every rule
added, removed, or edited, every signer registered, added to a rule, or
removed from one, and every policy installed and uninstalled; the
controller emits one per revoked credential. `apply_doc` applies only the
delta between documents (spec §7.5): rules are matched by name and scope,
and each changed rule takes the cheaper of an in-place edit (signer by
signer) and a whole replacement, priced in event bytes and then ledger
writes. So a completion's cost depends on how the source and the target
differ, and the worst cases are the ones with the largest difference, both
ways the diff can go:

- **Compromise recovery after a thief replaced every key.** A thief holding
  the owner key under `Protected` changes every signer's key without a
  condition (no recovery text changes), and the completion revokes both key
  sets. The thief also chooses the diff: keeping every rule's name leaves
  the reconcile to pick each rule's cheaper path; renaming every rule forces
  every rule to be removed and added. **The renamed variant is the binding
  row**: the cheaper-path choice keeps the kept-name variant below it.
- **Lost-key recovery replacing every signer.**
- **A `Protected` reconfiguration replacing every key**, with recorded
  quorum and proof and a new ZK enrollment, both with every rule kept by
  name and with every rule renamed.
- **Compromise recovery after a thief kept every name but changed every
  policy**: every interpreter program and cap (reparam), every program
  (reprogram), or every cap (recap). Each forces every policy to be
  reinstalled, whichever path the reconcile takes. Here (events priced
  first) all three replace every rule and cost what the kept-name row
  costs, within 0.4 points.

Before the reconcile priced its paths it always edited a matched rule in
place, one `signer_removed` and one `signer_added` event per signer
swapped, which outgrows a whole replacement once a rule names a few
signers: the frontier then fell to 4 signers and 9 rules. Choosing the
cheaper path restores it.

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
2026-10-07 the sweep added the two, counting every read-write key twice;
those footprint figures were too high by the written entries.
`the_metered_footprint_is_the_simulated_transactions` simulates each
binding `apply_doc` the way RPC simulation runs it and checks both counts
against the simulated footprint's key sets. `cap-sweep.py --simulate` does
the same inside a sweep.

The sweep ran on a stack built from this branch with the compiler's caps
raised (15 signers, OZ's per-rule maximum; 32 rules; 32 768 bytes). The
shapes and padding are the same ones PR 106 and PR 107 were swept with. The
corrected frontier, each shape's worst share over every row of every flow:

| Signers | Rules | Instructions | Memory | Footprint | Written entries | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 | 11 | 54.7% | 50.5% | 28.8% | 52.5% | 34.0% | 71.5% |
| 2 | 12 | 56.0% | 54.1% | 30.2% | 55.5% | 35.0% | **76.7%** |
| 4 | 9 | 55.3% | 45.6% | 29.2% | 52.5% | 34.4% | 69.7% |
| 4 | 10 | 56.9% | 49.4% | 30.8% | 55.5% | 35.7% | 75.0% (12 284 B, on the line) |
| **6** | **8** | **56.3%** | **44.0%** | **31.2%** | **55.5%** | **35.4%** | **72.9%** |
| 6 | 9 | 58.5% | 48.1% | 32.8% | 58.5% | 36.9% | **78.3%** |
| 8 | 6 | 53.7% | 37.6% | 31.8% | 55.5% | 34.2% | 70.4% |
| 8 | 7 | 56.4% | 42.0% | 33.2% | 58.5% | 35.9% | **75.9%** |
| 10 | 5 | 52.5% | 35.0% | 33.8% | 58.5% | 34.0% | 73.1% |
| 10 | 6 | 55.8% | 39.7% | 35.2% | 61.5% | 35.9% | **78.7%** |
| 12 | 5 | 54.2% | 37.0% | 37.2% | 64.5% | 35.5% | **81.3%** |
| 15 | 3 | 47.3% | 29.1% | 39.5% | 67.5% | 32.7% | **81.9%** |

**Events bind at every frontier row**, in the compromise whose thief
renamed every rule. The frontier runs from 10 signers and 5 rules to 2
signers and 11. At 12 and 15 signers not even the smallest measured
documents fit (5 and 3 rules). No other limit is near the budget at those
points. Measured up to 18 rules:
- the footprint never passes 44.0% (15 signers, 6 rules);
- instructions reach 73.0% at 6 signers and 15 rules;
- memory first passes 75% at 2 signers and 18 rules;
- written entries first pass it at 4 and 17, and at 6 and 15.

**With OZ's events, the caps are 6 signers, 8 rules, and 8 192 canonical
bytes** (events
72.9%, the compromise whose thief renamed every rule), the same 75% rule
and the same frontier point as when `apply_doc` replaced every rule: the
point that keeps the most rules (a scope per contract) without dropping
signers below 6. 2 signers and 11 rules, 4 and 10, 8 and 6, or 10 and 5
are the alternatives. Rerun `scripts/cap-sweep.py` after a change to the
reconcile's cost model, OZ's events, the controller's, or the policies,
and after a network limit change.

At the caps, the worst rows are:

| Row | Instructions | Memory | Footprint | Written | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Enroll `Combined` through `apply_doc` | 185.2M | 12.1 MB | 76 | 50 | 42 184 | 6 876 |
| `begin_lost_key` / `begin_compromise` | 138.9M | 5.2 MB | 23 | 2 | 1 888 | 248 |
| Thief's `apply_doc` (every key swapped, every rule renamed) | 171.1M | 14.7 MB | 96 | 76 | 38 472 | 8 908 |
| Compromise completion, every rule renamed (12 revoked) | 215.8M (54.0%) | 18.3 MB (43.6%) | 125 (31.2%) | 111 (55.5%) | 46 756 (35.4%) | 11 940 (72.9%) |
| Compromise completion, every rule kept by name (12 revoked) | 224.4M (56.1%) | 18.4 MB (43.9%) | 123 (30.8%) | 107 (53.5%) | 46 484 (35.2%) | 11 428 (69.8%) |
| Compromise completion, names kept, every program and cap changed | 225.1M (56.3%) | 18.4 MB (44.0%) | 123 | 107 | 46 484 | 11 428 (69.8%) |
| Compromise completion, names kept, every program changed | 224.6M (56.2%) | 18.4 MB | 123 | 107 | 46 484 | 11 428 |
| Compromise completion, names kept, every cap changed | 225.0M (56.3%) | 18.4 MB | 123 | 107 | 46 484 | 11 428 |
| Lost-key completion (`Combined`, ZK rotation, 6 revoked) | 221.2M | 17.5 MB | 117 | 101 | 45 840 | 10 636 |
| `Protected` reconfiguration, every rule kept by name | 222.8M | 17.9 MB | 111 | 84 | 42 368 | 9 616 |
| `Protected` reconfiguration, every rule renamed | 214.5M | 17.7 MB | 113 | 88 | 42 632 | 10 132 |

The `worst_case_*` tests in `release_stack.rs` run all eight flows at the
compiled-in caps and assert each stays within budget, so lowering a limit
or growing an event fails CI's `release-stack-source` job.

The compiler also refuses a rule name longer than OZ's 20-byte context-rule
limit (`MAX_RULE_NAME_BYTES`). Before, such a document compiled and failed
only at install, so a published compromise baseline with one could never be
restored. A rule cannot name more signers than OZ's per-rule 15 because the
document cannot declare more than 6.

Assumption: signer keys are at most a passkey's (81 bytes of key data). A
custom verifier with keys up to the 256 bytes the IR admits would grow every
signer's registration event and needs its own measurement.

### Experiment: OZ's per-item events suppressed

Quiet-events experiment, 2026-10-07. This branch only, not PR 103.
`stellar-accounts` is pinned to theahaco/stellar-contracts-OZ PR #4
(`fm/oz-quiet-events-x1`, 74f9f64). That PR adds `_no_events` variants of
every context-rule, signer, and policy mutation, and of `spending_limit`'s
install and uninstall. `apply_doc` makes every mutation through them, and
then emits one `DocApplied`: `doc_hash` is its topic, and the delta's
counts are its data (rules added, removed, and edited in place; signers and
policies added and removed by the in-place edits). The controller's
`CredentialRevoked`, one per revoked credential, is unchanged. Nothing is
emitted, so the reconcile prices only ledger writes, counted per operation
as WS3's model counts them. Each changed rule takes whichever path writes
fewer entries.

Same method, budget, eight flows, shapes, and padding as above, with the
footprint counted as distinct keys, on a stack built from this branch with
the compiler's caps raised. Contract events drop from the binding limit
(72.9% at 6 signers and 8 rules) to at most 31%, which is reached at 15
signers. The frontier moves out. For each signer count, the most rules
within budget and the first row past it, each the worst share over every
row of every flow:

| Signers | Rules | Instructions | Memory | Footprint | Written entries | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 | 17 | 62.4% | 73.1% | 37.8% | 70.5% | 40.1% | 10.0% |
| 2 | 18 | 63.8% | **77.3%** | 39.2% | 73.5% | 41.1% | 10.0% |
| 4 | 16 | 67.6% | 74.2% | 39.8% | 73.5% | 43.2% | 13.3% |
| 4 | 17 | 69.6% | **78.7%** | 41.2% | **76.5%** | 44.4% | 13.3% |
| 6 | 13 | 67.5% | 65.5% | 38.8% | 70.5% | 42.8% | 16.5% |
| **6** | **14** | **70.0%** | **70.2%** | **40.2%** | **73.5%** | **44.3%** | **16.5%** |
| 6 | 15 | 72.5% | **75.1%** | 41.8% | **76.5%** | 45.8% | 16.5% |
| 8 | 12 | 70.3% | 65.3% | 40.8% | 73.5% | 44.5% | 19.7% |
| 8 | 13 | 73.3% | 70.4% | 42.2% | **76.5%** | 46.2% | 19.7% |
| 10 | 10 | 69.3% | 59.4% | 41.2% | 73.5% | 43.8% | 22.9% |
| 10 | 11 | 72.9% | 64.7% | 42.8% | **76.5%** | 45.7% | 22.9% |
| 12 | 8 | 66.0% | 52.5% | 41.8% | 73.5% | 42.1% | 26.1% |
| 12 | 9 | 70.1% | 58.1% | 43.2% | **76.5%** | 44.3% | 26.1% |
| 15 | 5 | 56.8% | 39.8% | 42.5% | 73.5% | 37.8% | 31.0% |
| 15 | 6 | 61.8% | 45.8% | 44.0% | **76.5%** | 40.3% | 31.0% |

**What binds.** From 6 signers up, written entries bind, in the compromise
whose thief renamed every rule. That completion replaces every rule whole,
and each capped rule it replaces writes 6 entries (old and new rule, old
and new program, old and new spending window), against a 200-entry limit.
At 2 and 4 signers memory binds, in the keep-names thieves. The footprint
is never above 44.0%. The double-counted figures this section reported
before showed it binding everywhere (74.0% at 6 and 13); the real count
there is 155 of 400 (38.8%).

**The keep-names thieves.** Reparam, reprogram, and recap all replace
every rule here, because the in-place edit (a `remove_signer` per leaving
signer, one batch addition, and the policy reinstall) writes more. They
cost 67.4 to 67.5% of instructions and 137 written entries at 6 and 13,
which is within budget but the highest instruction rows. 8 and 11, and 10
and 9, the points the double-counted sweep ended at, are well inside:
70.5% written entries, and 67.3% and 65.7% instructions, at worst.

**On this branch the caps stay 6 signers, 13 rules, and 8 192 canonical
bytes.** The worst shares are written entries at 70.5% (the renamed thief)
and instructions at 67.5% (reparam). They are provisional, like PR 107's,
until the captain's decision. 6 and 14 also fits (written entries 73.5%,
instructions 70.0%), as do 2 and 17, 4 and 16, 8 and 12, 10 and 10, 12 and
8, and 15 and 5. Compared with OZ's events (6 and 8), the experiment gains
5 rules at the current caps.

At the caps (on WS3's batched signer additions, 4d11470), the worst rows
are:

| Row | Instructions | Memory | Footprint | Written | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Enroll `Combined` through `apply_doc` | 199.2M (49.8%) | 15.9 MB | 91 | 65 | 52 000 | 888 |
| `begin_lost_key` / `begin_compromise` | 134.0M (33.5%) | 4.7 MB | 23 | 2 | 1 888 | 248 |
| Thief's `apply_doc` (every key swapped, every rule renamed) | 205.3M (51.3%) | 22.4 MB | 126 | 106 | 48 280 | 340 |
| Compromise completion, every rule kept by name | 254.5M (63.6%) | 14.7 MB (35.1%) | 95 | 80 (40.0%) | 44 112 | 2 700 (16.5%) |
| Compromise completion, every rule renamed | 254.9M (63.7%) | 27.1 MB (64.7%) | 155 (38.8%) | 141 (70.5%) | 56 572 (42.8%) | 2 700 (16.5%) |
| Compromise completion, names kept, every program and cap changed | 270.2M (67.5%) | 27.5 MB (65.5%) | 153 | 137 (68.5%) | 56 300 | 2 700 |
| Compromise completion, names kept, every program changed | 269.4M (67.4%) | 27.5 MB | 153 | 137 | 56 300 | 2 700 |
| Compromise completion, names kept, every cap changed | 270.1M (67.5%) | 27.5 MB | 153 | 137 | 56 300 | 2 700 |
| Lost-key completion (`Combined`, ZK rotation, every signer revoked) | 252.1M (63.0%) | 14.1 MB | 89 | 74 | 43 276 | 1 908 |
| `Protected` reconfiguration, every rule edited | 253.2M (63.3%) | 14.5 MB | 83 | 58 | 39 932 | 888 |
| `Protected` reconfiguration, every rule replaced | 248.7M (62.2%) | 25.5 MB | 143 | 118 | 52 440 | 888 |

The "Release stack, in process" table above is from PR 103, with OZ's
events. On this branch, the `worst_case_*` tests hold the rows above at the
compiled-in caps.

### Experiment: in-place signer changes through `reconcile_signers`

Reconcile experiment, 2026-10-07. This branch only, stacked on the
quiet-events experiment (PR 106); not PR 103. `stellar-accounts` is pinned
to theahaco/stellar-contracts-OZ PR #5 (`fm/oz-quiet-events-x1-reconcile`,
3372676), which adds `reconcile_signers[_no_events]` on top of PR #4. An
in-place edit changes a rule's signers in one
`reconcile_signers_no_events` call instead of a `remove_signer` per leaving
signer and one `batch_add_signer`. That call checks the final set as a
whole (size, key sizes, canonical duplicates), releases the leaving
signers, registers the joining ones, keeps the retained signers' registry
ids, and writes the rule once. The edit no longer needs room for old and
new keys side by side. The cost model prices it as one rule write plus each
leaving and joining signer's registry and lookup entries.

**Signer transitions, in release wasm.** `signer_transitions`
(`release_stack.rs`) applies one document change per row. Each change is
to `pay`, a 1-of-n rule (the interpreter policy), and to the spending cap
in the capped row. All three branches are measured at WS3's 4d11470
(batched signer additions), on stacks built with the compiler's caps
raised so the 15-signer rows run. The caps gate documents, not costs. In
"full six-key rotation" every declared key changes, the owner's (and so
`admin`'s) too: at the 6-signer cap no seventh key can hold `admin`. Each
row's cost is the whole `apply_doc`, compiling the document included.

**CPU instructions**

| Transition | #103 (OZ events) | #106 (quiet) | This branch (quiet + reconcile) |
| --- | ---: | ---: | ---: |
| single addition | 22.51M | 22.36M | 23.08M |
| several additions | 25.01M | 24.77M | 25.75M |
| full six-key rotation | 30.81M | 30.36M | 30.40M |
| one swap at the signer cap | 28.21M | 28.03M | 28.93M |
| five swaps at the signer cap | 28.74M | 28.38M | 31.19M |
| shared signers | 27.10M | 27.76M | 28.44M |
| full rotation with an active spending cap | 32.54M | 32.07M | 34.02M |
| one swap at OZ's 15 | 52.61M | 52.26M | 54.87M |
| seven swaps at OZ's 15 | 57.04M | 56.24M | 58.84M |

**Memory**

| Transition | #103 (OZ events) | #106 (quiet) | This branch (quiet + reconcile) |
| --- | ---: | ---: | ---: |
| single addition | 2.42 MB | 2.40 MB | 2.41 MB |
| several additions | 2.50 MB | 2.46 MB | 2.48 MB |
| full six-key rotation | 3.11 MB | 3.03 MB | 3.02 MB |
| one swap at the signer cap | 2.54 MB | 2.50 MB | 2.50 MB |
| five swaps at the signer cap | 2.75 MB | 2.70 MB | 2.75 MB |
| shared signers | 2.49 MB | 2.48 MB | 2.48 MB |
| full rotation with an active spending cap | 3.68 MB | 3.61 MB | 3.13 MB |
| one swap at OZ's 15 | 2.88 MB | 2.81 MB | 2.82 MB |
| seven swaps at OZ's 15 | 3.45 MB | 3.34 MB | 3.30 MB |

**Footprint entries**

| Transition | #103 (OZ events) | #106 (quiet) | This branch (quiet + reconcile) |
| --- | ---: | ---: | ---: |
| single addition | 39 | 39 | 39 |
| several additions | 47 | 47 | 47 |
| full six-key rotation | 87 | 87 | 87 |
| one swap at the signer cap | 47 | 47 | 47 |
| five swaps at the signer cap | 81 | 81 | 75 |
| shared signers | 49 | 41 | 41 |
| full rotation with an active spending cap | 99 | 99 | 84 |
| one swap at OZ's 15 | 65 | 65 | 65 |
| seven swaps at OZ's 15 | 107 | 107 | 107 |

**Event bytes**

| Transition | #103 (OZ events) | #106 (quiet) | This branch (quiet + reconcile) |
| --- | ---: | ---: | ---: |
| single addition | 1,020 | 340 | 340 |
| several additions | 1,812 | 340 | 340 |
| full six-key rotation | 3,340 | 340 | 340 |
| one swap at the signer cap | 1,244 | 340 | 340 |
| five swaps at the signer cap | 2,720 | 340 | 340 |
| shared signers | 844 | 340 | 340 |
| full rotation with an active spending cap | 4,020 | 340 | 340 |
| one swap at OZ's 15 | 1,244 | 340 | 340 |
| seven swaps at OZ's 15 | 4,964 | 340 | 340 |

**Path and what it preserved** (rule id, spending window)

| Transition | #103 (OZ events) | #106 (quiet) | This branch (quiet + reconcile) |
| --- | --- | --- | --- |
| single addition | in place, id kept | in place, id kept | in place, id kept |
| several additions | in place, id kept | in place, id kept | in place, id kept |
| full six-key rotation | replaced, new id | replaced, new id | replaced, new id |
| one swap at the signer cap | in place, id kept | in place, id kept | in place, id kept |
| five swaps at the signer cap | replaced, new id | replaced, new id | in place, id kept |
| shared signers | replaced, new id | in place, id kept | in place, id kept |
| full rotation with an active spending cap | replaced, new id, window reset | replaced, new id, window reset | in place, id kept, window kept |
| one swap at OZ's 15 | in place, id kept | in place, id kept | in place, id kept |
| seven swaps at OZ's 15 | in place, id kept | in place, id kept | in place, id kept |

Every row's rule ends up with exactly the target signers: a joining key
acts and a leaving key cannot. Retained signers keep their registry ids on
all three branches. `a_rejected_signer_transition_changes_nothing` passes
on all three. In it, a duplicate key (one passkey under a second credential
id) and a budget running out at 25, 50, 75, and 95% of a full rotation
leave every ledger entry unchanged.

What `reconcile_signers` changes:

- **Two more transitions stay in place**: five swaps at the signer cap, and
  the full rotation under an active spending cap. The second now keeps the
  rule id and the spending window. Before, its replacement reset the
  window, so a key rotation also reset what the cap had already counted.
  Both write fewer entries (footprint 81 to 75, and 99 to 84).
- **It costs more CPU.** Where both branches edit in place, an apply takes
  0.7 to 2.6M more instructions: single addition 22.36M to 23.08M, one swap
  at OZ's 15 52.26M to 54.87M. The two rows that moved in place cost 2.8M
  (five swaps) and 2.0M (the capped rotation) more than the replacements
  they displace. OZ's `reconcile_signers` reads the rule's current signers
  back from the registry and checks canonical duplicates over the whole
  final set on every call. Memory is the same or lower: 3.61 to 3.13 MB for
  the capped rotation.
- **The uncapped full rotation is still replaced**: the write-count model
  prices its replacement below the in-place edit.

**Caps.** The sweep over the same shapes as PR 106 gives the same frontier
to within 0.1 point of footprint, and every row binds on the footprint:
2 and 17, 4 and 15, 6 and 13 (74.0%), 8 and 11, 10 and 9 (75.0%, on the
line), 12 and 6, 13 and 5, 14 and 4, 15 and 3. The binding row is the
compromise whose thief renamed every rule. That completion replaces every
rule whole, and `reconcile_signers` never runs in it. **The caps stay 6
signers, 13 rules, 8 192 bytes**, as on PR 106.

At the caps, the flows that edit every rule in place come out cheaper than
on PR 106. There, an edit removes each leaving signer with its own call;
here a rule's whole swap is one call:

| Row | PR 106 | This branch |
| --- | --- | --- |
| Compromise completion, every rule kept by name | 254.3M, 14.7 MB, 175 entries | 249.8M, 12.9 MB, 162 entries |
| Lost-key completion, every signer revoked | 252.1M, 14.1 MB, 163 entries | 248.1M, 12.4 MB, 150 entries |
| `Protected` reconfiguration, every rule edited | 253.2M, 14.5 MB, 141 entries | 249.4M, 12.9 MB, 129 entries |
| Compromise completion, every rule renamed (binding) | 254.7M, 27.1 MB, 296 entries (74.0%) | 254.7M, 27.1 MB, 296 entries (74.0%) |
