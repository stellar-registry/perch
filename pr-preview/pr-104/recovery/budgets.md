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
the footprint entries, written entries, and contract-event bytes as well:
each is a hard per-transaction limit, and contract events turned out to be
the one the caps hit first. That tightens the rule; it relaxes nothing. The
document caps (spec §7.5) are then set to the largest values for which the
completion and reconfiguration rows stay within budget: see "Document caps"
under Results (`perch_doc_compiler::MAX_DOC_SIGNERS` = 4, `MAX_DOC_RULES` =
9, `MAX_DOC_CANONICAL_BYTES` = 8 192).

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
delta `apply_doc`, the final caps, and the 64 KiB (adapter: 128 KiB) wasm
stacks, real proofs, and enforcing authorization. The worst row of each §2
kind, as a share of the protocol-29 limits:

| Row | Instructions | Memory | Footprint | Written | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Enroll `Combined` through `apply_doc`, at the caps | 185.5M (46.4%) | 12.7 MB | 122 | 49 | 41 696 | 6 808 |
| `begin_lost_key` / `begin_compromise`, at the caps | 140.9M (35.2%) | 4.6 MB | 23 | 2 | 1 600 | 248 |
| `publish_baseline`, at the caps | 105.0M (26.3%) | 2.4 MB | 11 | 1 | 7 476 | 0 |
| `submit_guardian` (promoting, sets the freeze) | 1.8M | 0.7 MB | 19 | 6 | 1 996 | 368 |
| `submit_zk` (promoting, `Combined`, sets the freeze) | 119.1M (29.8%) | 5.7 MB | 22 | 5 | 2 284 | 368 |
| Completion, at the caps (compromise, both key sets revoked, every rule edited) | 212.1M (53.0%) | 16.6 MB (39.5%) | 130 | 59 | 31 516 | 12 184 (74.4%) |
| Completion, at the caps (compromise, both key sets revoked, every rule replaced) | 209.1M (52.3%) | 18.9 MB (45.0%) | 222 (55.5%) | 105 (52.5%) | 45 452 (34.4%) | 11 416 (69.7%) |
| Completion, at the caps (lost-key, every signer revoked) | 211.4M (52.8%) | 16.3 MB | 122 | 55 | 30 944 | 11 656 (71.1%) |
| Cancellation (`Combined`, ZK last) | 118.6M (29.7%) | 5.4 MB | 21 | 5 | 2 132 | 332 |
| `approve_change` | 0.9M | 0.3 MB | 10 | 2 | 392 | 192 |
| `submit_zk_change` | 117.6M (29.4%) | 5.1 MB | 13 | 1 | 240 | 192 |
| `Protected` reconfiguration `apply_doc`, at the caps | 213.2M (53.3%) | 18.5 MB (44.2%) | 195 | 86 | 42 144 | 10 900 |
| `Protected` `schedule_upgrade` | 6.2M | 1.2 MB | 15 | 2 | 1 116 | 196 |
| `execute_upgrade` | 6.3M | 1.2 MB | 17 | 5 | 1 232 | 696 |
| Enrollment that seals a tree (small document) | 58.5M | 4.4 MB | 52 | 18 | 8 016 | 1 460 |

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
a matched rule is edited in place signer by signer, and an unmatched one
removed or added. So a completion's cost depends on how the source and the
target differ, and the worst cases are the ones with the largest
difference, both ways the diff can go:

- **Compromise recovery after a thief replaced every key.** A thief holding
  the owner key under `Protected` changes every signer's key without a
  condition (no recovery text changes), and the completion revokes both key
  sets. The thief also chooses the diff: **keeping every rule's name**
  makes the completion edit every rule in place, one `signer_removed` and
  one `signer_added` event (about 120 bytes each) per rule and signer;
  renaming every rule makes it remove and add every rule instead. In place
  is the dearer of the two once a rule names enough signers (about 240
  bytes of events per signer swapped, against about 880 to replace a rule
  with both policies), and **it is the binding row from 4 signers on**: at 6 signers and 8 rules its
  in-place edits alone emit 86 events and 10.5 KB, where replacing those
  rules whole would emit about 6 KB. Below 4 signers the renamed variant
  binds.
- **Lost-key recovery replacing every signer**: every rule edited in place,
  every signer revoked.
- **A `Protected` reconfiguration replacing every key**, with recorded
  quorum and proof and a new ZK enrollment, both with every rule edited
  and with every rule renamed.

**Method.** `cap_sweep` (in `release_stack.rs`) runs those five flows over
a document shape, and `scripts/cap-sweep.py` runs it over S,R shapes and
tabulates the worst share of every limit. The shape is the costliest the
caps admit. Every signer is a passkey (the longest key the stack's
verifiers take), named by some rule, as many per rule as OZ allows. Every
rule but `admin` and the owner's activity rule carries both policies (the
interpreter and a spending cap). The document is padded to the larger of
8 192 bytes and its own size with a `string-in` argument constraint and
rule names at OZ's 20-byte limit. The sweep ran on a stack built from this
branch with the compiler's caps raised (15 signers, OZ's per-rule maximum;
32 rules; 32 768 bytes), from 2 to 15 signers and 4 to 32 rules, until every
limit passed the budget, then around the frontier with all five flows. The
frontier rows (the worst share over every row of every flow):

| Signers | Rules | Instructions | Memory | Footprint | Written entries | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 | 11 | 52.9% | 50.0% | 55.0% | 52.5% | 34.0% | 71.5% |
| 2 | 12 | 54.0% | 53.6% | 58.0% | 55.5% | 35.0% | **76.7%** |
| 3 | 10 | 52.7% | 47.6% | 55.2% | 52.5% | 34.3% | 70.6% |
| 3 | 11 | 53.9% | 51.3% | 58.2% | 55.5% | 35.4% | **75.9%** |
| **4** | **9** | **53.3%** | **45.0%** | **55.5%** | **52.5%** | **34.4%** | **74.4%** |
| 4 | 10 | 54.8% | 48.7% | 58.5% | 55.5% | 35.7% | **80.3%** |
| 5 | 6 | 51.5% | 35.9% | 49.8% | 46.5% | 31.5% | 67.8% |
| 5 | 7 | 53.1% | 39.3% | 52.8% | 49.5% | 32.9% | **75.3%** |
| 6 | 5 | 50.9% | 35.4% | 50.0% | 46.5% | 30.9% | 70.3% |
| 6 | 6 | 53.2% | 39.5% | 53.0% | 49.5% | 32.4% | **79.2%** |
| 7 | 4 | 49.8% | 33.4% | 50.2% | 46.5% | 30.1% | 69.7% |
| 7 | 5 | 52.4% | 38.3% | 53.2% | 49.5% | 31.7% | **80.1%** |
| 8 | 4 | 50.9% | 35.8% | 53.5% | 49.5% | 30.7% | **78.1%** |

Past the frontier, where every other limit first passes 75% (the first
sweep, without the in-place compromise variant, which binds only events):
footprint at 15 signers and 4 rules; instructions and memory at 8 and 12;
written entries at 2 and 20; write bytes at 12 and 20. Events bind
everywhere on the frontier, which runs from 7 signers and 4 rules to 2
signers and 11 rules.

**The caps are 4 signers, 9 rules, and 8 192 canonical bytes** (events
74.4%, the compromise with every rule edited), the same 75% rule as before
and, as before, the frontier point that keeps the most rules (a scope per
contract) without dropping signers below 4. 5 signers and 6 rules, or 6
and 5, are the alternatives with more signers. When `apply_doc` replaced
every rule, 6 signers and 8 rules were within budget; the replace-every-rule
rows have not changed since, only the in-place edits grew. A diff that
replaces a rule whole whenever that emits fewer events than editing it
would bring the frontier back to about there. Rerun `scripts/cap-sweep.py`
after any such change, after a change to OZ's events, the controller's, or
the policies, and after a network limit change.

At the caps, the worst rows are:

| Row | Instructions | Memory | Footprint | Written | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Enroll `Combined` through `apply_doc` | 185.5M | 12.7 MB | 122 | 49 | 41 696 | 6 808 |
| `begin_lost_key` / `begin_compromise` | 140.9M | 4.6 MB | 23 | 2 | 1 600 | 248 |
| `publish_baseline` | 105.0M | 2.4 MB | 11 | 1 | 7 476 | 0 |
| Thief's `apply_doc` (every key swapped, every rule kept) | 171.8M | 14.0 MB | 76 | 30 | 24 296 | 9 680 |
| Compromise completion, every rule edited (8 revoked) | 212.1M (53.0%) | 16.6 MB (39.5%) | 130 (32.5%) | 59 (29.5%) | 31 516 (23.9%) | 12 184 (74.4%) |
| Compromise completion, every rule replaced (8 revoked) | 209.1M (52.3%) | 18.9 MB (45.0%) | 222 (55.5%) | 105 (52.5%) | 45 452 (34.4%) | 11 416 (69.7%) |
| Lost-key completion (`Combined`, ZK rotation, 4 revoked) | 211.4M | 16.3 MB | 122 | 55 | 30 944 | 11 656 |
| `Protected` reconfiguration, every rule edited | 213.2M (53.3%) | 16.9 MB | 105 | 42 | 28 256 | 10 900 |
| `Protected` reconfiguration, every rule replaced | 208.8M | 18.5 MB (44.2%) | 195 | 86 | 42 144 | 10 136 |

The `worst_case_*` tests in `release_stack.rs` assert these flows stay
within budget at the compiled-in caps, so lowering a limit or growing an
event fails CI's `release-stack-source` job.

The compiler also refuses a rule name longer than OZ's 20-byte context-rule
limit (`MAX_RULE_NAME_BYTES`). Before, such a document compiled and failed
only at install, so a published compromise baseline with one could never be
restored. A rule cannot name more signers than OZ's per-rule 15 because the
document cannot declare more than 4.

Assumption: signer keys are at most a passkey's (81 bytes of key data). A
custom verifier with keys up to the 256 bytes the IR admits would grow every
signer's registration event and needs its own measurement.
