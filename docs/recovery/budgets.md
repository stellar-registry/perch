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
under Results (`perch_doc_compiler::MAX_DOC_SIGNERS` = 6, `MAX_DOC_RULES` =
8, `MAX_DOC_CANONICAL_BYTES` = 8 192).

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
deployed depth-32 release wasm (`deployments/testnet.json`) under enforcing
authorization with real proofs; see
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

**The binding limit: contract events.** OZ emits a full event per rule
added and removed, per signer registered, and per policy installed and
uninstalled, and the controller emits one per revoked credential. The
worst completion is a compromise: a thief holding the owner key swaps every
signer's key under `Protected` (no recovery text changes, so no condition),
and the completion revokes both key sets. At 16 signers and 16 rules it
would emit more than the 16 384-byte limit.

**Method.** `cap_sweep` (in `release_stack.rs`) runs three worst-case flows
over a document shape: `Combined` lost-key recovery under `Loss`
(enrollment, `begin_lost_key`, and a completion replacing every signer
with ZK rotation); `Combined` compromise recovery under `Protected` as
above; and a `Protected` `Combined` reconfiguration with recorded quorum
and proof and a new ZK enrollment. The shape is the costliest the caps
admit. Every signer is a passkey (the longest key the stack's verifiers
take), named by some rule, as many per rule as OZ allows. Every rule but
`admin` and the owner's activity rule carries both policies (the
interpreter and a spending cap). The document is padded to the byte cap
with a `string-in` argument constraint and rule names at OZ's 20-byte
limit. The worst share of any limit, over every row of all three flows:

| Signers | Rules | Instructions | Memory | Footprint | Written entries | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 4 | 8 | 51.5% | 39.3% | 52.5% | 49.5% | 26.6% | 65.5% |
| 4 | 10 | 53.7% | 46.7% | 58.5% | 55.5% | 27.4% | **76.0%** |
| 5 | 9 | 53.7% | 44.1% | 58.8% | 55.5% | 27.3% | 75.0% |
| 6 | 6 | 50.6% | 33.6% | 53.0% | 49.5% | 26.4% | 63.2% |
| **6** | **8** | **53.4%** | **41.3%** | **59.0%** | **55.5%** | **27.1%** | **73.9%** |
| 6 | 9 | 54.8% | 45.4% | 62.0% | 58.5% | 27.5% | **79.3%** |
| 7 | 7 | 52.8% | 38.4% | 59.2% | 55.5% | 27.0% | 72.7% |
| 7 | 8 | 54.4% | 42.5% | 62.2% | 58.5% | 27.4% | **78.2%** |
| 8 | 6 | 51.9% | 35.2% | 59.5% | 55.5% | 26.9% | 71.4% |
| 8 | 8 | 55.5% | 43.8% | 65.5% | 61.5% | 27.7% | **82.4%** |
| 10 | 10 | 62.4% | 56.4% | 78.0% | 73.5% | 29.0% | **102.1%** |
| 12 | 12 | 71.1% | 71.8% | 90.5% | 85.5% | 30.2% | **123.1%** |

Every row's binding limit is the compromise completion's events. The
frontier within budget runs from 8 signers and 6 rules to 5 signers and 9
rules. **The caps are 6 signers, 8 rules, and 8 192 canonical bytes:**
documents grow in rules (a scope per contract) more than in signers, and
the byte cap is already in every measurement. At the caps, the worst rows
are:

| Row | Instructions | Memory | Footprint | Written | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Enroll `Combined` through `apply_doc` | 191.4M | 11.4 MB | 130 | 53 | 31 756 | 7 668 |
| `begin_lost_key` / `begin_compromise` | 149.6M | 5.1 MB | 25 | 2 | 1 888 | 248 |
| `publish_baseline` | 108.3M | 2.2 MB | 11 | 1 | 7 464 | 0 |
| Lost-key completion (`Combined`, ZK rotation, 6 revoked) | 209.4M | 16.2 MB | 224 | 105 | 35 220 | 11 320 |
| Compromise completion (`Combined`, ZK rotation, 12 revoked) | 213.5M (53.4%) | 17.3 MB (41.3%) | 236 (59.0%) | 111 (55.5%) | 35 864 (27.1%) | 12 112 (73.9%) |
| `Protected` reconfiguration (`Combined`, new enrollment) | 210.1M | 16.3 MB | 189 | 82 | 31 748 | 10 300 |

The `worst_case_*` tests in `release_stack.rs` assert these flows stay
within budget at the compiled-in caps, so lowering a limit or growing an
event fails CI's `release-stack-source` job. Rerun `cap_sweep` (it
documents its `PERCH_CAP_SWEEP` shape list) after any change to OZ's
events, the controller's, the policies, or the network's limits.

The compiler also refuses a rule name longer than OZ's 20-byte context-rule
limit (`MAX_RULE_NAME_BYTES`). Before, such a document compiled and failed
only at install, so a published compromise baseline with one could never be
restored. A rule cannot name more signers than OZ's per-rule 15 because the
document cannot declare more than 6.

Assumption: signer keys are at most a passkey's (81 bytes of key data). A
custom verifier with keys up to the 256 bytes the IR admits would grow every
signer's registration event and needs its own measurement.
