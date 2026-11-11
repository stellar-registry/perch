# Recovery resource budgets

The resource budgets every recovery transaction and client proof must meet,
the rule that chooses the membership pool's depth from them
([`spec.md`](spec.md) §14, D15), the results against them, and how the
document caps (spec §7.5) were sized.

Where each number lives:

- **ZK components and client proving** (adapter, pool, proof generation,
  client downloads) and the network limits:
  [`docs/zk/measurements.md`](../zk/measurements.md).
- **Full transactions on testnet**, against the deployed wasm:
  [`docs/deploy/testnet-exercise.md`](../deploy/testnet-exercise.md), from
  the raw record `deployments/testnet-exercise.json`.
- **Full transactions in process** (the release-stack suite), the document
  cap sizing, and signer transitions: this file.

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

| Workload | Reference device | Metric | Proposed budget |
| --- | --- | --- | --- |
| Witness fetch (indexer to path) | — | latency p95 | ≤ 2 s |
| Witness generation | browser, mid-range phone | time p95 | ≤ 2 s |
| Proof generation, bb.js in the browser | mid-range phone (named in results) | time p95 | ≤ 30 s |
| Proof generation, bb.js in the browser | mid-range phone | peak memory | ≤ 1 GiB |
| Proof generation, bb.js in the browser | mid-range laptop | time p95 | ≤ 10 s |
| Proof generation, native `bb` | mid-range laptop | time p95 | ≤ 5 s |
| Artifacts the client downloads (circuit, CRS slice, prover Wasm) | — | bytes | ≤ 50 MiB |
| Proof size | — | bytes | fits the transaction-size budget below |

## 2. Full transactions (on-chain)

Each row is the complete transaction against the release Wasm under
enforcing authorization, with real proofs and no mock verifier. Each
records CPU instructions, memory, footprint entries, written entries, disk
read bytes, write bytes, transaction size, event bytes, resource fee, and
inclusion latency.

| Transaction | Worst case to measure |
| --- | --- |
| Enroll ZK through `apply_doc` (compile, `rcv_sync` wiring checks, `rcv_insert`) | insertion that seals a tree and opens the next |
| `begin_lost_key` (includes `derive_target`) | largest supported document |
| `begin_compromise` (includes `derive_target` over the baseline) | largest supported document |
| `publish_baseline` | largest supported document |
| `submit_guardian` | promoting approval under `Protected` (includes `rcv_gate`) |
| `submit_zk` (adapter, verifier, root check, nullifier) | promoting proof, `Combined` |
| Completion `apply_doc` (recovery rule) | `Combined`, ZK rotation (pool insert), a pre-recovery document and a target both at the document caps with every slot differing (spec §7.5), every removed credential revoked |
| Completion after rule churn | the row above, after many prior ordinary applies of a maximum-size document; must not grow with the number of past applies |
| Cancellation | `Combined` (both factors in the last transaction) |
| `approve_change` | one guardian, `Reconfigure` or `Upgrade` |
| `submit_zk_change` (adapter, verifier, root check) | `Reconfigure` or `Upgrade` |
| `Protected` reconfiguration `apply_doc` | `Combined`: reading the recorded quorum and proof, a new enrollment insert, documents at the caps |
| `Protected` `schedule_upgrade` | `Combined`, reading recorded approvals |
| `execute_upgrade` (includes the `rcv_upgrade` epoch bump) | — |
| Promotion after an attacker opened many collecting attempts | promotion with `invalidate_below` (must not grow with the number of siblings) |
| Ordinary authorization overhead | `__check_auth` reading the freeze mirror and checking reserved names, versus plain `do_check_auth` |

**Budget for every row:** at most 75% of the network's per-transaction
limit for instructions, memory, footprint entries (the transaction's
distinct ledger keys, read-only plus read-write, of 400), written entries
(the read-write keys, of 200), disk read bytes, write bytes, transaction
size, and contract-event bytes. Each is a hard per-transaction limit. The
headroom covers authorization growth (more guardians) and network limit
changes. The document caps (spec §7.5) are set from the frontier where
every completion and reconfiguration row stays within budget
([Document caps](#document-caps)).

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

The budgets above are the proposed values. The rule has been applied with
them; no reviewed confirmation or replacement of them is recorded.

## Results

### Status of every budget row

States: **Measured** (within budget unless stated; the cell says where);
**Required before launch** (unmeasured, and an input to the depth rule);
**Unmeasured** (no result, and not an input to the depth rule).

| Row | State | Result and evidence |
| --- | --- | --- |
| §1 witness fetch, latency p95 | Required before launch | No measurement. |
| §1 witness generation | Measured on a desktop; reference phone required before launch | Within budget at both depths on a desktop (`nargo execute`): [measurements.md, Proving](../zk/measurements.md#proving). |
| §1 bb.js proving, mid-range phone, time and peak memory | Required before launch | No phone measurement. |
| §1 bb.js proving, mid-range laptop | Measured on a desktop; reference laptop required before launch | Within budget at both depths in desktop Chromium and Node, one thread: [measurements.md, Proving](../zk/measurements.md#proving). |
| §1 native `bb` proving, mid-range laptop | Measured on a desktop; reference laptop required before launch | Within budget at both depths on a desktop: [measurements.md, Proving](../zk/measurements.md#proving). |
| §1 client artifacts | Measured | Within budget at both depths: [measurements.md, Proving](../zk/measurements.md#proving). |
| §1 proof size | Measured | Within the transaction-size budget: [measurements.md](../zk/measurements.md#on-chain-components-compiled-wasm-metered), "Evidence size". |
| §2 enrollment through `apply_doc` | Measured: in process (at the caps, and sealing a tree) and on testnet | Within budget. Sealing a tree is in process only: a full tree takes 2^32 insertions. |
| §2 `begin_lost_key`, `begin_compromise`, `publish_baseline` | Measured: in process (at the caps) and on testnet | Within budget. |
| §2 `submit_guardian`, `submit_zk` (promoting) | Measured: in process and on testnet | Within budget. |
| §2 completion `apply_doc` | Measured: in process (at the caps, every worst-case flow) and on testnet | Within budget. Binding row at the caps: [The account's own rule registry](#the-accounts-own-rule-registry). |
| §2 completion after rule churn | Measured without churn; bounded by construction | The reconcile reads only its installed-rule records, never historical rule ids ([implementation.md](implementation.md#delta-apply-spec-75)). `completion_cost_does_not_grow_with_policy_churn` (native contracts, in process) finds the same completion entry count after 1 and after 40 applies of one document near the rule cap; identical re-applies create no new rule ids, so the test does not itself produce churn. |
| §2 cancellation, `approve_change`, `submit_zk_change` | Measured: in process and on testnet | Within budget. |
| §2 `Protected` reconfiguration, `schedule_upgrade` | Measured: in process (reconfiguration at the caps) and on testnet | Within budget. |
| §2 `execute_upgrade` | Measured in process only | Within budget. Not run on testnet: the upgrade delay is 120 960 ledgers. |
| §2 promotion after many collecting attempts | Measured without siblings; bounded by construction | Promotion writes one `invalidate_below` value whatever the number of siblings (spec §6.3 T4); the promoting rows above are within budget. No run with many siblings. |
| §2 ordinary authorization overhead | Measured on testnet (absolute cost) and in process | Direct authorization and `execute` are within budget ([testnet-exercise.md](../deploy/testnet-exercise.md), "Against the budget"). The grant generation gate adds one footprint entry per selected rule ([Grant documents](#grant-documents)). Rule-eval's `check_auth` decides an authorization in 5.6M to 6.3M instructions in process, a capped transfer more with a long spending history, up to 47.40M (11.8%) for the longest one window holds ([Rule-eval in `__check_auth`](#rule-eval-in-__check_auth)). |
| §2 disk read bytes, every row | Required before launch | Neither the release-stack suite nor the testnet exercise reports disk read bytes. |
| §2 transaction size, every row | Measured on testnet | Within budget. The in-process suite does not meter transaction size. |
| §2 memory, every row | Measured in process | Within budget. The RPC does not report memory, so testnet rows have none. |
| §3 every flow | Unmeasured | No end-to-end p95. The testnet exercise reports single-transaction inclusion latency per row. |
| §4 pool frontier, root → tree entry (with the pool's leaf and enrollment entries) | Measured | [measurements.md](../zk/measurements.md#on-chain-components-compiled-wasm-metered): rent per insertion and per year. |
| §4 controller state, revoked set, nullifier records, recorded change approvals, `renew` fees | Unmeasured | The testnet exercise reports the total fees of enrollment and promotion, which are dominated by rent. |

### Depth decision

**D = 32.** Every measured §1 and §2 row is within budget at D = 32. The
decision is provisional on the rows marked required before launch. Depth 24
would save about 9M instructions per insertion (21%), about 2M per
verification, and about 250 ms of single-threaded proving
([measurements.md](../zk/measurements.md)), but no budget outcome depends on
that saving, and it would cap each tree at 16.8M leaves instead of 4.3B,
making rollover routine rather than exceptional. The depth-24 build stays
buildable and tested as the fallback (`perch-zk-pool/tree-depth-24`,
`perch-zk-adapter/tree-depth-24`, `circuits/perch_zk_recovery_d24`).
Rollover is implemented and tested at both depths.

### Testnet

[`docs/deploy/testnet-exercise.md`](../deploy/testnet-exercise.md) holds
the per-row figures ("Against the budget") and every transaction. Source:
the stack deployed from commit `7ae915dc1ac6ae36cacf6db87794b056923d3b1f`
([`deployments/testnet.json` at `bb746f9`](https://github.com/stellar-registry/perch/blob/bb746f9d03c593f0d5a2518c6900e00c938f95ec/deployments/testnet.json):
builder `scaffold`, rustc 1.97.1, stellar
27.0.0, scaffold 0.0.27), protocol-29 limits, enforcing authorization with
real passkeys, G-account guardians, and real proofs over witnesses rebuilt
from the deployed pool. Every row is within budget. The deployed adapter's
`circuit_id()` is
`9e39c41f4f35aad43e64b255dfe3ba13f10e8c9d36d6f56fce23c2d97c0a0b4a`, the
`vk_sha256` of `perch_zk_recovery` in `circuits/manifest.json`. The
release-stack suite passed 18 of 18 (every test but `cap_sweep`) against
the bytes fetched back from that deployment, and CI reruns it on those
bytes whenever the deployment's commit is in the branch's history.

### In-process measurements (release-stack suite)

`crates/integration-tests/tests/release_stack.rs` meters every flow in
process on release wasm, with real proofs from the pinned nargo/bb, real
passkey assertions, and enforcing authorization, and asserts each row
within 75% of every limit it meters (instructions, memory, footprint,
written entries, write bytes, events; not disk read bytes or transaction
size). Footprint is the transaction's distinct ledger keys, read-only plus
read-write, which is what the network limits (400); written entries are the
read-write keys (200).
`the_metered_footprint_is_the_simulated_transactions` checks both counts
against an RPC-style simulation of every binding `apply_doc`.

**Source of the figures below:** 2026-10-07, protocol-29 limits, the stack
`scripts/build-stack.sh --builder contract` built from commit
`8e59862f8fd5c8152faf2c76377262563df9053c` (branch
`fm/perch-epic99-release-p8-archive-17f2c9c`; its contract code is identical
to `704aa23f3cebe1e291f70385b4d55f704a30e994`), with the current reconciler,
the 8 × 11 caps, and the small wasm stacks. That source does not include the
configuration revision (its measured effect is
[below](#configuration-revision)) or the controller's §3.4 check in
`rcv_sync` (a comparison of the old and new ZK factor, not separately
measured). CI's `release-stack-source` job runs the same assertions on
every change to the current source.

"At the caps" rows use the costliest document the caps admit
([Document caps](#document-caps)). Percentages are of the protocol-29
limits ([measurements.md, Network limits](../zk/measurements.md#network-limits)).

| Row | Instructions | Memory | Footprint | Written | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Enroll `Combined` through `apply_doc`, at the caps | 197.2M (49.3%) | 14.6 MB | 91 | 63 | 51 144 | 888 |
| Enrollment that seals a tree (small document) | 58.7M | 4.4 MB | 34 | 18 | 8 016 | 888 |
| `begin_lost_key` / `begin_compromise`, at the caps | 134.8M (33.7%) | 5.4 MB | 25 | 2 | 2 176 | 248 |
| `publish_baseline`, at the caps | 96.1M (24.0%) | 1.8 MB | 10 | 1 | 7 452 | 0 |
| `submit_guardian` (promoting, sets the freeze) | 1.8M | 0.7 MB | 13 | 6 | 1 996 | 368 |
| `submit_zk` (promoting, `Combined`, sets the freeze) | 119.2M (29.8%) | 5.7 MB | 17 | 5 | 2 284 | 368 |
| Thief's `apply_doc`, at the caps (every key swapped, every rule renamed) | 201.7M (50.4%) | 20.1 MB | 124 | 102 | 47 408 | 340 |
| Thief's `apply_doc`, at the caps (names kept, every program changed) | 249.3M (62.3%) | 16.2 MB | 83 | 61 | 44 156 | 340 |
| Compromise completion, at the caps, names kept, every program changed (binding) | 294.5M (73.6%) | 19.8 MB (47.1%) | 116 (29.0%) | 99 (49.5%) | 53 160 (40.2%) | 3 228 (19.7%) |
| Compromise completion, at the caps, names kept, every program and cap changed | 276.2M (69.0%) | 25.4 MB (60.5%) | 155 (38.8%) | 137 (68.5%) | 56 260 | 3 228 |
| Compromise completion, at the caps, names kept, every cap changed | 275.6M (68.9%) | 24.7 MB | 152 | 134 | 55 812 | 3 228 |
| Compromise completion, at the caps, every rule renamed | 251.6M (62.9%) | 24.9 MB (59.3%) | 157 (39.2%) | 141 (70.5%) | 56 532 (42.8%) | 3 228 |
| Compromise completion, at the caps, every rule kept by name | 259.6M (64.9%) | 13.2 MB | 99 | 85 | 44 852 | 3 228 |
| Lost-key completion, at the caps (`Combined`, ZK rotation, every signer revoked) | 257.0M (64.2%) | 12.5 MB | 91 | 77 | 43 752 | 2 172 |
| Cancellation (`Combined`, ZK last) | 118.6M (29.7%) | 5.4 MB | 16 | 5 | 2 132 | 332 |
| `approve_change` | 0.9M | 0.3 MB | 8 | 2 | 392 | 192 |
| `submit_zk_change` | 117.7M (29.4%) | 5.1 MB | 12 | 1 | 240 | 192 |
| `Protected` reconfiguration, at the caps, every rule edited | 257.5M (64.4%) | 12.9 MB | 83 | 60 | 39 960 | 888 |
| `Protected` reconfiguration, at the caps, every rule replaced | 244.3M (61.1%) | 23.1 MB | 141 | 114 | 51 592 | 888 |
| `Protected` `schedule_upgrade` | 6.3M | 1.2 MB | 13 | 2 | 1 116 | 196 |
| `execute_upgrade` | 6.3M | 1.2 MB | 12 | 5 | 1 232 | 696 |

Every row is within 75% of every metered limit.

### Configuration revision

The configuration revision adds one instance field, written by every
`apply_doc` and executed upgrade, and 28 bytes to `DocApplied` (its
`revision` field). The release-stack suite on stacks built from `704aa23`
and from the source with the revision (`build-stack.sh --builder contract`,
real proofs, the same toolchain), all eighteen measured rows:

| Change per row | Instructions | Memory | Footprint | Written entries | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Every `apply_doc` (thieves, completions, enrollment, reconfigurations) | -0.29M to +0.21M | +5 to +8 KB | 0 | 0 | +28 | +28 bytes |
| `begin_*`, `publish_baseline`, factory `create_passkey` | +0.02M to +0.15M | +4 to +89 KB | 0 | 0 | 0 | 0 |

Every apply already writes the instance, so no row gains a footprint or
written entry. Instructions move by at most 0.07% of the limit, in both
directions. The binding rows stay binding: the reprogram thief's completion
at 294.4M (73.6%), and written entries at 141 (70.5%, the renamed thief).

### Document caps

**The caps are 8 declared signers, 10 document rules, 8 192 canonical
bytes, and rule names of at most 20 bytes**
(`perch_doc_compiler::{MAX_DOC_SIGNERS, MAX_DOC_RULES,
MAX_DOC_CANONICAL_BYTES, MAX_RULE_NAME_BYTES}`). The generated recovery rule
is additional to the 10. The rule cap is 10, not 11, because the account
stores the rule-eval rule sets its documents lower to
([Rule-eval rule sets](#rule-eval-rule-sets)). The `worst_case_*` tests in `release_stack.rs` run
all eight worst-case flows at the compiled-in caps and assert each stays
within budget, so lowering a limit or growing a flow's cost fails CI's
`release-stack-source` job. The compromise flows run with a thief's grant
documents installed and budget their completion on a forked host
([Grant documents](#grant-documents)). Rerun `scripts/cap-sweep.py` after a change to
the reconcile, the account's records, the controller's storage, or a
network limit.

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
over signer and rule counts and tabulates the worst share of every limit.
The shape is the costliest the caps admit:

- every signer is a passkey (the longest key the stack's verifiers take),
  named by some rule, as many per rule as the account allows (15);
- every rule but `admin` and the owner's activity rule carries both
  policies (the interpreter and a spending cap);
- the document is padded to the larger of 8 192 bytes and its own size,
  with a `string-in` argument constraint and rule names at the 20-byte
  limit.

`cap-sweep.py --simulate` checks the metered footprint and written entries
against an RPC-style simulation inside a sweep: 63 of 63 `apply_doc` calls
matched at 6 signers and 14 rules, 8 and 11, and 10 and 9.

**Frontier.** Source: 2026-10-07, a stack built from the archive branch's
source with the current reconciler and the compiler's caps raised (15
signers, OZ's per-rule maximum; 32 rules; 32 768 bytes); exact commit not
recorded. For each signer count, the most rules within budget and the first
row past it, as the worst share of each limit over the eight flows (bold:
over 75%, or the caps):

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
- **The footprint is never above 44.0%; events never above 31.0%.**

On that source, at the caps the worst share was instructions at 73.6%, in
the reprogram thief's completion, and written entries at 70.5% (the
renamed thief).
Every shape up to the caps fits the 8 192-byte canonical cap. Other
frontier points are 2 and 17, 4 and 16, 6 and 14, 10 and 9, 12 and 8, and
15 and 5.

The frontier above was measured when OZ's context-rule registry held the
account's rules, so every in-place edit re-read the rule and its signers
through OZ; [The account's own rule registry](#the-accounts-own-rule-registry)
has this source's costs and its sweep.

**Rule names.** The compiler refuses a rule name longer than the account's
20-byte limit (`MAX_RULE_NAME_BYTES`, OZ's), so a document that would fail
at install never compiles; otherwise a published compromise baseline with
such a name could never be restored. A rule cannot name more signers than
the account's per-rule 15 because the document cannot declare more than 8.

**Assumption.** Signer keys are at most a passkey's (81 bytes of key data).
A custom verifier with keys up to the 256 bytes the IR admits would grow
the records, the stored sets and the write bytes, and needs its own
measurement.

### Grant documents

Grant documents (spec §7.6) move app grants out of the account document.
Source: 2026-11-03, protocol-29 limits, the stack `scripts/build-stack.sh
--builder contract` built from the source that adds them, real proofs,
passkeys, and enforcing authorization. The rows come from
`release_stack.rs`'s `docsplit_*` tests and the `worst_case_*` compromise
flows; the commands are at the end of this section.

**Two hosts.** "Fork" rows run the one transaction on a fresh host forked
from the ledger (`Env::from_ledger_snapshot`): its storage holds only what
the transaction touches, as a network transaction's does. The long-lived
test host holds every entry earlier calls wrote, and every later call's
instructions and memory grow with their number; footprint, written entries,
write bytes, and events do not. Earlier in-process rows above were all
measured on the long-lived host, without grant documents.

**Recovery does not depend on grant documents.** The compromise worst cases at the
caps, with the thief also installing grant documents of 8 capped grants
each (its own passkeys), and the owner holding one grant document of its own:

| Completion (8 × 11, 8 KiB) | Thief grant documents | Fork | Long-lived host | Footprint | Written | Write bytes |
| --- | --- | --- | --- | --- | --- | --- |
| Names kept, every program changed (binding) | 0 | 284.71M (71.2%), 13.7 MB | 291.41M (72.9%), 16.2 MB | 117 | 99 | 52 408 |
| Names kept, every program changed | 3 | 284.70M (71.2%), 13.7 MB | 311.52M (77.9%), 21.6 MB | 117 | 99 | 52 408 |
| Names kept, every program changed | 12 | 284.77M (71.2%), 13.7 MB | 365.95M (91.5%), 37.9 MB | 117 | 99 | 52 408 |
| Every rule renamed | 0 | 248.52M (62.1%), 15.8 MB | 257.35M, 19.1 MB | 156 | 137 | 55 508 |
| Every rule renamed | 3 | 248.34M (62.1%), 15.8 MB | 279.19M, 25.6 MB | 156 | 137 | 55 508 |
| Lean account document (8 signers, 3 rules), 8 KiB | 0 / 3 / 12 | 185.15M / 185.15M / 185.11M (46.3%), 7.8 MB | 186.92M / 195.62M / 220.82M | 102 | 85 | 37 676 |
| Lean account document, 4 KiB | 0 / 3 | 112.53M / 112.56M (28.1%), 5.6 MB | 114.44M / 123.18M | 102 | 85 | 25 388 |

The completion advances one counter whatever the number of grant documents, and the
fork rows are the same to within 0.2M with 0, 3, or 12 thief grant documents. The
`worst_case_*` compromise flows therefore install 3 thief grant documents and budget
their completion on the fork; the long-lived host's row is reported,
unbudgeted. A control with no grant documents at all shows the cause: 650 unrelated
entries, written to another contract before the completion and never
touched by it, take the long-lived row from 291.41M to 344.68M (and the
lean one from 186.92M to 211.56M), while the fork rows stay at 284.71M and
185.15M.

Every compromise flow at the caps, with 3 thief grant documents of 8 (fork):

| Thief | Instructions | Memory | Footprint | Written | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Names kept, every program changed (binding) | 284.79M (71.2%) | 13.7 MB | 117 | 99 | 52 408 | 3 364 |
| Names kept, every program and cap changed | 266.77M (66.7%) | 16.2 MB | 156 | 137 (68.5%) | 55 508 | 3 364 |
| Names kept, every cap changed | 266.18M (66.5%) | 15.8 MB | 153 | 134 | 55 060 | 3 364 |
| Every rule kept | 249.52M (62.4%) | 9.6 MB | 100 | 85 | 43 588 | 3 364 |
| Every rule renamed | 248.45M (62.1%) | 15.8 MB | 156 | 137 (68.5%) | 55 508 | 3 364 |

Their long-lived rows are 311.55M (77.9%), 298.10M (74.5%), 296.80M
(74.2%), 271.05M, and 279.27M. The other three worst-case flows install no
grant document and are budgeted on the long-lived host: the lost-key completion
251.90M (63.0%), the `Protected` reconfiguration editing every rule 252.01M
(63.0%), and the one replacing every rule 249.04M (62.3%).

Each thief grant document of 8 capped grants costs 68.9M to 77.1M on the long-lived
host (86 footprint entries, 64 written). After the completion, every
grant document's rules are refused, the owner's included. With 3 thief grant documents,
`gc_grant` of a wiped 8-grant document costs 18.1M to 19.6M (62 footprint
entries, 57 or 58 written), and re-granting one grant over a wiped grant document,
to a fresh session key, 16.8M to 19.2M; both rows are on the long-lived
host.

**Grant operations are flat.** One transaction each, on the fork
(`docsplit_grant_lifecycle_forked`). Each grant is one session passkey on a
rule scoped to a token, allowed `transfer`, with a spending cap. "One
document" applies the whole document with `apply_doc`; "split" keeps the
owner's admin rule in the account document and each grant in its own grant document.

| Operation | One document, 1 grant | 3 grants | 7 grants | Split, 1 to 21 grant documents |
| --- | --- | --- | --- | --- |
| Add a grant | 16.45M, fp 28, w 14, 4 812 B | 27.14M | 49.03M, fp 34, 11 428 B | **13.98M to 14.02M**, fp 30, w 15 to 17, 4 324 to 4 596 B |
| Change a grant's cap | 18.85M | 29.51M | 51.47M, 11 000 B | **16.09M to 16.13M**, fp 26 to 28, w 8 to 13, 3 008 to 3 656 B |
| Revoke a grant | 11.38M | 21.93M | 43.78M, 8 800 B | **7.02M**, fp 24 to 26, w 14 to 16, 448 to 824 B (`remove_grant`) |
| Rotate the owner key | 16.21M | 26.85M | 48.80M, 10 328 B | **11.02M**, fp 17, w 10, 2 320 B |
| Capped transfer through a grant | 6.17M, fp 20 | 6.17M | 6.17M | 6.22M, fp 20 |
| `execute` through the admin rule (long-lived host) | 5.49M, fp 9 | 5.50M | 5.53M | 5.50M to 5.71M, fp 9 |

A whole-document change compiles every rule and rewrites the admin records
and `applied_doc`, about 5.4M per existing grant. A grant document compiles and
rewrites only its own, and writes one credential-index entry per credential
it names for the first time. The generation gate reads one tag per selected
rule, present or absent, so every authorization's footprint, the account
document's included, holds one more entry per selected rule than without
grant documents. A grant rule's present tag costs about 0.05M more than
an admin rule's absent one.

**The credential index** costs one persistent entry per credential a grant document
names (144 bytes, written once with the maximum TTL and never removed) and
one read per declared credential in each `apply_grant`. `apply_doc` reads
it only once a completion has advanced the grant generation, and then for
every declared credential (at most 8), except in a completion.

**At rest** (`docsplit_grant_lifecycle`): the account's own entries plus the
policy state kept for it, after the operations above. Rent at the mainnet
floor (1 000 stroops per KB, denominator 1 215, 6 307 200 ledgers a year),
uncalibrated.

| | Bytes | Rent, XLM a year |
| --- | --- | --- |
| One document, 6 grants | 18 860 | 9.56 |
| Split, 6 grant documents of 1 grant | 24 264 | 12.30 |
| Per grant | one document 2 736; split 3 608 (+872, +32%) | 1.39 against 1.83 |

A grant document's own entries are its record (856 B for one grant, which repeats the
`InstalledRule`), its canonical bytes (652 B), the tag (156 B), its two
index entries (212 B), and one credential-index entry (144 B) per
credential, which stays after the grant document is removed: the split account above
holds 7, for its 6 live grants and the one revoked. The account document's
equivalents are its share of the admin records and `applied_doc`.
[Account storage](#account-storage) measures the layout that stores each
rule once and drops the grant document's canonical copy.

**Many grant documents** (`docsplit_many_grants`, 40 grant documents of 8 grants, 321 rules
installed, fork): a capped transfer through the first or the last grant document
6.21M (20 entries), the owner key's rotation 11.02M, a new one-grant document
14.05M; `execute` through the admin rule 7.75M on the long-lived host, 9
entries. At rest the account then holds 951 840 bytes (483 XLM a year at
the floor, 3.0 KB per grant). The 40th grant document's `apply_grant` on the
long-lived host, which holds every earlier grant document, reads 177.34M and 41.5 MB:
the host's growth, which the fork rows do not show.

**Grant document size.** One `apply_grant` costs about 7M instructions and 7 written
entries per own-key capped grant (`docsplit_grant_size_sweep`, long-lived
host):

| Grants in one `apply_grant` | Add | Replace every rule in one call | `remove_grant` |
| --- | --- | --- | --- |
| 1 | 14.07M, w 17 | 15.69M, w 23 | 7.05M, w 16 |
| 4 | 35.35M, w 38 | 44.28M, w 62 | 11.69M, w 34 |
| 8 | 64.98M, 5.6 MB, w 66 | 88.58M, 9.6 MB, w 114 (57%) | 19.07M, w 58 |

A grant document is bounded by the compiler's caps like any document: 8
own-key grants (8 signers) and 10 rules (11 when these rows were measured). Caps above that need a new
compiler build, and so a new account build, and are not measured here.

**Code.** The account wasm grows from 79 321 to 90 681 bytes (+14.3%) under
`stellar contract build`: code 45 939 to 51 391 bytes, contract spec
(types, entry points, and their documentation) 28 119 to 33 519 bytes. The
code entry is shared by every account on one wasm.

**Commands.**

```sh
scripts/build-stack.sh --builder contract --registry "$(jq -r .registry.id deployments/testnet.json)" --out target/source-stack
eval "$(scripts/zk-toolchain.sh)"
T="cargo test -p perch-integration-tests --test release_stack"
export PERCH_STACK_DIR=target/source-stack
$T worst_case -- --ignored --nocapture --test-threads 1
PERCH_SPLIT_KS=0,2,6,20 $T docsplit_grant_lifecycle_forked -- --ignored --nocapture --test-threads 1
PERCH_SPLIT_KS=0,2,6,20 $T docsplit_grant_lifecycle -- --ignored --nocapture --test-threads 1      # at rest
PERCH_SPLIT_GRANTS=40 $T docsplit_many_grants -- --ignored --nocapture
PERCH_SPLIT_NS=1,4,8 $T docsplit_grant_size_sweep -- --ignored --nocapture
# signers,both,interp,plain,fan,bytes,thief (0 keep, 1 rename, 2 reprogram),docs,grants per document
PERCH_SPLIT_RECOVERY="8,9,0,0,8,8192,2,0,8;8,9,0,0,8,8192,2,3,8;8,9,0,0,8,8192,2,12,8;8,9,0,0,8,8192,1,0,8;8,9,0,0,8,8192,1,3,8;8,0,1,0,8,8192,2,0,8;8,0,1,0,8,8192,2,3,8;8,0,1,0,8,8192,2,12,8;8,0,1,0,8,4096,2,0,8;8,0,1,0,8,4096,2,3,8" \
  $T docsplit_compromise_completion -- --ignored --nocapture --test-threads 1
PERCH_SPLIT_FILLER=650 PERCH_SPLIT_RECOVERY="8,9,0,0,8,8192,2,0,8;8,0,1,0,8,8192,2,0,8" \
  $T docsplit_compromise_completion -- --ignored --nocapture --test-threads 1
```

### Rule-eval rule sets

`apply_doc` lowers the compiled account document's model with rule-core's
`rule_eval::lower`, and `apply_grant` a grant document's with
`rule_eval::lower_scoped`, and each stores the result beside the records it
installs (`implementation.md`, "Delta apply"). Source: 2026-11-04, the stack
`scripts/build-stack.sh --builder contract` built from the source that adds
them on top of grant documents, real proofs, passkeys, enforcing
authorization; compromise completions with 3 thief grant documents of 8, budgeted on
the fork ([Grant documents](#grant-documents)).

At the earlier caps of 8 signers and 11 rules, the completions cost about
24M more instructions:

| Fork completion, 8 × 11, 3 thief grant documents | Without the stored sets | With them |
| --- | --- | --- |
| Names kept, every program changed (binding) | 284.79M (71.2%) | 309.05M (77.3%) |
| Names kept, every program and cap changed | 266.77M (66.7%) | 291.16M (72.8%) |
| Names kept, every cap changed | 266.18M (66.5%) | 290.38M (72.6%) |
| Every rule kept | 249.52M (62.4%) | 273.81M (68.5%) |
| Every rule renamed | 248.45M (62.1%) | 272.48M (68.1%) |

In the binding row, about 15M of the increase is wasm execution in the
account: reading the model, `rule_eval::lower`, and converting the lowered
rules back to host values. The rest is the model in the compiled document
and the stored set's write.

`scripts/cap-sweep.py` over every worst-case flow, 8 KiB documents, the
worst share of each limit:

| Signers | Rules | Instructions | Memory | Footprint | Written entries | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 8 | 11 | **77.3%** | 42.8% | 39.2% | 69.0% | 63.8% | 20.5% |
| **8** | **10** | **74.2%** | **40.5%** | **37.8%** | **66.0%** | **62.2%** | **20.5%** |
| 8 | 9 | 71.3% | 38.4% | 36.2% | 63.0% | 60.7% | 20.5% |
| 8 | 8 | 68.3% | 36.5% | 34.8% | 60.0% | 59.1% | 20.5% |
| 6 | 10 | 68.9% | 39.6% | 34.2% | 60.0% | 60.0% | 17.3% |
| 4 | 10 | 64.2% | 39.0% | 30.8% | 54.0% | 57.9% | 14.1% |
| 2 | 10 | 59.9% | 39.0% | 27.2% | 48.0% | 55.7% | 10.9% |

Instructions bound in every row, in the fork completion whose thief kept
every name and changed every program. Ten rules was the largest rule cap at
8 signers within 75% on that source, which set `MAX_DOC_RULES` to 10; this
source's sweep is in [The account's own rule registry](#the-accounts-own-rule-registry).

### Rule-eval in `__check_auth`

`__check_auth` decides every authorization but a recovery completion with
rule-eval's `check_auth` over the stored rules of the chosen rules, and the
account's `authenticate` checks the signers (`implementation.md`, "Rule-eval in
`__check_auth`"). A document rule carries no policy, so an
authorization calls neither the interpreter nor the spending limit, and an
apply installs and uninstalls neither. Source: 2026-11-04, stacks built with
`scripts/build-stack.sh --builder contract` from this source, from the
source where OZ's `do_check_auth` with the interpreter and the spending
limit ran first and rule-eval's `check_auth` second, and from the source
before rule-eval's check, each through every `release_stack.rs` flow (25
tests, `--skip cap_sweep`), real proofs, passkeys, enforcing authorization.
Instructions, as a share of the 400M limit:

| Flow | OZ and its policies | Both, OZ first | Rule-eval |
| --- | --- | --- | --- |
| Capped transfer through a grant, 1 grant in the account document | 6.10M (1.5%) | 7.07M (1.8%) | 5.59M (1.4%) |
| The same, 7 grants | 6.19M (1.5%) | 7.49M (1.9%) | 5.92M (1.5%) |
| Capped transfer through a grant, 1 grant document | 6.17M (1.5%) | 7.20M (1.8%) | 5.70M (1.4%) |
| Capped transfer through the last of 8 grant documents, 65 rules installed (fork) | 6.25M (1.6%) | 8.00M (2.0%) | 6.33M (1.6%) |
| `execute` through the admin rule, no grant documents | 5.55M (1.4%) | 6.26M (1.6%) | 5.85M (1.5%) |
| `execute` through the admin rule, 65 rules installed | 5.99M (1.5%) | 6.71M (1.7%) | 6.17M (1.5%) |
| Capped transfer after 100 spends in the window (fork) | 6.98M (1.7%) | 12.66M (3.2%) | 10.31M (2.6%) |
| Capped transfer after 400 spends in the window (fork) | 9.31M (2.3%) | 28.73M (7.2%) | 24.05M (6.0%) |
| Capped transfer after 906 spends in the window (fork) | not run | not run | 47.40M (11.8%) |

- **What an authorization reads and writes.** A capped transfer reads 13
  footprint entries and writes 4, 764 bytes after one spend: the stored
  set, the account document's records or the grant document's record and set, and the
  rule's spending record, which it writes. With OZ first it read 23 and
  wrote 5, 1,156 bytes. `execute` through the admin rule reads 9 entries
  (11 with OZ first).
- **Long spending histories.** Rule-eval copies and charges the record's
  whole window in the account's wasm, so a capped transfer's cost grows
  with the spends in its window: about 0.046M instructions and 72 write
  bytes per spend. A record is one ledger entry of 172 bytes plus 72 per
  spend, so the network's 65,536-byte entry limit holds 907 spends in one
  window, below rule-eval's own bound of 1,000: the transfer after 906
  spends writes 65,996 bytes (50.0%) and uses 9.9 MB of memory (23.7%), and
  the next capped transfer through that rule fails until spends leave the
  window. OZ's window entry, 80 bytes per spend, would hold about 815 by the
  same arithmetic (not run).
- **Applies install fewer entries.** Applying or completing a document
  writes no interpreter program, spending-limit window, or policy registry
  entry. The binding fork completion at the caps (the thief kept every name
  and changed every program) went from 297.45M (74.4%) to 263.48M (65.9%),
  its footprint from 116 to 100 entries and its memory from 14.7 MB to 10.3
  MB. The costliest budgeted row became the `Protected` reconfiguration that
  edits every rule, 265.93M (66.5%). Every budgeted completion and
  reconfiguration over 200M fell by 2.5M to 35.4M. On the long-lived host
  the compromise completions at the caps went from 285.37M to 321.61M
  (71.3% to 80.4%) to 256.84M to 278.11M (64.2% to 69.5%), within 75%
  unbudgeted too.
- **Every budgeted row stays within 75%**: `release_stack.rs` passes, 25
  tests. The worst shares of the other limits are memory 37.2%, footprint
  29.2%, written entries 47.0%, write bytes 51.6%, and events 20.5%. The
  document caps were sized when applies installed the policies
  ([Rule-eval rule sets](#rule-eval-rule-sets)); `scripts/cap-sweep.py` has
  not been rerun on this source.

The account's size on this source is in
[The account's own rule registry](#the-accounts-own-rule-registry). Its
contract spec carries the doc comments of its entry points and contract
types, so some of those are plain `//` comments. It reads stored rules and
records from their XDR in one pass and a batch of calls one host value at a
time, rather than through `#[contracttype]` decoding and soroban-facade's
context reading, which would add to its code; reading a compiled model
builds its vectors with plain loops rather than iterator adapters, which
saves another 2 KB. `apply_doc` and `apply_grant` keep `#[contracttype]` conversion: in
the account's wasm, where a call costs 67 fuel and a short copy is a byte
loop, reading the model or writing the set as XDR costs the binding
completion 7M to 9M more instructions than the host's conversion does.

### The account's own rule registry

The account keeps its rule ids, rules and signers in its own records
(`implementation.md`, "Delta apply"). An apply writes no OZ rule, signer,
policy or lookup entry, and asks no verifier to canonicalize a key. Source:
2026-11-08, stacks built with `scripts/build-stack.sh --builder contract`
from the source that made the records the registry, where OZ's registry
still held the recovery rule's two entries for `do_check_auth`, and from
the source before it, where OZ's registry held every rule, through
every `release_stack.rs` flow (26 tests, `--skip cap_sweep`), real proofs,
passkeys, enforcing authorization. Both pass. Each of the 264 metered rows
on both stacks:

| Row (8 signers, 10 rules, 8 per rule) | Instructions | Footprint | Written entries | Memory |
| --- | --- | --- | --- | --- |
| Compromise completion on the long-lived host, the thief kept every name and changed every program and cap (3 thief grant documents of 8) | 251.26M (62.8%) → 165.81M (41.5%) | 108 → 64 | 85 → 41 | 14.7 → 5.9 MB |
| The same on the fork | 236.93M → 165.50M (41.4%) | 108 → 64 | 85 → 41 | 9.9 → 5.3 MB |
| Compromise completion on the long-lived host, the thief renamed every rule | 229.71M → 163.71M (40.9%) | 117 → 64 | 94 → 41 | 15.1 → 6.0 MB |
| Lost-key completion (`Combined`, ZK rotation, every signer revoked) | 235.77M → 162.97M (40.7%) | 92 → 48 | 77 → 33 | 10.3 → 5.1 MB |
| `Protected` reconfiguration, every rule edited | 238.09M → 166.37M (41.6%) | 84 → 40 | 60 → 16 | 10.4 → 5.4 MB |
| `Protected` reconfiguration, every rule replaced | 214.84M → 163.88M (41.0%) | 101 → 48 | 69 → 16 | 10.2 → 5.4 MB |
| Thief's `apply_doc`, names kept, every program and cap changed | 197.02M → 125.68M (31.4%) | 75 → 33 | 48 → 6 | 8.6 → 3.6 MB |
| `gc_grant` of a wiped grant document (8 grants) | 7.79M → 2.57M | 49 → 25 | 40 → 16 | |
| Factory `create_passkey` | 2.28M → 1.96M | 11 → 8 | 6 → 3 | |
| Capped transfer through a grant | 5.58M → 5.54M | 13 → 13 | 4 → 4 | |

- **Every row is within 75%,** and no row rises on any limit but one row's
  instructions: `submit_zk_change` for an upgrade, +0.002M at 29.3%. The
  costliest row became the `Protected` reconfiguration that edits every
  rule, at 41.6% of the instruction limit, where the costliest had been a
  compromise completion at 62.8%. The worst shares of the other limits are
  memory 23.6% and write bytes 50.0% (both the capped transfer after 906
  spends, [Rule-eval in `__check_auth`](#rule-eval-in-__check_auth)),
  footprint 16.0%, written entries 20.5%, and events 20.5%, where they were
  36.1%, 51.6%, 29.2%, 47.0% and 20.5%.
- **Events.** The constructor stopped announcing each signer
  (`signer_registered`, 260 bytes for one passkey); 50 rows emit fewer
  bytes, none more.
- **Authorizations** read no entry of OZ's registry before and after; the
  32 authorization rows fall by 0.02M to 0.20M instructions.

`scripts/cap-sweep.py --bytes 0` over every worst-case flow, on a stack
built from this source with the compiler's caps raised (15 signers, 32
rules, 32 768 bytes) and padded to the larger of 8 192 bytes and the
document's own size, the worst share of each limit:

| Signers | Rules | Canonical bytes | Instructions | Memory | Footprint | Written entries | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **8** | **10** | **8 192** | **41.6%** | **12.9%** | **16.0%** | **20.5%** | **45.9%** | **20.5%** |
| 8 | 11 | 8 192 | 41.5% | 12.5% | 16.2% | 20.5% | 46.9% | 20.5% |
| 8 | 12 | 8 192 | 41.7% | 12.2% | 16.5% | 20.5% | 47.9% | 20.5% |
| 8 | 14 | 8 192 | 42.0% | 11.8% | 17.0% | 20.5% | 49.8% | 20.5% |
| 8 | 16 | 8 192 | 42.5% | 11.6% | 17.5% | 20.5% | 51.8% | 20.5% |
| 8 | 20 | 9 216 | 47.9% | 12.4% | 18.5% | 20.5% | 60.6% | 20.5% |
| 8 | 24 | 11 264 | 58.4% | 14.2% | 19.5% | 20.5% | 74.7% | 20.5% |
| 15 | 10 | 8 192 | 43.6% | 13.2% | 21.2% | 27.5% | 53.9% | 31.8% |
| 15 | 12 | 9 216 | 49.2% | 13.4% | 21.8% | 27.5% | 63.6% | 31.8% |
| 15 | 16 | 10 240 | 56.0% | 14.4% | 22.8% | 27.5% | **77.3%** | 31.8% |

Write bytes bind in every row, in the fork completion whose thief kept
every rule: the records and stored sets it rewrites grow with the rules
and their signers, while instructions barely move up to 16 rules. The caps
are unchanged at 8 signers and 10 rules. At 8 signers, 16 rules fit the
8 192-byte cap with every limit at most 51.8%, and 24 rules stay within
75% (write bytes 74.7%) if the byte cap rises to 11 264, so
`MAX_DOC_RULES` could rise to 16 without another cap changing.

That source's account wasm was 107,603 bytes as `stellar contract build`
builds it (75,274 of code, 25,783 of contract spec, 4,604 of data), 12,231
fewer than the source before it (119,834).

### The recovery completion's own check

A recovery completion is decided by the account's `authorize_completion`,
which calls the controller's `enforce` over the account's record of the
recovery rule, so a completion reads no entry of OZ's registry and the
account writes none (`implementation.md`, "Rule-eval in `__check_auth`").
Source: 2026-11-08, stacks built with `scripts/build-stack.sh --builder
contract` from this source and from the source before it, where OZ's
`do_check_auth` decided a completion over two registry entries the account
kept for the recovery rule, through every `release_stack.rs` flow (26
tests, `--skip cap_sweep`), real proofs, passkeys, enforcing authorization.
Both pass. The completion rows:

| Row | Instructions | Footprint | Written entries | Write bytes |
| --- | --- | --- | --- | --- |
| Compromise completion on the long-lived host (8 signers, 10 rules), the worst of its rows | 165.83M → 165.34M (41.3%) | 64 → 61 | 41 → 38 | 60,688 → 60,172 |
| The same on the fork, the worst of its rows | 165.50M → 165.22M (41.3%) | 64 → 61 | 41 → 38 | 60,688 → 60,172 |
| Lost-key completion (`Combined`, ZK rotation, every signer revoked; 8 signers, 10 rules) | 162.97M → 162.73M (40.7%) | 48 → 45 | 33 → 30 | 60,088 → 59,572 |
| Lost-key completion (`Combined`, ZK rotation) | 59.27M → 58.80M | 34 → 31 | 24 → 21 | 10,396 → 9,880 |
| Lost-key completion (`GuardianOnly`) | 16.19M → 15.98M | 24 → 22 | 14 → 14 | 6,424 → 6,424 |
| Compromise completion (revokes the stolen and added keys) | 17.49M → 17.28M | 25 → 23 | 14 → 14 | 6,592 → 6,592 |

- **Every completion's** footprint holds OZ's rule and policy entries for
  the recovery rule no more, and it costs 0.2M to 0.6M fewer instructions.
  One that installs the recovery rule again under a new id (a ZK rotation)
  also drops the new rule's entry from its footprint and writes three
  entries fewer: the new rule's and the policy's, and the old rule's
  removal.
- **Every row is within 75%.** Of the 264 metered rows, 256 cost fewer
  instructions and 263 less memory. Eight cost more instructions, by
  0.002M to 0.03M: three evidence submissions (`submit_guardian`
  `Combined` not promoting, `submit_zk` promoting `Combined`, and
  `submit_zk_change` `Reconfigure`, which also uses 404 more bytes of
  memory), the `Combined` cancellation, three capped transfers through a
  grant, and the eighth `apply_grant` on the long-lived host; the largest is `submit_zk` at
  29.7%. The cause was not investigated. The worst share of each limit:
  instructions 41.6% → 41.5%, memory 23.6%, write bytes 50.0%, footprint
  16.0% → 15.2%, written entries 20.5% → 19.0%, and events 20.5%.

The account wasm is 99,988 bytes as `stellar contract build` builds it
(68,822 of code, 24,791 of contract spec, 4,453 of data), 7,615 fewer than
the source before it (107,603), and 31,084 under the 131,072-byte limit.
The recovery controller, the doc compiler and every other tier-0 contract
build byte-identical; the factory changes only in the account hash it pins.

### The recovery controller's own hooks

The account calls its recovery controller through Perch's hooks
`rcv_install` and `rcv_complete`, which take the recovery rule as a
`RecoveryRule` (its signer count and scope); the controller has no OZ
`Policy` hooks (`spec.md` §10, T5). Source: 2026-11-07, stacks built with
`scripts/build-stack.sh --builder contract` from this source and from the
source before it, where the account called the controller's OZ `install`
and `enforce`, through every `release_stack.rs` flow (26 tests, `--skip
cap_sweep`), real proofs, passkeys, enforcing authorization. Both pass.
The completion rows:

| Row | Instructions | Memory |
| --- | --- | --- |
| Compromise completion on the long-lived host (8 signers, 10 rules), the worst of its rows | 165.36M → 165.27M (41.3%) | 5,838,538 → 5,826,967 |
| The same on the fork, the worst of its rows | 165.22M → 165.13M (41.3%) | 5,271,945 → 5,260,374 |
| Lost-key completion (`Combined`, ZK rotation, every signer revoked; 8 signers, 10 rules) | 162.73M → 162.64M (40.7%) | 5,073,720 → 5,062,149 |
| Lost-key completion (`Combined`, ZK rotation) | 58.80M → 58.70M | 2,850,548 → 2,838,977 |
| Lost-key completion (`GuardianOnly`) | 15.98M → 15.93M | 1,538,187 → 1,531,127 |
| Compromise completion (revokes the stolen and added keys) | 17.28M → 17.25M | 1,553,682 → 1,546,622 |

- **Footprint, written entries, write bytes and events** are unchanged in
  all 264 metered rows.
- **Every row that calls the controller costs fewer instructions**: each
  completion 0.03M to 0.13M fewer and 7 to 12 KB less memory, each
  enrollment and `Protected` reconfiguration 0.04M to 0.06M fewer.
- **Rows that only authorize cost more instructions**: the 41 rows of
  grants, transfers and signer transitions 7,600 to 10,600 more, and the
  10 calls through `execute` 9,700 to 21,100 more, because `__check_auth`,
  and `execute`, refuse ten reserved names instead of eight. The same
  account built without `rcv_install` and `rcv_complete` in the list costs
  3,000 to 17,300 fewer instructions on those 41 rows and 8,800 to 18,900
  fewer through `execute`. Rows over grant-document sweeps and thief grant documents move by
  up to ±0.06M between any two of the three builds, which differ in the
  account's code and so in where the factory puts each account; the six
  rows that verify a real ZK proof move by up to ±0.05M between two runs
  of one stack.
- **Every row is within 75%.** The worst share of each limit, unchanged:
  instructions 41.5% (the `Protected` reconfiguration that edits every
  rule), memory 23.6%, write bytes 50.0%, footprint 15.2%, written entries
  19.0%, and events 20.5%.

The recovery controller wasm is 67,700 bytes as `stellar contract build`
builds it (32,067 of code, 30,879 of contract spec, 3,374 of data), 2,088
fewer than the source before it (69,788): its spec names no OZ type or
hook. The account wasm is 100,119 bytes (68,901 of code, 24,787 of
contract spec, 4,509 of data), 131 more, for the two reserved names, and
30,953 under the 131,072-byte limit. The doc compiler, the pool, the ZK
adapter and every other tier-0 contract build byte-identical; the factory
changes only in the account hash it pins.

### Account storage

The account stores each rule once and keeps a grant document's signer ids
instead of its text (`implementation.md`, "Delta apply"; `spec.md` §7.6).
Its entries:

- `RuleSet`: the account document's records, one `RuleRecord` per rule (id,
  name, policies, and the stored rule-eval rule, which holds the scope,
  signers and last ledger);
- `Grants(grant)`: a grant document's generation, `doc_hash`, records,
  index position, and signer ids;
- `GrantTags(id)`: a grant rule's grant id; `GrantIndex(n)`, what `grants`
  lists; `GrantCredentials`, `SpendRecords`, the applied account document
  (`AppliedDocBytes`, `AppliedFingerprints`), and the instance.

Source: 2026-11-05, stacks built with `scripts/build-stack.sh --builder
contract` from this source, from the source before it, and at each step
between them.

**The testnet preview account's grant** (`release_stack.rs`'s
`census_of_the_preview_grant`): the factory's `create_passkey`, two
`apply_grant`s in the preview's documents' shape, grant ids and expiries,
then a 1 XLM transfer through the second app's capped rule. The account's
own entries, host nonces aside, as each change lands; rent at the floor
(1 000 stroops per KB, denominator 1 215):

| Layout | Bytes | Entries | Rent, XLM a year | 180-day prepay |
| --- | --- | --- | --- | --- |
| Before: records beside stored sets, grant document text, positions, tags with a generation | 9 536 | 20 | 4.834 | 2.384 |
| One record per rule (no `InstalledRules`, no `ScopeRuleSets`) | 7 704 | 17 | 3.905 | 1.926 |
| A tag holds only its grant id | 7 496 | 17 | 3.800 | 1.874 |
| The index position in the grant record (no `ScopePosition`) | 7 320 | 15 | 3.711 | 1.830 |
| Signer ids for the grant document text (no `ScopeDocs`) | **5 296** | **13** | **2.685** | **1.324** |

The constructor alone writes 752 bytes in 2 entries, where it wrote 1 144
in 3. Each figure equals, to the byte, the size computed beforehand by
re-encoding the testnet preview account's own entries in that layout.

**At rest** (`docsplit_grant_lifecycle`, the account's own entries plus the
policy state kept for it), before and after:

| | Before | After |
| --- | --- | --- |
| One document, 6 grants | 11 032 | 8 840 |
| Split, 6 grant documents of 1 grant | 17 156 | 9 876 |
| Split, 8 grant documents of 8 grants | 120 784 | 66 856 |

**Every `release_stack.rs` flow** (26 tests, `--skip cap_sweep`, real
proofs, passkeys, enforcing authorization) passes on both stacks, the source
before this one running its own copy of the suite. Of the 321 metered rows:

| Row | Instructions | Footprint | Written entries | Write bytes |
| --- | --- | --- | --- | --- |
| Compromise completion on the long-lived host (8 signers, 10 rules, 3 thief grant documents of 8), the worst of its rows | 165.27M → 161.97M (40.5%) | 61 → 60 | 38 → 37 | 60 172 → 47 852 |
| The same on the fork | 165.13M → 161.66M (40.4%) | 61 → 60 | 38 → 37 | 60 172 → 47 852 |
| Lost-key completion (`Combined`, ZK rotation, every signer revoked; 8 signers, 10 rules) | 162.64M → 159.67M (39.9%) | 45 → 44 | 30 → 29 | 59 572 → 47 252 |
| `Protected` reconfiguration, every rule edited (8 signers, 10 rules) | 165.94M → 161.97M (40.5%) | 37 → 36 | 13 → 12 | 55 624 → 43 304 |
| Lost-key completion (`GuardianOnly`) | 15.93M → 15.65M | 22 → 21 | 14 → 13 | 6 424 → 5 576 |
| Add a grant (`apply_grant`, fork) | 11.75M → 11.57M | 18 → 14 | 9 → 6 | 2 808 → 1 660 |
| Capped transfer through a grant (fork) | 5.66M → 5.57M | 14 → 13 | 4 → 4 | 764 → 764 |
| `execute` through the admin rule (fork) | 5.79M → 5.73M | 9 → 8 | 2 → 2 | 200 → 200 |
| `gc_grant` of a wiped grant document (8 grants) | 2.55M → 2.82M | 25 → 22 | 16 → 13 | 960 → 6 940 |
| Factory `create_passkey` | 1.95M → 1.90M | 8 → 7 | 3 → 2 | 1 144 → 752 |

- **Every row is within 75%,** and no row's footprint, written entries or
  events rise. The worst share of each limit: instructions 41.5% → 40.5%,
  memory 23.6%, write bytes 50.0% (both the capped transfer after 906
  spends, unchanged), footprint 15.2% → 15.0%, written entries 19.0% →
  18.5%, events 20.5%.
- **Every authorization reads one entry fewer** (a grant rule's record
  holds its stored rule; an admin rule's position needs no second entry)
  and costs 0.04M to 0.31M fewer instructions.
- **Applies write one record per document** instead of records beside a
  stored set: 231 rows cost fewer instructions, by up to 6.3M.
- **33 rows cost more instructions:** `gc_grant` of a grant document that is not
  last in the index rewrites the grant document moved into its position, whose
  record now holds that position (+0.27M to +0.29M, and about 6 KB more
  written for an 8-grant record), where it rewrote an 8-byte position
  (`remove_grant` does the same); the controller's `begin_lost_key`,
  `begin_compromise` and `publish_baseline` run the compiler's
  normal-form check (+0.03M to +0.24M); the grant-document size sweep's 8-grant
  `apply_grant` costs +0.16M; and three evidence rows move by at most
  0.04M.

`scripts/cap-sweep.py --bytes 0` over every worst-case flow, on stacks of
this source and the one before it built with the compiler's caps raised
(15 signers, 32 rules, 32 768 bytes), padded to the larger of 8 192 bytes
and the document's own size, the worst share of each limit (before →
after):

| Signers | Rules | Instructions | Memory | Footprint | Written entries | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **8** | **10** | **41.5% → 40.5%** | 12.7% → 12.2% | 15.2% → 15.0% | 19.0% → 18.5% | **45.6% → 36.2%** | 20.5% |
| 8 | 12 | 41.6% → 40.2% | 12.0% → 11.4% | 15.8% → 15.5% | 19.0% → 18.5% | 47.5% → 36.2% | 20.5% |
| 8 | 16 | 42.4% → 40.1% | 11.5% → 10.6% | 16.8% → 16.5% | 19.0% → 18.5% | 51.4% → 36.1% | 20.5% |
| 8 | 20 | 47.8% → 44.4% | 12.4% → 11.2% | 17.8% → 17.5% | 19.0% → 18.5% | 60.2% → 40.9% | 20.5% |
| 8 | 24 | 58.2% → 52.9% | 14.1% → 12.8% | 18.8% → 18.5% | 19.0% → 18.5% | 74.3% → 51.1% | 20.5% |
| 15 | 10 | 43.5% → 42.4% | 13.0% → 12.9% | 20.5% → 20.2% | 26.0% → 25.5% | 53.5% → 37.3% | 31.8% |
| 15 | 12 | 49.1% → 47.7% | 13.2% → 13.1% | 21.0% → 20.8% | 26.0% → 25.5% | 63.2% → 43.5% | 31.8% |
| 15 | 16 | 56.0% → 53.6% | 14.4% → 13.2% | 22.0% → 21.8% | 26.0% → 25.5% | **77.0% → 50.2%** | 31.8% |

Write bytes bound every shape before, in the fork completion whose thief
kept every rule, since its records and stored sets were rewritten side by
side. After it no shape is past 75% on any limit, and instructions bind. The
caps are unchanged at 8 signers and 10 rules.

The account wasm is 103,294 bytes as `stellar contract build` builds it
(71,866 of code, 24,963 of contract spec, 4,529 of data), 3,175 more than
the source before it (100,119), and 27,778 under the 131,072-byte limit.
The doc compiler is 107,236 bytes (+1,287, the normal-form check and its
flag), and the recovery controller 67,753 (+53: it decodes the compiler's
`CompiledDoc` in `publish_baseline`). The other tier-0 contracts build
byte-identical; the factory changes only in the account hash it pins.

### Wasm stack

Every stack contract links a 64 KiB wasm stack (`build.rs`,
`-zstack-size=65536`; 2 pages), except the ZK adapter, 128 KiB (3 pages),
and the ML-DSA verifier, 256 KiB (its `build.rs` has the measurement). The
host charges every cross-contract call's VM its whole initial linear
memory, and rustc's default 1 MiB stack makes that 17 pages (1 088 KiB) per
VM. A completion makes many cross-contract calls (the compiler, the
controller's hooks, the ZK adapter and pool, and every verifier it
authenticates through). Measured in process on 2026-10-06: with the default stack a
completion at the then-provisional caps of 16 signers and 16 rules took
107 MB against the 41.9 MB limit, and on the same flows the 64 KiB stack
takes about a quarter of the default's memory (the largest row then
measured: 17 MB with the default, 4.5 MB with 64 KiB).

The stack is laid out first, so an overflow wraps below address 0 and
traps instead of corrupting data. The UltraHonk verifier is the deepest
code: the ZK-flavor verifier traps at a 32 KiB stack (the controller then
reports `ZkEvidenceRejected`, failing closed) and passes at 48 KiB, so the
adapter links more than twice that, at one VM per ZK transaction. The
verifier's stack use does not depend on its input, and the compiler's only
input-driven recursion (JSON nesting) refuses cleanly at its depth limit on
the 64 KiB stack.

### Signer transitions

`signer_transitions` (`release_stack.rs`) applies one document change per
row to `pay`, a 1-of-n rule, and to its spending cap in the capped row. In
"full six-key rotation" every declared key changes, the owner's (and so
`admin`'s) too. Each cost is the whole `apply_doc`, compiling the document
included. The test asserts that the rule ends with exactly the target
signers (a joining key acts, a leaving key cannot); it reports the path and
the costs. Source: 2026-11-08, the stacks of
[The account's own rule registry](#the-accounts-own-rule-registry), this
source's figure first and the source before it in parentheses:

| Transition | Instructions | Memory | Footprint | Written entries | Events (bytes) | Path (rule id, spending window) |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| single addition | 18.76M (21.01M) | 1.34 MB | 16 (22) | 6 (9) | 368 | in place, id kept |
| several additions | 20.88M (23.49M) | 1.35 MB | 17 (26) | 6 (13) | 368 | in place, id kept |
| full six-key rotation | 23.39M (30.55M) | 1.36 MB | 18 (44) | 6 (32) | 368 | in place, id kept |
| one swap in a six-key rule | 23.15M (26.65M) | 1.36 MB | 18 (28) | 6 (11) | 368 | in place, id kept |
| five swaps in a six-key rule | 23.27M (28.67M) | 1.36 MB | 18 (40) | 6 (27) | 368 | in place, id kept |
| shared signers | 23.00M (25.84M) | 1.36 MB | 17 (25) | 6 (11) | 368 | in place, id kept |
| full rotation with an active spending cap | 23.81M (31.01M) | 1.36 MB | 18 (44) | 6 (32) | 368 | in place, id kept, window kept |

A transition writes the admin records, the stored rule set and the
instance whatever changes, so its written entries no longer grow with the
signers that join or leave. The 15-signer rows need a stack with the
compiler's caps raised and were not run on this source.
`a_rejected_signer_transition_changes_nothing` passes: a duplicate key (one
passkey under a second credential id), and the budget running out at 25,
50, 75, and 95% of a full rotation, leave every ledger entry unchanged.

### Verifier names

A document that names a verifier (`verifier-name`, `docs/account-interface.md`,
"Verifiers") makes the compiler call `perch/verifiers`' `fetch_hash` once per
distinct name, and `apply_grant` stores each signer's name beside its id. The
release-stack suite names the WebAuthn verifier in every passkey document and
publishes it through the stack's own `perch-constructorless-registry` wasm.
Source: 2026-11-05, `build-stack.sh --builder contract` stacks of the source
before this change and this source, all 160 rows common:

- Every row stays within 75% of every limit. The worst share moves 40.5% to
  40.7% on instructions and 15.0% to 15.8% on footprint; memory 23.6%,
  written entries 18.5%, write bytes 50.0% and events 20.5% are unchanged.
- A document naming one verifier: about +0.6M to +2.8M instructions on an
  `apply_doc` and +5.7M on a thief's 8-grant `apply_grant` (the largest),
  +3 footprint entries (the registry's instance, its code, the name's
  entry), and up to +1.0 MB of memory: the registry wasm links rustc's
  default 1 MiB stack ([Wasm stack](#wasm-stack)), unlike the stack
  contracts, and each call instantiates it.
- `create_passkey` +0.13M instructions: the constructor reads the verifier's
  code hash and derives its content address, with no call.
- Storage: a grant record holds an empty name list when no signer is named
  (+36 bytes); the testnet preview's grant takes 5,368 bytes in 13 entries
  (5,296 before). A name takes about 40 bytes of the 8,192-byte canonical
  cap per signer, so the cap documents hold fewer `string-in` values and
  write up to 2.1 KB less.
