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
| §2 completion `apply_doc` | Measured: in process (at the caps, every worst-case flow) and on testnet | Within budget. Binding row at the caps: [Document caps](#document-caps). |
| §2 completion after rule churn | Measured without churn; bounded by construction | The reconcile reads only its installed-rule records, never historical rule ids ([implementation.md](implementation.md#delta-apply-spec-75)). `completion_cost_does_not_grow_with_policy_churn` (native contracts, in process) finds the same completion entry count after 1 and after 40 applies of one document near the rule cap; identical re-applies create no new rule ids, so the test does not itself produce churn. |
| §2 cancellation, `approve_change`, `submit_zk_change` | Measured: in process and on testnet | Within budget. |
| §2 `Protected` reconfiguration, `schedule_upgrade` | Measured: in process (reconfiguration at the caps) and on testnet | Within budget. |
| §2 `execute_upgrade` | Measured in process only | Within budget. Not run on testnet: the upgrade delay is 120 960 ledgers. |
| §2 promotion after many collecting attempts | Measured without siblings; bounded by construction | Promotion writes one `invalidate_below` value whatever the number of siblings (spec §6.3 T4); the promoting rows above are within budget. No run with many siblings. |
| §2 ordinary authorization overhead | Measured on testnet (absolute cost) | Direct authorization and `execute` are within budget ([testnet-exercise.md](../deploy/testnet-exercise.md), "Against the budget"). The overhead versus plain `do_check_auth` is unmeasured. The scope generation gate adds one footprint entry per selected rule ([Scoped documents](#scoped-documents)). |
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

**The caps are 8 declared signers, 11 installed document rules, 8 192
canonical bytes, and rule names of at most OZ's 20 bytes**
(`perch_doc_compiler::{MAX_DOC_SIGNERS, MAX_DOC_RULES,
MAX_DOC_CANONICAL_BYTES, MAX_RULE_NAME_BYTES}`). The generated recovery rule
is additional to the 11. A cross-token cap
([`../cross-token-caps.md`](../cross-token-caps.md)) installs two rules and
counts two; neither costs more than a capped rule of the measured shape below
(the scope rule carries only the interpreter, the transfer rule a
one-predicate program and the cap), so the frontier bounds those documents too. The `worst_case_*` tests in `release_stack.rs` run
all eight worst-case flows at the compiled-in caps and assert each stays
within budget, so lowering a limit or growing a flow's cost fails CI's
`release-stack-source` job. The compromise flows run with a thief's scoped
documents installed and budget their completion on a forked host
([Scoped documents](#scoped-documents)). Rerun `scripts/cap-sweep.py` after a change to
the reconcile's cost model, OZ's mutations, the controller's or the
policies' storage, or a network limit.

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
  named by some rule, as many per rule as OZ allows;
- every rule but `admin` and the owner's activity rule carries both
  policies (the interpreter and a spending cap);
- the document is padded to the larger of 8 192 bytes and its own size,
  with a `string-in` argument constraint and rule names at OZ's 20-byte
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

At the caps the worst share is instructions at 73.6%, in the reprogram
thief's completion; written entries are at 70.5% (the renamed thief).
Every shape up to the caps fits the 8 192-byte canonical cap. Other
frontier points are 2 and 17, 4 and 16, 6 and 14, 10 and 9, 12 and 8, and
15 and 5.

**Why the reprogram thief binds on instructions.** The reconcile's cost
model prices ledger writes only ([`implementation.md`](implementation.md#delta-apply-spec-75)).
For a rule whose name is kept and whose program changed, the in-place edit
writes fewer entries than a replacement (one `reconcile_signers` and a
reinstall of the interpreter policy, against a removal and an addition), so
the reconcile edits the rule in place. Each of those OZ calls re-reads the
rule and its signers, so the in-place path costs more instructions than the
replacement would.

**Rule names.** The compiler refuses a rule name longer than OZ's 20-byte
context-rule limit (`MAX_RULE_NAME_BYTES`), so a document that would fail
at install never compiles; otherwise a published compromise baseline with
such a name could never be restored. A rule cannot name more signers than
OZ's per-rule 15 because the document cannot declare more than 8.

**Assumption.** Signer keys are at most a passkey's (81 bytes of key data).
A custom verifier with keys up to the 256 bytes the IR admits would grow
every signer's registry entry and the write bytes, and needs its own
measurement.

### Scoped documents

Scoped documents (spec §7.6) move app grants out of the admin document.
Source: 2026-10-28, protocol-29 limits, the stack `scripts/build-stack.sh
--builder contract` built from the branch that adds them (stacked on the
cross-token caps), real proofs, passkeys, and enforcing authorization. The
rows come from `release_stack.rs`'s `docsplit_*` tests and the `worst_case_*`
compromise flows; the commands are at the end of this section.

**Two hosts.** "Fork" rows run the one transaction on a fresh host forked
from the ledger (`Env::from_ledger_snapshot`): its storage holds only what
the transaction touches, as a network transaction's does. The long-lived
test host holds every entry earlier calls wrote, and every later call's
instructions and memory grow with their number; footprint, written entries,
write bytes, and events do not. Earlier in-process rows above were all
measured on the long-lived host, without scoped documents.

**Recovery does not depend on scopes.** The compromise worst cases at the
caps, with the thief also installing scoped documents of 8 capped grants
each (its own passkeys), and the owner holding one scope of its own:

| Completion (8 × 11, 8 KiB) | Thief scopes | Fork | Long-lived host | Footprint | Written | Write bytes |
| --- | --- | --- | --- | --- | --- | --- |
| Names kept, every program changed (binding) | 0 | 283.15M (70.8%), 18.0 MB | 291.19M (72.8%), 20.5 MB | 117 | 99 | 52 396 |
| Names kept, every program changed | 3 | 283.14M (70.8%), 18.0 MB | 307.93M (77.0%), 25.3 MB | 117 | 99 | 52 396 |
| Names kept, every program changed | 12 | 283.27M (70.8%), 18.0 MB | 355.53M (88.9%), 39.7 MB | 117 | 99 | 52 396 |
| Every rule renamed | 0 | 246.36M (61.6%), 22.4 MB | 256.17M, 25.6 MB | 156 | 137 | 55 496 |
| Every rule renamed | 3 | 246.33M (61.6%), 22.4 MB | 275.00M, 31.4 MB (74.8%) | 156 | 137 | 55 496 |
| Lean admin document (8 signers, 3 rules), 8 KiB | 0 / 3 / 12 | 184.29M / 184.32M / 184.25M (46.1%) | 186.79M / 194.26M / 215.88M | 102 | 85 | 37 664 |
| Lean admin document, 4 KiB | 0 / 3 | 111.82M / 111.86M (28.0%), 7.2 MB | 114.32M / 121.80M | 102 | 85 | 25 376 |

The completion advances one counter whatever the number of scopes, and the
fork rows are the same to within 0.13M with 0, 3, or 12 thief scopes. The
`worst_case_*` compromise flows therefore install 3 thief scopes and budget
their completion on the fork; the long-lived host's row is reported,
unbudgeted. A control with no scopes at all shows the cause: 650 unrelated
entries, written to another contract before the completion and never
touched by it, take the long-lived row from 291.19M to 342.95M (and the
lean one from 186.79M to 210.65M), while the fork rows stay at 283.15M and
184.26M.

Every compromise flow at the caps, with 3 thief scopes of 8 (fork):

| Thief | Instructions | Memory | Footprint | Written | Write bytes | Events |
| --- | --- | --- | --- | --- | --- | --- |
| Names kept, every program changed (binding) | 282.81M (70.7%) | 18.0 MB | 117 | 99 | 52 396 | 3 360 |
| Names kept, every program and cap changed | 265.11M (66.3%) | 22.7 MB (54.1%) | 156 | 137 (68.5%) | 55 496 | 3 360 |
| Names kept, every cap changed | 264.50M (66.1%) | 22.1 MB | 153 | 134 | 55 048 | 3 360 |
| Every rule kept | 248.44M (62.1%) | 11.6 MB | 100 | 85 | 43 576 | 3 360 |
| Every rule renamed | 246.33M (61.6%) | 22.4 MB | 156 | 137 (68.5%) | 55 496 | 3 360 |

After the completion, every scope's rules are refused, the owner's included.
`gc_scope` of a wiped 8-grant scope costs 17.5M to 18.7M (62 footprint
entries, 58 written), and re-granting one grant over a wiped scope 13.1M.

**Grant operations are flat.** One transaction each, on the fork
(`docsplit_grant_lifecycle_forked`). Each grant is one session passkey on a
rule scoped to a token, allowed `transfer`, with a spending cap. "One
document" applies the whole document with `apply_doc`; "split" keeps the
owner's admin rule in the admin document and each grant in its own scope.

| Operation | One document, 1 grant | 3 grants | 7 grants | Split, 1 to 21 scopes |
| --- | --- | --- | --- | --- |
| Add a grant | 16.64M, fp 28, w 14, 4 812 B | 27.36M | 49.36M, fp 34, 11 428 B | **14.14M**, fp 29, w 14, 4 172 B |
| Change a grant's cap | 18.86M | 29.60M | 51.68M, 11 000 B | **16.07M**, fp 25, w 8, 3 004 B |
| Revoke a grant | 11.34M | 21.99M | 43.93M, 8 800 B | **6.90M**, fp 24, w 14, 824 B (`remove_scope`) |
| Rotate the owner key | 16.34M | 27.06M | 49.12M, 10 328 B | **11.10M**, fp 17, w 10, 2 320 B |
| Capped transfer through a grant | 6.07M, fp 20 | 6.07M | 6.07M | 6.10M, fp 20 |
| `execute` through the admin rule (long-lived host) | 5.53M, fp 9 | 5.55M | 5.57M | 5.53M to 5.74M, fp 9 |

A whole-document change compiles every rule and rewrites `installed_rules`
and `applied_doc`, about 5.4M per existing grant. A scope compiles and
rewrites only its own. The generation gate reads one tag per selected rule,
present or absent, so every authorization's footprint, the admin
document's included, holds one more entry than without scoped documents. A
scoped rule's present tag costs about 0.03M more than an admin rule's
absent one.

**At rest** (`docsplit_grant_lifecycle`): the account's own entries plus the
policy state kept for it, after the operations above. Rent at the mainnet
floor (1 000 stroops per KB, denominator 1 215, 6 307 200 ledgers a year),
uncalibrated.

| | Bytes | Rent, XLM a year |
| --- | --- | --- |
| One document, 6 grants | 18 860 | 9.56 |
| Split, 6 scopes of 1 grant | 23 208 | 11.77 |
| Per grant | one document 2 736; split 3 456 (+720, +26%) | 1.39 against 1.75 |

A scope's own entries are its record (852 B for one grant, which repeats the
`InstalledRule`), its canonical bytes (652 B), the tag (152 B), and its two
index entries (212 B). The admin document's equivalents are its share of
`installed_rules` and `applied_doc`. Dropping the canonical copy and slimming
the record would make a scoped grant cheaper at rest than one in the admin
document.

**Many scopes** (`docsplit_many_scopes`, 40 scopes of 8 grants, 321 rules
installed, fork): a capped transfer through the first or the last scope
6.10M (20 entries), the owner key's rotation 11.10M, a new one-grant scope
14.12M; `execute` through the admin rule 7.46M on the long-lived host, 9
entries. At rest the account then holds 904 320 bytes (458 XLM a year at
the floor, 2.8 KB per grant).

**Scope size.** One `apply_scope` costs about 8M instructions, 1 MB, and 6
written entries per own-key capped grant (`docsplit_scope_size_sweep`, long-
lived host):

| Grants in one `apply_scope` | Add | Replace every rule in one call | `remove_scope` |
| --- | --- | --- | --- |
| 1 | 14.23M, w 16 | 15.80M, w 22 | 7.05M, w 16 |
| 4 | 35.29M, w 34 | 43.65M, w 58 | 11.60M, w 34 |
| 8 | 64.45M, 8.8 MB, w 58 | 85.86M, 14.3 MB, w 106 (53%) | 18.68M, w 58 |
| 11 (raised caps) | 86.8M, 11.7 MB, w 74 | 119.2M, w 142 (71%) | 24.4M, w 74 |
| 16 (raised caps) | 125.4M, 16.8 MB, w 104 | 182.8M, **w 202** | 35.9M, w 104 |
| 24 (raised caps) | 190.2M, 25.6 MB, **w 152 (76%)** | — | 58.3M, w 152 |

Today a scoped document is bounded by the compiler's caps like any
document: 8 own-key grants (8 signers) and 11 rules. The rows marked
"raised caps" ran on a prototype of this account, with a compiler that
admitted 64 signers, 64 rules, and 64 KiB (exact commit not recorded). Written entries
bind at about 23 grants for an add or a removal, and at about 11 for
replacing every rule in one call; no flow forces that call, since a wallet
can remove and then add, or use a fresh scope id. Scoped caps above 8 × 11
need a new compiler build, and so a new account build.

**Code.** The account wasm grows from 70 536 to 79 712 bytes (+13.0%): code
44 521 to 48 829 bytes, contract spec (types, entry points, and their
documentation) 20 859 to 25 227 bytes. The code entry is shared by every
account on one wasm.

**Commands.**

```sh
scripts/build-stack.sh --builder contract --network-passphrase "$(jq -r .network_passphrase deployments/testnet.json)" --out target/source-stack
eval "$(scripts/zk-toolchain.sh)"
T="cargo test -p perch-integration-tests --test release_stack"
export PERCH_STACK_DIR=target/source-stack
$T worst_case -- --ignored --nocapture
PERCH_SPLIT_KS=0,2,6,20 $T docsplit_grant_lifecycle_forked -- --ignored --nocapture --test-threads 1
PERCH_SPLIT_KS=0,2,6,20 $T docsplit_grant_lifecycle -- --ignored --nocapture --test-threads 1      # at rest
PERCH_SPLIT_SCOPES=40 $T docsplit_many_scopes -- --ignored --nocapture
PERCH_SPLIT_NS=1,4,8 $T docsplit_scope_size_sweep -- --ignored --nocapture
# signers,both,interp,plain,fan,bytes,thief (0 keep, 1 rename, 2 reprogram),scopes,grants per scope
PERCH_SPLIT_RECOVERY="8,9,0,0,8,8192,2,0,8;8,9,0,0,8,8192,2,3,8;8,9,0,0,8,8192,2,12,8;8,9,0,0,8,8192,1,0,8;8,9,0,0,8,8192,1,3,8;8,0,1,0,8,8192,2,0,8;8,0,1,0,8,8192,2,3,8;8,0,1,0,8,8192,2,12,8;8,0,1,0,8,4096,2,0,8;8,0,1,0,8,4096,2,3,8" \
  $T docsplit_compromise_completion -- --ignored --nocapture --test-threads 1
PERCH_SPLIT_FILLER=650 PERCH_SPLIT_RECOVERY="8,9,0,0,8,8192,2,0,8;8,0,1,0,8,8192,2,0,8" \
  $T docsplit_compromise_completion -- --ignored --nocapture --test-threads 1
```

### Wasm stack

Every stack contract links a 64 KiB wasm stack (`build.rs`,
`-zstack-size=65536`; 2 pages), and the ZK adapter 128 KiB (3 pages). The
host charges every cross-contract call's VM its whole initial linear
memory, and rustc's default 1 MiB stack makes that 17 pages (1 088 KiB) per
VM. A completion makes dozens of cross-contract calls (OZ canonicalizes
each rule's signers through their verifier, and installs and uninstalls
each policy). Measured in process on 2026-10-06: with the default stack a
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
row to `pay`, a 1-of-n rule (the interpreter policy), and to the spending
cap in the capped row. In "full six-key rotation" every declared key
changes, the owner's (and so `admin`'s) too. Each cost is the whole
`apply_doc`, compiling the document included. The test asserts that the
rule ends with exactly the target signers (a joining key acts, a leaving
key cannot); it reports the path and the costs. Source: stacks built from
the archive branch's source with the current reconciler and the compiler's
caps raised so the 15-signer rows run (beyond the released 8-signer cap);
exact commit not recorded.

| Transition | Instructions | Memory | Footprint | Written entries | Events (bytes) | Path (rule id, spending window) |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| single addition | 23.08M | 2.41 MB | 27 | 12 | 340 | in place, id kept |
| several additions | 25.75M | 2.48 MB | 31 | 16 | 340 | in place, id kept |
| full six-key rotation | 30.40M | 3.02 MB | 50 | 37 | 340 | replaced, new id |
| one swap in a six-key rule | 28.93M | 2.50 MB | 33 | 14 | 340 | in place, id kept |
| five swaps in a six-key rule | 31.19M | 2.75 MB | 45 | 30 | 340 | in place, id kept |
| shared signers | 28.44M | 2.48 MB | 29 | 12 | 340 | in place, id kept |
| full rotation with an active spending cap | 34.02M | 3.13 MB | 49 | 35 | 340 | in place, id kept, window kept |
| one swap at OZ's 15 | 54.87M | 2.82 MB | 51 | 14 | 340 | in place, id kept |
| seven swaps at OZ's 15 | 58.84M | 3.30 MB | 69 | 38 | 340 | in place, id kept |

Retained signers keep their registry ids. `reconcile_signers` reads the
current signers back from the registry and re-checks duplicates over the
whole set, which is most of an in-place edit's instruction cost.
`a_rejected_signer_transition_changes_nothing` passes: a duplicate key (one
passkey under a second credential id), and the budget running out at 25,
50, 75, and 95% of a full rotation, leave every ledger entry unchanged.
