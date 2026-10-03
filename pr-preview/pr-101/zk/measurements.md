# Measurements and the tree depth

These are workstream 2's measurements for
[`docs/recovery/budgets.md`](../recovery/budgets.md), and the depth decision
its rule produces from them.

Measured 2026-10-03 on an Apple M5 Max (18 cores, 128 GB, macOS 26). The
toolchain was nargo 1.0.0-beta.9, bb 0.87.0, bb.js 0.87.0, noir_js
1.0.0-beta.9, soroban-sdk 27.0.6, rustc 1.97.1, and Node 24.18. The release
circuit's `circuit_id` is
`2af21cd9ff84cc56e42e8086c72b6e7ac14c11e830e1fd35f60b3174b46c94c5` at depth
32 and `53e6e14e98b07f3e9073287b0008762126c1fca0b89a5941d5518bafe4702327` at
depth 24. Reproduce with `just zk-bench`. The on-chain rows come from
`crates/perch-zk-adapter/tests/costs.rs`, native proving from
`perch-zk-fixtures bench`, and WASM proving from
`packages/perch-zk/bench/prove.mjs` (Node) and
`packages/perch-zk/bench/browser` (headless Chromium).

## Network limits

`stellar network settings` on 2026-10-03. Testnet and mainnet both run
protocol 29 and agree on every limit below.

| Limit | Value |
| --- | --- |
| `tx_max_instructions` | 400,000,000 |
| `tx_memory_limit` | 41,943,040 B (40 MiB) |
| `tx_max_size_bytes` | 132,096 B |
| `contract_max_size_bytes` | 131,072 B |
| `tx_max_write_ledger_entries` / `tx_max_write_bytes` | 200 / 132,096 B |
| `max_entry_ttl` | 3,110,400 ledgers (about 180 days) |

## On-chain components (compiled wasm, metered)

Each row is one top-level invocation of the release-built wasm under the
limits above. These are components of the full transactions in
`budgets.md` §2, not those transactions. The controller and account
workstream measures the full transactions, which add the controller's and
the account's own work to these rows.

Fees use the SDK's mainnet fee snapshot. "Resource" is instructions, reads,
writes, and events. "Rent" is the persistent-entry rent for the TTL
extensions the call performs, at the SDK's deliberately high rate of 12,000
stroops per KB. Fees are in stroops (10^7 per XLM).

| Depth 32 | Instructions (% of limit) | Memory | Writes | Write bytes | Resource fee | Rent |
| --- | --- | --- | --- | --- | --- | --- |
| `rcv_insert`, first leaf (opens the tree) | 41,103,756 (10.3%) | 2.1 MB | 5 | 2,068 | 52,478 | 121,525,887 |
| `rcv_insert`, typical (201 leaves present) | 43,474,956 (10.9%) | 3.0 MB | 5 | 2,068 | 54,138 | 31,177,990 |
| `rcv_insert`, last slot (seals the tree) | 43,841,095 (11.0%) | 3.2 MB | 6 | 2,164 | 58,539 | 37,024,974 |
| `rcv_insert`, first leaf after rollover | 44,050,370 (11.0%) | 3.2 MB | 5 | 2,068 | 54,541 | 121,525,887 |
| adapter `verify` (circuit id, projection, pool root check, statement hash, UltraHonk) | 96,940,079 (24.2%) | 5.1 MB | 0 | 0 | 67,859 | 0 |
| adapter `verify_proof` (UltraHonk only) | 91,046,074 (22.8%) | 3.8 MB | 0 | 0 | 63,733 | 0 |
| pool `is_known_root` | 510,121 (0.1%) | 1.2 MB | 0 | 0 | 358 | 0 |

| Depth 24 | Instructions (% of limit) | Memory | Writes | Write bytes | Resource fee | Rent |
| --- | --- | --- | --- | --- | --- | --- |
| `rcv_insert`, first leaf | 32,035,956 (8.0%) | 1.9 MB | 5 | 1,748 | 45,857 | 102,044,409 |
| `rcv_insert`, typical | 34,457,132 (8.6%) | 2.9 MB | 5 | 1,748 | 47,551 | 31,177,990 |
| `rcv_insert`, last slot | 34,847,585 (8.7%) | 3.0 MB | 6 | 1,844 | 51,970 | 37,024,974 |
| adapter `verify` | 94,921,644 (23.7%) | 5.1 MB | 0 | 0 | 66,446 | 0 |
| adapter `verify_proof` | 89,029,403 (22.3%) | 3.7 MB | 0 | 0 | 62,321 | 0 |

- **Verification is about a quarter of a transaction at either depth.** Both
  circuits are 2^13 gates, and the audited verifier's cost depends on circuit
  size and public-input count, not tree depth. Nido's unaudited bb 3 verifier
  measured 179M instructions for `verify_proof` alone.
- **Rent dominates insertion fees.** A typical insertion creates three
  persistent entries (`Root`, `Leaf`, `Enrollment`), about 350 bytes each,
  and keeps them for `max_entry_ttl`. The network's rent rate per KB is not
  fixed. It rises linearly with total Soroban state size, from a floor of
  1,000 stroops (below two thirds of the 3 GB target) to 10,000 at the
  target. A typical insertion therefore pays about 0.26 to 2.6 XLM of rent,
  and opening a tree, with about 1.2 KB of frontier, about 1 to 10 XLM once
  per 2^32 insertions. Of the three entries, `Root` is required by the spec
  (§14.1). `Leaf` (storage-only witnesses) and `Enrollment` (pool-side
  one-per-id) are the additive safeguards described in
  [`README.md`](README.md); each costs about a third of the rent.
- **Rent per year**, per `budgets.md` §4: a `Root`, `Leaf`, or `Enrollment`
  entry (about 350 bytes) costs about 0.18 to 1.8 XLM to keep for a year at
  the rates above. The active tree's frontier (`Tree`, about 1.15 KB at depth
  32) costs about 0.6 to 6 XLM per year, paid incrementally by whoever
  inserts or calls `renew_tree`.
- **Evidence size.** A proof is 14,592 bytes; with the tree id, root, and
  nullifier, `ZkEvidence` is about 14.7 KB against `tx_max_size_bytes` of
  132,096.
- **Contract size.** The release-built wasm is 102,235 B for the adapter
  (which carries the verifier and VK) and 66,971 B for the pool, against
  131,072 B allowed.

## Proving

The witness and statement are those of the `lost_key` fixture. Every action
uses the same circuit, so the cost is the same for every action.

| Native (bb 0.87.0 CLI) | Depth 32 | Depth 24 |
| --- | --- | --- |
| `nargo execute` (witness), median of 7 | 67 ms | 67 ms |
| `bb prove`, median of 7 | 70 ms | 60 ms |
| `bb prove` peak RSS | 50.3 MB | 31.1 MB |

| WASM (bb.js 0.87.0 under Node 24, the browser prover's code path), median of 5 | Depth 32 | Depth 24 |
| --- | --- | --- |
| 1 thread | 664 ms | 515 ms |
| 18 threads | 243 ms | 222 ms |
| process peak RSS, Node and bb.js heap together | 545 MB | (same process) |

| Real browser (headless Chromium 151 via Playwright, cross-origin isolated page, the package's `prove`), median of 5 | Depth 32 | Depth 24 |
| --- | --- | --- |
| 1 thread | 660 ms | 503 ms |
| 18 threads | 227 ms | 197 ms |

The browser rows come from `packages/perch-zk/bench/browser` (`npm run
bench`). They agree with the Node rows: same WASM, same engine. One run
during heavy load on the shared machine (load average 24) measured 3.1 s
single-threaded at depth 32, so measure on an idle machine. Chrome's CPU
throttling is no phone proxy here: it slows the page but not bb.js's
worker, and 4× throttling moved single-threaded proving only from 660 ms to
917 ms.

| What a browser prover downloads | Bytes |
| --- | --- |
| Circuit artifact (`perch_zk_recovery.json`) | 5,933 |
| bb.js with its WASM inlined (`barretenberg.js`) | 3,403,772 |
| noir_js WASM (`acvm_js_bg.wasm`, `noirc_abi_wasm_bg.wasm`) | 4,439,657 |
| CRS slice for a 2^13 circuit (8,193 G1 points plus G2) | 524,480 |
| Total, uncompressed | about 8.4 MB |

On this machine, native proving at this size is dominated by process
start-up, so the depth difference is noise. Single-threaded WASM is the
relevant worst case, because browsers without cross-origin isolation cannot
use threads. There, depth 32 costs about 150 ms more than depth 24.

**Not measured:** the reference devices that `budgets.md` §1 names, a
mid-range phone and a mid-range laptop. Proving there, and the browser's own
memory ceiling, are open rows. Phones typically run WASM several times
slower than a desktop core, which would put depth-32 proving in the low
seconds against the 30-second budget.

## Applying the depth rule

`budgets.md` §5: choose 32 if every §1 and §2 row at D = 32 is within
budget. The table checks every row this workstream can measure against the
proposed budgets. Each §2 budget is 75% of a network limit, applied here to
the component alone.

| Row (`budgets.md`) | Proposed budget | D = 32 | D = 24 |
| --- | --- | --- | --- |
| §1 proof generation, native `bb`, laptop | ≤ 5 s | 0.07 s (desktop) ✓ | 0.06 s ✓ |
| §1 proof generation, bb.js, laptop | ≤ 10 s | 0.66 s (desktop Chromium, 1 thread) ✓ | 0.50 s ✓ |
| §1 proof generation, bb.js, phone | ≤ 30 s, ≤ 1 GiB | not measured | not measured |
| §1 witness generation | ≤ 2 s | 0.07 s (desktop, nargo) ✓ | 0.07 s ✓ |
| §1 client artifacts | ≤ 50 MiB | 8.4 MB ✓ | 8.4 MB ✓ |
| §1 proof size | within the tx-size budget | 14.6 KB of 99 KB ✓ | same ✓ |
| §2 `submit_zk` / `submit_zk_change`, ZK part (adapter `verify`) | ≤ 300M instructions, ≤ 30 MiB | 96.9M, 5.1 MB ✓ | 94.9M, 5.1 MB ✓ |
| §2 enrollment `apply_doc`, pool part (`rcv_insert`, sealing a tree) | ≤ 300M instructions, ≤ 99 KB written | 43.8M, 2.2 KB ✓ | 34.8M, 1.8 KB ✓ |
| §2 every other row | ≤ 75% of each limit | controller workstream | controller workstream |

**Decision: depth 32**, provisional on the rows still open. Every row
measured so far is within budget at depth 32, by a wide margin. The open
rows are the reference devices and the full controller and account
transactions. The ZK components leave the full transactions more than 200M
instructions of headroom under the 300M budget. Depth 24 would save about 9M
instructions per insertion (21%) and about 150 ms of single-threaded
proving, but no budget outcome depends on that saving. It would also cap
each tree at 16.8M leaves instead of 4.3B, making rollover routine rather
than exceptional.

The depth-24 build stays buildable and tested as the documented fallback
(`perch-zk-pool/tree-depth-24`, `perch-zk-adapter/tree-depth-24`,
`circuits/perch_zk_recovery_d24`). Rollover is implemented and tested at
both depths.
