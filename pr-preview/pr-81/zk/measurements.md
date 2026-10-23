# ZK measurements

Measured costs of the ZK components (the adapter and the membership pool)
and of client proving, with the circuit identities and the network limits
they are measured against. The budgets these numbers are checked against,
the status of every budget row, and the depth decision are in
[`docs/recovery/budgets.md`](../recovery/budgets.md#results), which also
holds the full recovery transactions.

**Provenance.** Measured 2026-10-06 on an Apple M5 Max (18 cores, 128 GB,
macOS 26), a shared machine at a load average of about 3.5. The toolchain
was nargo 1.0.0-beta.9, bb 0.87.0, bb.js 0.87.0, noir_js 1.0.0-beta.9,
soroban-sdk 27.0.6, rustc 1.97.1, and Node 24.18. Proofs are zero-knowledge
(`UltraKeccakZKFlavor`: `bb prove --zk`, bb.js `keccakZK`), and the adapter
verifies them with the vendored verifier's ZK delta
([`README.md`](README.md)). The source is pre-merge commit
`af9b442200ef20dcecace0ba97f211a5497c198b`. The deployed source
(`7ae915dc1ac6ae36cacf6db87794b056923d3b1f`) differs from it in the ZK
crates, the verifier, and the circuits only in comments and contract-spec
doc strings, and in the per-contract wasm stack setting (`build.rs`,
[`budgets.md`](../recovery/budgets.md#wasm-stack)). The measured wasm links
rustc's default 1 MiB stack, so the memory figures below are higher than
the release builds' (64 KiB pool stack, 128 KiB adapter stack).

Reproduce with `just zk-bench`. It builds with the small stacks, so its
memory figures are lower than these. The on-chain rows come from
`crates/perch-zk-adapter/tests/costs.rs`, native proving from
`perch-zk-fixtures bench`, and WASM proving from
`packages/perch-zk/bench/prove.mjs` (Node) and
`packages/perch-zk/bench/browser` (headless Chromium).

## Circuit identities

A ZK factor's configuration names the adapter's `circuit_id`. Copy it from
this table, which `perch-zk-fixtures generate` writes from
`circuits/manifest.json`. `perch-zk-fixtures check` and
`crates/perch-zk-prover/tests/docs.rs` fail if it drifts from the committed
VKs, as does any other 64-hex value in these docs that is not one of them.

<!-- BEGIN GENERATED from circuits/manifest.json by `perch-zk-fixtures generate`; do not edit -->
| Circuit | Depth | `circuit_id` (`sha256` of the VK) | Gates |
| --- | --- | --- | --- |
| `perch_zk_recovery` | 32 | `9e39c41f4f35aad43e64b255dfe3ba13f10e8c9d36d6f56fce23c2d97c0a0b4a` | 5685 |
| `perch_zk_recovery_d24` | 24 | `ecf0731f6e1b009da198278649b1e66926fbcf9bdd3cb04a32903eedf2f8ec66` | 4426 |
<!-- END GENERATED -->

## Network limits

`stellar network settings` on 2026-10-03. Testnet and mainnet both run
protocol 29 and agree on every limit below. Every per-transaction budget in
[`budgets.md`](../recovery/budgets.md) is a fraction of these.

| Limit | Value |
| --- | --- |
| `tx_max_instructions` | 400,000,000 |
| `tx_memory_limit` | 41,943,040 B (40 MiB) |
| `tx_max_size_bytes` | 132,096 B |
| `contract_max_size_bytes` | 131,072 B |
| `tx_max_write_ledger_entries` / `tx_max_write_bytes` | 200 / 132,096 B |
| `tx_max_footprint_entries` (distinct ledger keys, read-only plus read-write) | 400 |
| `tx_max_contract_events_size_bytes` | 16,384 B |
| `max_entry_ttl` | 3,110,400 ledgers (about 180 days) |

## On-chain components (compiled wasm, metered)

Each row is one top-level invocation of the measured wasm under the limits
above. These are components of the full transactions in `budgets.md` §2,
not those transactions: a full transaction adds the controller's and the
account's own work.

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
| adapter `verify` (circuit id, projection, pool root check, statement hash, ZK UltraHonk) | 136,918,968 (34.2%) | 6.7 MB | 0 | 0 | 95,844 | 0 |
| adapter `verify_proof` (ZK UltraHonk only) | 131,024,867 (32.8%) | 5.3 MB | 0 | 0 | 91,718 | 0 |
| pool `is_known_root` | 510,265 (0.1%) | 1.2 MB | 0 | 0 | 358 | 0 |

| Depth 24 | Instructions (% of limit) | Memory | Writes | Write bytes | Resource fee | Rent |
| --- | --- | --- | --- | --- | --- | --- |
| `rcv_insert`, first leaf | 32,035,956 (8.0%) | 1.9 MB | 5 | 1,748 | 45,857 | 102,044,409 |
| `rcv_insert`, typical | 34,457,132 (8.6%) | 2.9 MB | 5 | 1,748 | 47,551 | 31,177,990 |
| `rcv_insert`, last slot | 34,847,585 (8.7%) | 3.0 MB | 6 | 1,844 | 51,970 | 37,024,974 |
| adapter `verify` | 134,695,945 (33.7%) | 6.6 MB | 0 | 0 | 94,288 | 0 |
| adapter `verify_proof` | 128,803,704 (32.2%) | 5.3 MB | 0 | 0 | 90,163 | 0 |

- **Verification is about a third of a transaction at either depth.** The ZK
  verifier's `verify_proof` costs 131M instructions at depth 32. The audited
  non-ZK verifier cost 91M on the same circuit (measured 2026-10-03). The
  44M difference is mostly the small-subgroup IPA consistency check, a
  256-point barycentric evaluation over all 28 rounds' challenges: about
  2,000 field operations, 17M of the 76M host instructions natively. The rest
  is the Libra and masking terms: one more sumcheck evaluation per round, four
  more MSM points, and more transcript hashing. Depth hardly matters. The
  depth-32 circuit is 2^14 and the depth-24 circuit 2^13 (the VKs'
  `log_circuit_size`), but bb 0.87.0 pads every proof to 28 sumcheck rounds.
- **Rent dominates insertion fees.** A typical insertion creates three
  persistent entries (`Root`, `Leaf`, `Enrollment`), about 350 bytes each,
  and keeps them for `max_entry_ttl`. The network's rent rate per KB is not
  fixed. It rises linearly with total Soroban state size, from a floor of
  1,000 stroops (below two thirds of the 3 GB target) to 10,000 at the
  target. A typical insertion therefore pays about 0.26 to 2.6 XLM of rent,
  and opening a tree, with about 1.2 KB of frontier, about 1 to 10 XLM once
  per 2^32 insertions. Of the three entries, `Root` is required by the spec
  (§14.1). `Leaf` (storage-only witnesses) and `Enrollment` (pool-side
  one-per-id) are the additional safeguards described in
  [`README.md`](README.md#interface-notes); each costs about a third of the
  rent.
- **Rent per year** (`budgets.md` §4): a `Root`, `Leaf`, or `Enrollment`
  entry (about 350 bytes) costs about 0.18 to 1.8 XLM to keep for a year at
  the rates above. The active tree's frontier (`Tree`, about 1.15 KB at depth
  32) costs about 0.6 to 6 XLM per year, paid incrementally by whoever
  inserts or calls `renew_tree`.
- **Evidence size.** A ZK proof is 16,224 bytes (a non-ZK proof of the same
  circuit is 14,592). With the tree id, root, and nullifier, `ZkEvidence` is
  about 16.3 KB against `tx_max_size_bytes` of 132,096.
- **Contract size.** The deployed wasm (`stellar scaffold build`, sizes in
  `deployments/testnet.json`) is 68,502 B for the adapter, which carries the
  verifier and VK (52% of the 131,072 B allowed), and 46,179 B for the pool.
  A plain `cargo build --release` of the measured source, which does not
  shake the contract spec, is 116,776 B and 75,264 B; in that build the ZK
  delta accounts for about 14.5 KB of the adapter.

## Proving

The witness and statement are those of the `lost_key` fixture. Every action
uses the same circuit, so the cost is the same for every action.

| Native (bb 0.87.0 CLI) | Depth 32 | Depth 24 |
| --- | --- | --- |
| `nargo execute` (witness), median of 7 | 72 ms | 72 ms |
| `bb prove --zk`, median of 7 | 101 ms | 83 ms |
| `bb prove --zk` peak RSS | 51.9 MB | 32.9 MB |

| WASM (bb.js 0.87.0 under Node 24, the browser prover's code path), median of 5 | Depth 32 | Depth 24 |
| --- | --- | --- |
| 1 thread | 838 ms | 566 ms |
| 18 threads | 278 ms | 235 ms |
| largest process RSS, Node and bb.js heap together | 417 MB | (same process) |

| Real browser (headless Chromium 151 via Playwright, cross-origin isolated page, the package's `prove`), median of 5 | Depth 32 | Depth 24 |
| --- | --- | --- |
| 1 thread | 820 ms | 565 ms |
| 18 threads | 258 ms | 219 ms |

The browser rows come from `packages/perch-zk/bench/browser` (`npm run
bench`). They agree with the Node rows: same WASM, same engine. Zero
knowledge costs about a quarter more single-threaded WASM time at depth 32
than the non-ZK flavor of the same circuit (660 ms in Chromium, measured
2026-10-03). The release-stack suite's own native proofs (15 proofs on an
Apple M-series desktop, 2026-10-07, the same toolchain) took 69 ms median
witness generation, and 97 ms median and 117 ms maximum proof generation.

Proving time depends on machine load, so measure on an idle machine: at a
load average of 24 on the same machine, single-threaded depth-32 proving
measured 3.1 s. Chrome's CPU throttling is no phone proxy: it slows the
page but not bb.js's worker (4× throttling moved single-threaded non-ZK
proving only from 660 ms to 917 ms).

| What a browser prover downloads | Bytes |
| --- | --- |
| Circuit artifact (`perch_zk_recovery.json`) | 5,933 |
| bb.js with its WASM inlined (`barretenberg.js`) | 3,403,772 |
| noir_js WASM (`acvm_js_bg.wasm`, `noirc_abi_wasm_bg.wasm`) | 4,439,657 |
| CRS slice, depth 32: a 2^14 circuit, so 16,385 G1 points plus G2 | 1,048,768 |
| CRS slice, depth 24: a 2^13 circuit, so 8,193 G1 points plus G2 | 524,480 |
| Total, uncompressed | about 8.9 MB at depth 32, 8.4 MB at depth 24 |

bb.js sizes the CRS from `acirGetCircuitSizes`: 9,232 rows padded to 16,384
at depth 32, and 7,973 padded to 8,192 at depth 24. The ZK flavor needs no
larger CRS.

On this machine, native proving at this size is dominated by process
start-up, so the depth difference is noise. Single-threaded WASM is the
relevant worst case, because browsers without cross-origin isolation cannot
use threads. There, depth 32 costs about 250 ms more than depth 24.

**Not measured:** the reference devices that `budgets.md` §1 names, a
mid-range phone and a mid-range laptop, and the browser's own memory
ceiling. These are required before launch
([`budgets.md`](../recovery/budgets.md#results)). As an estimate only:
phones typically run WASM several times slower than a desktop core, which
would put single-threaded depth-32 proving in the low seconds against the
30-second budget.
