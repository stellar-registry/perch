# EXPERIMENT: modest document-cap increase, measured on #107 (do not merge)

> **DO NOT MERGE. EXPERIMENTAL LAB BRANCH.** This branch raises the doc
> compiler's caps far past anything safe (15 signers, 40 rules, 32 KiB) so a
> sweep can measure past the real caps, and it carries lab-only test flows and
> build-time what-if switches. It exists to make the s5 research reproducible.
> No PR is open for it and none should be.

Base: #107's head `f4fac2a9927d5c96c8aa169de8614e81104053ed`
(https://github.com/stellar-registry/perch/pull/107, stacked on
https://github.com/stellar-registry/perch/pull/106 and
https://github.com/stellar-registry/perch/pull/103). The companion branch
`experiment/modest-caps-lab-103` runs the same hostile thief flows on #103's
head at its own caps.

## What changed against `f4fac2a`

| Commit | Change |
| --- | --- |
| `f04c751` | `perch-doc-compiler`: `MAX_DOC_SIGNERS` 6 to 15, `MAX_DOC_RULES` 13 to 40, `MAX_DOC_CANONICAL_BYTES` 8 192 to 32 768. The caps gate documents, not costs, so this only lets the sweep build larger documents. |
| `a333980` | `release_stack.rs`: `PERCH_FLOWS` filter for `cap_sweep`; `PERCH_KEYS` breakdown of the keys a completion changes; flow 5 (reparam thief). `rules.rs`: the `PERCH_LAB_INPLACE` build-time switch (W2). |
| `d758f03` | `release_stack.rs`: flows 6 (reprogram thief) and 7 (recap thief). |
| `afa75d4` | Local `[patch]` of `stellar-accounts` to a copy of the OZ fork for W1 (reverted in the next commit; see below). |
| last commit | Reverts `afa75d4`'s `Cargo.toml`/`Cargo.lock` so a clean clone builds; ships W1 as `lab/oz-w1.patch` + `lab/w1-cargo.patch` + `lab/setup-w1.sh`; formats the test; adds `lab/` (scripts, raw results, stack metadata) and this file. |

## Toolchain and pins

| Item | Version |
| --- | --- |
| rustc | 1.97.1 (8bab26f4f 2026-07-14), target `wasm32v1-none` |
| stellar CLI | 27.0.0 (5a7c5fe76530bf4248477ac812fc757146b98cc4); stacks built with `--builder contract` (`stellar contract build`) |
| soroban-sdk / soroban-env-host | 27.0.6 / 27.0.1 (from `Cargo.lock`) |
| stellar-accounts | theahaco/stellar-contracts-OZ rev `33726766a1fd5e7e3d2977d79f64ee29e1ea3ca9` (https://github.com/theahaco/stellar-contracts-OZ/pull/5 head, on PR #4) |
| ZK toolchain | nargo 1.0.0-beta.9, bb 0.87.0, installed and sha-checked by `scripts/zk-toolchain.sh` |
| Stateless registry | `CDOTZIJUS2CZ62GCVQAI2VMZQC7QZJQ35REFAKJLVTZOJXCJ3VMYEJX2` (`deployments/testnet.json`) |
| Limits | protocol 29 per-transaction limits, hard-coded in `release_stack.rs` (400M instructions, 41 943 040 B memory, 400 footprint entries, 200 written entries, 132 096 write bytes, 16 384 event bytes); budget 75% of each |
| Machine | Apple M5 Max, macOS (Darwin 25.5.0) |

Each measured stack's artifacts and hashes are in `lab/stacks/*.build.json`.
The W1 stack was built from `d758f03` with the W1 `[patch]` applied
(`"dirty": true`).

## Build and run from a clean clone

```sh
git clone https://github.com/stellar-registry/perch && cd perch
git checkout experiment/modest-caps-lab
REG="$(jq -r .registry.id deployments/testnet.json)"

# The stack every normal flow ran on.
scripts/build-stack.sh --builder contract --registry "$REG" --out target/lab-stack

# W2 what-if: every editable rule is edited in place (the pairing design's worst case).
PERCH_LAB_INPLACE=1 scripts/build-stack.sh --builder contract --registry "$REG" --out target/lab-stack-inplace

# W1 what-if: OZ's per-call canonical-duplicate verifier round trip compiled out.
lab/setup-w1.sh                      # clones the OZ fork at 3372676 into target/oz-lab/oz, patches it and Cargo.toml
OZ_LAB_SKIP_CANON=1 scripts/build-stack.sh --builder contract --registry "$REG" --out target/lab-stack-w1
git checkout Cargo.toml Cargo.lock   # undo the [patch] before running tests

# Sweeps. lab/run.sh <log-name> <shapes> [flows]; STACK picks the stack.
lab/run.sh both "6,5,0,0,6,8192;6,8,0,0,6,8192;6,11,0,0,6,8192;6,12,0,0,6,8192;6,14,0,0,6,8192;6,16,0,0,6,8192"
STACK=target/lab-stack-inplace lab/run.sh w2-inplace "6,11,0,0,6,8192;6,12,0,0,6,8192" 0,1,3,5
STACK=target/lab-stack-w1      lab/run.sh w1 "6,11,0,0,6,8192;6,12,0,0,6,8192"

# Tables: worst share per shape over every log in a group.
python3 lab/merge.py "capped=lab/results/both.log,lab/results/w3.log"
```

`lab/run.sh` is the same as:

```sh
eval "$(scripts/zk-toolchain.sh)"
PERCH_KEYS=1 PERCH_FLOWS=0,1,2,3,4,5,6,7 PERCH_STACK_DIR=target/lab-stack \
  PERCH_CAP_SWEEP="6,12,0,0,6,8192" \
  cargo test -q -p perch-integration-tests --test release_stack cap_sweep -- --ignored --nocapture --test-threads 1
```

The exact shape lists and flow sets of every committed log are in
`lab/results/INDEX.md`. Rerunning writes to `lab/results/<log-name>.log`, so
use a new name to keep the committed results.

### Variables

| Variable | When | Meaning |
| --- | --- | --- |
| `PERCH_CAP_SWEEP` | test run | `signers,capped,interp,plain,fan,bytes;...`. **Always pass `bytes` (8192)**: on this branch the default is the raised 32 KiB cap. |
| `PERCH_FLOWS` | test run | comma-separated `WORST_FLOWS` indices (below); unset runs all 8 |
| `PERCH_KEYS` | test run | print a `{"keys_of":"completion",...}` line: contract-data keys each completion changed, by contract and key type |
| `PERCH_STACK_DIR` | test run | the built stack to load |
| `PERCH_LAB_INPLACE` | stack build | compiled into `rules.rs`: `Mode::Cheapest` edits every editable rule in place (W2) |
| `OZ_LAB_SKIP_CANON` | stack build, after `lab/setup-w1.sh` | compiled into the OZ copy: `validate_no_canonical_duplicates` returns early (W1) |

## Workloads

A shape `S,c,i,p,f,b` is one document with `S` declared signers and
`2 + c + i + p` rules, padded to exactly `b` canonical bytes. Every signer is a
passkey (`SoftPasskey`, verified by the WebAuthn verifier), ids `owner`,
`s01`, `s02`, .... The rules, in order:

| Rule | Count | Document JSON (scope is `{"type":"contract","address":<target contract>}` unless stated) | Compiled policies |
| --- | --- | --- | --- |
| `admin` | 1 | `{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}` | none |
| `target` | 1 | `principals {"type":"threshold","m":1,"signers":[f signers]}`, `"functions":["protected"]`, `"args":[{"index":0,"pred":{"type":"is-self"}}]` | interpreter |
| capped `rNN` | c | the `target` body plus `"cap":{"limit":"10","period-ledgers":1000}` | interpreter + spending limit |
| interpreter `rNN` | i | the `target` body | interpreter |
| signer-only `rNN` | p | `"principals":{"type":"all","signers":["owner"]}` | none |

Rule `k` (0 is `target`) names `f` signers starting at `k*f` mod `S`, so every
signer is some rule's. Padding: the first rule after `target` gets a second
argument constraint `{"index":1,"pred":{"type":"string-in","values":["v0000",...]}}`
with as many strings as fit, then rule names grow with `x` up to OZ's 20-byte
limit. Recovery is `Protected` (`Loss` in flow 0), mode `Combined` (ZK + two
guardians), with a baseline for the compromise flows.

### Flows (`WORST_FLOWS` indices)

Each flow runs on a fresh `World` with the network limits disabled, so a row
past the budget still prints. The rows that matter are the completion
`apply_doc` and the reconfiguration `apply_doc`.

| # | Flow | What the thief or owner changes |
| --- | --- | --- |
| 0 | lost-key recovery | `Loss`: begin replacing every signer and the ZK credential; completion revokes every replaced signer. |
| 1 | compromise, kept | A thief holding the owner key under `Protected` swaps every key, keeps every rule name; completion restores the baseline with new keys and revokes both key sets. |
| 2 | compromise, renamed | As 1, but the thief renames every rule (tag `t`), forcing every rule to be replaced. budgets.md's binding row. |
| 3 | reconfiguration, edited | `Protected` reconfiguration with recorded quorum and proof, every key changes, a new ZK enrollment, names kept. |
| 4 | reconfiguration, replaced | As 3, every rule renamed (tag `n`). |
| 5 | compromise, reparam (**new**) | As 1, and the thief changes every program (`"functions":["protectee"]`) and every cap (`"limit":"11"`). |
| 6 | compromise, reprogram (**new**) | As 1, and the thief changes only every program. The cost model edits these rules in place (fewer writes), which costs the most instructions. |
| 7 | compromise, recap (**new**) | As 1, and the thief changes only every cap. |

## Results

Raw logs: `lab/results/*.log`. Index: `lab/results/INDEX.md`. Generated
tables: `lab/results/SUMMARY.md`. Footprint below is the network's count
(read-only + read-write keys); `release_stack.rs` adds `write_entries` to it a
second time (`report()`), which stellar-core does not
(`TransactionFrame.cpp`: `readOnly.size() + readWrite.size()`).

Compromise completion at 6 signers, normal stack:

| Rules | Thief | Instructions | Memory | Footprint | Written |
| --- | --- | ---: | ---: | ---: | ---: |
| 13 | renamed (flow 2) | 254.7M (63.7%) | 27.1 MB (64.6%) | 155 (38.8%) | 141 (70.5%) |
| 13 | reprogram (flow 6) | 287.0M (71.7%) | 20.5 MB (48.9%) | 106 | 91 |
| 14 | renamed | 263.5M (65.9%) | 29.0 MB (69.2%) | 161 (40.2%) | 147 (73.5%) |
| 14 | reprogram | 298.4M (74.6%) | 21.7 MB (51.8%) | 108 | 93 |

Most rules within 75% of every limit, all eight flows: 2x17 (memory), 4x16
(memory), 6x14 (instructions 74.6%), 8x11 and 10x9 (instructions, reprogram),
12x8, 15x5 (written entries). By rule kind at 6 signers: 14 capped (12 + admin
+ target), 17 interpreter-only, about 36 signer-only (the 8 KiB cap binds).
W1 saves about 8 points of memory and 2 of instructions, no capped rules. W2
(forced in place) costs 79.3% instructions at 6x13.

The analysis, option table and recommendation are in the s5 report kept by
firstmate (`data/perch-modest-caps-s5/report.md`).

## Known issues

- The compiler caps are raised, so `worst_case_*` (which size their shape from
  the caps) and any test asserting the shipping caps fail or mean nothing
  here. Use `cap_sweep`.
- A shape whose first rule after `target` is signer-only (`6,0,0,N,6`) never
  finishes: the padding loop grows a `string-in` list that only interpreter
  rules carry. Put one interpreter rule first (`6,0,1,N,6`).
- Logs measured before flows 5 to 7 existed cover only flows 0 to 4; INDEX.md
  lists each log's flow set.
