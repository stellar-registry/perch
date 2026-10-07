# EXPERIMENT: hostile kept-name thief flows on #103 (do not merge)

> **DO NOT MERGE. EXPERIMENTAL LAB BRANCH.** This branch adds lab-only thief
> flows to `release_stack.rs` to check whether #103's release candidate has
> the instruction worst case found on #107. It exists to make the s5 research
> reproducible. No PR is open for it and none should be.

Base: #103's head `b1f3ec6603daf361b569ad87cc6351357b2921a9`
(https://github.com/stellar-registry/perch/pull/103, the WS4 release branch,
caps 6 signers, 8 rules, 8 192 bytes, OZ's per-item events kept). The
companion branch `experiment/modest-caps-lab` holds the main lab on #107.

## What changed against `b1f3ec6`

| Commit | Change |
| --- | --- |
| `23a7c0d` | `release_stack.rs`: `PERCH_FLOWS` filter for `cap_sweep`, and flows 5 to 7 (the reparam, reprogram and recap thieves), identical to the main lab branch. No contract code changes and the caps are #103's own. |
| last commit | Formats the test; adds `lab/` (run script, tabulators, raw results, stack metadata) and this file. |

## Toolchain and pins

| Item | Version |
| --- | --- |
| rustc | 1.97.1 (8bab26f4f 2026-07-14), target `wasm32v1-none` |
| stellar CLI | 27.0.0 (5a7c5fe76530bf4248477ac812fc757146b98cc4); stack built with `--builder contract` |
| soroban-sdk / soroban-env-host | 27.0.6 / 27.0.1 (from `Cargo.lock`) |
| stellar-accounts | theahaco/stellar-contracts-OZ rev `82002206b1da48167091f33fe2ecfc97ce915857` (`cap-71-delegate-auth`, as #103 pins it) |
| ZK toolchain | nargo 1.0.0-beta.9, bb 0.87.0 via `scripts/zk-toolchain.sh` |
| Stateless registry | `CDOTZIJUS2CZ62GCVQAI2VMZQC7QZJQ35REFAKJLVTZOJXCJ3VMYEJX2` (`deployments/testnet.json`) |
| Limits | protocol 29, hard-coded in `release_stack.rs`; budget 75% of each |
| Machine | Apple M5 Max, macOS (Darwin 25.5.0) |

The measured stack's artifacts and hashes: `lab/stacks/lab-stack-103.build.json`
(built from `23a7c0d`, clean tree).

## Build and run from a clean clone

```sh
git clone https://github.com/stellar-registry/perch && cd perch
git checkout experiment/modest-caps-lab-103
scripts/build-stack.sh --builder contract \
  --registry "$(jq -r .registry.id deployments/testnet.json)" --out target/lab-stack-103

# The committed run: every flow at #103's caps (6 signers, 8 rules, 8 192 bytes).
lab/run.sh pr103 "6,6,0,0,6" 0,1,2,3,4,5,6,7

# The same, without the wrapper:
eval "$(scripts/zk-toolchain.sh)"
PERCH_FLOWS=0,1,2,3,4,5,6,7 PERCH_STACK_DIR=target/lab-stack-103 PERCH_CAP_SWEEP="6,6,0,0,6" \
  cargo test -q -p perch-integration-tests --test release_stack cap_sweep -- --ignored --nocapture --test-threads 1

python3 lab/merge.py "pr103=lab/results/pr103.log"
```

`PERCH_CAP_SWEEP` is `signers,capped,interp,plain,fan[,bytes]` (bytes default
to this build's 8 192 cap). `PERCH_FLOWS` picks `WORST_FLOWS` indices. The
main lab's `PERCH_KEYS`, `PERCH_LAB_INPLACE` and `OZ_LAB_SKIP_CANON` switches
are not on this branch.

## Workloads

The shape `6,6,0,0,6` is #103's worst document at its caps: 6 passkey signers;
8 rules (`admin`, `target`, and 6 rules with both the interpreter and a
spending cap); every rule naming all 6 signers; padded to exactly 8 192
canonical bytes with a `string-in` constraint and 20-byte rule names. The rule
JSON, padding and recovery configuration are the same as on the main lab branch
(see its `EXPERIMENT.md`, "Workloads").

| # | Flow | What the thief or owner changes |
| --- | --- | --- |
| 0 | lost-key recovery | `Loss`: replace every signer and the ZK credential; revoke every replaced signer. |
| 1 | compromise, kept | Thief with the owner key under `Protected` swaps every key, keeps names; completion restores the baseline, revokes both key sets. |
| 2 | compromise, renamed | As 1, every rule renamed. budgets.md's binding row on #103. |
| 3 | reconfiguration, edited | `Protected` reconfiguration, every key changes, new ZK enrollment, names kept. |
| 4 | reconfiguration, replaced | As 3, every rule renamed. |
| 5 | compromise, reparam (**new**) | As 1, plus every program (`"functions":["protectee"]`) and cap (`"limit":"11"`) changed. |
| 6 | compromise, reprogram (**new**) | As 1, plus every program changed. |
| 7 | compromise, recap (**new**) | As 1, plus every cap changed. |

## Results

Raw log: `lab/results/pr103.log`. Tables: `lab/results/SUMMARY.md`.

| Completion | Instructions | Memory | Footprint (RO+RW) | Written | Events |
| --- | ---: | ---: | ---: | ---: | ---: |
| compromise, renamed (flow 2) | 215.8M (53.9%) | 18.3 MB | 125 (31.2%) | 111 (55.5%) | 11 940 B (**72.9%**, binding) |
| compromise, kept (flow 1) | 224.2M (56.1%) | 18.4 MB | 123 | 107 | 11 428 B |
| reparam (flow 5) | 225.1M (56.3%) | 18.4 MB | 123 | 107 | 11 428 B |
| reprogram (flow 6) | 224.6M (56.2%) | 18.4 MB | 123 | 107 | 11 428 B |
| recap (flow 7) | 225.0M (56.2%) | 18.4 MB | 123 | 107 | 11 428 B |

On #103 the reconcile prices contract events first. At 6 signers an in-place
signer swap emits more event bytes than a replacement, so every kept-name
variant replaces its rules and costs the same as the kept-name row. The new
flows find nothing past #103's existing worst case: the renamed thief stays
binding on events at 72.9%. The instruction worst case found on #107 (a
reprogram thief at 71.7% at 6x13) comes from #106/#107's write-priced cost
model and does not occur here.
