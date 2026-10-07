# EXPERIMENT: versioned policy backend spike

> **DO NOT MERGE. Throwaway experiment, not part of any release.**
> This branch is #107's head (`f4fac2a`) plus a prototype and a benchmark. It exists so the measurements can be reproduced and audited.
> No PR will be opened from it. Nothing here was deployed to testnet or mainnet.

Related: https://github.com/stellar-registry/perch/pull/107 (base of this branch, quiet events plus `reconcile_signers`), https://github.com/stellar-registry/perch/pull/106 (quiet events, caps 6 × 13), https://github.com/stellar-registry/perch/pull/103 (caps 6 × 8), and issue https://github.com/stellar-registry/perch/issues/105 (per-rule `doc_hash`).

## The question

Codex proposed replacing the OZ context-rule backend with a versioned one. Rules would reference stable principal ids, a binding table would map principals to credentials, versions would be prepared in batches and activated by a pointer flip, and authorization would load only the selected rules. The claim is that authorize, activate, rotate and restore stop depending on how many rules a document has. This branch measures that claim in release wasm at 8, 13, 32, 128 and 512 rules, and compares it against the OZ backend on #106 and #107.

## Commits

| Commit | Contents |
| --- | --- |
| `f4fac2a9927d5c96c8aa169de8614e81104053ed` | base: #107's head |
| `d904c800018d41196112ba197b0037ef5ca4c655` | `crates/perch-vspike` (the account), `crates/perch-vspike-eval` (stateless evaluator), workspace members, `Cargo.lock` |
| `c12eab8d27e652b6d6c578e391a14dba720b6bc4` | `crates/integration-tests/tests/vspike.rs` (the benchmark), its dev-dependency |
| the commit adding this file | `EXPERIMENT.md`, `results/` |

The results in `results/` were produced from tree `bb484d13f7e63e63e148a265f6a5e402642afe28`, which is the tree of `c12eab8`.

## Build and run from a clean clone

```sh
git clone --branch experiment/versioned-backend-spike https://github.com/stellar-registry/perch.git
cd perch
rustup target add wasm32v1-none

# 1. The release stack, built the way CI's release-stack-source job builds it.
scripts/build-stack.sh --builder contract \
  --registry "$(jq -r .registry.id deployments/testnet.json)" --out target/stack

# 2. The spike's two contracts, in release wasm.
stellar contract build --package perch-vspike-eval --out-dir target/vspike
stellar contract build --package perch-vspike --out-dir target/vspike

# 3. Every versioned and OZ row (16 tests, about 70 s on an M5 Max).
cargo test -p perch-integration-tests --test vspike -- --ignored --nocapture --test-threads 1
```

Each metered transaction prints one `{"case": ...}` JSON line. `--test-threads 1` keeps the output in order. The run is deterministic: every number in `results/pr107-vspike.jsonl` reproduces exactly on the same toolchain.

Optional, the documented #107 worst rows with real proofs (needs the pinned ZK toolchain, which the script downloads into `target/zk-toolchain`):

```sh
eval "$(scripts/zk-toolchain.sh)"
cargo test -p perch-integration-tests --test release_stack -- --ignored --nocapture worst_case_compromise
```

Optional, the OZ rows on #106 instead of #107:

```sh
git fetch origin pull/106/head
git checkout --detach 38cc7177b3eb3e03786db0d7434bcfbcd6186749
git cherry-pick d904c800018d41196112ba197b0037ef5ca4c655 c12eab8d27e652b6d6c578e391a14dba720b6bc4
scripts/build-stack.sh --builder contract \
  --registry "$(jq -r .registry.id deployments/testnet.json)" --out target/stack106
PERCH_STACK_DIR=target/stack106 cargo test -p perch-integration-tests --test vspike -- \
  --ignored --nocapture --test-threads 1 oz
```

## Pins

| Item | Version |
| --- | --- |
| rustc, cargo | 1.97.1 (`8bab26f4f` 2026-07-14), cargo 1.97.1 |
| stellar CLI | 27.0.0 (`5a7c5fe76530bf4248477ac812fc757146b98cc4`), stellar-xdr 27.0.0 |
| soroban-sdk | 27.0.6, from `Cargo.lock` (the workspace asks for 27.0.2) |
| soroban-env-host | 27.0.1 |
| soroban-ledger-snapshot | 27.0.6 |
| OZ fork `stellar-accounts` on this branch | theahaco/stellar-contracts-OZ `33726766a1fd5e7e3d2977d79f64ee29e1ea3ca9` (OZ fork PR #5, reconcile) |
| OZ fork on the #106 runs | `74f9f644589d2edec0881443ede6bea0f63a1cd5` (OZ fork PR #4, quiet events) |
| nargo, bb | 1.0.0-beta.9 and 0.87.0 from `scripts/zk-toolchain.sh`, used only by the real-proof `release_stack` rows |
| jq | 1.8.1 |
| machine | Apple M5 Max, macOS 26.5.2, arm64. In-process metering counts instructions, so the machine does not change the numbers. |
| network limits | the SDK's mainnet defaults, the protocol-29 values in `release_stack.rs`: 400M instructions, 41,943,040 memory bytes, 400 footprint entries, 200 written entries, 132,096 write bytes, 200 disk-read entries, 200,000 disk-read bytes, 16,384 event bytes, 65,536 bytes per contract-data entry |

Wasm: `results/stack-pr107-build.json` and `results/stack-pr106-build.json` record each stack's per-contract sha256 and pins. `results/spike-wasm.sha256` records the spike's two wasm files. I checked the instructions above from a fresh `git clone` of this branch in another directory. It reproduced every stack hash in `stack-pr107-build.json`, both spike hashes, and every row of `results/pr107-vspike.jsonl` exactly.

## Workloads

### The document shape, for both backends

- 6 signers, all WebAuthn passkeys verified by the release `perch-webauthn-verifier`. The ids are `owner`, `s01` to `s05`.
- Rule 0 is `admin`: self-admin scope, owner only, no policy.
- Rule 1 is `multi`: any 1 of the 6 signers may call `Multi.run` with the account as argument 0. It has the interpreter only.
- Rules 2 to n−1 each have a 20-byte name. Any 1 of the 6 signers may call `transfer` on a token stub with the account as argument 0, under the interpreter and a spending cap of limit 1,000,000 over 1,000 ledgers. Every rule names all 6 signers.
- The OZ backend receives the same JSON through `apply_doc`, at n = 8 and n = 13. The compiler caps a document at 13 rules.
- The versioned backend receives it in batches of up to 13 rules, the compiler's cap. Each batch is a document with the same signer table and that batch's rules.

This shape authorizes real transfers. `release_stack.rs`'s `worst_shape` is a cost shape, padded to 8,192 bytes with a recovery member, so the OZ rows here sit below the documented worst rows. Those are quoted separately, re-measured.

### Operations, each one transaction

| Row | What it does |
| --- | --- |
| `begin` | open version v with n rules, 6 principals, and a principal-name hash |
| `prepare raw` | upload one batch of client-compiled rules: storage and commitment only |
| `prepare compiled` | the same batch, also compiled on chain by the release `perch-doc-compiler`. Each stored rule must match its compiled twin in program, provenance, scope, cap and signer count. |
| `activate` | check that the version is complete, its commitment is the approved one and it has an admin rule, then flip `Active` |
| `authorize 1 rule` | `token.transfer(account, sink, 10)` selecting rule 2, signed by the owner. A second row selects the last rule, signed by `s03`. |
| `authorize 4 rules` | `Multi.run` plus 3 transfers in one auth entry: 4 contexts, rules 1 to 4, one `__check_auth` |
| `rotate owner` | rebind principal 0, whom every rule names, to a new passkey |
| `publish_baseline` | record the active version and its credentials as the compromise baseline. This is a stand-in for the controller's `publish_baseline`. |
| `thief set_bindings` | the thief, holding the owner key, rebinds all 6 principals to thief keys |
| `thief prepare`, `thief activate` | the thief prepares and activates a version of n renamed rules |
| `restore baseline` | the completion: reactivate the baseline version under 6 fresh keys, revoking the 6 baseline credentials and the 6 thief credentials |
| OZ `apply_doc`, rotate, thief, restore-shaped | the same transitions as `apply_doc` calls on `perch-account`: install, a one-key change, every key swapped with every rule renamed, and every key and name swapped back |

### The thief construction

The thief holds the owner key, as in `release_stack.rs`'s `worst_compromise` (`crates/integration-tests/tests/release_stack.rs:1822`). The thief swaps every credential, then prepares and activates a version of n renamed rules, the variant that forces OZ to replace every rule. In the versioned backend, renaming changes nothing restore does, because restore reads no rule. What does grow restore is how many credentials the thief binds. `restore_thief_bindings_sweep` therefore binds 6, 15, 30, 45, 60, 75 and 90 thief credentials against a 6-credential baseline and restores each case.

### Measurement method

- Metering is `env.cost_estimate()`, as in `release_stack.rs`. Footprint is reads plus writes, the way the host's limit check counts it.
- **Each transaction runs on a fresh fork.** `fork()` builds an `Env::from_ledger_snapshot` of the state the previous transaction left. The test host keeps every entry a test ever touched in one metered map, so later transactions get dearer as a long test writes more. `control_storage_map_size` shows this: the same authorization costs 4.97M instructions and 0.76 MB normally, but 6.27M and 2.18 MB with 3,000 unrelated entries in the map. On a fork it costs 4.95M again. A fork's map starts empty and holds only what the transaction touches, as on chain. Every row in `results/` uses the fork method.
- **Archived entries.** `fork_archived` gives the chosen persistent entries a short TTL, reads them once while they are live, and moves the ledger past that TTL. The host then auto-restores them in the measured transaction and meters them as disk reads plus writes. The read-while-live step matters, because the host counts an entry as a disk read only if it was in the storage map when the invocation began. `archived_control`, which archives an entry the transaction never touches, shows that this procedure adds 1 written entry and 104 write bytes on its own. Compare archived rows with that control, not with the live row.
- Fees: rows report the resource fee only. The rent the SDK prints is a test-ledger artifact, because every write extends to a 10M-ledger TTL.

## Results, as separate line items

All numbers are from `results/pr107-vspike.jsonl` unless marked. "fp" is footprint entries.

### Preparation, storage and commitment without compilation

| | Instructions | Memory | fp | Written | Write bytes | Events | Resource fee |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| one 13-rule batch | 7.83M | 1.41 MB | 36 | 15 | 9,756 | 204 | 75,759 |
| 512 rules, 40 batches, total | 314.13M | | | 592 | 401,788 | 8,160 | 3,008,420 |

About 4.9M of each batch is the owner's passkey authorization of the call.

### Compilation

| | Instructions | Memory |
| --- | ---: | ---: |
| `compile_doc` alone, 8-rule document | 45.40M | 0.75 MB |
| `compile_doc` alone, 13-rule document | 69.63M | 0.81 MB |
| prepare compiled minus prepare raw, 13-rule batch | 70.8M | |

That is about 4.85M per rule plus about 6.6M fixed. The same compile runs inside every OZ `apply_doc`, over the whole document.

### Preparation with on-chain compilation

| n | Batches | Worst batch | Total instructions | Total write bytes | Total resource fee |
| ---: | ---: | --- | ---: | ---: | ---: |
| 8 | 1 | 52.85M (13.2%), fp 30 | 52.85M | 10,068 | 91,291 |
| 13 | 1 | 78.64M (19.7%), fp 40 | 78.64M | 15,564 | 134,356 |
| 32 | 3 | 83.43M (20.9%), fp 40 | 209.45M | 40,528 | 350,824 |
| 128 | 10 | 83.43M (20.9%), fp 40 | 819.24M | 160,316 | 1,362,393 |
| 512 | 40 | 83.43M (20.9%), fp 40 | 3,291.35M | 643,564 | 5,461,609 |

### Authorization

| | Versioned, identical at n = 8 to 512 | OZ, #107, identical at n = 8 and 13 | OZ, #106, n = 13 |
| --- | --- | --- | --- |
| 1 rule | 4.94M, 0.75 MB, fp 13, 2 written, 0 event bytes | 6.45M, 1.07 MB, fp 23, 2 written, 524 event bytes | 6.45M, fp 23 |
| 4 rules, 4 contexts | 6.79M, 1.47 MB, fp 21 | 12.20M, 2.39 MB, fp 34, 1,572 event bytes | 12.20M, fp 34 |

Breakdown of the versioned 1-rule row: one passkey verify is 3.69M, program evaluation is 0.32M, and the remaining ~0.9M is the reads, the counter write and the digest.

### Archived-entry restore inside a transaction

| Row | Restored entries | Disk-read bytes | Instructions | fp | Written | Write bytes | Resource fee |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| control: versioned authorize, an untouched entry archived | 0 | 0 | 4.96M | 14 | 3 | 372 | 15,980 |
| versioned authorize, the selected rule archived | 1 | 760 | 4.96M | 15 | 4 | 1,132 | 22,585 |
| versioned authorize, every persistent account entry archived | 3: rule, bindings, counter | 2,492 | 5.07M | 16 | 5 | 2,668 | 31,922 |
| versioned authorize, every persistent data entry archived | 3 | 2,492 | 5.02M | 16 | 5 | 2,668 | 31,887 |
| versioned activate, version metadata archived | 1 | 256 | 5.07M | 12 | 4 | 1,012 | 23,067 |
| versioned restore, live reference | 0 | 0 | 3.59M | 42 | 15 | 3,772 | 75,143 |
| versioned restore, every persistent account entry archived | 3: baseline record, version metadata, bindings | 2,236 | 4.05M | 45 | 18 | 4,576 | 94,004 |
| OZ #107 authorize, the selected rule archived | 1 | 396 | 6.48M | 27 | 6 | 1,252 | 34,276 |
| OZ #107 authorize, every persistent data entry archived | 13 | 3,664 | 6.82M | 36 | 15 | 3,920 | 93,551 |

- A restored entry costs one disk-read entry, its size in disk-read bytes, one written entry and its size in write bytes. It adds almost no instructions.
- The versioned rows at n = 512 have the same footprint, restore counts and bytes as at n = 13. Their instructions are inflated, 8.46M for authorize and 19.04M for restore, because the read-while-live step loads all 1,031 archived account entries into the test host's map, which is the artifact described above.
- In the OZ row with only the rule archived, the transaction writes 6 entries against 2 live. The procedure accounts for 1 and the restored rule for 1. I did not attribute the other 2: the host does not expose the footprint.

### Activation, rotation, restore, at every n

| | Instructions | Memory | fp | Written | Write bytes | Events |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| activate | 5.07M | 0.80 MB | 10 | 2 | 652 | 148 |
| rotate the owner, whom every rule names | 5.70M | 1.09 MB | 11 | 3 | 2,188 | 176 |
| restore baseline after the thief's swap and rename, 12 revoked | 3.58M | 0.77 MB | 42 (10.5%) | 15 | 3,772 | 1,732 (10.6%) |

For comparison on #107 at 13 rules, rotating the owner through `apply_doc` costs 135.82M (34.0%), fp 60, 30,108 write bytes. #106 costs 133.34M. The documented binding completion, re-measured in `results/pr107-release-stack-worst-compromise.jsonl`, costs 254.7M, 27.1 MB, fp 296 (74.0%), 141 written, 56,572 write bytes and 2,700 event bytes.

### Restore against the thief's credential count

| Thief credentials | Revoked | Instructions | fp | Written | Events |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 6 | 12 | 3.59M | 42 | 15 | 1,732 |
| 15 | 21 | 4.90M | 60 | 24 | 2,920 |
| 30 | 36 | 7.33M | 90 | 39 | 4,900 |
| 45 | 51 | 10.02M | 120 | 54 | 6,880 |
| 60 | 66 | 12.99M | 150 | 69 | 8,860 |
| 75 | 81 | 16.23M | 180 | 84 | 10,840 |
| 90 | 96 | 19.71M | 210 | 99 | 12,820 (78.2%) |

Events reach the 75% budget at about 92 revocations. A production design must cap principals.

### Entry sizes

| Entry | Key bytes | Value bytes |
| --- | ---: | ---: |
| versioned `Rule(v, id)`, capped transfer rule, 6 principals | 40 | 664 |
| versioned `Bindings`, 6 passkeys | 28 | 1,452 |
| versioned `Version(v)` | 36 | 164 |
| versioned `Doc(v, batch)`, canonical bytes of a 13-rule batch | 40 | 5,712 |
| OZ `installed_rules`, one entry, n = 8 and 13 | | 10,624 and 18,004 |
| OZ `applied_doc`, one entry, n = 8 and 13 | | 4,007 and 5,702 |

### Not measured

- The recovery controller's share of a completion: `rcv_sync`, the recovery-rule check, guardian and ZK evidence, the pool insert. `restore` is authorized by a stand-in custom account.
- Any versioned replacement for the controller's `publish_baseline` or `begin_*`. On #107 these compile or derive over the whole document: 97.4M and 132.9M at 6 × 13.
- Batches larger than 13 rules, which would need a compiler with higher caps.
- Versions that share unchanged rules. In this prototype a one-rule edit re-prepares all n rules.
- Archived contract instances or code. Only persistent data entries were archived.
- Delegated signers. Only passkeys were exercised.
- On-chain transaction size, which `cost_estimate` does not report.
- Rent. The test ledger's TTL settings make it meaningless here.

## Shortcuts in the prototype

1. No recovery controller. `restore` is authorized by a stand-in address, and `publish_baseline` is self-authorized and recorded in the account.
2. No `Protected` freeze gate and no reserved-function guard in `__check_auth`.
3. OZ's `smart_account::authenticate` and verifier contracts do the signature checks. OZ's `do_check_auth` is not used, because it is tied to OZ's context-rule storage. Rule selection and policy enforcement are reimplemented.
4. The principal mapping between a compiled batch and the stored rules is not proven on chain. `prepare` checks program, provenance hash, scope, cap and signer count. It does not check which principal ids the rule names.
5. The commitment is a running hash chain over each rule's `perch_ir::rule_hash`, seeded with the counts and the principal-name hash. It is not a Merkle tree and has no inclusion proofs.
6. Bindings are one entry with no history. `doc_id = sha256(commitment ‖ sha256(xdr(bindings)))`.
7. Spending counters live in the account, keyed by `sha256(rule name)`, as a fixed window. OZ's `spending_limit` uses rolling history.
8. The interpreter is a stateless shim, `perch-vspike-eval`, running the same `perch_program::rpn::eval`, not the deployed interpreter.
9. There is no version garbage collection, no TTL renewal for rule entries, no duplicate-credential check across bindings, and no principal cap.
10. The batch size is fixed at 13, the release compiler's cap, and each batch re-sends the signer table.

## Files in `results/`

| File | Contents |
| --- | --- |
| `pr107-vspike.txt` | the full output of the 16-test `vspike` run on this branch |
| `pr107-vspike.jsonl` | its JSON rows, 516 lines |
| `pr106-oz.txt`, `pr106-oz.jsonl` | `oz_8`, `oz_13`, `archived_oz_13` on #106 `38cc717` plus this harness |
| `pr107-release-stack-worst-compromise.txt`, `.jsonl` | `release_stack.rs` `worst_case_compromise_*` on this branch's stack, real proofs. It matches `docs/recovery/budgets.md`. |
| `stack-pr107-build.json`, `stack-pr106-build.json` | each built stack's `build.json`: wasm sha256, pins, toolchain |
| `spike-wasm.sha256` | sha256 of `perch_vspike.wasm` and `perch_vspike_eval.wasm` |
