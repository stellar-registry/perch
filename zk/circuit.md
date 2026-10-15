# The recovery circuit

`circuits/perch_zk/src/lib.nr` holds the relation; `perch_zk_recovery`
instantiates it at depth 32 (the release build), `perch_zk_recovery_d24` at
depth 24 (the fallback). The normative statement of the circuit is
[`docs/recovery/spec.md`](../recovery/spec.md) §13.3 (D14); this file
covers its encodings, the implementations that must agree with it, and its
fixtures.

## Relation

Inputs are BN254 scalar-field elements. A 32-byte value (a contract id, an
enrollment id, a statement digest) enters as two big-endian 128-bit halves
`x_hi = x[0..16]`, `x_lo = x[16..32]`, so the split is exact and both halves
are canonical. `H` is `Poseidon2::hash(inputs, inputs.len())` from
noir-lang/poseidon v0.2.0 (state width 4, rate 3, input length in the
capacity IV).

```text
inner          = H(DOM_LEAF, secret)                                       client
leaf           = H(DOM_BIND, acct_hi, acct_lo, enr_hi, enr_lo, inner)      pool, on-chain
root           = fold over i in 0..32: bit_i(leaf_index) ? H(sib_i, cur) : H(cur, sib_i)
nullifier      = H(DOM_NULLIFIER, acct_hi, acct_lo, enr_hi, enr_lo, secret)
statement_hash = H(DOM_AUTH, acct_hi, acct_lo, enr_hi, enr_lo, digest_hi, digest_lo)
```

**Public inputs, in order: `root`, `nullifier`, `statement_hash`.** The
verifier's input blob is their 96-byte concatenation. Everything else is
private: `secret`, `acct_*`, `enr_*`, `digest_*`, `leaf_index`, and
`siblings`.

- `leaf_index` is decomposed into exactly 32 little-endian bits, which also
  constrains it to `[0, 2^32)`. Index `2^32` cannot alias index 0
  (`index_past_capacity_is_unprovable`).
- An empty slot is the field element `0`, and an empty subtree at level `i` is
  `ZERO_HASHES[i]` (`zero[i+1] = H(zero[i], zero[i])`). Interior nodes carry
  no domain tag. Leaves are 6-input hashes under `DOM_BIND`, and Poseidon2's
  length-encoded IV keeps 2-input and 6-input hashes apart in any case
  (`hash_arity_is_domain_separated`).
- The account and enrollment id feed all three of leaf, nullifier, and
  statement hash. A leaf enrolled for one account or enrollment id therefore
  cannot back a statement checked against another
  (`statement_for_another_account_fails`,
  `statement_for_another_enrollment_fails`).
- The nullifier depends only on `(account, enrollment_id, secret)`, so it is
  the same for every tree, every pool, and every action. Re-enrolling the
  same secret under the same id cannot mint a second nullifier, and the pool
  refuses that re-enrollment anyway. The controller records it as spent for
  that account only when a completion consumes the credential (spec §11).

The domain constants are `BE(sha256("perch/recovery/zk/v2/<name>")) mod r`
for `leaf`, `bind`, `nullifier`, and `auth`. They and the 16/16 split are
defined once in `perch-recovery-interface::zk`, which tests the derivation.
The `v2` labels keep these tags distinct from the `v1` tags of Nido's
earlier recovery circuit, so no `v1` proof, leaf, or nullifier is valid
here (spec §13.3).

## Parameters

| | `perch_zk_recovery` |
| --- | --- |
| Toolchain | nargo 1.0.0-beta.9, bb 0.87.0 (the audited verifier's target) |
| Verifier | NethermindEth's OpenZeppelin-audited UltraHonk verifier (non-ZK), plus Perch's `UltraKeccakZKFlavor` delta, which is not audited ([`README.md`](README.md#open-release-criteria)) |
| Proof flavor | zero-knowledge (`bb prove --zk`, bb.js `keccakZK`) |
| Depth | 32; 24 as a buildable fallback |
| Leaf binding | `H(DOM_BIND, acct, enrollment_id, inner)` |
| Nullifier | `H(DOM_NULLIFIER, acct, enrollment_id, secret)` |
| Authorization | arity-7 `statement_hash` over account, enrollment, and the statement digest; independent of the statement's layout |
| Timing | none in-circuit; ledger counts live in the statement |
| Domain tags | `perch/recovery/zk/v2/*` |
| Poseidon2 dependency | vendored by path (`circuits/vendor/poseidon`), checksummed |
| Proof / VK size | 16,224 B / 1,760 B |
| Circuit size | about 5,700 gates at depth 32 and 4,400 at depth 24, which bb pads to 2^14 and 2^13 (the VK's `log_circuit_size`); exact counts in [`measurements.md`](measurements.md#circuit-identities) |

The release circuit pads to `log_circuit_size` 14. The verifier's
fold-commitment padding convention (`vendor/ultrahonk-soroban-verifier/src/utils.rs`)
is accompanied by a comment confirming it only at `log_circuit_size` 12 and 13;
confirming it at 14 for the release VK is an open verifier-review item.

## Three implementations, one set of vectors

| Implementation | Used by | Pinned in |
| --- | --- | --- |
| Noir `Poseidon2::hash` (vendored poseidon v0.2.0) | the circuit | `circuits/perch_zk/src/tests.nr::parity_vectors` |
| `soroban-poseidon` `Poseidon2Sponge::<4, Bn254Fr>` (host `poseidon2_permutation`) | pool, adapter, native prover | `crates/perch-zk-primitives/src/test.rs::parity` |
| bb.js `poseidon2Hash` | `packages/perch-zk` | `packages/perch-zk/test/parity.test.ts` |

All three assert identical outputs for the same inputs, at every arity the
relation uses (2, 6, 7) and for the depth-32 empty root, plus the
known-answer vector `hash2(1, 2)` (`0x038682aa…d7383`) that Nido's earlier
Poseidon2 tests also pin. On top of that, every fixture's public inputs are
recomputed from its enrollment history by the Rust tests and by the TS
tests, and both must match the public inputs bb committed the proof to.

## Cross-prover and on-chain evidence

- **Proving.** bb.js 0.87.0 in Node and the bb 0.87.0 CLI prove the same
  statement in the same flavor, with the same verification key. Each accepts
  the other's proofs, and the adapter verifies a committed bb.js proof
  (`packages/perch-zk/test/prove.test.ts`, `testdata/zk/lost_key/proof.bbjs`).
  ZK proofs are randomized, so the two never match byte for byte.
- **Verification.** Every fixture verifies on-chain through the compiled
  adapter (`crates/perch-zk-adapter`), and the depth-32 boundary proof
  verifies against a pool that reached index 2^32 − 1 and rolled over.

## Fixtures

`perch-zk-fixtures generate` writes these to `testdata/zk/<name>/`:

| Fixture | Statement subject | Point |
| --- | --- | --- |
| `lost_key` | `LostKey` attempt 1 | leaf at index 1 between two other accounts |
| `compromise` | `Compromise` attempt 2 | baseline source |
| `cancel` | `Cancel` attempt 1, naming `lost_key`'s digest | cancellation domain |
| `reconfigure` | `Reconfigure(Set(config v2))` | Protected reconfiguration |
| `reconfigure_remove` | `Reconfigure(Remove)` | removing recovery |
| `upgrade` | `Upgrade` request 1 | Protected upgrade approval |
| `earlier_tree` | `LostKey` attempt 3 | last slot of a full depth-32 tree, proved after rollover |
| `later_root` | `LostKey` attempt 1 | the `lost_key` credential proved against the root after 129 more insertions; both roots verify |

Each `fixture.json` carries the structured statement, the enrollment history
to replay into a pool at `pool_id`, the secret, and the expected public
values. Next to it are `proof` (ZK, from the bb CLI) and `public_inputs`.
`lost_key` also has `proof.bbjs`, a ZK proof from bb.js, and `proof.non-zk`,
a valid non-ZK proof the adapter must refuse. When the statement encoding
changes (`perch-recovery-interface`), regenerate with `just zk-artifacts`,
then `PERCH_ZK_WRITE_VECTORS=1 npm test` in `packages/perch-zk` for
`proof.bbjs`. The circuit and VK stay the same, and only the digests and
proofs change.
