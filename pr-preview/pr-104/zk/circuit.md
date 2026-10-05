# The recovery circuit

`circuits/perch_zk/src/lib.nr` holds the relation; `perch_zk_recovery`
instantiates it at depth 32, `perch_zk_recovery_d24` at depth 24.

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
  length-encoded IV keeps 2-input and 6-input hashes apart in any case.
- The account and enrollment id feed all three of leaf, nullifier, and
  statement hash. A leaf enrolled for one account or enrollment id therefore
  cannot back a statement checked against another
  (`statement_for_another_account_fails`,
  `statement_for_another_enrollment_fails`).
- The nullifier depends only on `(account, enrollment_id, secret)`, so it is
  the same for every tree and every pool. Re-enrolling the same secret under
  the same id cannot mint a second nullifier, and the pool refuses that
  re-enrollment anyway.

The domain constants are `BE(sha256("perch/recovery/zk/v2/<name>")) mod r`
for `leaf`, `bind`, `nullifier`, and `auth`. They and the 16/16 split are
defined once in `perch-recovery-interface::zk`, which tests the derivation.

## Three implementations, one set of vectors

| Implementation | Used by | Pinned in |
| --- | --- | --- |
| Noir `Poseidon2::hash` (vendored poseidon v0.2.0) | the circuit | `circuits/perch_zk/src/tests.nr::parity_vectors` |
| `soroban-poseidon` `Poseidon2Sponge::<4, Bn254Fr>` (host `poseidon2_permutation`) | pool, adapter, native prover | `crates/perch-zk-primitives/src/test.rs::parity` |
| bb.js `poseidon2Hash` | `packages/perch-zk` | `packages/perch-zk/test/parity.test.ts` |

All three assert identical outputs for the same inputs, at every arity the
relation uses (2, 6, 7) and for the depth-32 empty root. On top of that, every
fixture's public inputs are recomputed from its enrollment history by the Rust
tests and by the TS tests, and both must match the public inputs bb committed
the proof to.

## Compatibility with Nido's circuits

Nido shipped `circuits/zk_recovery` (M1) and `circuits/zk_recovery_doc` (the
document-recovery adaptation). This circuit reuses their shape: a Poseidon2
Merkle membership proof with an account-bound leaf, a secret-derived
nullifier, and an authorization hash, with the same three public inputs. It
does not reuse their artifacts, and nothing assumes they still verify.

| | Nido `zk_recovery_doc` | Perch `perch_zk_recovery` |
| --- | --- | --- |
| Toolchain | nargo 1.0.0-beta.18, bb 3.0.0-nightly.20260102 | nargo 1.0.0-beta.9, bb 0.87.0 (the audited verifier's target) |
| Verifier | unaudited bb 3 fork | NethermindEth, OpenZeppelin-audited, vendored unmodified |
| Depth | 24 | 32 (24 as a buildable fallback) |
| Leaf binding | `H(DOM_BIND, acct, inner)` | `H(DOM_BIND, acct, enrollment_id, inner)` |
| Nullifier | `H(DOM_NULL, acct, secret)` | `H(DOM_NULLIFIER, acct, enrollment_id, secret)` |
| Authorization | arity-15 `auth_hash` over the raw statement fields, so the circuit encodes the statement layout | arity-7 `statement_hash` over account, enrollment, and the statement digest; layout-independent |
| Timing | seconds (`timelock_secs`) | none in-circuit; ledger counts live in the statement |
| Domain tags | `nido` v1 constants | `perch/recovery/zk/v2/*` (no v1 proof, leaf, or nullifier is valid here) |
| Poseidon2 dependency | git tag | vendored by path, checksummed |
| Proof / VK size | 6,976 B / 1,888 B | 14,592 B / 1,760 B |
| Circuit size | n/a | 5,684 gates (depth 32), 4,425 (depth 24); both 2^13 |

What demonstrates compatibility, and not just similarity:

- **Poseidon2.** The parity vectors above, plus Nido's own
  `hash2(1, 2)` vector, which this circuit reproduces unchanged
  (`0x038682aa…d7383`).
- **Proving.** bb.js 0.87.0 in Node and the bb 0.87.0 CLI produce
  byte-identical proofs for the same witness, so a browser prover and the
  committed fixtures agree (`packages/perch-zk/test/prove.test.ts`).
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
values. When the statement encoding changes (`perch-recovery-interface`),
regenerate with `just zk-artifacts`. The circuit and VK stay the same, and
only the digests and proofs change.
