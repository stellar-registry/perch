# @stellar-registry/perch-zk

Proof helpers for Perch ZK recovery, in the browser or Node. The package
computes commitments, rebuilds a pool tree from its leaves to get a witness
path, and proves with bb.js against the release circuit. The proofs it
produces are byte-identical to the pinned `bb` CLI's, and the on-chain adapter
verifies them (see [`docs/zk/`](../../docs/zk/README.md)).

```ts
import { init, commitment, PoolWitnessIndex, prove, evidence, randomSecret } from '@stellar-registry/perch-zk';
import circuit from '@stellar-registry/perch-zk/artifacts/perch_zk_recovery.json' with { type: 'json' };

await init(); // loads Barretenberg's WASM once

// Enrollment: keep `secret` safe. The account's recovery document names a
// fresh random `enrollmentId` and `commitment(secret)`; its `apply_doc`
// inserts the leaf through the pool's invoker-only `rcv_insert`.
const secret = randomSecret();
const inner = commitment(secret);

// Recovery: an index fed the pool's insertions (`LeafInserted` events or
// `leaves` pages) in order, reading leaves back from wherever you keep them.
// It stores only a frontier and completed subtree roots, never a whole tree.
const index = new PoolWitnessIndex((treeId, start, count) => myLeafStore.read(treeId, start, count));
for (const ins of insertions) index.ingest(ins); // { treeId, index, leaf }
const { root, siblings } = await index.witness(treeId, leafIndex);
// check `pool.is_known_root(treeId, root)` before proving
const proof = await prove(circuit, {
  secret,
  accountId,      // the account's 32-byte contract id
  enrollmentId,   // the id the account's recovery configuration names
  digest,         // RecoveryStatement::digest of the statement being authorized
  leafIndex,
  siblings,
});
const zk = evidence(treeId, proof); // { treeId, root, nullifier, proof } → ZkEvidence
```

Pinned toolchain: `@noir-lang/noir_js` 1.0.0-beta.9 and `@aztec/bb.js`
0.87.0. These are the versions NethermindEth's audited verifier targets. A
proof from any other bb version does not verify on-chain.

`npm test` checks Poseidon2 parity with the circuit and the Soroban host,
recomputes every committed fixture's public inputs, checks the shipped
artifacts against `circuits/manifest.json`, and proves one fixture with bb.js,
which must match the committed CLI proof byte for byte. `npm run bench`
measures WASM proving time at both packaged depths under Node, and
`bench/browser` (`npm install && npm run bench` there) measures it in
headless Chromium.
