# @stellar-registry/perch-zk

Proof helpers for Perch ZK recovery, in the browser or Node. The package
computes commitments, rebuilds a pool tree from its leaves to get a witness
path, and proves with bb.js against the release circuit. Proofs are
zero-knowledge (`UltraKeccakZKFlavor`): they reveal nothing about the secret
or the leaf's position beyond the public root, nullifier, and statement hash.
They are randomized, so two proofs of one statement differ, and the on-chain
adapter verifies them (see [`docs/zk/`](../../docs/zk/README.md)). `verify`
checks a proof locally with bb.js before you submit it.

```ts
import { init, commitment, PoolWitnessIndex, prove, verify, evidence, randomSecret } from '@stellar-registry/perch-zk';
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
if (!(await verify(circuit, proof))) throw new Error('proof does not verify'); // optional local check
const zk = evidence(treeId, proof); // { treeId, root, nullifier, proof } → ZkEvidence
```

Pinned toolchain: `@noir-lang/noir_js` 1.0.0-beta.9 and `@aztec/bb.js`
0.87.0, the versions the adapter's verifier targets. A proof from any other bb
version does not verify on-chain, and neither does a non-ZK proof
(`{ keccak: true }`).

`npm test` checks Poseidon2 parity with the circuit and the Soroban host,
recomputes every committed fixture's public inputs, and checks the shipped
artifacts against `circuits/manifest.json`. It also proves one fixture with
bb.js and requires the proof to:

- carry the committed public inputs;
- verify under bb.js;
- differ from a second proof.

It also checks that bb.js accepts the committed CLI and bb.js proofs, and
that its verification key is the one the adapter compiles in.
`PERCH_ZK_WRITE_VECTORS=1 npm test` rewrites the committed bb.js proof, which
the adapter's tests verify on-chain. `npm run bench`
measures WASM proving time at both packaged depths under Node, and
`bench/browser` (`npm install && npm run bench` there) measures it in
headless Chromium.
