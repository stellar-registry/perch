// The lost_key witness proved in the page, at both packaged depths, single-
// and multi-threaded, with the package's own `prove`.
import { IncrementalTree, LeafChunks, fromHex, init, leaf, prove } from '../../dist/index.js';
import fixture from '../../../../testdata/zk/lost_key/fixture.json';
import d32 from '../../artifacts/perch_zk_recovery.json';
import d24 from '../../artifacts/perch_zk_recovery_d24.json';

const runs = Number(new URLSearchParams(location.search).get('runs') ?? 5);
const b = (s) => fromHex(s);

async function path(leaves, index, depth) {
  const store = new LeafChunks();
  const tree = new IncrementalTree({ depth });
  for (const l of leaves) {
    store.push(l);
    tree.append(l);
  }
  return (await tree.witness(BigInt(index), store.read)).siblings;
}

async function main() {
  await init();
  const leaves = fixture.enrollments.map((x) =>
    leaf(b(x.account_id), b(x.enrollment_id), b(x.commitment)),
  );
  const results = [];
  for (const [circuit, depth] of [[d32, 32], [d24, 24]]) {
    const witness = {
      secret: b(fixture.secret),
      accountId: b(fixture.account_id),
      enrollmentId: b(fixture.enrollment_id),
      digest: b(fixture.digest),
      leafIndex: BigInt(fixture.leaf_index),
      siblings: await path(leaves, fixture.leaf_index, depth),
    };
    for (const threads of [1, navigator.hardwareConcurrency]) {
      await prove(circuit, witness, { threads }); // warm-up
      const ms = [];
      for (let i = 0; i < runs; i++) {
        const t = performance.now();
        await prove(circuit, witness, { threads });
        ms.push(performance.now() - t);
      }
      ms.sort((x, y) => x - y);
      results.push({ depth, threads, runs, median_ms: Math.round(ms[Math.floor(runs / 2)]) });
    }
  }
  return { userAgent: navigator.userAgent, crossOriginIsolated, results };
}

main().then(
  (r) => (document.getElementById('out').textContent = 'DONE ' + JSON.stringify(r)),
  (e) => (document.getElementById('out').textContent = 'ERROR ' + (e.stack || e)),
);
