// WASM proving cost (bb.js under Node, the browser prover's code path) for the
// lost_key witness at both packaged depths, single- and multi-threaded.
//   npm run bench -- [runs]   (builds dist/ first)
// Numbers are recorded in docs/zk/measurements.md.

import { readFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { Tree, fromHex, init, leaf, prove } from '../dist/index.js';

const repo = new URL('../../../', import.meta.url);
const b = (s) => fromHex(s);
const runs = Number(process.argv[2] ?? 5);

await init();
const f = JSON.parse(readFileSync(new URL('testdata/zk/lost_key/fixture.json', repo), 'utf8'));
const leaves = f.enrollments.map((x) =>
  leaf(b(x.account_id), b(x.enrollment_id), b(x.commitment)),
);

const results = [];
for (const [name, depth] of [
  ['perch_zk_recovery', 32],
  ['perch_zk_recovery_d24', 24],
]) {
  const circuit = JSON.parse(
    readFileSync(new URL(`circuits/artifacts/${name}.json`, repo), 'utf8'),
  );
  const witness = {
    secret: b(f.secret),
    accountId: b(f.account_id),
    enrollmentId: b(f.enrollment_id),
    digest: b(f.digest),
    leafIndex: BigInt(f.leaf_index),
    siblings: new Tree(leaves, depth).path(f.leaf_index),
  };
  for (const threads of [1, availableParallelism()]) {
    await prove(circuit, witness, { threads }); // warm-up: WASM compile + SRS
    const ms = [];
    for (let i = 0; i < runs; i++) {
      const t = performance.now();
      await prove(circuit, witness, { threads });
      ms.push(performance.now() - t);
    }
    ms.sort((a, c) => a - c);
    results.push({
      circuit: name,
      depth,
      threads,
      runs,
      median_ms: Math.round(ms[Math.floor(ms.length / 2)]),
      max_ms: Math.round(ms[ms.length - 1]),
      peak_rss_mb: Math.round(process.memoryUsage().rss / 2 ** 20),
    });
  }
}
console.log(JSON.stringify({ node: process.version, cpus: availableParallelism(), results }, null, 2));
process.exit(0);
