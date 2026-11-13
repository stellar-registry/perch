// Builds the core's two wasm modules into ../wasm/ with cargo (target
// wasm32v1-none, the workspace's release profile), then `wasm-opt -Oz` when
// wasm-opt is on PATH and PERCH_WASM_OPT is not 0:
//
//   wasm/perch_review_core.wasm   review, budget, chosen  (feature abi-review)
//   wasm/perch_review_witness.wasm witness                 (feature abi-witness)
//
// Each module imports nothing; test/core.test.ts checks that and their sizes.
import { execFileSync, spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const crate = join(here, '..', '..');
const repo = join(crate, '..', '..');
const out = join(here, '..', 'wasm');
mkdirSync(out, { recursive: true });

const optimize =
  process.env.PERCH_WASM_OPT !== '0' && spawnSync('wasm-opt', ['--version']).status === 0;

for (const [feature, name] of [
  ['abi-review', 'perch_review_core.wasm'],
  ['abi-witness', 'perch_review_witness.wasm'],
]) {
  execFileSync(
    'cargo',
    [
      'rustc', '--locked', '-q', '-p', 'perch-review-core', '--release',
      '--target', 'wasm32v1-none', '--features', feature, '--crate-type', 'cdylib',
    ],
    { cwd: repo, stdio: 'inherit' },
  );
  const built = join(repo, 'target', 'wasm32v1-none', 'release', 'perch_review_core.wasm');
  const dest = join(out, name);
  copyFileSync(built, dest);
  if (optimize) {
    execFileSync(
      'wasm-opt',
      [
        '-Oz', '--enable-bulk-memory', '--enable-sign-ext', '--enable-mutable-globals',
        '--enable-nontrapping-float-to-int', '-o', dest, dest,
      ],
      { stdio: 'inherit' },
    );
  }
  console.log(`built ${name}${optimize ? ' (wasm-opt -Oz)' : ''}`);
}
