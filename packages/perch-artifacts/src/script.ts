// Runs one of the repository scripts this package ships with bash. npm links
// a bin into node_modules/.bin, where the script would resolve its own
// directory wrong, so each bin is this wrapper.

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { root } from './index.js';

export function runScript(name: string): never {
  const run = spawnSync('bash', [join(root, 'scripts', name), ...process.argv.slice(2)], { stdio: 'inherit' });
  if (run.error) throw run.error;
  process.exit(run.status ?? 1);
}
