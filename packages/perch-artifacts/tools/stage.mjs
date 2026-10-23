#!/usr/bin/env node
// Copy the repository files this package ships into it. sources.json maps a
// package path to a repository path (a file, or a directory whose tracked
// files are copied); the copies are git-ignored, so the repository stays the
// only source.
//
//   node tools/stage.mjs                stage into this package
//   node tools/stage.mjs --check <dir>  fail unless <dir> (this package, or an
//                                       installed copy) holds exactly those
//                                       files, byte for byte

import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkg = fileURLToPath(new URL('..', import.meta.url));
const repo = join(pkg, '..', '..');
const sources = JSON.parse(readFileSync(join(pkg, 'sources.json'), 'utf8'));
const roots = [...new Set(Object.keys(sources).map((to) => to.split('/')[0]))];

/** Every shipped file: [package path, repository path]. */
function entries() {
  const out = [];
  for (const [to, from] of Object.entries(sources)) {
    const tracked = execFileSync('git', ['-C', repo, 'ls-files', '-z', '--', from], { encoding: 'utf8' })
      .split('\0')
      .filter(Boolean);
    if (!tracked.length) throw new Error(`sources.json: ${from} names no tracked file`);
    for (const file of tracked) out.push([to + file.slice(from.length), file]);
  }
  return out;
}

function walk(dir) {
  if (!existsSync(dir)) return [];
  if (!statSync(dir).isDirectory()) return [dir];
  return readdirSync(dir).flatMap((name) => walk(join(dir, name)));
}

if (process.argv[2] === '--check') {
  const dir = process.argv[3];
  if (!dir) throw new Error('usage: stage.mjs --check <dir>');
  const want = new Map(entries());
  const problems = [];
  for (const [to, from] of want) {
    const have = join(dir, to);
    if (!existsSync(have)) problems.push(`missing ${to} (${from})`);
    else if (!readFileSync(have).equals(readFileSync(join(repo, from)))) problems.push(`stale ${to}: differs from ${from}`);
  }
  for (const root of roots) {
    for (const file of walk(join(dir, root))) {
      const to = relative(dir, file).split('\\').join('/');
      if (!want.has(to)) problems.push(`extra ${to}: no source in sources.json`);
    }
  }
  if (problems.length) {
    console.error(`${dir} does not match its sources (rerun: npm run build):\n  ${problems.join('\n  ')}`);
    process.exit(1);
  }
  console.error(`${want.size} artifacts match their sources`);
} else {
  for (const root of roots) rmSync(join(pkg, root), { recursive: true, force: true });
  const all = entries();
  for (const [to, from] of all) cpSync(join(repo, from), join(pkg, to));
  console.error(`staged ${all.length} artifacts`);
}
