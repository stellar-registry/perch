#!/usr/bin/env python3
"""Regenerate the paper's figure files from their generators and data.

    python3 docs/perch-paper/build/figures/make.py          # write source/figures/
    python3 docs/perch-paper/build/figures/make.py --check  # fail if a committed file differs

Each fig_*.py draws one figure (wide and narrow SVG, and where it has them the
step list, phase text or listing panels) from source/facts and its JSON data,
with figlib.py's shape vocabulary. build/paper.py --check runs the check.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIGDIR = HERE.parents[1] / 'source' / 'figures'
SCRIPTS = sorted(HERE.glob('fig_*.py'))


def run(out):
    env = dict(os.environ, PERCH_FIG_OUT=str(out), PYTHONDONTWRITEBYTECODE='1')
    for script in SCRIPTS:
        r = subprocess.run([sys.executable, str(script)], cwd=HERE, env=env, capture_output=True, text=True)
        if r.returncode:
            sys.exit(f'{script.name} failed:\n{r.stderr}')


def main(argv):
    if '--check' not in argv:
        run(FIGDIR)
        print(f'regenerated figures from {len(SCRIPTS)} generators')
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        # Generators read their own data (steps, phases) from the output directory.
        for f in FIGDIR.iterdir():
            (tmp / f.name).write_bytes(f.read_bytes())
        before = {f.name: f.read_bytes() for f in tmp.iterdir()}
        run(tmp)
        stale = sorted(n for n in set(before) | {f.name for f in tmp.iterdir()}
                       if not (tmp / n).exists() or before.get(n) != (tmp / n).read_bytes())
    if stale:
        print('figure files differ from their generators (run build/figures/make.py):', file=sys.stderr)
        for n in stale:
            print('  ' + n, file=sys.stderr)
        return 1
    print('figures agree with their generators')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
