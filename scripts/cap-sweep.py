#!/usr/bin/env python3
"""Size the document caps: run release_stack.rs's `cap_sweep` over worst-case
document shapes and tabulate each shape's worst share of every
per-transaction limit (docs/recovery/budgets.md, "Document caps").

Usage:
  eval "$(scripts/zk-toolchain.sh)"
  scripts/cap-sweep.py [--stack target/stack] [--bytes N|0] [--budget 75] S,R [S,R ...]
  scripts/cap-sweep.py --log sweep.log      # tabulate an earlier run's output

Each S,R is the worst shape with S signers and R rules: every signer a
passkey some rule names (up to OZ's 15 per rule), every rule but `admin` and
`target` with both policies, padded to --bytes (default: the build's byte
cap; 0: the larger of 8 192 and the shape's own size rounded up to 1 KiB).
The stack's compiler must admit the shapes: to measure past the current
caps, build a stack with them raised. Standard library only.
"""

import argparse
import json
import os
import re
import subprocess
import sys

LIMITS = {  # protocol-29 per-transaction limits
    "instructions": 400_000_000,
    "mem_bytes": 41_943_040,
    "footprint_entries": 400,
    "write_entries": 200,
    "write_bytes": 132_096,
    "events_bytes": 16_384,
}
NAMES = {
    "instructions": "Instructions",
    "mem_bytes": "Memory",
    "footprint_entries": "Footprint",
    "write_entries": "Written entries",
    "write_bytes": "Write bytes",
    "events_bytes": "Events",
}


def run(args) -> str:
    shapes = []
    for sr in args.shapes:
        s, r = (int(x) for x in sr.split(","))
        shape = f"{s},{r - 2},0,0,{min(s, 15)}"
        if args.bytes is not None:
            shape += f",{args.bytes}"
        shapes.append(shape)
    env = dict(os.environ, PERCH_STACK_DIR=args.stack, PERCH_CAP_SWEEP=";".join(shapes))
    out = subprocess.run(
        ["cargo", "test", "-q", "-p", "perch-integration-tests", "--test", "release_stack",
         "cap_sweep", "--", "--ignored", "--nocapture", "--test-threads", "1"],
        env=env, capture_output=True, text=True,
    )
    if out.returncode != 0:
        sys.stderr.write(out.stdout[-4000:] + out.stderr[-4000:])
        sys.exit(f"cap_sweep failed ({out.returncode})")
    return out.stdout


def tabulate(log: str, budget: float) -> None:
    worst: dict = {}
    skipped = []
    for line in log.splitlines():
        line = line.strip()
        if not line.startswith('{"case"'):
            continue
        d = json.loads(line)
        if d["case"] == "skipped":
            skipped.append(d)
            continue
        m = re.search(r"\[(\d+) signers, (\d+) rules", d["case"])
        if not m:
            continue
        key = (int(m.group(1)), int(m.group(2)))
        row = worst.setdefault(key, {})
        for k, lim in LIMITS.items():
            share = d[k] * 100 / lim
            if share > row.get(k, (0.0, ""))[0]:
                row[k] = (share, d["case"].split(" [")[0])
    print("| Signers | Rules | " + " | ".join(NAMES[k] for k in LIMITS) + " | Binding |")
    print("| --- | --- | " + " | ".join("---" for _ in LIMITS) + " | --- |")
    for (s, r), row in sorted(worst.items()):
        cells = []
        for k in LIMITS:
            share = row[k][0]
            cells.append(f"**{share:.1f}%**" if share > budget else f"{share:.1f}%")
        binding = max(LIMITS, key=lambda k: row[k][0])
        print(f"| {s} | {r} | " + " | ".join(cells) + f" | {NAMES[binding]}: {row[binding][1]} |")
    print()
    for k in LIMITS:
        over = [(s, r) for (s, r), row in sorted(worst.items()) if row[k][0] > budget]
        if over:
            s, r = min(over, key=lambda x: (x[0] + x[1], x))
            print(f"- {NAMES[k]}: past {budget:g}% first at {s} signers, {r} rules "
                  f"({worst[(s, r)][k][0]:.1f}%, {worst[(s, r)][k][1]})")
        else:
            top = max(worst.items(), key=lambda kv: kv[1][k][0])
            print(f"- {NAMES[k]}: within {budget:g}% everywhere measured "
                  f"(at most {top[1][k][0]:.1f}%, {top[0][0]} signers, {top[0][1]} rules)")
    for d in skipped:
        print(f"- skipped {d['signers']} signers, {d['rules']} rules, {d['bytes']} bytes: {d['why']}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("shapes", nargs="*", help="S,R pairs")
    p.add_argument("--stack", default="target/stack")
    p.add_argument("--bytes", type=int, default=None)
    p.add_argument("--budget", type=float, default=75.0)
    p.add_argument("--log", help="tabulate this cap_sweep output instead of running")
    args = p.parse_args()
    log = open(args.log).read() if args.log else run(args)
    tabulate(log, args.budget)


if __name__ == "__main__":
    main()
