#!/usr/bin/env python3
"""Size the document caps: run release_stack.rs's `cap_sweep` over worst-case
document shapes and tabulate each shape's worst share of every
per-transaction limit (docs/recovery/budgets.md, "Document caps"); with
--grants, run `grant_cap_sweep` over grant-document shapes instead
("Grant-document caps").

Usage:
  eval "$(scripts/zk-toolchain.sh)"
  scripts/cap-sweep.py [--stack target/stack] [--bytes N|0] [--budget 75]
                       [--flows 0,1,...] [--simulate] [--save sweep.log] S,R [S,R ...]
  scripts/cap-sweep.py --grants [--stack ...] [--save ...] S,R[,F[,B[,D]]] [...]
  scripts/cap-sweep.py [--grants] --log sweep.log   # tabulate an earlier run's output

With --grants, each S,R,F,B,D is a grant document of S session passkeys and R
capped grants, each rule naming F of the signers (default: as many as a rule
may, 15), padded to B canonical bytes (default 0: unpadded); D 1 makes it
dense (bare rules and the shortest ids: the most rules and signer
references per document byte), and D 2 dense with `all` principals, shorter
still, and D 3 that with its last two rules capped transfers asking 8 and
all of their signers. Every grant flow
runs on a forked host: apply_grant adding every rule, a capped transfer,
every cap changed, every rule replaced, remove_grant, and, after a recovery
wipes the document, gc_grant and a re-grant over it. Two more columns: the
largest contract-data entry the account holds (the grant document's record)
against the 64 KiB entry limit, and the transaction's size, which carries
the document twice, against the 132 096-byte limit.

Each S,R is the worst shape with S signers and R rules: every signer a
passkey some rule names (up to OZ's 15 per rule), every rule but `admin` and
`target` with both policies, padded to --bytes (default: the build's byte
cap; 0: the larger of 8 192 and the shape's own size rounded up to 1 KiB).
The stack's compiler must admit the shapes: to measure past the current
caps, build a stack with them raised. --flows runs only those indices of
release_stack.rs's WORST_FLOWS (default: all eight); --simulate also checks
every apply_doc's footprint against an RPC-style simulation (slower).

Footprint is the transaction's distinct ledger keys, read-only plus
read-write, the count the network limits (400); written entries are the
read-write keys (200). Logs from before 2026-10-07 counted every read-write
key twice in footprint_entries. Standard library only.
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
SIZE_LIMITS = {  # the two sizes a grant row also reports (`report_sizes`)
    "max_entry_bytes": 65_536,
    "tx_bytes": 132_096,
}
SIZE_NAMES = {"max_entry_bytes": "Largest entry", "tx_bytes": "Tx size"}


def run(args) -> str:
    shapes = []
    for sr in args.shapes:
        s, r = (int(x) for x in sr.split(","))
        shape = f"{s},{r - 2},0,0,{min(s, 15)}"
        if args.bytes is not None:
            shape += f",{args.bytes}"
        shapes.append(shape)
    env = dict(os.environ, PERCH_STACK_DIR=args.stack, PERCH_CAP_SWEEP=";".join(shapes))
    if args.flows:
        env["PERCH_FLOWS"] = args.flows
    if args.simulate:
        env["PERCH_SIMULATE"] = "1"
    out = subprocess.run(
        ["cargo", "test", "-q", "-p", "perch-integration-tests", "--test", "release_stack",
         "cap_sweep", "--", "--ignored", "--nocapture", "--test-threads", "1"],
        env=env, capture_output=True, text=True,
    )
    if out.returncode != 0:
        sys.stderr.write(out.stdout[-4000:] + out.stderr[-4000:])
        sys.exit(f"cap_sweep failed ({out.returncode})")
    return out.stdout


def run_grants(args) -> str:
    shapes = []
    for item in args.shapes:
        v = [int(x) for x in item.split(",")]
        s, r = v[0], v[1]
        f = v[2] if len(v) > 2 else min(s, 15)
        b = v[3] if len(v) > 3 else 0
        dense = v[4] if len(v) > 4 else 0
        shapes.append(f"{s},{r},{f},{b},{dense}")
    env = dict(os.environ, PERCH_STACK_DIR=args.stack, PERCH_GRANT_SWEEP=";".join(shapes))
    out = subprocess.run(
        ["cargo", "test", "-q", "-p", "perch-integration-tests", "--test", "release_stack",
         "grant_cap_sweep", "--", "--ignored", "--nocapture", "--test-threads", "1"],
        env=env, capture_output=True, text=True,
    )
    if out.returncode != 0:
        sys.stderr.write(out.stdout[-4000:] + out.stderr[-4000:])
        sys.exit(f"grant_cap_sweep failed ({out.returncode})")
    return out.stdout


GRANT_SHAPE = re.compile(r"\[(\d+) signers, (\d+) rules, (\d+) per rule, (\d+) bytes(, dense(?: all(?:, quorum rules)?)?)?\]")


GRANT_DENSE = ["", ", dense", ", dense all", ", dense all, quorum rules"]


def print_skipped(skipped: list) -> None:
    for d in skipped:
        print(f"- skipped {d['signers']} signers, {d['rules']} rules, {d['bytes']} bytes: {d['why']}")


def print_unmeasured(skipped: list) -> None:
    if not skipped:
        print("No shape was measured.")
        return
    print("No shape was measured: every one was skipped.")
    print_skipped(skipped)


def tabulate_grants(log: str, budget: float) -> None:
    limits = dict(LIMITS, **SIZE_LIMITS)
    names = dict(NAMES, **SIZE_NAMES)
    worst: dict = {}
    skipped = []
    for line in log.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        d = json.loads(line)
        if d.get("case") == "skipped":
            skipped.append(d)
            continue
        label = d.get("case") or d.get("sizes_of")
        m = GRANT_SHAPE.search(label or "")
        if not m:
            continue
        key = tuple(int(x) for x in m.groups()[:4]) + (GRANT_DENSE.index(m.group(5) or ""),)
        flow = label.split(": ", 2)[-1].split(" [")[0]
        row = worst.setdefault(key, {})
        for k, lim in limits.items():
            if k in d:
                share = d[k] * 100 / lim
                if share > row.get(k, (0.0, ""))[0]:
                    row[k] = (share, flow)
    if not worst:
        print_unmeasured(skipped)
        return
    print("| Shape | Signers | Rules | Per rule | Bytes | " + " | ".join(names[k] for k in limits)
          + " | Binding |")
    print("| --- | --- | --- | --- | --- | " + " | ".join("---" for _ in limits) + " | --- |")
    for key, row in sorted(worst.items(), key=lambda kv: (kv[0][4], kv[0][:4])):
        cells = []
        for k in limits:
            share = row.get(k, (0.0, ""))[0]
            cells.append(f"**{share:.1f}%**" if share > budget else f"{share:.1f}%")
        binding = max(limits, key=lambda k: row.get(k, (0.0, ""))[0])
        print(f"| {GRANT_DENSE[key[4]][2:] or 'capped'} | " + " | ".join(str(x) for x in key[:4]) + " | "
              + " | ".join(cells) + f" | {names[binding]}: {row[binding][1]} |")
    print()
    for k in limits:
        over = [key for key, row in sorted(worst.items()) if row.get(k, (0.0,))[0] > budget]
        if over:
            key = min(over, key=lambda x: (x[1], x[0], x[3], x))
            print(f"- {names[k]}: past {budget:g}% first at {key[0]} signers, {key[1]} rules, "
                  f"{key[2]} per rule, {key[3]} bytes{GRANT_DENSE[key[4]]} "
                  f"({worst[key][k][0]:.1f}%, {worst[key][k][1]})")
        else:
            top = max(worst.items(), key=lambda kv: kv[1].get(k, (0.0,))[0])
            print(f"- {names[k]}: within {budget:g}% everywhere measured "
                  f"(at most {top[1][k][0]:.1f}%, {top[0][0]} signers, {top[0][1]} rules, "
                  f"{top[0][3]} bytes, {top[1][k][1]})")
    print_skipped(skipped)


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
    if not worst:
        print_unmeasured(skipped)
        return
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
    print_skipped(skipped)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("shapes", nargs="*", help="S,R pairs")
    p.add_argument("--stack", default="target/stack")
    p.add_argument("--bytes", type=int, default=None)
    p.add_argument("--budget", type=float, default=75.0)
    p.add_argument("--flows", help="comma-separated WORST_FLOWS indices to run (default: all)")
    p.add_argument("--simulate", action="store_true", help="check each footprint against a simulation")
    p.add_argument("--save", help="also write the raw cap_sweep output here")
    p.add_argument("--log", help="tabulate this cap_sweep output instead of running")
    p.add_argument("--grants", action="store_true", help="sweep grant-document shapes S,R[,F[,B[,D]]]")
    args = p.parse_args()
    if args.log:
        log = open(args.log).read()
    else:
        log = run_grants(args) if args.grants else run(args)
    if args.save and not args.log:
        with open(args.save, "w") as f:
            f.write(log)
    (tabulate_grants if args.grants else tabulate)(log, args.budget)


if __name__ == "__main__":
    main()
