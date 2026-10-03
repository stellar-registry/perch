#!/usr/bin/env python3
"""Render a perch-testnet exercise report (deployments/<network>-exercise.json)
as the Markdown tables in docs/deploy/testnet-exercise.md.

Usage: scripts/exercise-report.py [deployments/testnet-exercise.json]

Standard library only. Every number comes from the report: instructions,
footprint entries, and write bytes from the submitted transaction's
resources (the enforcing re-simulation), size from the signed envelope, the
fee from the network's TransactionResult, latency from send to inclusion.
"""

import json
import sys

BUDGET = 0.75  # docs/recovery/budgets.md section 2

# docs/recovery/budgets.md section 2 rows, and the step labels that measure
# them (prefix match).
ROWS = [
    ("Enroll ZK through `apply_doc`", ["enroll ZkOnly", "enroll Combined"]),
    ("`begin_lost_key`", ["begin_lost_key"]),
    ("`begin_compromise`", ["begin_compromise"]),
    ("`publish_baseline`", ["publish_baseline"]),
    ("`submit_guardian`", ["submit_guardian", "cancel: guardian"]),
    ("`submit_zk`", ["submit_zk (", "cancellation ("]),
    ("Completion `apply_doc`", ["completion apply_doc"]),
    ("Owner cancellation (`Loss`)", ["Loss owner cancel_recovery"]),
    ("`approve_change`", ["approve_change"]),
    ("`submit_zk_change`", ["submit_zk_change"]),
    ("`Protected` reconfiguration `apply_doc`", ["Protected reconfiguration", "Protected Combined reconfiguration"]),
    ("`Protected` `schedule_upgrade`", ["Protected schedule_upgrade"]),
    ("Ordinary activity (direct authorization)", ["ordinary activity: direct", "activity", "the new passkey", "the new owner", "Loss: activity", "the thief's signer moves"]),
    ("Ordinary activity (`execute`)", ["ordinary activity: execute", "execute after"]),
    ("Factory `create_passkey`", ["factory create_passkey"]),
]


def footprint_limit(lim):
    # `tx_max_footprint_entries` (protocol 23+); the 200 disk-read entries
    # bound only entries read from disk, which live Soroban state is not.
    return lim.get("tx_max_footprint_entries", 400)


def pct(used, limit):
    return 100.0 * used / limit


def xlm(stroops):
    return f"{stroops / 1e7:.4f}"


def main(path):
    r = json.load(open(path))
    lim = r["limits"]
    steps = r["steps"]
    ok = [s for s in steps if s["outcome"] == "ok"]
    refused = [s for s in steps if s["outcome"] == "refused"]
    out = []
    w = out.append

    w(f"Run `{r['run']}` against `{r['manifest']}` (stack commit `{r['manifest_commit'][:12]}`), "
      f"ledgers {r['ledgers']['from']}–{r['ledgers']['to']}: {len(ok)} transactions submitted, "
      f"{len(refused)} refusals checked, {len(r['failures'])} scenario failures. "
      f"Fees paid: {xlm(sum(s['fee_charged_stroops'] or 0 for s in ok))} XLM.")
    w("")

    w("### Against the budget")
    w("")
    w(f"Worst measured transaction per row of `docs/recovery/budgets.md` §2, as a share of the "
      f"protocol-29 per-transaction limits ({lim['tx_max_instructions']:,} instructions, "
      f"{footprint_limit(lim)} footprint entries, {lim['tx_max_write_ledger_entries']} written entries, "
      f"{lim['tx_max_write_bytes']:,} write bytes, {lim['tx_max_size_bytes']:,} bytes of transaction). "
      f"Budget: {int(BUDGET * 100)}% of each. Memory is not reported by the RPC; "
      f"the release-stack suite meters it locally.")
    w("")
    w("| Row | Worst step | Instructions | Footprint entries | Written entries | Write bytes | Tx size | Fee (XLM) | Latency (s) | Within budget |")
    w("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for row, prefixes in ROWS:
        matched = [s for s in ok if any(s["label"].startswith(p) for p in prefixes)]
        if not matched:
            w(f"| {row} | not on testnet | | | | | | | | |")
            continue
        s = max(matched, key=lambda s: s["instructions"] or 0)
        shares = [
            pct(s["instructions"], lim["tx_max_instructions"]),
            pct(s["read_entries"], footprint_limit(lim)),
            pct(s["write_entries"], lim["tx_max_write_ledger_entries"]),
            pct(s["write_bytes"], lim["tx_max_write_bytes"]),
            pct(s["tx_size_bytes"], lim["tx_max_size_bytes"]),
        ]
        within = "yes" if max(shares) <= BUDGET * 100 else "**no**"
        w(f"| {row} | {s['label']} | {s['instructions']:,} ({shares[0]:.1f}%) | {s['read_entries']} ({shares[1]:.1f}%) "
          f"| {s['write_entries']} ({shares[2]:.1f}%) | {s['write_bytes']:,} ({shares[3]:.1f}%) | {s['tx_size_bytes']:,} ({shares[4]:.1f}%) "
          f"| {xlm(s['fee_charged_stroops'])} | {s['latency_ms'] / 1000:.1f} | {within} |")
    w("")

    proving = r["native_proving"]
    if proving:
        execs = sorted(p["execute_ms"] for p in proving)
        proves = sorted(p["prove_ms"] for p in proving)
        rss = max((p["peak_rss_bytes"] or 0) for p in proving)
        w(f"Native proving, {len(proving)} proofs (`nargo execute` + `bb prove`, the pinned toolchain): "
          f"witness {execs[len(execs) // 2]} ms median / {execs[-1]} ms max, proof "
          f"{proves[len(proves) // 2]} ms median / {proves[-1]} ms max, peak RSS {rss / 2**20:.0f} MiB.")
        w("")

    scenario = None
    for s in steps:
        if s["scenario"] != scenario:
            scenario = s["scenario"]
            w(f"### {scenario}")
            w("")
            w("| Step | Result | Instructions | Fee (XLM) | Transaction |")
            w("| --- | --- | --- | --- | --- |")
        if s["outcome"] == "ok":
            tx = s["tx_hash"]
            w(f"| {s['label']} | ok | {s['instructions']:,} | {xlm(s['fee_charged_stroops'])} "
              f"| [`{tx[:10]}…`](https://stellar.expert/explorer/testnet/tx/{tx}) |")
        else:
            code = s["error"]
            if s.get("auth_error_code") is not None:
                code += f", `__check_auth` #{s['auth_error_code']}"
            where = f" ({s['refused_in']} simulation)" if s.get("refused_in") else ""
            w(f"| {s['label']} | refused{where}: `{code}` | | | |")
    w("")
    print("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "deployments/testnet-exercise.json")
