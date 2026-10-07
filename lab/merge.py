#!/usr/bin/env python3
"""Worst share per resource per shape across several cap_sweep logs (same
stack). Shape key = signers, rules, both, fan + a family tag given as
name=log1,log2 groups so interp/plain families with equal labels stay apart."""
import json, re, sys
L = {"instructions":400_000_000,"mem_bytes":41_943_040,"net_fp":400,"write_entries":200,"write_bytes":132_096,"events_bytes":16_384}
N = {"instructions":"Instr","mem_bytes":"Memory","net_fp":"Footprint (RO+RW)","write_entries":"Written","write_bytes":"Write bytes","events_bytes":"Events"}
rows, order = {}, []
for group in sys.argv[1:]:
    fam, logs = group.split("=")
    for path in logs.split(","):
        for line in open(path):
            if not line.startswith('{"case"'): continue
            d = json.loads(line)
            m = re.search(r"\[(\d+) signers, (\d+) rules, (\d+) with both policies, (\d+) per rule\]", d["case"])
            if not m or "instructions" not in d: continue
            d["net_fp"] = d["read_entries"]
            key = (fam,) + tuple(int(x) for x in m.groups())
            if key not in rows: rows[key] = {}; order.append(key)
            flow = d["case"].split(" [")[0]
            for k, lim in L.items():
                sh = d[k]*100/lim
                if sh > rows[key].get(k, (0, ""))[0]: rows[key][k] = (sh, flow)
print("| Family | Signers | Rules | Capped | Fan | " + " | ".join(N[k] for k in L) + " | Binding |")
print("| --- | ---: | ---: | ---: | ---: | " + " | ".join("---:" for _ in L) + " | --- |")
for key in sorted(order, key=lambda k: (k[0], k[1], k[2])):
    r = rows[key]
    cells = [("**%.1f%%**" if r[k][0] > 75 else "%.1f%%") % r[k][0] for k in L]
    b = max(L, key=lambda k: r[k][0])
    fl = r[b][1].replace("completion apply_doc (compromise, Combined, ZK rotation, both key sets revoked; ", "compromise completion (").replace("Protected reconfiguration apply_doc (Combined: recorded quorum and proof, a new enrollment; ", "reconfiguration (")
    print(f"| {key[0]} | {key[1]} | {key[2]} | {key[3]} | {key[4]} | " + " | ".join(cells) + f" | {N[b]}: {fl[:70]} |")
