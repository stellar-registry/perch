#!/usr/bin/env python3
"""Tabulate cap_sweep logs: worst share per resource per shape, with the
network footprint (RO+RW = read_entries) and the sweep's double-counted one."""
import json, re, sys
L = {"instructions":400_000_000,"mem_bytes":41_943_040,"net_fp":400,"sweep_fp":400,"write_entries":200,"write_bytes":132_096,"events_bytes":16_384}
rows = {}
order = []
for path in sys.argv[1:]:
    for line in open(path):
        line=line.strip()
        if not line.startswith('{"case"'): continue
        d=json.loads(line)
        m=re.search(r"\[(\d+) signers, (\d+) rules, (\d+) with both policies, (\d+) per rule\]", d["case"])
        if not m or "instructions" not in d: continue
        if d["case"].startswith("factory"): continue
        d["net_fp"]=d["read_entries"]; d["sweep_fp"]=d["footprint_entries"]
        flow=d["case"].split(" [")[0]
        key=(path.split('/')[-1], m.group(0))
        if key not in rows: rows[key]={}; order.append(key)
        for k,lim in L.items():
            sh=d[k]*100/lim
            if sh>rows[key].get(k,(0,""))[0]: rows[key][k]=(sh,flow,d[k])
hdr=["instr","mem","netFP","sweepFP","written","wbytes","events"]
print("| log | shape | "+" | ".join(hdr)+" | binding (net) |")
for key in order:
    r=rows[key]
    cells=[f"{r[k][0]:.1f}%" for k in L]
    net=[k for k in L if k!="sweep_fp"]
    b=max(net,key=lambda k:r[k][0])
    print(f"| {key[0]} | {key[1]} | "+" | ".join(cells)+f" | {b} {r[b][0]:.1f}% ({r[b][1][:60]}) |")
