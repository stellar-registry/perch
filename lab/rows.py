import sys, json
want = sys.argv[2] if len(sys.argv) > 2 else ""
for l in open(sys.argv[1]):
    if not l.startswith('{"case"'): continue
    d = json.loads(l)
    if "instructions" not in d or d["case"].startswith("factory"): continue
    c = d["case"]
    if want and want not in c: continue
    print("%5.1f%% instr %5.1f%% mem fp %3d w %3d | %s" % (d["instructions"]/4e6, d["mem_bytes"]/419430.4, d["read_entries"], d["write_entries"], c[:140]))
