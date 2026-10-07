import sys, json
want = sys.argv[2]
for l in open(sys.argv[1]):
    if not l.startswith('{"case"'): continue
    d = json.loads(l)
    if "instructions" not in d or want not in d["case"] or "completion" not in d["case"]: continue
    c = d["case"].split("(")[1].split(")")[0] if "(" in d["case"] else d["case"]
    print("| %s | %.1fM (%.1f%%) | %.1f MB (%.1f%%) | %d (%.1f%%) | %d (%.1f%%) | %d | %d |" % (c[:160], d["instructions"]/1e6, d["instructions"]/4e6, d["mem_bytes"]/1e6, d["mem_bytes"]/419430.4, d["read_entries"], d["read_entries"]/4, d["write_entries"], d["write_entries"]/2, d["footprint_entries"], d["events_bytes"]))
