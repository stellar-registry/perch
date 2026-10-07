# Summary (generated)

`python3 lab/merge.py "pr103=lab/results/pr103.log"`. Footprint is the network count (RO+RW). Bold = over 75%.

| Family | Signers | Rules | Capped | Fan | Instr | Memory | Footprint (RO+RW) | Written | Write bytes | Events | Binding |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| pr103 | 6 | 8 | 6 | 6 | 56.3% | 44.0% | 31.2% | 55.5% | 35.4% | 72.9% | Events: compromise completion (the thief renamed every rule) |

Completion rows (instructions, memory, footprint RO+RW, written, sweep footprint, event bytes):

| Flow | Instructions | Memory | Footprint | Written | Sweep footprint | Events |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Combined, ZK rotation, every signer revoked | 221.1M (55.3%) | 17.5 MB (41.6%) | 117 (29.2%) | 101 (50.5%) | 218 | 10636 |
| compromise, Combined, ZK rotation, both key sets revoked; the thief kept every rule | 224.2M (56.1%) | 18.4 MB (43.9%) | 123 (30.8%) | 107 (53.5%) | 230 | 11428 |
| compromise, Combined, ZK rotation, both key sets revoked; the thief renamed every rule | 215.8M (53.9%) | 18.3 MB (43.6%) | 125 (31.2%) | 111 (55.5%) | 236 | 11940 |
| compromise, Combined, ZK rotation, both key sets revoked; the thief kept every name but changed every policy | 225.1M (56.3%) | 18.4 MB (44.0%) | 123 (30.8%) | 107 (53.5%) | 230 | 11428 |
| compromise, Combined, ZK rotation, both key sets revoked; the thief kept every name but changed every program | 224.6M (56.2%) | 18.4 MB (44.0%) | 123 (30.8%) | 107 (53.5%) | 230 | 11428 |
| compromise, Combined, ZK rotation, both key sets revoked; the thief kept every name but changed every cap | 225.0M (56.2%) | 18.4 MB (44.0%) | 123 (30.8%) | 107 (53.5%) | 230 | 11428 |
