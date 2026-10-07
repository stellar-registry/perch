# Raw results index

Every `.log` here is the unedited stdout+stderr of one `lab/run.sh` (or the
equivalent `cargo test ... cap_sweep` command) run. Rows are the JSON lines
`release_stack.rs`'s `report()` prints (`{"case":...}`); `{"keys_of":...}`
lines (with `PERCH_KEYS=1`) list the contract-data keys a completion changed,
grouped by contract (first 6 hex digits of its id) and key type.

Shapes are `signers,capped,interp,plain,fan,bytes` (`PERCH_CAP_SWEEP`); a
document has `2 + capped + interp + plain` rules. Flows are `WORST_FLOWS`
indices (`PERCH_FLOWS`), defined in `EXPERIMENT.md`. Stacks are described in
`lab/stacks/*.build.json`.

Early logs ran before flows 5 to 7 existed; their flow set says so. Indices
0 to 4 mean the same thing in every log.

| Log | Stack | Shapes | Flows | Notes |
| --- | --- | --- | --- | --- |
| `sweep-A.log` | lab-stack | `6,11,0,0,6` | 0-4 | No byte argument, so padded to the raised 32 KiB cap: not comparable to the others. Kept as the first reproduction. |
| `sweep-A8.log` | lab-stack | `6,11,0,0,6,8192` | 1,2 | Reproduces #107's binding row exactly (254.7M, 27.1 MB, 296 sweep footprint, 141 written); written-key breakdown. |
| `both.log` | lab-stack | `6,{5,8,11,12,14,16},0,0,6,8192` | 0-4 | Capped-rule slope at 6 signers. |
| `interp.log` | lab-stack | `6,0,{5,11,16,20,24},0,6,8192` | 0-4 | 22 and 26 rules do not fit 8 KiB (skipped). |
| `plain.log` | lab-stack | `6,0,1,{4,10,20,30,37},6,8192` | 0-4 | One interpreter rule carries the padding (see EXPERIMENT.md, known issues). 40 rules do not fit. |
| `fan.log` | lab-stack | `6,11,0,0,1`, `6,11,0,0,3`, `6,16,0,0,1`, `6,5,0,0,1` (all `,8192`) | 0-4 | Signers named per rule. |
| `mixed.log` | lab-stack | `6,6,6,6,6`, `6,4,8,12,6`, `6,8,4,4,6` (all `,8192`) | 0-4 | 26 rules do not fit. |
| `frontier.log` | lab-stack | `2,{16,17},0,0,2`; `4,{14,15},0,0,4`; `8,{10,11},0,0,8`; `10,{8,9},0,0,10`; `12,{5,6},0,0,12`; `15,{2,3},0,0,15` (all `,8192`) | 0-4 | Frontier with the corrected footprint count. |
| `w2-normal.log` | lab-stack | `6,{11,12},0,0,6,8192` | 2,5 | First reparam measurement. |
| `w2-inplace.log` | lab-stack-inplace | `6,{11,12,14,16,18},0,0,6,8192` | 0,1,3,5 | W2: every editable rule edited in place. |
| `f5-frontier.log` | lab-stack | `2,15,0,0,2`; `4,14,0,0,4`; `6,12,0,0,6`; `8,10,0,0,8`; `10,{8,7},0,0,10`; `12,{6,5},0,0,12`; `15,3,0,0,15` (all `,8192`) | 2,4,5 | Frontier with reparam. |
| `f5-interp.log` | lab-stack | `6,0,{11,14,16,18},0,6,8192` | 2,4,5 | |
| `f5-plain.log` | lab-stack | `6,0,1,{30,35},6,8192` | 2,4,5 | 38 rules do not fit. |
| `f5-mixed.log` | lab-stack | `6,6,6,6,6`, `6,8,4,4,6`, `6,4,8,8,6` (all `,8192`) | 2,4,5 | |
| `w3.log` | lab-stack | `6,{11,12},0,0,6`; `6,0,{14,15},0,6`; `8,10,0,0,8`; `10,8,0,0,10`; `4,14,0,0,4` (all `,8192`) | 5,6,7 | Reprogram and recap. The interpreter-only rows appear in SUMMARY.md's capped table with Capped = 0. |
| `w3b.log` | lab-stack | `2,{15,14},0,0,2`; `4,13,0,0,4`; `8,9,0,0,8`; `10,7,0,0,10`; `12,{6,5},0,0,12`; `15,{3,2},0,0,15` (all `,8192`) | 5,6,7 | |
| `w3-mixed.log` | lab-stack | `6,6,6,6,6`, `6,8,4,4,6`, `6,4,8,8,6`, `6,3,10,0,6`, `6,0,1,34,6` (all `,8192`) | 0-7 | 37 rules do not fit. |
| `w1.log` | lab-stack-w1 | `6,{11,12,13,14},0,0,6`; `6,0,{16,18},0,6`; `8,10,0,0,8`; `10,8,0,0,10` (all `,8192`) | 0-7 | W1: OZ's per-call canonical-duplicate verifier call compiled out. |

`SUMMARY.md` is generated from these logs by `lab/merge.py`.
