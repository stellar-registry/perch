# Wire-format benchmark: node arena vs postfix (RPN)

Issue: <https://github.com/stellar-registry/perch/issues/2>

Both candidate encodings of the on-chain constraint program are implemented
side by side in this crate (`arena` and `rpn` modules, sharing the `leaf`
evaluation semantics and the Kleene `Verdict`). This report records their
real, metered evaluation cost as compiled wasm, and recommends which format
to freeze. Neither implementation is deleted — the freeze decision happens
on top of these numbers.

## Methodology

Metered costs only accrue to code executing **as wasm** — native test
execution goes through unmetered host-native code and would understate
everything. So:

1. Each encoding is wrapped in a minimal bench-only `#[contract]` crate
   (`crates/perch-bench-arena`, `crates/perch-bench-rpn`) exposing
   `validate(program)` and
   `eval(program, context, signer_count, self_addr)`. Two separate
   contracts so each wasm's size isolates one encoding's code contribution.
2. Both are built with `cargo build --target wasm32v1-none --release`
   (workspace release profile: `opt-level = "z"`, LTO, panic=abort; no
   `wasm-opt` post-pass — it would shrink both wasms but not change the
   comparison).
3. The harness test (`crates/perch-bench/tests/metered.rs`) registers each
   contract **from its wasm bytes** (`env.register(&wasm[..], ())`) so every
   call runs through the metered wasm VM, then invokes `validate` and
   `eval` once per matrix program and reads
   `env.cost_estimate().resources()`. That reading covers exactly the last
   top-level invocation (it resets before every top-level call), so each
   row is one call, nothing else.
4. Serialized program size is the length of the program's XDR
   (`ToXdr::to_xdr`), i.e. the bytes that would sit in ledger storage /
   the install invocation.

Programs are constructed deterministically (no randomness) from a shared
abstract `Spec` lowered into both encodings, so every comparison is the
same logical program; the harness asserts both encodings produce the same
verdict natively and metered before recording anything.

Composites deliberately do **not** short-circuit in either encoding: every
node is evaluated, so measured cost depends on program shape only, not on
runtime data, and the two encodings do identical logical work per program.
(Short-circuiting is discussed under "Analysis" — it is an arena-only
option, and giving it to arena would have made the comparison
data-dependent.)

Matrix:

- **ci-publish (4 nodes)** — the expected common case:
  `All(MinSigners(1), FnIn["publish","yank"], ArgAddrIsSelf(1))`,
  1 authenticated signer.
- **mixed-8 / mixed-32 / mixed-64** — synthetic mixed-op programs with
  exactly 8/32/64 nodes: a root `All` over a `Not(LedgerBefore)` subtree
  and a nested `Any` (itself containing a `Not`), padded with leaves
  cycling through all leaf kinds so dispatch is realistic; 2 signers.

The evaluation context is a contract-call context
(`transfer(42u32, Symbol("transfer"), self_addr)`), which exercises True,
False, and Unknown (decode-failure) leaf paths. All matrix programs
evaluate to `False` in both encodings (identical work either way — no
short-circuit).

Reproduce with `just bench`. Numbers below are from a run on 2026-08-07,
soroban-sdk 26.0.1 / soroban-env-host 26.1.3, rustc stable, Apple Silicon
(instruction counts are the host's cost model, not hardware-dependent).

## Numbers

| program | encoding | eval cpu insns | eval mem bytes | validate cpu insns | program XDR bytes |
|---|---|---:|---:|---:|---:|
| ci-publish (4 nodes) | arena | 427,825 | 1,204,423 | 392,893 | 272 |
| ci-publish (4 nodes) | rpn   | 434,303 | 1,204,816 | 375,027 | 240 |
| mixed-8  | arena | 533,597   | 1,204,543 | 495,019   | 420   |
| mixed-8  | rpn   | 526,495   | 1,204,912 | 460,233   | 352   |
| mixed-32 | arena | 1,408,004 | 1,205,695 | 1,126,897 | 1,800 |
| mixed-32 | rpn   | 1,325,278 | 1,206,064 | 1,003,527 | 1,540 |
| mixed-64 | arena | 2,573,880 | 1,207,231 | 1,969,401 | 3,640 |
| mixed-64 | rpn   | 2,390,322 | 1,207,600 | 1,727,919 | 3,124 |

Bench contract wasm sizes (identical scaffolding, so the delta is the
encoding machinery):

| bench contract | wasm bytes |
|---|---:|
| perch_bench_arena.wasm | 14,832 |
| perch_bench_rpn.wasm   | 15,457 |

## Analysis

**Eval CPU.** The crossover sits between 4 and 8 nodes. At the 4-node
common case arena is 1.5% cheaper (6,478 insns — noise against the ~380k
per-invocation VM floor, and 0.002% of the 400M per-transaction budget).
From 8 nodes up RPN wins, and the gap widens with size: 1.3% at 8, 5.9% at
32, 7.1% at 64. Marginal cost per node (mixed-8 → mixed-64 slope):
~36.4k insns/node arena vs ~33.3k insns/node RPN. The reason: arena
composites carry a `Vec<u32>` of child indices — a host object per
composite plus a metered `vec_get` per child edge on top of the per-node
fetch both encodings pay; RPN combiners pop verdicts from a wasm-local
array, which the host meters as plain wasm instructions. Both scale
linearly; there is no second crossover.

**Validate CPU.** RPN is cheaper at every size (4.5% at 4 nodes, 12.3% at
64): stack-effect simulation reads each op's arity and keeps one counter,
while arena validation must iterate every child-index vector (host reads
per edge) to prove forward-only references.

**Memory.** Identical to within ~400 bytes at every size; both are
dominated by the fixed ~1.2 MB VM-instantiation baseline. RPN's fixed
128-slot verdict stack costs nothing measurable.

**Wire size.** RPN is smaller for every program (11.8% at 4 nodes, 14.2%
at 64) because composites encode as `(op, arity)` with no child-index
vectors. This is rent-bearing ledger state per installed policy, so it
compounds across installs.

**Wasm size.** Arena's contract is 625 bytes smaller (14,832 vs 15,457);
the explicit stack loop and its underflow guards compile slightly larger.
One-time, per-interpreter-deployment cost; both trivial.

**Validation complexity.** RPN's validator is O(ops) with O(1) state, and
validity gives a strong structural guarantee: every op pushes exactly one
value and the program nets to one, so `pops = ops − 1` — every
intermediate verdict is consumed exactly once and **dead code is
unrepresentable** in a valid program. Arena's single forward pass proves
acyclicity (that is the point of forward-only indices), but must also
check per-edge range and arity, and *unreachable nodes remain
representable* — rejecting them would need an extra reachability pass that
the current validator deliberately does not do.

**Decompilability.** Arena is already tree-shaped: pretty-printing walks
from node 0. RPN reconstructs the AST with the standard single reverse
pass (pop one subtree per operand); equally mechanical, and the
no-dead-code property means the decompiled tree is exactly the whole
program. Neither format obscures anything from an explorer/audit tool.

**Short-circuiting (arena's one structural advantage).** A tree walk
could skip whole subtrees on `All`-meets-`False` / `Any`-meets-`True`;
RPN evaluates operands before their combiner and cannot. Two reasons this
doesn't move the decision: budgets and fees must provision for the
worst case, which short-circuiting doesn't improve; and at realistic
policy sizes the entire evaluation is ≤ 2.6M insns — 0.65% of one
transaction's 400M CPU allowance.

## Recommendation

**Freeze the postfix (RPN) encoding.**

- Cheaper to evaluate at every size from 8 nodes up (to −7.1% at 64),
  and the 4-node case where arena wins by 1.5% is inside measurement
  noise relative to the invocation floor.
- Cheaper to validate at every size (−4.5% to −12.3%).
- Smaller on the wire at every size (−11.8% to −14.2%) — recurring
  ledger-rent savings per installed policy.
- Materially simpler validator (one counter) with a stronger guarantee:
  valid programs cannot contain dead ops, whereas arena admits
  unreachable nodes unless a second pass is added.
- Arena's remaining advantages — 625 bytes of one-time wasm and the
  *option* of short-circuit evaluation — are immaterial at policy scale
  (≤ 256 ops by `MAX_PROGRAM_LEN`, ≤ 0.65% of a transaction's CPU
  budget worst-case).

## Caveats

- Absolute numbers include the fixed per-invocation cost (VM
  instantiation, argument decode); the ~375–393k "validate ci-publish"
  rows approximate that floor. Encoding deltas are the meaningful signal;
  slopes above isolate the per-node marginal cost.
- Wasms are `opt-level = "z"` + LTO release builds without a `wasm-opt`
  pass; `stellar contract build --optimize` would shrink both but not
  reorder them.
- Instruction counts come from soroban-env-host 26.1.3's calibrated cost
  model (protocol-version dependent), not wall-clock; they are what the
  network bills against, which is the quantity that matters.
- Eval performs identical logical work in both encodings by design (no
  short-circuit); an arena interpreter *with* short-circuiting would beat
  these arena numbers on favorable data, but not in the worst case that
  budgets must provision for.

## Decision

The postfix (RPN) encoding is **frozen as perch-program v1**, on the
numbers and analysis above. The arena implementation (the `arena` module,
its bench contract `perch-bench-arena`, and its tests) was removed in this
commit; it remains retrievable at the previous commit, alongside the exact
code both columns of the tables were measured from. The RPN bench contract
and harness are kept as an instruction-count canary for the frozen format
(`just bench`).
