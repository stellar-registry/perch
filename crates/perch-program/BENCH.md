# Wire-format benchmark: the postfix (RPN) program encoding

perch-program v1 encodes a constraint program in postfix (RPN): a flat list
of ops, each leaf pushing one verdict and each combiner (`All(n)`,
`Any(n)`, `Not`) popping its operands. This file records the metered cost of
evaluating and validating that encoding as compiled Wasm, and the
benchmark that measures it. `just bench` is an instruction-count canary
for the frozen format. Full-transaction costs of the deployed contracts are
in [`docs/recovery/budgets.md`](../../docs/recovery/budgets.md).

## Properties of the encoding

- `validate` is one pass over the ops with one counter (a stack-effect
  simulation): O(ops) time, O(1) state. A valid program never underflows,
  never exceeds `MAX_STACK_DEPTH` (128), and nets exactly one verdict, so
  every intermediate verdict is consumed once and a valid program contains
  no dead ops.
- `MAX_PROGRAM_LEN` is 256 ops. Evaluation has no recursion and no backward
  jump, so it always halts.
- Combiners pop verdicts from a fixed Wasm-local stack, which the host meters
  as plain Wasm instructions; composites carry no child-index vectors.
- Combiners do not short-circuit: every op is evaluated, so the cost of a
  program depends on its shape, not on the invocation's data. Budgets and
  fees provision for that worst case.
- A program's tree is recoverable by one reverse pass (pop one subtree per
  operand).

## Method

Metered costs accrue only to code executing as Wasm; native test execution
is unmetered. So:

1. The encoding is wrapped in a bench-only contract, `crates/perch-bench-rpn`,
   exposing `validate(program)` and
   `eval(program, context, signer_count, self_addr)`.
2. It is built with `cargo build --target wasm32v1-none --release` (the
   workspace release profile: `opt-level = "z"`, LTO, `panic = "abort"`; no
   `wasm-opt` pass).
3. The harness (`crates/perch-bench/tests/metered.rs`) registers the
   contract from its Wasm bytes, so every call runs through the metered Wasm
   VM, and invokes `validate` and `eval` once per program, reading
   `env.cost_estimate().resources()` after each. That reading covers exactly
   the last top-level invocation, so each row is one call.
4. Program size is the length of the program's XDR (`ToXdr`): the bytes
   stored in ledger state per installed rule.

Programs are built deterministically from an abstract shape. The harness
checks that each program validates and that the native and metered verdicts
agree before recording anything.

- **ci-publish (4 ops)**, the common case:
  `All(MinSigners(1), FnIn["publish","yank"], ArgAddrIsSelf(1))`, one
  authenticated signer.
- **mixed-8 / mixed-32 / mixed-64**: synthetic programs of exactly 8, 32,
  and 64 ops: a root `All` over a `Not(LedgerBefore)` subtree and a nested
  `Any` (itself containing a `Not`), padded with leaves cycling through
  every leaf kind; two signers.

The evaluation context is a contract call
(`transfer(42u32, Symbol("transfer"), self_addr)`) that exercises `True`,
`False`, and `Unknown` (decode-failure) leaf paths. Every program evaluates
to `False`.

## Numbers

Recorded 2026-08-07 with soroban-sdk 26.0.1 / soroban-env-host 26.1.3, rustc
stable, on Apple Silicon. Instruction counts come from the host's cost model
(protocol-version dependent), not from hardware. The workspace locks
soroban-sdk 27.0.6, and these rows were not re-recorded with it; `just
bench` prints the current values.

| program | eval cpu insns | eval mem bytes | validate cpu insns | program XDR bytes |
|---|---:|---:|---:|---:|
| ci-publish (4 ops) | 434,303 | 1,204,816 | 375,027 | 240 |
| mixed-8  | 526,495   | 1,204,912 | 460,233   | 352   |
| mixed-32 | 1,325,278 | 1,206,064 | 1,003,527 | 1,540 |
| mixed-64 | 2,390,322 | 1,207,600 | 1,727,919 | 3,124 |

`perch_bench_rpn.wasm` was 15,457 bytes.

- **Marginal cost.** About 33.3k instructions per op (mixed-8 to mixed-64),
  linear in program length.
- **Floor.** The ~375k-instruction `validate` of the 4-op program
  approximates the fixed per-invocation cost (VM instantiation, argument
  decoding); deltas between rows are the meaningful signal.
- **Memory.** The ~1.2 MB VM-instantiation baseline dominates; the 128-slot
  verdict stack adds nothing measurable.
- **Scale.** A 64-op program evaluates in about 2.4M instructions, under
  0.6% of a transaction's 400M-instruction limit.
