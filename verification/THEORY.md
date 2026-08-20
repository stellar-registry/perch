# What perch can enforce, as a theorem

Perch's constraint on itself — every predicate is stateless and ranges over a *single*
invocation — is usually presented as a design choice (see the README's "Stateless policies"
section). Enforceability theory makes it a theorem-shaped boundary: it tells us exactly which
policies a perch-style monitor *can* enforce, and proves the ones it can't need something
strictly stronger.

## The framing

Model an execution as the (finite or infinite) sequence of authorization-relevant events a
smart account observes; for perch the alphabet is **invocations**:

```
inv = (contract, function, args, signer-set, ledger-seq)
```

A **security policy** is a set of acceptable executions. Schneider's classic result
("Enforceable Security Policies", ACM TISSEC 2000) is that an *execution monitor* — a watcher
that sees events one at a time and can only halt the target (deny) — can enforce **exactly the
safety properties**: policies where every violating execution has a finite prefix after which
the violation is irrevocable. A monitor cannot enforce liveness ("the admin key can always
eventually rotate signers") because no finite prefix ever proves liveness has failed.

`Policy::enforce` in `perch-interpreter` (like any `__check_auth`-style hook) is precisely
such a monitor: the Soroban host presents each invocation *before its effects execute*, and
the policy's only power is to allow or abort. So Schneider's upper bound applies verbatim.

## Where perch sits inside that bound

Schneider's monitors may keep **state** — an automaton state updated on every event. Perch
deliberately keeps none: the interpreter evaluates a pure predicate `P(inv)` and forgets the
invocation. In automata terms, perch is a **memoryless (single-state) truncation automaton**.

**Claim.** A memoryless truncation automaton enforces exactly the policies of the form

> every invocation in the execution satisfies `P`,

i.e. the **per-invocation safety properties** — safety properties whose violating prefixes are
determined by their last event alone.

*Why:* with a single state, the transition function degenerates to an accept/reject predicate
on the current event; conversely any such predicate is trivially a one-state automaton. ∎

The constraint language (the frozen v1 op set: `FnIn`, arg predicates, `MinSigners`, ledger
windows, under `All`/`Any`/`Not`) is a boolean algebra over decidable atomic predicates on
`inv` — so what a perch document denotes is a per-invocation safety property, and *every*
per-invocation safety property over the atoms' vocabulary is expressible. Fail-closed
evaluation (decode failure ⇒ `Unknown` ⇒ deny; see `Verdict`) only ever *shrinks* the accepted
set, which is the safe direction for a safety property: enforcement remains sound when the
monitor can't decide, at the price of precision, never of soundness.

## What provably needs more than perch

- **Cumulative limits** — spend caps, rate limits, "at most N per day". The violating prefix
  is determined by the *running total*, not the last event. Enforcing it requires automaton
  state that counts, i.e. a multi-state security automaton. This is exactly why `cap:` lowers
  to OZ's stateful `spending_limit` policy attached to the same context rule rather than to
  interpreter ops, and why no amount-shaped per-call predicate should ever be documented as a
  spend cap (a per-call bound is satisfied by every prefix of a repeat-caller's spree).
- **Ordering / protocol rules** — "configure before use", "no publish after revoke-request":
  state again (typestate-flavored safety).
- **Liveness / availability** — "the account can always recover": not enforceable by *any*
  execution monitor, stateful or not (Schneider). Perch addresses the adjacent risk
  structurally instead: INV-2 lowers constraint-free admin rules policy-free, so an
  interpreter deny-bug cannot brick the admin path — a design mitigation, not a monitored
  property.
- **Result-dependent policies** — predicates over what the call *returned*: the monitor runs
  before effects; only suppression/insertion monitors (Bauer–Ligatti–Walker **edit automata**,
  IJIS 2005) get leverage there, and a `__check_auth` hook has no insertion power.

Basin et al.'s refinement ("Enforceable Security Policies Revisited", TISSEC 2013)
distinguishes actions a monitor merely *observes* from those it *controls*. In Soroban terms:
perch controls invocations authorized through the smart account; it only observes (and cannot
constrain) ledger time, other accounts' calls, or re-entrant paths not routed through
`enforce`. Policy documents should be read with that scoping in mind: `LedgerBefore` is a
condition on an observed clock, not control over it.

## Why this matters for the proofs

The verification plan ([PLAN.md](./PLAN.md)) states its theorems against a model whose
semantic domain is a single invocation. This note is the license for that: by the claim above,
nothing enforceable by the artifact is lost by modeling one invocation at a time. Conversely,
any future feature that smuggles state into the interpreter (a counter, a nonce, a seen-set)
leaves this fragment — it would change the enforceable class, the model's domain, and the
theorems' shape, and should be treated as a new design, not an incremental op.

## References

- F. B. Schneider, *Enforceable Security Policies*, ACM TISSEC 3(1), 2000.
- L. Bauer, J. Ligatti, D. Walker, *More Enforceable Security Policies* / *Edit Automata:
  Enforcement Mechanisms for Run-time Security Policies*, IJIS 4(1–2), 2005.
- D. Basin, V. Jugé, F. Klaedtke, E. Zălinescu, *Enforceable Security Policies Revisited*,
  ACM TISSEC 16(1), 2013.
