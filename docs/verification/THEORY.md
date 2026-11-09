# What perch can enforce, as a theorem

Perch's constraint on itself, that every predicate is stateless and ranges over a *single*
invocation, reads as a design choice (see the README's "Stateless predicates and cumulative caps"
section). Enforceability theory turns it into a theorem: it says exactly which policies a
perch-style monitor can enforce, and shows that the rest need a strictly stronger monitor.

## The framing

Model an execution as the (finite or infinite) sequence of authorization-relevant events a
smart account observes; for perch the alphabet is **invocations**:

```
inv = (contract, function, args, signer-set, ledger-seq)
```

A **security policy** is a set of acceptable executions. Schneider's classic result
("Enforceable Security Policies", ACM TISSEC 2000) is that an *execution monitor*, a watcher
that sees events one at a time and can only halt the target (deny), can enforce exactly the
safety properties: policies where every violating execution has a finite prefix after which
the violation is irrevocable. A monitor cannot enforce liveness ("the admin key can always
eventually rotate signers") because no finite prefix ever proves liveness has failed.

The account's `__check_auth`, which decides each authorization with rule-eval's `check_auth`
over its stored rules, is such a monitor, as is the legacy interpreter's `Policy::enforce`.
The Soroban host presents each invocation *before its effects execute*, and the check's only
power is to allow or abort. So Schneider's upper bound applies verbatim.

## Where perch sits inside that bound

Schneider's monitors may keep state, an automaton state updated on every event. Apart from a
rule's cap (below), Perch keeps none: it evaluates a rule's pure predicate `P(inv)` and
forgets the invocation. In automata terms, that predicate is a memoryless (single-state)
truncation automaton.

**Claim.** A memoryless truncation automaton enforces exactly the policies of the form

> every invocation in the execution satisfies `P`,

i.e. the per-invocation safety properties, those whose violating prefixes are
determined by their last event alone.

*Why:* with a single state, the transition function degenerates to an accept/reject predicate
on the current event; conversely any such predicate is trivially a one-state automaton. ∎

The constraint language (the frozen v1 op set: `FnIn`, arg predicates, `MinSigners`, ledger
windows, under `All`/`Any`/`Not`) is a boolean algebra over decidable atomic predicates on
`inv`. So what a perch document denotes is a per-invocation safety property, and *every*
per-invocation safety property over the atoms' vocabulary is expressible. Fail-closed
evaluation (decode failure ⇒ `Unknown` ⇒ deny; see `Verdict`) only ever *shrinks* the accepted
set, which is the safe direction for a safety property. Enforcement remains sound when the
monitor can't decide, at the price of precision, never of soundness.

## What provably needs more than perch

- **Cumulative limits.** Spend caps, rate limits, "at most N per day". The violating prefix
  is determined by the *running total*, not the last event. Enforcing it requires automaton
  state that counts, i.e. a multi-state security automaton. This is why a rule's `cap` is a
  spending record the account keeps, which rule-eval charges with every transfer it allows,
  rather than a predicate, and why no amount-shaped per-call predicate should be documented
  as a spend cap (a per-call bound is satisfied by every prefix of a repeat-caller's spree).
- **Ordering / protocol rules.** "Configure before use" and "no publish after revoke-request"
  need state again (typestate-flavored safety).
- **Liveness / availability.** No execution monitor, stateful or not, can enforce "the
  account can always recover" (Schneider). Perch addresses the adjacent risks in its design
  instead. Account recovery ([`../recovery/spec.md`](../recovery/spec.md)) is ordinary
  stateful contract logic in a controller, and the account decides a recovery completion
  over its record of the recovery rule and the controller's `rcv_complete`, never the
  evaluator, so an evaluator deny bug cannot keep an account from recovering (INV-2). This
  is a design mitigation, not a monitored property.
- **Result-dependent policies.** Predicates over what the call *returned*. The monitor runs
  before effects; only suppression/insertion monitors (Bauer–Ligatti–Walker *edit automata*,
  IJIS 2005) can act there, and a `__check_auth` hook has no insertion power.

Basin et al.'s refinement ("Enforceable Security Policies Revisited", TISSEC 2013)
distinguishes actions a monitor merely *observes* from those it *controls*. In Soroban terms,
perch controls invocations authorized through the smart account; it only observes (and cannot
constrain) ledger time, other accounts' calls, or re-entrant paths not routed through
`__check_auth`. Read policy documents with that scoping in mind. `LedgerBefore` is a condition on
an observed clock, not control over it.

## Why this matters for the proofs

The Lean model ([`formal/README.md`](../../formal/README.md); coverage in
[PLAN.md](./PLAN.md)) states its evaluator and lowering theorems against a model whose
semantic domain is a single invocation. This note is the license for that. By the claim above,
modeling one invocation at a time loses nothing the artifact can enforce. Conversely, any
future feature that adds state to the predicate evaluator (a counter, a nonce, a seen-set)
leaves this fragment. It would change the enforceable class, the model's domain, and the
theorems' shape. Treat it as a new design, not an incremental op.

## References

- F. B. Schneider, *Enforceable Security Policies*, ACM TISSEC 3(1), 2000.
- L. Bauer, J. Ligatti, D. Walker, *More Enforceable Security Policies* / *Edit Automata:
  Enforcement Mechanisms for Run-time Security Policies*, IJIS 4(1–2), 2005.
- D. Basin, V. Jugé, F. Klaedtke, E. Zălinescu, *Enforceable Security Policies Revisited*,
  ACM TISSEC 16(1), 2013.
