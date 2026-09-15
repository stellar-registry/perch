# Open decision: activity during a pending recovery attempt (release-blocking)

**Status: OPEN. This is a release-blocking gate, not a design note.** No
recovery-enabled account should be deployed to production, and no
integration should advertise recovery as safe to rely on, until this
decision is made explicitly by whoever operates the account or protocol —
not inferred from this codebase, not defaulted by the library, and not
resolved by this change.

## The question

While a recovery attempt is pending — from the moment its evidence is
satisfied until it completes, is cancelled, or expires — should the
account's *ordinary*, admin-authorized activity (calling other contracts,
moving funds) continue, or be frozen? And should lost-key and
suspected-compromise attempts behave differently on this axis?

This is deliberately unresolved, and the schema encodes that: an account
enrolling recovery must name `pending_activity` explicitly
(`RecoveryConfig::pending_activity`, `crates/perch-ir/src/doc.rs`) as either
`Freeze` or `Continue` — there is no default, and no way to enroll recovery
without making this choice. A third candidate, restricting only *selected*
operations rather than all-or-nothing, was considered and is **not
modeled** — it needs an explicit capability-boundary design this change does
not attempt, so it's left out entirely rather than half-built.

Each candidate has a real cost:

- **Freeze everything.** Limits what a compromised admin can do during the
  delay window, at the cost of the account's own availability for that
  window — including for the legitimate owner, if the attempt turns out to
  be spurious or contested.
- **Continue everything.** Preserves availability, at the cost that a
  genuinely compromised admin can keep acting — including moving funds or
  changing external state — for the entire delay window before recovery
  takes effect.
- **Restrict selectively** (not modeled here). Could in principle preserve
  more of both properties, but requires deciding *which* operations are safe
  to continue and building the machinery to distinguish them — real design
  and implementation work this change does not do.

Do not infer an answer from any of: the delay/expiry timing values an
account chooses, the `Protected` profile's name, or the fact that this
document is otherwise complete. None of those settle the tradeoff above.

## What is, and is not, already enforced

- **Blocking a *conflicting policy-document change* while an attempt is
  pending is a separate, already-decided property — not part of this open
  question.** The controller refuses any `apply_doc` call not authorized by
  the recovery evidence itself while an attempt is pending (see
  [`controller-governance.md`](controller-governance.md)), regardless of the
  enrolled `pending_activity` value. This has to hold unconditionally:
  without it, an admin could race a pending attempt with a conflicting
  document change, silently reinterpreting what the attempt was approved
  against. `pending_activity` governs something narrower and genuinely
  open: **ordinary contract calls the account authorizes that are not a
  policy-document change at all** (moving funds, calling another contract)
  — the freeze/continue tradeoff described above.
- **`Freeze`/`Continue` are recorded and queryable, not mechanically
  enforced end to end.** The controller exposes the pending attempt's state
  and the enrolled policy so an integration can check it. Actually
  *enforcing* `Freeze` against arbitrary non-recovery context rules would
  require threading a pending-recovery check through the interpreter's
  context-rule evaluation for every rule on the account, not only the
  recovery-authorizing one — a cross-cutting change to the interpreter's
  evaluation path that this change does not make. Until that exists, an
  account enrolled with `Freeze` records that intent reviewably, but does
  not yet have it mechanically enforced against every other rule on the
  account. There is little point building that enforcement machinery before
  the tradeoff above is actually decided, since the answer shapes what needs
  building.

## What must happen before production reliance

1. Whoever operates the account/protocol decides: freeze, continue,
   restrict (which would first need its own design), or some other
   precisely-defined rule — including the related question of what happens
   to a *stale lost-key source document* if an ordinary policy write is
   attempted while an attempt targeting an older snapshot is pending (block
   the write, invalidate the attempt, or another explicit conflict rule —
   this change does not silently choose overwrite-or-merge behavior for
   that case; see [`schema.md`](schema.md) for how a lost-key target is
   constructed).
2. If the decision requires enforcement beyond what's already unconditional
   (blocking conflicting document changes), that enforcement is designed and
   implemented as its own reviewed change.
3. Only after both of the above should `Protected`-profile,
   recovery-enrolled accounts be treated as production-ready for resisting a
   compromised admin specifically during the pending window.

Until then: this schema field and the controller's current behavior are
available for experimentation, review, and further design work — not for a
production deployment relying on the pending-activity guarantee to hold.
