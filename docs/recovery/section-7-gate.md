# Release gate: pending-activity policy (open, release-blocking)

**Status: OPEN. This is a release-blocking gate, not a design note.** No
recovery-enabled account should be deployed to production, and no
integration should advertise recovery as safe to rely on, until this gate is
explicitly resolved by the party the follow-up review named to resolve it
(the captain) — not by this codebase, not by a library default, and not by
this PR.

This mirrors the authoritative decision record's §7 verbatim: *"Decision
status: OPEN, deliberately deferred by the user. No default selected."* That
review also warns explicitly: *"Do not infer an answer from expiry
behavior, the protection profile name, or the fact that this write-up is
finished."* The same warning applies to this codebase shipping: **do not
infer that landing this PR resolves the question.**

## What is open

Whether ordinary account-authorized execution, and ordinary policy-mutation
attempts, continue or are blocked while a recovery attempt is pending — and
whether lost-key and suspected-compromise attempts should behave
differently on this axis. Three candidate behaviors were on the table:
freeze, continue, and restrict-selected-operations. None was selected.

## What this codebase does and does not do about it

- **The schema forces an explicit, no-default choice per account.**
  `RecoveryConfig::pending_activity` (`crates/perch-ir/src/doc.rs`) is a
  required field with exactly two variants, `Freeze` and `Continue`, and no
  `Default` implementation. `restrict-selected-operations` is deliberately
  **not modeled** — adding it needs an explicit capability-boundary design
  this stage did not do, so it is out of scope rather than half-built. An
  enrolling document must name one of the two modeled choices; there is no
  way to enroll recovery without making this choice reviewable in the
  document itself.
- **Blocking ordinary *policy-document* mutation while an attempt is
  pending is not part of this open question, and is already enforced
  unconditionally.** The controller refuses `apply_doc` calls not
  authorized by the recovery evidence itself while an attempt is pending —
  see [`controller-governance.md`](controller-governance.md) — regardless
  of the enrolled `pending_activity` value. This is required for property 9
  (configuration consistency) independent of §7: without it, an admin could
  race a pending attempt with a conflicting document change, which §7 never
  proposed making optional. `pending_activity` governs a narrower,
  genuinely-open question: **ordinary contract calls the account authorizes
  that are not policy mutation at all** (moving funds, calling another
  contract) — the freeze/continue axis §7 actually names.
- **`Freeze`/`Continue` are recorded and queryable, not fully wired end to
  end.** The controller exposes the pending attempt's state and the
  enrolled policy so an integration can check it. Actually *enforcing*
  `Freeze` against arbitrary non-recovery context rules would require
  threading a pending-recovery check through perch-interpreter's
  context-rule evaluation for every rule, not only the recovery-authorizing
  one — a cross-cutting change to the interpreter's evaluation path that is
  explicitly **not implemented in this stage**. Until it is, an account
  enrolled with `Freeze` records that intent reviewably, but does not yet
  have it mechanically enforced against every other rule on the account.
  Shipping that enforcement is itself gated on §7 actually being resolved
  (there is no point hardening a mechanism for a policy that might change).

## What must happen before production reliance

1. The captain (or whoever the follow-up review names as the decision
   owner) resolves §7: freeze, continue, restrict, or some other
   precisely-defined rule — including the related, separately-named
   question of what happens to a *stale lost-key source snapshot* when
   ordinary policy writes are attempted during a pending attempt (block,
   invalidate the attempt, or another explicit conflict rule; see the
   follow-up review §4.2 and §7).
2. If the resolution requires enforcement beyond what `pending_activity`
   already records (i.e. anything beyond "freeze policy mutation," which is
   already unconditional), that enforcement is designed and implemented as
   its own reviewed change — not inferred from this document or shipped
   silently alongside an unrelated change.
3. Only after both of the above should `Protected`-profile, `Freeze`- or
   `Continue`-enrolled accounts intended to resist a compromised admin be
   treated as production-ready for that specific guarantee.

Until then: this schema field and the controller's current behavior are
available for experimentation, review, and further design work — not for a
production deployment relying on the pending-activity guarantee to hold.
