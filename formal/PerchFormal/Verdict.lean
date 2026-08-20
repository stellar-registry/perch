/-!
# The Kleene three-valued verdict lattice

Model twin of `Verdict` in `crates/perch-program/src/lib.rs`, ordered
`F < U < T`: conjunction is minimum, disjunction is maximum, negation swaps the
definite verdicts and fixes `U`. Only `T` authorizes — `U` denies, and is
preserved under negation, which is the fail-closed property the whole design
leans on (theorem `neg_unknown` / `allows_neg_unknown` below).
-/

namespace PerchFormal

inductive Verdict where
  | F
  | U
  | T
deriving DecidableEq, Repr

namespace Verdict

/-- Conjunction: the minimum under `F < U < T`. -/
def and : Verdict → Verdict → Verdict
  | F, _ => F
  | _, F => F
  | U, _ => U
  | _, U => U
  | T, T => T

/-- Disjunction: the maximum under `F < U < T`. -/
def or : Verdict → Verdict → Verdict
  | T, _ => T
  | _, T => T
  | U, _ => U
  | _, U => U
  | F, F => F

/-- Negation: `U` stays `U`. -/
def neg : Verdict → Verdict
  | F => T
  | U => U
  | T => F

/-- A decoded boolean check is always definite. -/
def ofBool : Bool → Verdict
  | true => T
  | false => F

/-- Whether this verdict authorizes. Only `T` does. -/
def allows : Verdict → Bool
  | T => true
  | _ => false

/-! ## T1 — lattice laws -/

theorem and_comm (a b : Verdict) : and a b = and b a := by
  cases a <;> cases b <;> rfl

theorem and_assoc (a b c : Verdict) : and (and a b) c = and a (and b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem or_comm (a b : Verdict) : or a b = or b a := by
  cases a <;> cases b <;> rfl

theorem or_assoc (a b c : Verdict) : or (or a b) c = or a (or b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem de_morgan_and (a b : Verdict) : neg (and a b) = or (neg a) (neg b) := by
  cases a <;> cases b <;> rfl

theorem de_morgan_or (a b : Verdict) : neg (or a b) = and (neg a) (neg b) := by
  cases a <;> cases b <;> rfl

theorem neg_neg (a : Verdict) : neg (neg a) = a := by
  cases a <;> rfl

theorem and_T_left (a : Verdict) : and T a = a := by cases a <;> rfl

theorem and_F_left (a : Verdict) : and F a = F := rfl

theorem and_F_right (a : Verdict) : and a F = F := by cases a <;> rfl

/-- Rebalancing lemma used to reorder folds. -/
theorem and_right_comm (a b c : Verdict) : and (and a b) c = and (and a c) b := by
  cases a <;> cases b <;> cases c <;> rfl

/-! ## T2 — fail-closed root -/

/-- `U` never authorizes. -/
theorem allows_unknown : allows U = false := rfl

/-- `F` never authorizes. -/
theorem allows_false : allows F = false := rfl

theorem allows_iff (v : Verdict) : allows v = true ↔ v = T := by
  cases v <;> simp [allows]

/-- The fail-open trap this design closes: a decode failure (`U`) under
negation still denies — `neg U = U` and `U` does not allow. -/
theorem neg_unknown : neg U = U := rfl

theorem allows_neg_unknown : allows (neg U) = false := rfl

/-- An `U` conjunct can never raise a verdict to `T`: the conjunction with an
unknown is at most `U`. -/
theorem and_unknown_never_allows (a : Verdict) : allows (and U a) = false := by
  cases a <;> rfl

end Verdict

end PerchFormal
