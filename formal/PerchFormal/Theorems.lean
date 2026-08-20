import PerchFormal.Lowering

/-!
# The theorems (PLAN.md T1–T6)

- **T1/T2** live in `Verdict.lean` (lattice laws, fail-closed root).
- **T3** (totality/termination) is inherent: `eval` is a total Lean function
  by structural recursion — there is nothing left to state.
- **T4** (`validated_no_structural_unknown` / `validate_sound`): a program
  accepted by `validate` never trips a defensive guard — the guarded machine
  agrees with an unguarded, purely structural one, so the verdict is a pure
  function of the leaves ("Validation ⇒ analyzable", `rpn.rs`).
- **T5** (`zero_signers_denied` / `zero_signers_never_allow`): a lowered rule
  denies — definite `F` — any invocation with zero authenticated signers.
  INV-1 at the model level.
- **T6** (`lowering_preserves`): the machine over the emitted postfix program
  computes exactly the rule's doc-level Kleene conjunction, with the op
  translation proved meaning-preserving per predicate (`leafEval_lowerPred`).
  The model-to-Rust link stays empirical (shared vectors + differential suite).
-/

namespace PerchFormal

/-! ## Fold auxiliaries -/

theorem foldl_and_shift (l : List Verdict) (e a : Verdict) :
    l.foldl Verdict.and (e.and a) = (l.foldl Verdict.and e).and a := by
  induction l generalizing e with
  | nil => rfl
  | cons x l ih =>
    simp only [List.foldl_cons]
    rw [Verdict.and_right_comm e a x]
    exact ih (e.and x)

theorem foldl_and_reverse (l : List Verdict) (e : Verdict) :
    l.reverse.foldl Verdict.and e = l.foldl Verdict.and e := by
  induction l generalizing e with
  | nil => rfl
  | cons a l ih =>
    simp only [List.reverse_cons, List.foldl_append, List.foldl_cons, List.foldl_nil]
    rw [ih e]
    exact (foldl_and_shift l e a).symm

theorem foldl_and_F (l : List Verdict) : l.foldl Verdict.and .F = .F := by
  induction l with
  | nil => rfl
  | cons x l ih => simp only [List.foldl_cons, Verdict.and_F_left]; exact ih

/-- The unguarded, purely structural machine: `none` is a structural failure
(underflow, zero arity, non-single result). No depth cap, no defensive
returns. Used by T4. -/
def evalPure (inp : Inputs) : List Op → List Verdict → Option Verdict
  | [], st =>
    match st with
    | [v] => some v
    | _ => none
  | op :: rest, st =>
    match op with
    | .all n =>
      if n = 0 ∨ st.length < n then none
      else evalPure inp rest (((st.take n).foldl Verdict.and .T) :: st.drop n)
    | .any n =>
      if n = 0 ∨ st.length < n then none
      else evalPure inp rest (((st.take n).foldl Verdict.or .F) :: st.drop n)
    | .not =>
      match st with
      | [] => none
      | v :: st' => evalPure inp rest (v.neg :: st')
    | op => evalPure inp rest (leafEval inp op :: st)

/-! ## Leaf step lemmas

A leaf op steps every machine the same way: it pushes its verdict. Stated once
over an abstract leaf so the sixteen-constructor case analysis happens exactly
here and nowhere else. -/

theorem pops_leaf (op : Op) (hleaf : op.isLeaf) : pops op = .ok 0 := by
  cases op <;> first
    | rfl
    | simp [Op.isLeaf] at hleaf

theorem evalGo_leaf_step (inp : Inputs) (op : Op) (rest : List Op) (st : List Verdict)
    (hleaf : op.isLeaf) (hlen : st.length < MAX_STACK_DEPTH) :
    evalGo inp (op :: rest) st = evalGo inp rest (leafEval inp op :: st) := by
  have h1 : ¬ (st.length > MAX_STACK_DEPTH) := by omega
  have h2 : ¬ (st.length ≥ MAX_STACK_DEPTH) := by omega
  cases op <;> first
    | (simp only [evalGo, if_neg h1, if_neg h2]; done)
    | simp [Op.isLeaf] at hleaf

theorem evalPure_leaf_step (inp : Inputs) (op : Op) (rest : List Op) (st : List Verdict)
    (hleaf : op.isLeaf) :
    evalPure inp (op :: rest) st = evalPure inp rest (leafEval inp op :: st) := by
  cases op <;> first
    | (simp only [evalPure]; done)
    | simp [Op.isLeaf] at hleaf

theorem validateGo_leaf_step (op : Op) (rest : List Op) (d : Nat) (hleaf : op.isLeaf) :
    validateGo (op :: rest) d
      = if d + 1 > MAX_STACK_DEPTH then .error .stackOverflow
        else validateGo rest (d + 1) := by
  simp only [validateGo, pops_leaf op hleaf, Nat.not_lt_zero, if_false, Nat.sub_zero]

/-! ## Leaves execute transparently

Pushing a block of leaf ops is exactly mapping their verdicts onto the stack
(reversed — the stack grows at the head), provided the block fits under the
depth cap, so no guard can fire. -/

theorem evalGo_leaves (inp : Inputs) :
    ∀ (ls rest : List Op) (st : List Verdict),
      (∀ op ∈ ls, op.isLeaf) →
      ls.length + st.length ≤ MAX_STACK_DEPTH →
      evalGo inp (ls ++ rest) st
        = evalGo inp rest ((ls.map (leafEval inp)).reverse ++ st) := by
  intro ls
  induction ls with
  | nil => intro rest st _ _; simp
  | cons op ls ih =>
    intro rest st hleaf hlen
    have hlt : st.length < MAX_STACK_DEPTH := by
      simp only [List.length_cons] at hlen; omega
    rw [List.cons_append, evalGo_leaf_step inp op (ls ++ rest) st (hleaf op (by simp)) hlt,
      ih rest (leafEval inp op :: st)
        (fun o ho => hleaf o (List.mem_cons_of_mem _ ho))
        (by simp only [List.length_cons] at hlen ⊢; omega)]
    simp [List.append_assoc]

/-! ## T6 — lowering preservation -/

theorem lowering_preserves (r : DocRule) (inp : Inputs)
    (hcap : (leafOps r).length ≤ MAX_STACK_DEPTH) :
    eval (buildProgram r) inp = docSemantics r inp := by
  unfold eval buildProgram
  rw [evalGo_leaves inp (leafOps r) [.all (leafOps r).length] []
      (leafOps_are_leaves r) (by simpa using hcap)]
  simp only [List.append_nil]
  have hpos : 1 ≤ (leafOps r).length := leafOps_nonempty r
  have hlenvs : ((leafOps r).map (leafEval inp)).reverse.length = (leafOps r).length := by
    simp
  have h1 : ¬ (((leafOps r).map (leafEval inp)).reverse.length > MAX_STACK_DEPTH) := by
    omega
  have hguard : ¬ ((leafOps r).length = 0
      ∨ ((leafOps r).map (leafEval inp)).reverse.length < (leafOps r).length) := by
    omega
  have htake : ((leafOps r).map (leafEval inp)).reverse.take (leafOps r).length
      = ((leafOps r).map (leafEval inp)).reverse := by
    rw [← hlenvs]; exact List.take_length ..
  have hdrop : ((leafOps r).map (leafEval inp)).reverse.drop (leafOps r).length = [] := by
    rw [← hlenvs]; exact List.drop_length ..
  simp only [evalGo, if_neg h1, if_neg hguard, htake, hdrop]
  rw [foldl_and_reverse, map_leafEval_leafOps]
  rfl

/-! ## T5 — INV-1 at the model level -/

theorem zero_signers_denied (r : DocRule) (inp : Inputs)
    (hcap : (leafOps r).length ≤ MAX_STACK_DEPTH)
    (hzero : inp.signerCount = 0) :
    eval (buildProgram r) inp = .F := by
  rw [lowering_preserves r inp hcap]
  unfold docSemantics docLeaves
  have hge : ¬ (inp.signerCount ≥ max r.signerCount 1) := by omega
  have hfloor : Verdict.ofBool (inp.signerCount ≥ max r.signerCount 1) = .F := by
    simp [hge, Verdict.ofBool]
  simp only [List.foldl_cons, hfloor, Verdict.and_F_right]
  exact foldl_and_F _

/-- INV-1 on the authorization bit: with zero authenticated signers the
lowered program never allows. -/
theorem zero_signers_never_allow (r : DocRule) (inp : Inputs)
    (hcap : (leafOps r).length ≤ MAX_STACK_DEPTH)
    (hzero : inp.signerCount = 0) :
    (eval (buildProgram r) inp).allows = false := by
  rw [zero_signers_denied r inp hcap hzero]; rfl

/-! ## T4 — validation soundness -/

/-- A validated program never trips a defensive guard: the guarded machine
agrees with the structural one, which succeeds. -/
theorem validated_no_structural_unknown (inp : Inputs) :
    ∀ (ops : List Op) (st : List Verdict),
      validateGo ops st.length = .ok () →
      st.length ≤ MAX_STACK_DEPTH →
      ∃ v, evalPure inp ops st = some v ∧ evalGo inp ops st = v := by
  intro ops
  induction ops with
  | nil =>
    intro st hval hlen
    by_cases h1 : st.length = 1
    · obtain ⟨v, rfl⟩ : ∃ v, st = [v] := by
        cases st with
        | nil => simp at h1
        | cons a t =>
          cases t with
          | nil => exact ⟨a, rfl⟩
          | cons b t' => simp at h1
      exact ⟨v, by simp [evalPure], by simp [evalGo]⟩
    · simp [validateGo, h1] at hval
  | cons op rest ih =>
    intro st hval hlen
    have h128 : ¬ (st.length > MAX_STACK_DEPTH) := by omega
    by_cases hleaf : op.isLeaf
    · -- a leaf pushes its verdict; validate simulates depth + 1
      rw [validateGo_leaf_step op rest st.length hleaf] at hval
      by_cases ho : st.length + 1 > MAX_STACK_DEPTH
      · rw [if_pos ho] at hval; simp at hval
      · rw [if_neg ho] at hval
        have hlt : st.length < MAX_STACK_DEPTH := by omega
        obtain ⟨v, hp, he⟩ :=
          ih (leafEval inp op :: st) (by simpa using hval)
            (by simp only [List.length_cons]; omega)
        exact ⟨v,
          by rw [evalPure_leaf_step inp op rest st hleaf]; exact hp,
          by rw [evalGo_leaf_step inp op rest st hleaf hlt]; exact he⟩
    · cases op with
      | all n =>
        by_cases hn : n = 0
        · simp [validateGo, pops, hn] at hval
        · have hpops : pops (Op.all n) = .ok n := by simp [pops, hn]
          simp only [validateGo, hpops] at hval
          by_cases hu : st.length < n
          · rw [if_pos hu] at hval; simp at hval
          · rw [if_neg hu] at hval
            by_cases hover : st.length - n + 1 > MAX_STACK_DEPTH
            · rw [if_pos hover] at hval; simp at hval
            · rw [if_neg hover] at hval
              have hg : ¬ (n = 0 ∨ st.length < n) := by omega
              have hpush : ¬ ((st.drop n).length ≥ MAX_STACK_DEPTH) := by
                simp only [List.length_drop]; omega
              have hlen' :
                  (((st.take n).foldl Verdict.and .T) :: st.drop n).length
                    = st.length - n + 1 := by
                simp [List.length_drop]
              obtain ⟨v, hp, he⟩ :=
                ih (((st.take n).foldl Verdict.and .T) :: st.drop n)
                  (by rw [hlen']; exact hval) (by rw [hlen']; omega)
              refine ⟨v, ?_, ?_⟩
              · simpa only [evalPure, if_neg hg] using hp
              · simpa only [evalGo, if_neg h128, if_neg hg, if_neg hpush] using he
      | any n =>
        by_cases hn : n = 0
        · simp [validateGo, pops, hn] at hval
        · have hpops : pops (Op.any n) = .ok n := by simp [pops, hn]
          simp only [validateGo, hpops] at hval
          by_cases hu : st.length < n
          · rw [if_pos hu] at hval; simp at hval
          · rw [if_neg hu] at hval
            by_cases hover : st.length - n + 1 > MAX_STACK_DEPTH
            · rw [if_pos hover] at hval; simp at hval
            · rw [if_neg hover] at hval
              have hg : ¬ (n = 0 ∨ st.length < n) := by omega
              have hpush : ¬ ((st.drop n).length ≥ MAX_STACK_DEPTH) := by
                simp only [List.length_drop]; omega
              have hlen' :
                  (((st.take n).foldl Verdict.or .F) :: st.drop n).length
                    = st.length - n + 1 := by
                simp [List.length_drop]
              obtain ⟨v, hp, he⟩ :=
                ih (((st.take n).foldl Verdict.or .F) :: st.drop n)
                  (by rw [hlen']; exact hval) (by rw [hlen']; omega)
              refine ⟨v, ?_, ?_⟩
              · simpa only [evalPure, if_neg hg] using hp
              · simpa only [evalGo, if_neg h128, if_neg hg, if_neg hpush] using he
      | not =>
        have hpops : pops Op.not = .ok 1 := rfl
        simp only [validateGo, hpops] at hval
        cases st with
        | nil => simp at hval
        | cons v st' =>
          have hu : ¬ ((v :: st').length < 1) := by simp
          rw [if_neg hu] at hval
          have harith : (v :: st').length - 1 + 1 = st'.length + 1 := by simp
          rw [harith] at hval
          by_cases hover : st'.length + 1 > MAX_STACK_DEPTH
          · rw [if_pos hover] at hval; simp at hval
          · rw [if_neg hover] at hval
            have hpush : ¬ (st'.length ≥ MAX_STACK_DEPTH) := by
              simp only [List.length_cons] at hlen; omega
            obtain ⟨w, hp, he⟩ :=
              ih (v.neg :: st') (by simpa using hval)
                (by simp only [List.length_cons] at hlen ⊢; omega)
            refine ⟨w, ?_, ?_⟩
            · simpa only [evalPure] using hp
            · simpa only [evalGo, if_neg h128, if_neg hpush] using he
      | minSigners n => exact absurd rfl hleaf
      | fnIn fns => exact absurd rfl hleaf
      | argAddrEq i a => exact absurd rfl hleaf
      | argAddrIsSelf i => exact absurd rfl hleaf
      | argSymEq i s => exact absurd rfl hleaf
      | argStrIn i set => exact absurd rfl hleaf
      | argStrPrefix i p => exact absurd rfl hleaf
      | argBytesEq i b => exact absurd rfl hleaf
      | argI128Eq i v => exact absurd rfl hleaf
      | argU32Eq i v => exact absurd rfl hleaf
      | argCount n => exact absurd rfl hleaf
      | ledgerBefore n => exact absurd rfl hleaf
      | ledgerAtOrAfter n => exact absurd rfl hleaf

/-- Whole-program corollary: a `validate`-accepted program has a purely
structural verdict and the guarded evaluator returns exactly it. -/
theorem validate_sound (p : Program) (inp : Inputs)
    (h : validate p = .ok ()) :
    ∃ v, evalPure inp p.ops [] = some v ∧ eval p inp = v := by
  unfold validate at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · split at h
      · simp at h
      · exact validated_no_structural_unknown inp p.ops []
          (by simpa using h) (by simp [MAX_STACK_DEPTH])

end PerchFormal
