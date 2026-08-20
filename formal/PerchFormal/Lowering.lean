import PerchFormal.Semantics

/-!
# The lowering (`perch-compile::build_program`)

Model twin of `build_program` in `crates/perch-compile/src/lib.rs`: a
constrained rule lowers to

```
MinSigners(max n 1) :: [FnIn fns]? :: (arg predicates …) :: All(#leaves)
```

`docSemantics` states the rule's meaning over `ArgPred` directly — no `Op`
constructors, no `lowerPred`, no stack machine — as the Kleene conjunction of
its leaves' meanings. The preservation theorem (`Theorems.lean`) then covers
both halves of the gap: the op translation is meaning-preserving leaf by leaf
(`leafEval_lowerPred`), and the guarded machine over the emitted postfix
program computes exactly the conjunction. What no Lean theorem can supply is
that these predicate meanings match the *Rust* leaf implementations — that
link is empirical, carried by the shared conformance vectors and the Rust
differential suite.
-/

namespace PerchFormal

/-- Doc-level argument predicate (`perch_ir::ArgPred`). -/
inductive ArgPred where
  | isSelf
  | addressEq (name : String)
  | u32Eq (v : Nat)
  | stringIn (vs : List (List UInt8))
  | stringPrefix (p : List UInt8)
deriving DecidableEq, Repr

/-- The slice of a validated `perch_ir::Rule` that reaches `build_program`:
the referenced-signer count and the constraints. (Expiry lowers to OZ
`valid_until` *outside* the program; caps lower to the stateful sibling
policy. Neither is program semantics.) -/
structure DocRule where
  signerCount : Nat
  functions : Option (List String)
  argPreds : List (Nat × ArgPred)
deriving Repr

/-- `lower_arg_pred`. -/
def lowerPred : Nat × ArgPred → Op
  | (i, .isSelf) => .argAddrIsSelf i
  | (i, .addressEq a) => .argAddrEq i a
  | (i, .u32Eq v) => .argU32Eq i v
  | (i, .stringIn vs) => .argStrIn i vs
  | (i, .stringPrefix p) => .argStrPrefix i p

/-- The leaves `build_program` pushes, in order: the INV-1 signer floor, the
function allowlist when present, then each argument predicate. -/
def leafOps (r : DocRule) : List Op :=
  .minSigners (max r.signerCount 1)
    :: ((match r.functions with
         | some fns => [.fnIn fns]
         | none => [])
        ++ r.argPreds.map lowerPred)

/-- `build_program`: the leaves followed by the single `All` fold. -/
def buildProgram (r : DocRule) : Program :=
  { version := PROGRAM_VERSION, ops := leafOps r ++ [.all (leafOps r).length] }

/-! ## The rule's doc-level meaning

Stated over `ArgPred` directly — no `Op` constructors, no `lowerPred`, no
stack machine. Necessarily these clauses *restate* the leaf semantics (a
predicate's meaning is what it is); the point of keeping them separate from
`leafEval` is that the op-translation now carries proof obligations: a
`lowerPred` bug (wrong constructor, shifted index, `min` for `max` in the
floor) breaks `leafEval_lowerPred` / `map_leafEval_leafOps` below instead of
silently changing both sides of the preservation theorem. -/

/-- Meaning of one argument predicate at index `i`. -/
def predSem (inp : Inputs) (i : Nat) : ArgPred → Verdict
  | .isSelf => decodeTest inp i asAddr fun a => .ofBool (a == selfName)
  | .addressEq name => decodeTest inp i asAddr fun a => .ofBool (a == name)
  | .u32Eq v => decodeTest inp i asU32 fun x => .ofBool (x == v)
  | .stringIn vs =>
    decodeTest inp i asStr fun s =>
      if s.length > MAX_STR_ARG_LEN then .U
      else .ofBool (vs.any fun c => c.length ≤ MAX_STR_ARG_LEN && c == s)
  | .stringPrefix p =>
    decodeTest inp i asStr fun s =>
      if s.length > MAX_STR_ARG_LEN || p.length > MAX_STR_ARG_LEN then .U
      else if p.length > s.length then .F
      else .ofBool (s.take p.length == p)

/-- Meaning of the function allowlist. -/
def fnSem (inp : Inputs) (fns : List String) : Verdict :=
  match inp.ctx with
  | .contract c => .ofBool (fns.contains c.fnName)
  | .nonContract => .U

/-- The rule's leaves, by meaning: the INV-1 signer floor, the allowlist when
present, then each argument predicate. -/
def docLeaves (r : DocRule) (inp : Inputs) : List Verdict :=
  Verdict.ofBool (inp.signerCount ≥ max r.signerCount 1)
    :: ((match r.functions with
         | some fns => [fnSem inp fns]
         | none => [])
        ++ r.argPreds.map fun x => predSem inp x.1 x.2)

/-- The rule's doc-level meaning: the Kleene conjunction of its leaves. -/
def docSemantics (r : DocRule) (inp : Inputs) : Verdict :=
  (docLeaves r inp).foldl Verdict.and .T

/-- The op translation is meaning-preserving, predicate by predicate. This is
the lemma a `lowerPred` bug would break. -/
theorem leafEval_lowerPred (inp : Inputs) (x : Nat × ArgPred) :
    leafEval inp (lowerPred x) = predSem inp x.1 x.2 := by
  obtain ⟨i, p⟩ := x
  cases p <;> rfl

theorem map_lowerPred_sem (inp : Inputs) :
    ∀ l : List (Nat × ArgPred),
      (l.map lowerPred).map (leafEval inp) = l.map fun x => predSem inp x.1 x.2
  | [] => rfl
  | x :: l => by
    simp only [List.map_cons, leafEval_lowerPred inp x, map_lowerPred_sem inp l]

/-- The lowered leaves mean exactly the rule's leaves, in order. -/
theorem map_leafEval_leafOps (r : DocRule) (inp : Inputs) :
    (leafOps r).map (leafEval inp) = docLeaves r inp := by
  unfold leafOps docLeaves
  cases r.functions <;>
    simp only [List.map_cons, List.map_append, List.map_nil, List.nil_append,
      map_lowerPred_sem inp] <;>
    rfl

/-- Every op the lowering emits below the root fold is a leaf. -/
theorem leafOps_are_leaves (r : DocRule) : ∀ op ∈ leafOps r, op.isLeaf := by
  intro op hop
  unfold leafOps at hop
  rcases List.mem_cons.mp hop with h | h
  · subst h; rfl
  · rcases List.mem_append.mp h with h | h
    · cases hfns : r.functions with
      | some fns => rw [hfns] at h; simp at h; subst h; rfl
      | none => rw [hfns] at h; simp at h
    · rcases List.mem_map.mp h with ⟨⟨i, p⟩, _, rfl⟩
      cases p <;> rfl

/-- The lowering always emits at least one leaf (the INV-1 floor). -/
theorem leafOps_nonempty (r : DocRule) : 1 ≤ (leafOps r).length := by
  unfold leafOps; simp

end PerchFormal
