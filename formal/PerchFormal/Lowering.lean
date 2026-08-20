import PerchFormal.Semantics

/-!
# The lowering (`perch-compile::build_program`)

Model twin of `build_program` in `crates/perch-compile/src/lib.rs`: a
constrained rule lowers to

```
MinSigners(max n 1) :: [FnIn fns]? :: (arg predicates …) :: All(#leaves)
```

`docSemantics` gives the rule's doc-level meaning directly — the Kleene
conjunction of its leaves' meanings, with no stack machine and no RPN encoding
in sight. The preservation theorem (`Theorems.lean`) closes the gap between
the two: the guarded machine over the emitted postfix program computes exactly
that conjunction.
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

/-- The rule's doc-level meaning: the Kleene conjunction of its leaves'
meanings — no machine, no encoding. -/
def docSemantics (r : DocRule) (inp : Inputs) : Verdict :=
  ((leafOps r).map (leafEval inp)).foldl Verdict.and .T

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
