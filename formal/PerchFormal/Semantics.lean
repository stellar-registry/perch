import PerchFormal.Verdict

/-!
# The perch-program v1 semantics

Executable model twin of `crates/perch-program/src/{rpn.rs,leaf.rs}`: the op
alphabet, the leaf predicate semantics (including every fail-closed decode
path), the guarded RPN stack machine `evalGo` (mirroring every defensive
guard in `rpn::eval` — the guards are part of the semantics, not noise), and
the install-time validator `validate` (the stack-effect simulation).

Host-value decoding is abstracted to a typed [`Value`] domain: a wrong-typed,
missing, or undecodable argument is an explicit decode failure, and every
decode failure yields `Verdict.U` — never `F` (`leaf.rs`'s fail-closed rule).

Conventions shared with `testdata/eval/eval-vectors.json` and the Rust
conformance runner (`crates/perch-conformance`):
- addresses are symbolic names, injectively mapped to concrete addresses by
  the runner; the protected account is the distinguished name `"self"`;
- strings and bytes are byte lists (string length = UTF-8 byte length, exactly
  soroban `String::len`).
-/

namespace PerchFormal

/-! ## Bounds (frozen v1 constants, `perch-program/src/lib.rs`) -/

def PROGRAM_VERSION : Nat := 1
def MAX_PROGRAM_LEN : Nat := 256
def MAX_STACK_DEPTH : Nat := 128
def MAX_STR_ARG_LEN : Nat := 256

/-- The distinguished symbolic name of the protected account. -/
def selfName : String := "self"

/-! ## The invocation domain -/

/-- A typed call-argument value. `void` stands for any host value no leaf can
decode. -/
inductive Value where
  | u32 (n : Nat)
  | i128 (n : Int)
  | addr (name : String)
  | sym (s : String)
  | str (bytes : List UInt8)
  | bytes (b : List UInt8)
  | void
deriving DecidableEq, Repr

structure ContractCtx where
  fnName : String
  args : List Value
deriving Repr

/-- The authorization context. Only `contract` is decodable by context leaves;
everything else fails closed. -/
inductive Ctx where
  | contract (c : ContractCtx)
  | nonContract
deriving Repr

/-- Everything a leaf may inspect (`EvalInputs` + the env reads). -/
structure Inputs where
  ctx : Ctx
  signerCount : Nat
  ledger : Nat
deriving Repr

/-! ## The op alphabet (frozen v1) -/

inductive Op where
  | all (n : Nat)
  | any (n : Nat)
  | not
  | minSigners (n : Nat)
  | fnIn (fns : List String)
  | argAddrEq (i : Nat) (name : String)
  | argAddrIsSelf (i : Nat)
  | argSymEq (i : Nat) (s : String)
  | argStrIn (i : Nat) (set : List (List UInt8))
  | argStrPrefix (i : Nat) (p : List UInt8)
  | argBytesEq (i : Nat) (b : List UInt8)
  | argI128Eq (i : Nat) (v : Int)
  | argU32Eq (i : Nat) (v : Nat)
  | argCount (n : Nat)
  | ledgerBefore (n : Nat)
  | ledgerAtOrAfter (n : Nat)
deriving DecidableEq, Repr

/-- A leaf pushes one verdict without popping; `all`/`any`/`not` are the only
composites. -/
def Op.isLeaf : Op → Bool
  | .all _ | .any _ | .not => false
  | _ => true

structure Program where
  version : Nat
  ops : List Op
deriving Repr

/-! ## Leaf semantics (`leaf.rs`) -/

/-- Argument lookup: `None` on a non-contract context or a missing index —
callers map `None` to `U`. -/
def arg? (inp : Inputs) (i : Nat) : Option Value :=
  match inp.ctx with
  | .contract c => c.args[i]?
  | .nonContract => none

def asAddr : Value → Option String
  | .addr n => some n
  | _ => none

def asSym : Value → Option String
  | .sym s => some s
  | _ => none

def asStr : Value → Option (List UInt8)
  | .str b => some b
  | _ => none

def asBytes : Value → Option (List UInt8)
  | .bytes b => some b
  | _ => none

def asI128 : Value → Option Int
  | .i128 n => some n
  | _ => none

def asU32 : Value → Option Nat
  | .u32 n => some n
  | _ => none

/-- Decode argument `i` as `α` and test it; decode failure is `U`. -/
def decodeTest (inp : Inputs) (i : Nat) (dec : Value → Option α) (test : α → Verdict) : Verdict :=
  match (arg? inp i).bind dec with
  | some a => test a
  | none => .U

/-- The verdict a single (leaf) op pushes. Composites never reach this
function in `evalGo`; they are mapped to `U` defensively. -/
def leafEval (inp : Inputs) : Op → Verdict
  | .minSigners n => .ofBool (inp.signerCount ≥ n)
  | .fnIn fns =>
    match inp.ctx with
    | .contract c => .ofBool (fns.contains c.fnName)
    | .nonContract => .U
  | .argAddrEq i want => decodeTest inp i asAddr fun a => .ofBool (a == want)
  | .argAddrIsSelf i => decodeTest inp i asAddr fun a => .ofBool (a == selfName)
  | .argSymEq i want => decodeTest inp i asSym fun s => .ofBool (s == want)
  | .argStrIn i set =>
    decodeTest inp i asStr fun s =>
      if s.length > MAX_STR_ARG_LEN then .U
      else .ofBool (set.any fun c => c.length ≤ MAX_STR_ARG_LEN && c == s)
  | .argStrPrefix i p =>
    decodeTest inp i asStr fun s =>
      if s.length > MAX_STR_ARG_LEN || p.length > MAX_STR_ARG_LEN then .U
      else if p.length > s.length then .F
      else .ofBool (s.take p.length == p)
  | .argBytesEq i b => decodeTest inp i asBytes fun x => .ofBool (x == b)
  | .argI128Eq i v => decodeTest inp i asI128 fun x => .ofBool (x == v)
  | .argU32Eq i v => decodeTest inp i asU32 fun x => .ofBool (x == v)
  | .argCount n =>
    match inp.ctx with
    | .contract c => .ofBool (c.args.length == n)
    | .nonContract => .U
  | .ledgerBefore n => .ofBool (inp.ledger < n)
  | .ledgerAtOrAfter n => .ofBool (inp.ledger ≥ n)
  | .all _ => .U
  | .any _ => .U
  | .not => .U

/-! ## The guarded stack machine (`rpn::eval`)

Every branch mirrors `rpn.rs` exactly: the loop-start defensive depth check,
the `n = 0 ∨ sp < n` composite guards, the pre-push `sp ≥ MAX_STACK_DEPTH`
guard, and the final single-result check. The stack is a list with its head as
the top; the fold over popped verdicts runs top-down exactly like the Rust
pop loop (both start from the fold identity and combine the top first). -/

def evalGo (inp : Inputs) : List Op → List Verdict → Verdict
  | [], st =>
    match st with
    | [v] => v
    | _ => .U
  | op :: rest, st =>
    if st.length > MAX_STACK_DEPTH then .U
    else
      match op with
      | .all n =>
        if n = 0 ∨ st.length < n then .U
        else if (st.drop n).length ≥ MAX_STACK_DEPTH then .U
        else evalGo inp rest (((st.take n).foldl Verdict.and .T) :: st.drop n)
      | .any n =>
        if n = 0 ∨ st.length < n then .U
        else if (st.drop n).length ≥ MAX_STACK_DEPTH then .U
        else evalGo inp rest (((st.take n).foldl Verdict.or .F) :: st.drop n)
      | .not =>
        match st with
        | [] => .U
        | v :: st' =>
          if st'.length ≥ MAX_STACK_DEPTH then .U
          else evalGo inp rest (v.neg :: st')
      | op =>
        if st.length ≥ MAX_STACK_DEPTH then .U
        else evalGo inp rest (leafEval inp op :: st)

/-- Evaluate a program. Version-blind, exactly like `rpn::eval` — the version
gate lives in [`validate`], which runs at install time. -/
def eval (p : Program) (inp : Inputs) : Verdict :=
  evalGo inp p.ops []

/-! ## The install-time validator (`rpn::validate`) -/

inductive ValidationError where
  | unknownVersion
  | empty
  | tooLarge
  | arityMismatch
  | stackUnderflow
  | stackOverflow
  | notSingleResult
deriving DecidableEq, Repr

/-- How many verdicts an op pops (every op pushes exactly one). -/
def pops : Op → Except ValidationError Nat
  | .all n | .any n => if n = 0 then .error .arityMismatch else .ok n
  | .not => .ok 1
  | _ => .ok 0

def validateGo : List Op → Nat → Except ValidationError Unit
  | [], depth => if depth = 1 then .ok () else .error .notSingleResult
  | op :: rest, depth =>
    match pops op with
    | .error e => .error e
    | .ok k =>
      if depth < k then .error .stackUnderflow
      else
        let d := depth - k + 1
        if d > MAX_STACK_DEPTH then .error .stackOverflow
        else validateGo rest d

def validate (p : Program) : Except ValidationError Unit :=
  if p.version ≠ PROGRAM_VERSION then .error .unknownVersion
  else if p.ops.length = 0 then .error .empty
  else if p.ops.length > MAX_PROGRAM_LEN then .error .tooLarge
  else validateGo p.ops 0

end PerchFormal
