import PerchFormal
import Lean.Data.Json

/-!
# The differential-testing executable

Replays `testdata/eval/eval-vectors.json` — the frozen conformance vectors
whose expectations are hand-authored in `crates/perch-conformance` and
executed against the real Rust evaluator in CI — through the Lean model, and
fails (exit 1) on any disagreement about the validate outcome or the verdict.

Green means: the hand-authored spec expectations, the Rust implementation, and
this proved-about model all agree on every case.
-/

open Lean (Json)
open PerchFormal

abbrev Dec α := Except String α

def getField (j : Json) (k : String) : Dec Json :=
  j.getObjVal? k

def getStr (j : Json) (k : String) : Dec String := do
  (← getField j k).getStr?

def getNat (j : Json) (k : String) : Dec Nat := do
  (← getField j k).getNat?

def strBytes (s : String) : List UInt8 :=
  s.toUTF8.toList

def hexNibble (c : Char) : Dec Nat :=
  if '0' ≤ c ∧ c ≤ '9' then .ok (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then .ok (c.toNat - 'a'.toNat + 10)
  else .error s!"bad hex digit {c}"

def hexBytes (s : String) : Dec (List UInt8) := do
  let rec go : List Char → Dec (List UInt8)
    | [] => .ok []
    | [_] => .error "odd-length hex"
    | hi :: lo :: rest => do
      let h ← hexNibble hi
      let l ← hexNibble lo
      let tail ← go rest
      .ok (UInt8.ofNat (h * 16 + l) :: tail)
  go s.toList

def decodeValue (j : Json) : Dec Value := do
  match (← getStr j "type") with
  | "u32" => return .u32 (← getNat j "value")
  | "i128" =>
    let s ← getStr j "value"
    match s.toInt? with
    | some n => return .i128 n
    | none => .error s!"bad i128 {s}"
  | "address" => return .addr (← getStr j "value")
  | "symbol" => return .sym (← getStr j "value")
  | "string" => return .str (strBytes (← getStr j "value"))
  | "bytes" => return .bytes (← hexBytes (← getStr j "hex"))
  | "void" => return .void
  | t => .error s!"unknown value type {t}"

def decodeStrList (j : Json) (k : String) : Dec (List String) := do
  let arr ← (← getField j k).getArr?
  arr.toList.mapM (·.getStr?)

def decodeOp (j : Json) : Dec Op := do
  match (← getStr j "op") with
  | "all" => return .all (← getNat j "n")
  | "any" => return .any (← getNat j "n")
  | "not" => return .not
  | "min-signers" => return .minSigners (← getNat j "n")
  | "fn-in" => return .fnIn (← decodeStrList j "fns")
  | "arg-addr-eq" => return .argAddrEq (← getNat j "i") (← getStr j "address")
  | "arg-addr-is-self" => return .argAddrIsSelf (← getNat j "i")
  | "arg-sym-eq" => return .argSymEq (← getNat j "i") (← getStr j "symbol")
  | "arg-str-in" =>
    return .argStrIn (← getNat j "i") ((← decodeStrList j "values").map strBytes)
  | "arg-str-prefix" =>
    return .argStrPrefix (← getNat j "i") (strBytes (← getStr j "prefix"))
  | "arg-bytes-eq" => return .argBytesEq (← getNat j "i") (← hexBytes (← getStr j "hex"))
  | "arg-i128-eq" =>
    let s ← getStr j "value"
    match s.toInt? with
    | some n => return .argI128Eq (← getNat j "i") n
    | none => .error s!"bad i128 {s}"
  | "arg-u32-eq" => return .argU32Eq (← getNat j "i") (← getNat j "value")
  | "arg-count" => return .argCount (← getNat j "n")
  | "ledger-before" => return .ledgerBefore (← getNat j "n")
  | "ledger-at-or-after" => return .ledgerAtOrAfter (← getNat j "n")
  | o => .error s!"unknown op {o}"

def decodeInputs (j : Json) : Dec Inputs := do
  let inv ← getField j "invocation"
  let signerCount ← getNat inv "signer_count"
  let ledger ← getNat inv "ledger"
  match (← getStr inv "context") with
  | "contract" =>
    let fnName ← getStr inv "fn"
    let args ← (← (← getField inv "args").getArr?).toList.mapM decodeValue
    return { ctx := .contract { fnName, args }, signerCount, ledger }
  | "non-contract" => return { ctx := .nonContract, signerCount, ledger }
  | c => .error s!"unknown context {c}"

def decodeProgram (j : Json) : Dec Program := do
  let p ← getField j "program"
  let version ← getNat p "version"
  let ops ← (← (← getField p "ops").getArr?).toList.mapM decodeOp
  return { version, ops }

def errorName : ValidationError → String
  | .unknownVersion => "unknown-version"
  | .empty => "empty"
  | .tooLarge => "too-large"
  | .arityMismatch => "arity-mismatch"
  | .stackUnderflow => "stack-underflow"
  | .stackOverflow => "stack-overflow"
  | .notSingleResult => "not-single-result"

def verdictName : Verdict → String
  | .T => "true"
  | .U => "unknown"
  | .F => "false"

structure CaseResult where
  name : String
  failures : List String

def runCase (j : Json) : Dec CaseResult := do
  let name ← getStr j "name"
  let program ← decodeProgram j
  let inputs ← decodeInputs j
  let expectValid ← (← getField j "valid").getBool?
  let mut failures : List String := []

  match validate program, expectValid with
  | .ok (), true => pure ()
  | .ok (), false =>
    failures := failures ++ [s!"validate: model accepted, vectors expect error"]
  | .error e, true =>
    failures := failures ++ [s!"validate: model rejected with {errorName e}, vectors expect ok"]
  | .error e, false =>
    let want ← getStr j "error"
    if errorName e ≠ want then
      failures := failures ++ [s!"validate: model error {errorName e}, vectors expect {want}"]

  let want ← getStr j "verdict"
  let got := verdictName (eval program inputs)
  if got ≠ want then
    failures := failures ++ [s!"verdict: model {got}, vectors expect {want}"]

  return { name, failures }

/-- Parse a Rust-emitted canonical document with the *verified* CANON v1
parser and re-emit it: the file must be byte-identical to the model's own
canonical form (and fully consumed). Ties `emitDoc_injective`'s model emitter
to the Rust emitter on the golden fixtures. -/
def checkCanonicalFile (path : String) : IO Bool := do
  let text ← IO.FS.readFile path
  let chars := text.toList
  match Canon.pDoc chars with
  | none =>
    IO.eprintln s!"FAIL {path}: not parseable as CANON v1 (model grammar diverges from Rust output)"
    return false
  | some (doc, rest) =>
    if !rest.isEmpty then
      IO.eprintln s!"FAIL {path}: {rest.length} trailing chars after the document"
      return false
    else if Canon.emitDoc doc ≠ chars then
      IO.eprintln s!"FAIL {path}: model re-emission differs from the Rust canonical bytes"
      return false
    else
      IO.println s!"{path}: parses and re-emits byte-identically under the verified canonicalizer"
      return true

def main (args : List String) : IO UInt32 := do
  let path := args.headD "../testdata/eval/eval-vectors.json"
  let text ← IO.FS.readFile path
  let json ← IO.ofExcept (Json.parse text)
  let cases ← IO.ofExcept do
    (← (← json.getObjVal? "cases").getArr?).toList.mapM runCase
  let failing := cases.filter (!·.failures.isEmpty)
  for c in failing do
    IO.eprintln s!"FAIL {c.name}"
    for f in c.failures do
      IO.eprintln s!"  {f}"
  IO.println s!"{cases.length - failing.length}/{cases.length} conformance cases agree with the Lean model"
  -- Any further arguments are Rust-emitted canonical documents to round-trip
  -- through the verified canonicalizer.
  let mut canonOk := true
  for p in args.drop 1 do
    canonOk := (← checkCanonicalFile p) && canonOk
  return if failing.isEmpty && canonOk then 0 else 1
