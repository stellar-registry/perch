import Lean
import PerchFormal

/-!
# Axiom audit

`lake build` accepts a proof that leans on `sorry` (with a warning) or on a
new axiom, and the source grep in CI only catches the words. This walks
every declaration under `PerchFormal`, collects the axioms each one depends
on, and fails unless they are all among Lean's standard three: `propext`,
`Classical.choice`, `Quot.sound`. A `sorry` anywhere shows up here as
`sorryAx`. Run with `lake env lean CheckAxioms.lean`.
-/

open Lean Elab Command

elab "#audit_perch_axioms" : command => do
  let env ← getEnv
  let allowed : List Name := [``propext, ``Classical.choice, ``Quot.sound]
  let mut checked := 0
  let mut theorems := 0
  let mut bad : Array String := #[]
  for (name, info) in env.constants.map₁.toList do
    if (`PerchFormal).isPrefixOf name && !name.isInternal then
      checked := checked + 1
      if info matches .thmInfo _ then theorems := theorems + 1
      for ax in ← collectAxioms name do
        if !allowed.contains ax then
          bad := bad.push s!"{name} depends on {ax}"
  if checked == 0 then
    throwError "no PerchFormal declarations found"
  unless bad.isEmpty do
    throwError m!"non-standard dependencies:\n{String.intercalate "\n" bad.toList}"
  logInfo m!"{checked} PerchFormal declarations ({theorems} theorems) depend only on propext, Classical.choice, Quot.sound"

#audit_perch_axioms
