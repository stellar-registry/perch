import PerchFormal.Canon

/-!
# CANON v1 round-trip and injectivity proofs

Bottom-up: exact-literal lemmas, digit/hex tables, the string-escape step,
then each grammar production's round-trip, ending in `emitDoc_injective` —
two documents with the same canonical form are the same document.
-/

namespace PerchFormal
namespace Canon

/-! ## pExact -/

theorem pExact_rt : ∀ (pat rest : List Char), pExact pat (pat ++ rest) = some ((), rest)
  | [], _ => rfl
  | p :: ps, rest => by
    simp only [List.cons_append, pExact, reduceIte]
    exact pExact_rt ps rest

theorem pExact_step_ne {c p : Char} (h : c ≠ p) (ps rest : List Char) :
    pExact (p :: ps) (c :: rest) = none := by
  simp [pExact, h]

/-- Mismatch after a shared concrete prefix: the workhorse for every
optional-field branch (all our grammar's choice points differ within their
concrete key literals). -/
theorem pExact_ne_after (common : List Char) {p c : Char} (h : c ≠ p) (ps rest : List Char) :
    pExact (common ++ p :: ps) (common ++ c :: rest) = none := by
  induction common with
  | nil => exact pExact_step_ne h ps rest
  | cons d ds ih =>
    simp only [List.cons_append, pExact, reduceIte]
    exact ih

/-! ## pOpt -/

theorem pOpt_hit (l : List Char) (t e : P α) (rest : List Char) :
    pOpt l t e (l ++ rest) = t rest := by
  simp [pOpt, pExact_rt]

theorem pOpt_miss (l : List Char) (t e : P α) (input : List Char)
    (h : pExact l input = none) : pOpt l t e input = e input := by
  simp [pOpt, h]

/-! ## Digits and hex -/

theorem isDigitC_digitChar : ∀ n, n < 10 → isDigitC (digitChar n) = true := by decide

theorem digitVal_digitChar : ∀ n, n < 10 → digitVal (digitChar n) = n := by decide

theorem hexVal_hexChar : ∀ n, n < 16 → hexVal? (hexChar n) = some n := by decide

/-! ## The string escape step -/

/-- One source character steps the string-body parser exactly one cluster. -/
theorem pStrBody_step (c : Char) (fuel : Nat) (tail : List Char) :
    pStrBody (fuel + 1) (escChar c ++ tail)
      = match pStrBody fuel tail with
        | some (s, r) => some (c :: s, r)
        | none => none := by
  by_cases hq : c = '"'
  · subst hq
    cases hres : pStrBody fuel tail <;> simp +decide [escChar, pStrBody, pEsc, hres]
  by_cases hb : c = '\\'
  · subst hb
    cases hres : pStrBody fuel tail <;> simp +decide [escChar, pStrBody, pEsc, hres]
  by_cases h8 : c = '\x08'
  · subst h8
    cases hres : pStrBody fuel tail <;> simp +decide [escChar, pStrBody, pEsc, hres]
  by_cases h9 : c = '\x09'
  · subst h9
    cases hres : pStrBody fuel tail <;> simp +decide [escChar, pStrBody, pEsc, hres]
  by_cases ha : c = '\x0a'
  · subst ha
    cases hres : pStrBody fuel tail <;> simp +decide [escChar, pStrBody, pEsc, hres]
  by_cases hc : c = '\x0c'
  · subst hc
    cases hres : pStrBody fuel tail <;> simp +decide [escChar, pStrBody, pEsc, hres]
  by_cases hd : c = '\x0d'
  · subst hd
    cases hres : pStrBody fuel tail <;> simp +decide [escChar, pStrBody, pEsc, hres]
  by_cases hctl : c.toNat < 0x20
  · -- \u00xx: two hex nibbles reassemble to the same scalar
    have hemit : escChar c
        = ['\\', 'u', '0', '0', hexChar (c.toNat / 16), hexChar (c.toNat % 16)] := by
      simp only [escChar, hq, hb, h8, h9, ha, hc, hd, reduceIte, if_pos hctl]
    have hhi : hexVal? (hexChar (c.toNat / 16)) = some (c.toNat / 16) :=
      hexVal_hexChar _ (by omega)
    have hlo : hexVal? (hexChar (c.toNat % 16)) = some (c.toNat % 16) :=
      hexVal_hexChar _ (by omega)
    have hnib : 16 * (c.toNat / 16) + c.toNat % 16 = c.toNat := by omega
    rw [hemit]
    cases hres : pStrBody fuel tail <;>
      simp +decide [pStrBody, pEsc, hhi, hlo, hnib, Char.ofNat_toNat, hres]
  · -- literal
    have hemit : escChar c = [c] := by
      simp only [escChar, hq, hb, h8, h9, ha, hc, hd, hctl, reduceIte]
    rw [hemit]
    cases hres : pStrBody fuel tail <;>
      simp [pStrBody, if_neg hq, if_neg hb, hres]

theorem pStrBody_emit :
    ∀ (s : Str) (fuel : Nat) (tail : List Char), s.length + 1 ≤ fuel →
      pStrBody fuel (s.flatMap escChar ++ '"' :: tail) = some (s, tail) := by
  intro s
  induction s with
  | nil =>
    intro fuel tail hfuel
    match fuel, hfuel with
    | fuel + 1, _ => simp [pStrBody]
  | cons c s ih =>
    intro fuel tail hfuel
    match fuel, hfuel with
    | fuel + 1, hfuel =>
      have : (c :: s).flatMap escChar ++ '"' :: tail
          = escChar c ++ (s.flatMap escChar ++ '"' :: tail) := by
        simp [List.flatMap_cons, List.append_assoc]
      rw [this, pStrBody_step c fuel _,
        ih fuel tail (by simp only [List.length_cons] at hfuel; omega)]

theorem escChar_length_pos (c : Char) : 0 < (escChar c).length := by
  unfold escChar
  repeat' split
  all_goals simp

theorem flatMap_escChar_length (s : Str) : s.length ≤ (s.flatMap escChar).length := by
  induction s with
  | nil => simp
  | cons c s ih =>
    simp only [List.flatMap_cons, List.length_append, List.length_cons]
    have := escChar_length_pos c
    omega

theorem pStr_rt (s : Str) (tail : List Char) :
    pStr (emitStr s ++ tail) = some (s, tail) := by
  have hshape : emitStr s ++ tail = '"' :: (s.flatMap escChar ++ '"' :: tail) := by
    simp [emitStr, List.append_assoc]
  rw [hshape]
  show pStrBody (s.flatMap escChar ++ '"' :: tail).length (s.flatMap escChar ++ '"' :: tail)
      = some (s, tail)
  refine pStrBody_emit s _ tail ?_
  have := flatMap_escChar_length s
  simp only [List.length_append, List.length_cons]
  omega

/-! ## Numbers -/

/-- Head of what remains is not a digit (trivially true for the empty rest). -/
def headNotDigit : List Char → Prop
  | c :: _ => isDigitC c = false
  | [] => True

theorem pNatAux_stop (fuel acc : Nat) (input : List Char) (h : headNotDigit input) :
    pNatAux fuel acc input = some (acc, input) := by
  cases fuel <;> cases input <;> simp_all [pNatAux, headNotDigit]

theorem emitNat_head_digit :
    ∀ n, ∃ c cs, emitNat n = c :: cs ∧ isDigitC c = true := by
  intro n
  induction n using emitNat.induct with
  | case1 n h => exact ⟨digitChar n, [], by rw [emitNat, dif_pos h], isDigitC_digitChar n h⟩
  | case2 n h ih =>
    obtain ⟨c, cs, hemit, hdig⟩ := ih
    exact ⟨c, cs ++ [digitChar (n % 10)], by rw [emitNat, dif_neg h, hemit]; rfl, hdig⟩

/-- The parser's digit fold. -/
def digitFold (acc : Nat) (ds : List Char) : Nat :=
  ds.foldl (fun a c => a * 10 + digitVal c) acc

/-- The digit-run parser over an all-digit block followed by a non-digit is
exactly the left fold. -/
theorem pNatAux_digits :
    ∀ (ds : List Char) (acc fuel : Nat) (tail : List Char),
      (∀ c ∈ ds, isDigitC c = true) → ds.length ≤ fuel → headNotDigit tail →
      pNatAux fuel acc (ds ++ tail) = some (digitFold acc ds, tail) := by
  intro ds
  induction ds with
  | nil =>
    intro acc fuel tail _ _ htail
    simpa [digitFold] using pNatAux_stop fuel acc tail htail
  | cons d ds ih =>
    intro acc fuel tail hdig hfuel htail
    match fuel, hfuel with
    | fuel + 1, hfuel =>
      have hd : isDigitC d = true := hdig d (by simp)
      simp only [List.cons_append, pNatAux, hd, reduceIte]
      rw [ih (acc * 10 + digitVal d) fuel tail
        (fun c hc => hdig c (List.mem_cons_of_mem _ hc))
        (by simp only [List.length_cons] at hfuel; omega) htail]
      rfl

theorem emitNat_all_digits : ∀ n, ∀ c ∈ emitNat n, isDigitC c = true := by
  intro n
  induction n using emitNat.induct with
  | case1 n hlt =>
    intro c hc
    rw [emitNat, dif_pos hlt] at hc
    simp at hc
    subst hc
    exact isDigitC_digitChar n hlt
  | case2 n hge ih =>
    intro c hc
    rw [emitNat, dif_neg hge] at hc
    rcases List.mem_append.mp hc with h | h
    · exact ih c h
    · simp at h
      subst h
      exact isDigitC_digitChar (n % 10) (by omega)

/-- Folding a number's own digits over accumulator `a` gives
`a * 10^digits + n`. -/
theorem digitFold_emitNat :
    ∀ n a, digitFold a (emitNat n) = a * 10 ^ (emitNat n).length + n := by
  intro n
  induction n using emitNat.induct with
  | case1 n hlt =>
    intro a
    rw [emitNat, dif_pos hlt]
    simp [digitFold, digitVal_digitChar n hlt, Nat.pow_succ]
  | case2 n hge ih =>
    intro a
    rw [emitNat, dif_neg hge]
    have hfold : digitFold a (emitNat (n / 10) ++ [digitChar (n % 10)])
        = digitFold (digitFold a (emitNat (n / 10))) [digitChar (n % 10)] := by
      simp [digitFold, List.foldl_append]
    rw [hfold, ih a]
    simp only [digitFold, List.foldl_cons, List.foldl_nil,
      List.length_append, List.length_cons, List.length_nil,
      digitVal_digitChar (n % 10) (by omega : n % 10 < 10)]
    rw [Nat.pow_succ, ← Nat.mul_assoc]
    omega

theorem pNat_rt (n : Nat) (tail : List Char) (htail : headNotDigit tail) :
    pNat (emitNat n ++ tail) = some (n, tail) := by
  obtain ⟨c, cs, hemit, hdig⟩ := emitNat_head_digit n
  have hshape : emitNat n ++ tail = c :: (cs ++ tail) := by rw [hemit]; rfl
  rw [hshape]
  show (if isDigitC c then pNatAux (c :: (cs ++ tail)).length 0 (c :: (cs ++ tail)) else none)
      = some (n, tail)
  rw [if_pos hdig, ← hshape,
    pNatAux_digits (emitNat n) 0 (emitNat n ++ tail).length tail
      (emitNat_all_digits n)
      (by simp) htail,
    digitFold_emitNat n 0]
  simp

/-! ## Lists -/

theorem pListAux_rt (pElem : P α) (emitElem : α → List Char)
    (helem : ∀ a tail, pElem (emitElem a ++ tail) = some (a, tail)) :
    ∀ (x : α) (xs : List α) (fuel : Nat) (tail : List Char), xs.length + 1 ≤ fuel →
      pListAux pElem fuel
        (emitElem x ++ (xs.flatMap (fun y => ',' :: emitElem y) ++ ']' :: tail))
        = some (x :: xs, tail) := by
  intro x xs
  induction xs generalizing x with
  | nil =>
    intro fuel tail hfuel
    match fuel, hfuel with
    | fuel + 1, _ => simp [pListAux, helem]
  | cons y ys ih =>
    intro fuel tail hfuel
    match fuel, hfuel with
    | fuel + 1, hfuel =>
      have hshape :
          emitElem x ++ ((y :: ys).flatMap (fun y => ',' :: emitElem y) ++ ']' :: tail)
            = emitElem x
              ++ (',' :: (emitElem y ++ (ys.flatMap (fun y => ',' :: emitElem y) ++ ']' :: tail))) := by
        simp [List.flatMap_cons, List.append_assoc]
      rw [hshape]
      have hstep := ih y fuel tail (by simp only [List.length_cons] at hfuel; omega)
      simp [pListAux, helem, hstep]

theorem flatMap_comma_length (emitElem : α → List Char) (xs : List α) :
    xs.length ≤ (xs.flatMap (fun y => ',' :: emitElem y)).length := by
  induction xs with
  | nil => simp
  | cons y ys ih =>
    simp only [List.flatMap_cons, List.length_append, List.length_cons]
    omega

theorem pList_rt (pElem : P α) (emitElem : α → List Char)
    (helem : ∀ a tail, pElem (emitElem a ++ tail) = some (a, tail))
    (hhead : ∀ a, ∃ c cs, emitElem a = c :: cs ∧ c ≠ ']') :
    ∀ (l : List α) (tail : List Char),
      pList pElem (emitList emitElem l ++ tail) = some (l, tail) := by
  intro l tail
  cases l with
  | nil => simp [emitList, pList, lit]
  | cons x xs =>
    obtain ⟨c, cs, hemit, hc⟩ := hhead x
    have hshape : emitList emitElem (x :: xs) ++ tail
        = '[' :: (emitElem x ++ (xs.flatMap (fun y => ',' :: emitElem y) ++ ']' :: tail)) := by
      simp [emitList, List.append_assoc]
    rw [hshape]
    have hrest : emitElem x ++ (xs.flatMap (fun y => ',' :: emitElem y) ++ ']' :: tail)
        = c :: (cs ++ (xs.flatMap (fun y => ',' :: emitElem y) ++ ']' :: tail)) := by
      rw [hemit]; rfl
    rw [show pList pElem ('[' :: (emitElem x ++ (xs.flatMap (fun y => ',' :: emitElem y) ++ ']' :: tail)))
        = if c = ']' then some ([], (cs ++ (xs.flatMap (fun y => ',' :: emitElem y) ++ ']' :: tail)))
          else pListAux pElem
            (emitElem x ++ (xs.flatMap (fun y => ',' :: emitElem y) ++ ']' :: tail)).length
            (emitElem x ++ (xs.flatMap (fun y => ',' :: emitElem y) ++ ']' :: tail))
      by rw [hrest]; rfl]
    rw [if_neg hc]
    refine pListAux_rt pElem emitElem helem x xs _ tail ?_
    have h1 := flatMap_comma_length emitElem xs
    have h2 : 0 < (emitElem x).length := by rw [hemit]; simp
    simp only [List.length_append, List.length_cons]
    omega

/-! ## Grammar productions

Uniform recipe: `lit` literals stay opaque atoms for simp; every choice point
is decided by a pre-proved hit (`pOpt_hit`/`pExact_rt`) or miss lemma (the
grammar's choice points all differ within their concrete key literals, via
`pExact_ne_after`); the sub-parser round-trip lemmas fire on the opaque
`emit*` payloads. -/

/-- Reduce the `do`-notation bind over a known `some`, so sub-parser
round-trip lemmas can match the projected continuation input. -/
theorem obind_some (a : α) (f : α → Option β) :
    (do let x ← some a; f x) = f a := rfl

theorem pStrList_rt (l : List Str) (tail : List Char) :
    pList pStr (emitList emitStr l ++ tail) = some (l, tail) :=
  pList_rt pStr emitStr pStr_rt (fun _ => ⟨'"', _, rfl, by decide⟩) l tail

/-! Miss lemmas, one per (tried key, actual next key) pair. -/

theorem miss_scope (t e : P α) (rest : List Char) :
    pOpt (lit "{\"address\":") t e (lit "{\"type\":\"self-admin\"}" ++ rest)
      = e (lit "{\"type\":\"self-admin\"}" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['{', '"'] (by decide) _ _)

theorem miss_principals (t e : P α) (rest : List Char) :
    pOpt (lit "{\"ack\":") t e (lit "{\"signers\":" ++ rest)
      = e (lit "{\"signers\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['{', '"'] (by decide) _ _)

theorem miss_signer (t e : P α) (rest : List Char) :
    pOpt (lit "{\"address\":") t e (lit "{\"id\":" ++ rest)
      = e (lit "{\"id\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['{', '"'] (by decide) _ _)

theorem miss_cap_token (t e : P α) (rest : List Char) :
    pOpt (lit ",\"token\":") t e (lit "}" ++ rest) = e (lit "}" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after [] (by decide) _ _)

theorem miss_addr_prefix (t e : P α) (rest : List Char) :
    pOpt (lit "{\"address\":") t e (lit "{\"prefix\":" ++ rest)
      = e (lit "{\"prefix\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['{', '"'] (by decide) _ _)

theorem miss_addr_isself (t e : P α) (rest : List Char) :
    pOpt (lit "{\"address\":") t e (lit "{\"type\":\"is-self\"}" ++ rest)
      = e (lit "{\"type\":\"is-self\"}" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['{', '"'] (by decide) _ _)

theorem miss_addr_stringin (t e : P α) (rest : List Char) :
    pOpt (lit "{\"address\":") t e (lit "{\"type\":\"string-in\",\"values\":" ++ rest)
      = e (lit "{\"type\":\"string-in\",\"values\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['{', '"'] (by decide) _ _)

theorem miss_addr_u32 (t e : P α) (rest : List Char) :
    pOpt (lit "{\"address\":") t e (lit "{\"type\":\"u32-eq\",\"value\":" ++ rest)
      = e (lit "{\"type\":\"u32-eq\",\"value\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['{', '"'] (by decide) _ _)

theorem miss_prefix_isself (t e : P α) (rest : List Char) :
    pOpt (lit "{\"prefix\":") t e (lit "{\"type\":\"is-self\"}" ++ rest)
      = e (lit "{\"type\":\"is-self\"}" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['{', '"'] (by decide) _ _)

theorem miss_prefix_stringin (t e : P α) (rest : List Char) :
    pOpt (lit "{\"prefix\":") t e (lit "{\"type\":\"string-in\",\"values\":" ++ rest)
      = e (lit "{\"type\":\"string-in\",\"values\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['{', '"'] (by decide) _ _)

theorem miss_prefix_u32 (t e : P α) (rest : List Char) :
    pOpt (lit "{\"prefix\":") t e (lit "{\"type\":\"u32-eq\",\"value\":" ++ rest)
      = e (lit "{\"type\":\"u32-eq\",\"value\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['{', '"'] (by decide) _ _)

theorem miss_isself_stringin (t e : P α) (rest : List Char) :
    pOpt (lit "{\"type\":\"is-self\"}") t e (lit "{\"type\":\"string-in\",\"values\":" ++ rest)
      = e (lit "{\"type\":\"string-in\",\"values\":" ++ rest) :=
  pOpt_miss _ _ _ _
    (pExact_ne_after ['{', '"', 't', 'y', 'p', 'e', '"', ':', '"'] (by decide) _ _)

theorem miss_isself_u32 (t e : P α) (rest : List Char) :
    pOpt (lit "{\"type\":\"is-self\"}") t e (lit "{\"type\":\"u32-eq\",\"value\":" ++ rest)
      = e (lit "{\"type\":\"u32-eq\",\"value\":" ++ rest) :=
  pOpt_miss _ _ _ _
    (pExact_ne_after ['{', '"', 't', 'y', 'p', 'e', '"', ':', '"'] (by decide) _ _)

theorem miss_stringin_u32 (t e : P α) (rest : List Char) :
    pOpt (lit "{\"type\":\"string-in\",\"values\":") t e
      (lit "{\"type\":\"u32-eq\",\"value\":" ++ rest)
      = e (lit "{\"type\":\"u32-eq\",\"value\":" ++ rest) :=
  pOpt_miss _ _ _ _
    (pExact_ne_after ['{', '"', 't', 'y', 'p', 'e', '"', ':', '"'] (by decide) _ _)

theorem miss_args_cap (t e : P α) (rest : List Char) :
    pOpt (lit "\"args\":") t e (lit "\"cap\":" ++ rest) = e (lit "\"cap\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['"'] (by decide) _ _)

theorem miss_args_functions (t e : P α) (rest : List Char) :
    pOpt (lit "\"args\":") t e (lit "\"functions\":" ++ rest)
      = e (lit "\"functions\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['"'] (by decide) _ _)

theorem miss_args_name (t e : P α) (rest : List Char) :
    pOpt (lit "\"args\":") t e (lit "\"name\":" ++ rest) = e (lit "\"name\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['"'] (by decide) _ _)

theorem miss_cap_functions (t e : P α) (rest : List Char) :
    pOpt (lit "\"cap\":") t e (lit "\"functions\":" ++ rest)
      = e (lit "\"functions\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['"'] (by decide) _ _)

theorem miss_cap_name (t e : P α) (rest : List Char) :
    pOpt (lit "\"cap\":") t e (lit "\"name\":" ++ rest) = e (lit "\"name\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['"'] (by decide) _ _)

theorem miss_functions_name (t e : P α) (rest : List Char) :
    pOpt (lit "\"functions\":") t e (lit "\"name\":" ++ rest)
      = e (lit "\"name\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['"'] (by decide) _ _)

theorem miss_nal_principals (t e : P α) (rest : List Char) :
    pOpt (lit ",\"not-after-ledger\":") t e (lit ",\"principals\":" ++ rest)
      = e (lit ",\"principals\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after [',', '"'] (by decide) _ _)

theorem miss_network_rules (t e : P α) (rest : List Char) :
    pOpt (lit "\"network\":") t e (lit "\"rules\":" ++ rest)
      = e (lit "\"rules\":" ++ rest) :=
  pOpt_miss _ _ _ _ (pExact_ne_after ['"'] (by decide) _ _)

/-! Non-digit heads for every literal that follows a number. -/

theorem hnd_pred (rest : List Char) : headNotDigit (lit ",\"pred\":" ++ rest) := rfl
theorem hnd_close (rest : List Char) : headNotDigit (lit "}" ++ rest) := rfl
theorem hnd_token (rest : List Char) : headNotDigit (lit ",\"token\":" ++ rest) := rfl
theorem hnd_principals (rest : List Char) :
    headNotDigit (lit ",\"principals\":" ++ rest) := rfl

/-! The productions. -/

set_option linter.unusedSimpArgs false in
theorem pScope_rt (s : CScope) (tail : List Char) :
    pScope (emitScope s ++ tail) = some (s, tail) := by
  cases s
  all_goals
    unfold pScope emitScope
    simp only [List.append_assoc, pOpt_hit, miss_scope, pStr_rt, pExact_rt, obind_some]
    try rfl

set_option linter.unusedSimpArgs false in
theorem pPrincipals_rt (p : CPrincipals) (tail : List Char) :
    pPrincipals (emitPrincipals p ++ tail) = some (p, tail) := by
  cases p
  all_goals
    unfold pPrincipals emitPrincipals
    simp only [List.append_assoc, pOpt_hit, miss_principals, pStr_rt,
      pStrList_rt, pExact_rt, obind_some]
    try rfl

set_option linter.unusedSimpArgs false in
theorem pPred_rt (p : CPred) (tail : List Char) :
    pPred (emitPred p ++ tail) = some (p, tail) := by
  cases p
  all_goals
    unfold pPred emitPred
    simp only [List.append_assoc, pOpt_hit,
      miss_addr_prefix, miss_addr_isself, miss_addr_stringin, miss_addr_u32,
      miss_prefix_isself, miss_prefix_stringin, miss_prefix_u32,
      miss_isself_stringin, miss_isself_u32, miss_stringin_u32,
      pStr_rt, pStrList_rt, pNat_rt, hnd_close, pExact_rt, obind_some]
    try rfl

set_option linter.unusedSimpArgs false in
theorem pArg_rt (a : CArg) (tail : List Char) :
    pArg (emitArg a ++ tail) = some (a, tail) := by
  obtain ⟨i, p⟩ := a
  unfold pArg emitArg
  simp only [List.append_assoc, pNat_rt, hnd_pred, pPred_rt, pExact_rt, obind_some]
  try rfl

theorem pArgList_rt (l : List CArg) (tail : List Char) :
    pList pArg (emitList emitArg l ++ tail) = some (l, tail) :=
  pList_rt pArg emitArg pArg_rt (fun _ => ⟨'{', _, rfl, by decide⟩) l tail

set_option linter.unusedSimpArgs false in
theorem pSigner_rt (s : CSigner) (tail : List Char) :
    pSigner (emitSigner s ++ tail) = some (s, tail) := by
  cases s
  all_goals
    unfold pSigner emitSigner
    simp only [List.append_assoc, pOpt_hit, miss_signer, pStr_rt, pExact_rt, obind_some]
    try rfl

theorem pSignerList_rt (l : List CSigner) (tail : List Char) :
    pList pSigner (emitList emitSigner l ++ tail) = some (l, tail) :=
  pList_rt pSigner emitSigner pSigner_rt
    (fun s => by cases s <;> exact ⟨'{', _, rfl, by decide⟩) l tail

set_option linter.unusedSimpArgs false in
theorem pCap_rt (c : CCap) (tail : List Char) :
    pCap (emitCap c ++ tail) = some (c, tail) := by
  obtain ⟨token, limit, pl⟩ := c
  cases token
  all_goals
    unfold pCap emitCap
    simp only [List.append_assoc, List.nil_append, pOpt_hit, miss_cap_token,
      pStr_rt, pNat_rt, hnd_token, hnd_close, pExact_rt, obind_some]
    try rfl

set_option linter.unusedSimpArgs false in
theorem pRule_rt (r : CRule) (tail : List Char) :
    pRule (emitRule r ++ tail) = some (r, tail) := by
  obtain ⟨name, scope, principals, functions, args, nal, cap⟩ := r
  cases args <;> cases cap <;> cases functions <;> cases nal
  all_goals
    unfold pRule emitRule
    simp only [List.append_assoc, List.nil_append, pOpt_hit,
      miss_args_cap, miss_args_functions, miss_args_name, miss_cap_functions,
      miss_cap_name, miss_functions_name, miss_nal_principals,
      pStr_rt, pNat_rt, hnd_principals, pArgList_rt, pCap_rt, pStrList_rt,
      pPrincipals_rt, pScope_rt, pExact_rt, obind_some]
    try rfl

theorem pRuleList_rt (l : List CRule) (tail : List Char) :
    pList pRule (emitList emitRule l ++ tail) = some (l, tail) :=
  pList_rt pRule emitRule pRule_rt (fun _ => ⟨'{', _, rfl, by decide⟩) l tail

set_option linter.unusedSimpArgs false in
/-- **The round-trip**: the canonical parser inverts the canonical emitter. -/
theorem pDoc_rt (d : CDoc) (tail : List Char) :
    pDoc (emitDoc d ++ tail) = some (d, tail) := by
  obtain ⟨version, network, signers, rules⟩ := d
  cases network
  all_goals
    unfold pDoc emitDoc
    simp only [List.append_assoc, List.nil_append, pOpt_hit,
      miss_network_rules, pStr_rt, pNat_rt, hnd_close, pRuleList_rt,
      pSignerList_rt, pExact_rt, obind_some]
    try rfl

/-! ## Injectivity -/

/-- **doc_hash names one document**: two documents with the same canonical
form are equal, so `doc_hash = SHA-256(canonical bytes)` identifies exactly
one document up to a SHA-256 collision. (The UTF-8 encoding the Rust side
applies to these scalars is itself injective, so injectivity at the scalar
level is injectivity at the byte level.) -/
theorem emitDoc_injective : Function.Injective emitDoc := by
  intro d1 d2 h
  have h1 := pDoc_rt d1 []
  have h2 := pDoc_rt d2 []
  rw [h] at h1
  exact congrArg Prod.fst (Option.some.inj (h1.symm.trans h2))

end Canon
end PerchFormal
