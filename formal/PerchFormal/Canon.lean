/-!
# CANON v1 — the canonical serializer, its inverse, and injectivity

Model twin of `crates/perch-ir/src/canon.rs` (the normative spec is
`CANONICAL.md`): the canonical JSON emitter for the exact document shapes a
`PolicyDoc` can take — JCS string escaping, plain-decimal `u32`s, sorted fixed
keys, `None` fields omitted, no whitespace, no nulls. That includes the
optional `recovery` member (`RecoveryConfig`: profile, the
`guardian-only`/`zk-only`/`combined` mode with its guardian and ZK fields,
controller, baseline, replaceable signer ids, ledger counts), and
`emitRecovery` on its own is `recovery_canonical_json`, the text the recovery
controller's `config_hash` commits to.

The point of this file is **injectivity**: two distinct documents can never
share canonical bytes, hence never share a `doc_hash` (modulo a SHA-256
collision, which no theorem prover will refute), and two distinct recovery
configurations never share a `config_hash` preimage. The proof is the classic
parser round-trip: `Parse.lean`-style combinators reconstruct the document
from its own canonical output (`pDoc (emitDoc d ++ rest) = some (d, rest)`),
and injectivity of `emitDoc` falls out; likewise `pRecovery` for
`emitRecovery`.

The parser here is a *proof artifact*, not a security boundary: it only needs
to invert what the emitter emits. It doubles as an empirical pin: `lake exe
drt` parses the frozen `testdata/*.canonical.json` files (Rust emitter output)
with it and re-emits byte-identically, tying this model's bytes to the Rust
implementation's bytes on the golden fixtures.

Since the emitter's object keys are fixed and sorted, the grammar is
prefix-deterministic: at every optional field the possible next tokens are
distinct concrete literals, so the parser needs no backtracking beyond one
literal try.
-/

namespace PerchFormal
namespace Canon

/-- Model strings: lists of unicode scalars (Lean `Char`), exactly what the
Rust emitter iterates (`s.chars()`). -/
abbrev Str := List Char

/-! ## The document model (`perch_ir::PolicyDoc`, canonical slice) -/

inductive CScope where
  | contract (address : Str)
  | selfAdmin
deriving DecidableEq, Repr

inductive CPrincipals where
  | all (signers : List Str)
  | threshold (signers : List Str) (m : Nat)
  | selfAuth (policy installParamHex ack : Str)
deriving DecidableEq, Repr

inductive CPred where
  | isSelf
  | addressEq (address : Str)
  | stringIn (values : List Str)
  | stringPrefix (prefix_ : Str)
  | u32Eq (value : Nat)
deriving DecidableEq, Repr

structure CArg where
  index : Nat
  pred : CPred
deriving DecidableEq, Repr

inductive CSigner where
  | external (id verifier key : Str)
  | delegated (id address : Str)
deriving DecidableEq, Repr

structure CCap where
  token : Option Str
  limit : Str
  periodLedgers : Nat
deriving DecidableEq, Repr

structure CRule where
  name : Str
  scope : CScope
  principals : CPrincipals
  functions : Option (List Str)
  args : Option (List CArg)
  notAfterLedger : Option Nat
  cap : Option CCap
deriving DecidableEq, Repr

/-! ## The recovery member (`perch_ir::RecoveryConfig`, canonical slice) -/

/-- `RecoveryProfile`. -/
inductive CProfile where
  | loss
  | protected_
deriving DecidableEq, Repr

/-- `GuardianSet`. -/
structure CGuardians where
  guardians : List Str
  quorum : Nat
deriving DecidableEq, Repr

/-- `ZkFactor`. -/
structure CZk where
  adapter : Str
  circuitId : Str
  pool : Str
  enrollmentId : Str
  commitment : Str
deriving DecidableEq, Repr

/-- `RecoveryMode`. -/
inductive CMode where
  | guardianOnly (g : CGuardians)
  | zkOnly (z : CZk)
  | combined (g : CGuardians) (z : CZk)
deriving DecidableEq, Repr

/-- `RecoveryConfig`. `baseline` is `BaselineCommitment.doc_hash`, the
baseline object's only field. -/
structure CRecovery where
  profile : CProfile
  mode : CMode
  controller : Str
  baseline : Option Str
  replaceable : List Str
  delayLedgers : Nat
  expiryLedgers : Nat
  maxCancels : Nat
deriving DecidableEq, Repr

structure CDoc where
  version : Nat
  network : Option Str
  signers : List CSigner
  rules : List CRule
  recovery : Option CRecovery
deriving DecidableEq, Repr

/-! ## Emitter -/

/-- Concrete key/punctuation literals (Lean string literals reduce to their
char lists definitionally). -/
def lit (s : String) : List Char := s.toList

def hexChar (n : Nat) : Char := Char.ofNat (if n < 10 then 48 + n else 87 + n)

/-- JCS §3.2.2.2 escaping, exactly `write_json_string`'s match arms. -/
def escChar (c : Char) : List Char :=
  if c = '"' then ['\\', '"']
  else if c = '\\' then ['\\', '\\']
  else if c = '\x08' then ['\\', 'b']
  else if c = '\x09' then ['\\', 't']
  else if c = '\x0a' then ['\\', 'n']
  else if c = '\x0c' then ['\\', 'f']
  else if c = '\x0d' then ['\\', 'r']
  else if c.toNat < 0x20 then ['\\', 'u', '0', '0', hexChar (c.toNat / 16), hexChar (c.toNat % 16)]
  else [c]

def emitStr (s : Str) : List Char :=
  '"' :: (s.flatMap escChar) ++ ['"']

def digitChar (n : Nat) : Char := Char.ofNat (48 + n)

/-- Plain decimal, no leading zeros (`u.to_string()`). -/
def emitNat (n : Nat) : List Char :=
  if _h : n < 10 then [digitChar n]
  else emitNat (n / 10) ++ [digitChar (n % 10)]
decreasing_by exact Nat.div_lt_self (by omega) (by omega)

/-- `[e1,e2,…]` with no whitespace. -/
def emitList (f : α → List Char) : List α → List Char
  | [] => lit "[]"
  | x :: xs => '[' :: f x ++ xs.flatMap (fun y => ',' :: f y) ++ [']']

def emitScope : CScope → List Char
  | .contract address => lit "{\"address\":" ++ emitStr address ++ lit ",\"type\":\"contract\"}"
  | .selfAdmin => lit "{\"type\":\"self-admin\"}"

def emitPrincipals : CPrincipals → List Char
  | .all signers =>
    lit "{\"signers\":" ++ emitList emitStr signers ++ lit ",\"type\":\"all\"}"
  | .threshold signers m =>
    lit "{\"m\":" ++ emitNat m
      ++ lit ",\"signers\":" ++ emitList emitStr signers
      ++ lit ",\"type\":\"threshold\"}"
  | .selfAuth policy installParamHex ack =>
    lit "{\"ack\":" ++ emitStr ack
      ++ lit ",\"install-param-hex\":" ++ emitStr installParamHex
      ++ lit ",\"policy\":" ++ emitStr policy
      ++ lit ",\"type\":\"self-authenticating\"}"

def emitPred : CPred → List Char
  | .isSelf => lit "{\"type\":\"is-self\"}"
  | .addressEq address =>
    lit "{\"address\":" ++ emitStr address ++ lit ",\"type\":\"address-eq\"}"
  | .stringIn values =>
    lit "{\"type\":\"string-in\",\"values\":" ++ emitList emitStr values ++ lit "}"
  | .stringPrefix p =>
    lit "{\"prefix\":" ++ emitStr p ++ lit ",\"type\":\"string-prefix\"}"
  | .u32Eq v => lit "{\"type\":\"u32-eq\",\"value\":" ++ emitNat v ++ lit "}"

def emitArg (a : CArg) : List Char :=
  lit "{\"index\":" ++ emitNat a.index ++ lit ",\"pred\":" ++ emitPred a.pred ++ lit "}"

def emitSigner : CSigner → List Char
  | .external id verifier key =>
    lit "{\"id\":" ++ emitStr id ++ lit ",\"key\":" ++ emitStr key
      ++ lit ",\"verifier\":" ++ emitStr verifier ++ lit "}"
  | .delegated id address =>
    lit "{\"address\":" ++ emitStr address ++ lit ",\"id\":" ++ emitStr id ++ lit "}"

def emitCap (c : CCap) : List Char :=
  lit "{\"limit\":" ++ emitStr c.limit
    ++ lit ",\"period-ledgers\":" ++ emitNat c.periodLedgers
    ++ (match c.token with
        | some t => lit ",\"token\":" ++ emitStr t
        | none => [])
    ++ lit "}"

def emitRule (r : CRule) : List Char :=
  lit "{"
    ++ (match r.args with
        | some args => lit "\"args\":" ++ emitList emitArg args ++ lit ","
        | none => [])
    ++ (match r.cap with
        | some c => lit "\"cap\":" ++ emitCap c ++ lit ","
        | none => [])
    ++ (match r.functions with
        | some fns => lit "\"functions\":" ++ emitList emitStr fns ++ lit ","
        | none => [])
    ++ lit "\"name\":" ++ emitStr r.name
    ++ (match r.notAfterLedger with
        | some n => lit ",\"not-after-ledger\":" ++ emitNat n
        | none => [])
    ++ lit ",\"principals\":" ++ emitPrincipals r.principals
    ++ lit ",\"scope\":" ++ emitScope r.scope
    ++ lit "}"

/-- The profile tag. Rust emits it as a JSON string (`Cv::Str("loss")`);
neither tag has a character `escChar` rewrites, so the quoted literal is
that string's canonical form. -/
def emitProfile : CProfile → List Char
  | .loss => lit "\"loss\""
  | .protected_ => lit "\"protected\""

/-- The mode object: the guardian fields, the ZK fields, or both, beside the
`type` tag, with keys sorted across the whole object (`combined` interleaves
`guardians` between `enrollment-id` and `pool`). -/
def emitMode : CMode → List Char
  | .guardianOnly g =>
    lit "{\"guardians\":" ++ emitList emitStr g.guardians
      ++ lit ",\"quorum\":" ++ emitNat g.quorum
      ++ lit ",\"type\":\"guardian-only\"}"
  | .zkOnly z =>
    lit "{\"adapter\":" ++ emitStr z.adapter
      ++ lit ",\"circuit-id\":" ++ emitStr z.circuitId
      ++ lit ",\"commitment\":" ++ emitStr z.commitment
      ++ lit ",\"enrollment-id\":" ++ emitStr z.enrollmentId
      ++ lit ",\"pool\":" ++ emitStr z.pool
      ++ lit ",\"type\":\"zk-only\"}"
  | .combined g z =>
    lit "{\"adapter\":" ++ emitStr z.adapter
      ++ lit ",\"circuit-id\":" ++ emitStr z.circuitId
      ++ lit ",\"commitment\":" ++ emitStr z.commitment
      ++ lit ",\"enrollment-id\":" ++ emitStr z.enrollmentId
      ++ lit ",\"guardians\":" ++ emitList emitStr g.guardians
      ++ lit ",\"pool\":" ++ emitStr z.pool
      ++ lit ",\"quorum\":" ++ emitNat g.quorum
      ++ lit ",\"type\":\"combined\"}"

/-- The canonical bytes of a `recovery` member: `recovery_canonical_json`. -/
def emitRecovery (r : CRecovery) : List Char :=
  lit "{"
    ++ (match r.baseline with
        | some h => lit "\"baseline\":{\"doc-hash\":" ++ emitStr h ++ lit "},"
        | none => [])
    ++ lit "\"controller\":" ++ emitStr r.controller
    ++ lit ",\"delay-ledgers\":" ++ emitNat r.delayLedgers
    ++ lit ",\"expiry-ledgers\":" ++ emitNat r.expiryLedgers
    ++ lit ",\"max-cancels\":" ++ emitNat r.maxCancels
    ++ lit ",\"mode\":" ++ emitMode r.mode
    ++ lit ",\"profile\":" ++ emitProfile r.profile
    ++ lit ",\"replaceable\":" ++ emitList emitStr r.replaceable
    ++ lit "}"

/-- `CONFIG_DOMAIN` in `perch-doc-compiler`. -/
def configDomain : List Char := lit "perch/recovery/config"

/-- The `config_hash` preimage: `config_hash = sha256(configPreimage r)`
(`docs/recovery/spec.md` §3.2). -/
def configPreimage (r : CRecovery) : List Char :=
  configDomain ++ emitRecovery r

/-- The canonical bytes of a document (as unicode scalars; the Rust side's
UTF-8 encoding of them is itself injective). -/
def emitDoc (d : CDoc) : List Char :=
  lit "{"
    ++ (match d.network with
        | some n => lit "\"network\":" ++ emitStr n ++ lit ","
        | none => [])
    ++ (match d.recovery with
        | some r => lit "\"recovery\":" ++ emitRecovery r ++ lit ","
        | none => [])
    ++ lit "\"rules\":" ++ emitList emitRule d.rules
    ++ lit ",\"signers\":" ++ emitList emitSigner d.signers
    ++ lit ",\"version\":" ++ emitNat d.version
    ++ lit "}"

/-! ## Parser (proof artifact — inverts exactly what the emitter emits) -/

/-- Parser type: consume a prefix, return the value and the rest. -/
abbrev P (α : Type) := List Char → Option (α × List Char)

/-- Consume an exact literal. -/
def pExact : List Char → P Unit
  | [], input => some ((), input)
  | p :: ps, input =>
    match input with
    | [] => none
    | c :: rest => if c = p then pExact ps rest else none

def hexVal? (c : Char) : Option Nat :=
  if 48 ≤ c.toNat ∧ c.toNat ≤ 57 then some (c.toNat - 48)
  else if 97 ≤ c.toNat ∧ c.toNat ≤ 102 then some (c.toNat - 87)
  else none

/-- One escape sequence, after the `\` has been consumed. -/
def pEsc : P Char
  | input =>
    match input with
    | 'u' :: '0' :: '0' :: h1 :: h2 :: rest => do
      let a ← hexVal? h1
      let b ← hexVal? h2
      some (Char.ofNat (16 * a + b), rest)
    | c :: rest =>
      if c = '"' then some ('"', rest)
      else if c = '\\' then some ('\\', rest)
      else if c = 'b' then some ('\x08', rest)
      else if c = 't' then some ('\x09', rest)
      else if c = 'n' then some ('\x0a', rest)
      else if c = 'f' then some ('\x0c', rest)
      else if c = 'r' then some ('\x0d', rest)
      else none
    | [] => none

/-- String body after the opening quote, fueled (one unit per source char). -/
def pStrBody : Nat → P Str
  | 0, _ => none
  | _ + 1, [] => none
  | fuel + 1, c :: rest =>
    if c = '"' then some ([], rest)
    else if c = '\\' then do
      let (e, rest') ← pEsc rest
      let (s, rest'') ← pStrBody fuel rest'
      some (e :: s, rest'')
    else do
      let (s, rest') ← pStrBody fuel rest
      some (c :: s, rest')

def pStr : P Str
  | input =>
    match input with
    | '"' :: rest => pStrBody rest.length rest
    | _ => none

def isDigitC (c : Char) : Bool := 48 ≤ c.toNat && c.toNat ≤ 57

def digitVal (c : Char) : Nat := c.toNat - 48

/-- Greedy digit run onto an accumulator, fueled. Stops (successfully) at the
first non-digit; fuel exhaustion with a digit pending is a failure. -/
def pNatAux : Nat → Nat → P Nat
  | 0, acc, input =>
    match input with
    | c :: _ => if isDigitC c then none else some (acc, input)
    | [] => some (acc, input)
  | fuel + 1, acc, input =>
    match input with
    | c :: rest =>
      if isDigitC c then pNatAux fuel (acc * 10 + digitVal c) rest
      else some (acc, input)
    | [] => some (acc, input)

/-- At least one digit, then greedy. -/
def pNat : P Nat
  | input =>
    match input with
    | c :: _ =>
      if isDigitC c then pNatAux input.length 0 input
      else none
    | [] => none

/-- `[…]` of `pElem`, fueled per element. -/
def pListAux (pElem : P α) : Nat → P (List α)
  | 0, _ => none
  | fuel + 1, input => do
    let (x, rest) ← pElem input
    match rest with
    | ',' :: rest' => do
      let (xs, rest'') ← pListAux pElem fuel rest'
      some (x :: xs, rest'')
    | ']' :: rest' => some ([x], rest')
    | _ => none

def pList (pElem : P α) : P (List α)
  | input =>
    match input with
    | '[' :: rest =>
      match rest with
      | c :: rest' => if c = ']' then some ([], rest') else pListAux pElem rest.length rest
      | [] => none
    | _ => none

/-- Try a literal; on match run `then_`, otherwise `else_` on the untouched
input. Sound because every use site distinguishes concrete literals. -/
def pOpt (litp : List Char) (then_ : P α) (else_ : P α) : P α
  | input =>
    match pExact litp input with
    | some ((), rest) => then_ rest
    | none => else_ input

def pScope : P CScope :=
  pOpt (lit "{\"address\":")
    (fun input => do
      let (a, rest) ← pStr input
      let ((), rest') ← pExact (lit ",\"type\":\"contract\"}") rest
      some (.contract a, rest'))
    (fun input => do
      let ((), rest) ← pExact (lit "{\"type\":\"self-admin\"}") input
      some (.selfAdmin, rest))

def pPrincipals : P CPrincipals :=
  pOpt (lit "{\"ack\":")
    (fun input => do
      let (ack, r1) ← pStr input
      let ((), r2) ← pExact (lit ",\"install-param-hex\":") r1
      let (iph, r3) ← pStr r2
      let ((), r4) ← pExact (lit ",\"policy\":") r3
      let (policy, r5) ← pStr r4
      let ((), r6) ← pExact (lit ",\"type\":\"self-authenticating\"}") r5
      some (.selfAuth policy iph ack, r6))
    (pOpt (lit "{\"m\":")
      (fun input => do
        let (m, r1) ← pNat input
        let ((), r2) ← pExact (lit ",\"signers\":") r1
        let (signers, r3) ← pList pStr r2
        let ((), r4) ← pExact (lit ",\"type\":\"threshold\"}") r3
        some (.threshold signers m, r4))
      (fun input => do
        let ((), r1) ← pExact (lit "{\"signers\":") input
        let (signers, r2) ← pList pStr r1
        let ((), r3) ← pExact (lit ",\"type\":\"all\"}") r2
        some (.all signers, r3)))

def pPred : P CPred :=
  pOpt (lit "{\"address\":")
    (fun input => do
      let (a, r1) ← pStr input
      let ((), r2) ← pExact (lit ",\"type\":\"address-eq\"}") r1
      some (.addressEq a, r2))
    (pOpt (lit "{\"prefix\":")
      (fun input => do
        let (p, r1) ← pStr input
        let ((), r2) ← pExact (lit ",\"type\":\"string-prefix\"}") r1
        some (.stringPrefix p, r2))
      (pOpt (lit "{\"type\":\"is-self\"}")
        (fun input => some (.isSelf, input))
        (pOpt (lit "{\"type\":\"string-in\",\"values\":")
          (fun input => do
            let (vs, r1) ← pList pStr input
            let ((), r2) ← pExact (lit "}") r1
            some (.stringIn vs, r2))
          (fun input => do
            let ((), r1) ← pExact (lit "{\"type\":\"u32-eq\",\"value\":") input
            let (v, r2) ← pNat r1
            let ((), r3) ← pExact (lit "}") r2
            some (.u32Eq v, r3)))))

def pArg : P CArg
  | input => do
    let ((), r1) ← pExact (lit "{\"index\":") input
    let (i, r2) ← pNat r1
    let ((), r3) ← pExact (lit ",\"pred\":") r2
    let (p, r4) ← pPred r3
    let ((), r5) ← pExact (lit "}") r4
    some (⟨i, p⟩, r5)

def pSigner : P CSigner :=
  pOpt (lit "{\"address\":")
    (fun input => do
      let (address, r1) ← pStr input
      let ((), r2) ← pExact (lit ",\"id\":") r1
      let (id, r3) ← pStr r2
      let ((), r4) ← pExact (lit "}") r3
      some (.delegated id address, r4))
    (fun input => do
      let ((), r1) ← pExact (lit "{\"id\":") input
      let (id, r2) ← pStr r1
      let ((), r3) ← pExact (lit ",\"key\":") r2
      let (key, r4) ← pStr r3
      let ((), r5) ← pExact (lit ",\"verifier\":") r4
      let (verifier, r6) ← pStr r5
      let ((), r7) ← pExact (lit "}") r6
      some (.external id verifier key, r7))

def pCap : P CCap
  | input => do
    let ((), r1) ← pExact (lit "{\"limit\":") input
    let (limit, r2) ← pStr r1
    let ((), r3) ← pExact (lit ",\"period-ledgers\":") r2
    let (pl, r4) ← pNat r3
    pOpt (lit ",\"token\":")
      (fun i => do
        let (t, r5) ← pStr i
        let ((), r6) ← pExact (lit "}") r5
        some (⟨some t, limit, pl⟩, r6))
      (fun i => do
        let ((), r5) ← pExact (lit "}") i
        some (⟨none, limit, pl⟩, r5))
      r4

def pRule : P CRule
  | input => do
    let ((), r0) ← pExact (lit "{") input
    let step := fun (args : Option (List CArg)) (i0 : List Char) =>
      pOpt (lit "\"cap\":")
        (fun i => do
          let (c, r) ← pCap i
          let ((), r') ← pExact (lit ",") r
          some ((args, some c), r'))
        (fun i => some ((args, (none : Option CCap)), i))
        i0
    let ((args, cap), r1) ←
      pOpt (lit "\"args\":")
        (fun i => do
          let (a, r) ← pList pArg i
          let ((), r') ← pExact (lit ",") r
          step (some a) r')
        (step none)
        r0
    let (functions, r2) ←
      pOpt (lit "\"functions\":")
        (fun i => do
          let (f, r) ← pList pStr i
          let ((), r') ← pExact (lit ",") r
          some (some f, r'))
        (fun i => some ((none : Option (List Str)), i))
        r1
    let ((), r3) ← pExact (lit "\"name\":") r2
    let (name, r4) ← pStr r3
    let (nal, r5) ←
      pOpt (lit ",\"not-after-ledger\":")
        (fun i => do
          let (n, r) ← pNat i
          some (some n, r))
        (fun i => some ((none : Option Nat), i))
        r4
    let ((), r6) ← pExact (lit ",\"principals\":") r5
    let (principals, r7) ← pPrincipals r6
    let ((), r8) ← pExact (lit ",\"scope\":") r7
    let (scope, r9) ← pScope r8
    let ((), r10) ← pExact (lit "}") r9
    some (⟨name, scope, principals, functions, args, nal, cap⟩, r10)

def pProfile : P CProfile :=
  pOpt (lit "\"loss\"")
    (fun input => some (.loss, input))
    (fun input => do
      let ((), r1) ← pExact (lit "\"protected\"") input
      some (.protected_, r1))

def pMode : P CMode :=
  pOpt (lit "{\"guardians\":")
    (fun input => do
      let (gs, r1) ← pList pStr input
      let ((), r2) ← pExact (lit ",\"quorum\":") r1
      let (q, r3) ← pNat r2
      let ((), r4) ← pExact (lit ",\"type\":\"guardian-only\"}") r3
      some (.guardianOnly ⟨gs, q⟩, r4))
    (fun input => do
      let ((), r1) ← pExact (lit "{\"adapter\":") input
      let (adapter, r2) ← pStr r1
      let ((), r3) ← pExact (lit ",\"circuit-id\":") r2
      let (circuitId, r4) ← pStr r3
      let ((), r5) ← pExact (lit ",\"commitment\":") r4
      let (commitment, r6) ← pStr r5
      let ((), r7) ← pExact (lit ",\"enrollment-id\":") r6
      let (enrollmentId, r8) ← pStr r7
      pOpt (lit ",\"guardians\":")
        (fun i => do
          let (gs, s1) ← pList pStr i
          let ((), s2) ← pExact (lit ",\"pool\":") s1
          let (pool, s3) ← pStr s2
          let ((), s4) ← pExact (lit ",\"quorum\":") s3
          let (q, s5) ← pNat s4
          let ((), s6) ← pExact (lit ",\"type\":\"combined\"}") s5
          some (.combined ⟨gs, q⟩ ⟨adapter, circuitId, pool, enrollmentId, commitment⟩, s6))
        (fun i => do
          let ((), s1) ← pExact (lit ",\"pool\":") i
          let (pool, s2) ← pStr s1
          let ((), s3) ← pExact (lit ",\"type\":\"zk-only\"}") s2
          some (.zkOnly ⟨adapter, circuitId, pool, enrollmentId, commitment⟩, s3))
        r8)

def pRecovery : P CRecovery
  | input => do
    let ((), r0) ← pExact (lit "{") input
    let (baseline, r1) ←
      pOpt (lit "\"baseline\":{\"doc-hash\":")
        (fun i => do
          let (h, r) ← pStr i
          let ((), r') ← pExact (lit "},") r
          some (some h, r'))
        (fun i => some ((none : Option Str), i))
        r0
    let ((), r2) ← pExact (lit "\"controller\":") r1
    let (controller, r3) ← pStr r2
    let ((), r4) ← pExact (lit ",\"delay-ledgers\":") r3
    let (delay, r5) ← pNat r4
    let ((), r6) ← pExact (lit ",\"expiry-ledgers\":") r5
    let (expiry, r7) ← pNat r6
    let ((), r8) ← pExact (lit ",\"max-cancels\":") r7
    let (maxCancels, r9) ← pNat r8
    let ((), r10) ← pExact (lit ",\"mode\":") r9
    let (mode, r11) ← pMode r10
    let ((), r12) ← pExact (lit ",\"profile\":") r11
    let (profile, r13) ← pProfile r12
    let ((), r14) ← pExact (lit ",\"replaceable\":") r13
    let (replaceable, r15) ← pList pStr r14
    let ((), r16) ← pExact (lit "}") r15
    some (⟨profile, mode, controller, baseline, replaceable, delay, expiry, maxCancels⟩, r16)

def pDoc : P CDoc
  | input => do
    let ((), r0) ← pExact (lit "{") input
    let (network, r1) ←
      pOpt (lit "\"network\":")
        (fun i => do
          let (n, r) ← pStr i
          let ((), r') ← pExact (lit ",") r
          some (some n, r'))
        (fun i => some ((none : Option Str), i))
        r0
    let (recovery, r2) ←
      pOpt (lit "\"recovery\":")
        (fun i => do
          let (rc, r) ← pRecovery i
          let ((), r') ← pExact (lit ",") r
          some (some rc, r'))
        (fun i => some ((none : Option CRecovery), i))
        r1
    let ((), r3) ← pExact (lit "\"rules\":") r2
    let (rules, r4) ← pList pRule r3
    let ((), r5) ← pExact (lit ",\"signers\":") r4
    let (signers, r6) ← pList pSigner r5
    let ((), r7) ← pExact (lit ",\"version\":") r6
    let (version, r8) ← pNat r7
    let ((), r9) ← pExact (lit "}") r8
    some (⟨version, network, signers, rules, recovery⟩, r9)

end Canon
end PerchFormal
