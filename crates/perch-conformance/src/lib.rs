//! Eval-semantics conformance vectors (#PLAN phase 0).
//!
//! Each [`Case`] is a `(program, invocation) → (validate outcome, verdict)`
//! pair whose expectations are **hand-authored against `CANONICAL.md` and the
//! documented leaf semantics** — never generated from the implementation, so a
//! bug in `rpn::eval` shows up as a failing case instead of being frozen into
//! the vectors. The table is the source of truth; `tests/eval_vectors.rs`
//! executes it against the real evaluator and pins its JSON serialization to
//! `testdata/eval/eval-vectors.json` (the file the Lean model in `formal/`
//! replays), `UPDATE_GOLDEN=1` to rebless.
//!
//! The JSON writer is hand-rolled like `perch-golden`'s manifest — this
//! workspace stays serde-free by design (see `perch-ir`'s crate docs).
//!
//! Conventions shared with the model:
//! - Addresses are symbolic names; `"self"` is the protected account. The
//!   runner maps distinct names to distinct concrete addresses, so equality
//!   semantics carry over exactly.
//! - Strings are UTF-8 text; lengths are byte lengths (soroban `String.len()`).
//! - `i128` values are decimal strings (JSON numbers are not wide enough).

use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, Env, IntoVal, String as SString, Symbol, Val, Vec as SVec};

use perch_program::{rpn, EvalInputs, Op, RpnProgram, ValidationError, Verdict, PROGRAM_VERSION};

/// A call argument in a conformance invocation.
#[derive(Clone, Debug)]
pub enum ValSpec {
    U32(u32),
    /// Decimal string in JSON.
    I128(i128),
    /// Symbolic address name; `"self"` is the protected account.
    Address(&'static str),
    Symbol(&'static str),
    Str(String),
    Bytes(&'static [u8]),
    /// An argument no leaf can decode (host `void`) — a decode-failure probe.
    Void,
}

/// A program op, mirrored from [`Op`] with symbolic addresses.
#[derive(Clone, Debug)]
pub enum OpSpec {
    All(u32),
    Any(u32),
    Not,
    MinSigners(u32),
    FnIn(&'static [&'static str]),
    ArgAddrEq(u32, &'static str),
    ArgAddrIsSelf(u32),
    ArgSymEq(u32, &'static str),
    ArgStrIn(u32, Vec<String>),
    ArgStrPrefix(u32, String),
    ArgBytesEq(u32, &'static [u8]),
    ArgI128Eq(u32, i128),
    ArgU32Eq(u32, u32),
    ArgCount(u32),
    LedgerBefore(u32),
    LedgerAtOrAfter(u32),
}

/// The authorization context shape under test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtxKind {
    /// A contract call: `fn_name` + `args` are present.
    Contract,
    /// A non-`Contract` context — every context-inspecting leaf must fail
    /// closed to `Unknown`; signer/ledger leaves stay definite.
    NonContract,
}

/// One invocation the program is evaluated against.
#[derive(Clone, Debug)]
pub struct InvSpec {
    pub ctx: CtxKind,
    pub fn_name: &'static str,
    pub args: Vec<ValSpec>,
    pub signer_count: u32,
    pub ledger: u32,
}

/// Expected `rpn::validate` outcome, as the kebab-case error name.
pub type ExpectValid = Result<(), &'static str>;

/// One conformance case.
pub struct Case {
    pub name: &'static str,
    /// Why this case exists / what it pins.
    pub pins: &'static str,
    pub version: u32,
    pub ops: Vec<OpSpec>,
    pub inv: InvSpec,
    pub expect_valid: ExpectValid,
    pub expect_verdict: Verdict,
}

/// Kebab-case name of a [`ValidationError`], shared with the JSON form.
#[must_use]
pub fn validation_error_name(err: ValidationError) -> &'static str {
    match err {
        ValidationError::UnknownVersion => "unknown-version",
        ValidationError::Empty => "empty",
        ValidationError::TooLarge => "too-large",
        ValidationError::ArityMismatch => "arity-mismatch",
        ValidationError::StackUnderflow => "stack-underflow",
        ValidationError::StackOverflow => "stack-overflow",
        ValidationError::NotSingleResult => "not-single-result",
    }
}

/// JSON name of a [`Verdict`].
#[must_use]
pub fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::True => "true",
        Verdict::Unknown => "unknown",
        Verdict::False => "false",
    }
}

// --- the curated table -------------------------------------------------------

fn s(x: &str) -> String {
    x.into()
}

fn long(n: usize) -> String {
    "a".repeat(n)
}

/// The default invocation: a contract call of `publish` with one argument of
/// each decodable type, one signer, ledger sequence 100.
fn inv() -> InvSpec {
    InvSpec {
        ctx: CtxKind::Contract,
        fn_name: "publish",
        args: vec![
            ValSpec::U32(7),          // 0
            ValSpec::Address("self"), // 1
            ValSpec::Symbol("kind"),  // 2
            ValSpec::Str(s("hello")), // 3
            ValSpec::Bytes(&[1, 2]),  // 4
            ValSpec::I128(-42),       // 5
            ValSpec::Void,            // 6
        ],
        signer_count: 1,
        ledger: 100,
    }
}

fn non_contract() -> InvSpec {
    InvSpec {
        ctx: CtxKind::NonContract,
        fn_name: "",
        args: vec![],
        signer_count: 1,
        ledger: 100,
    }
}

fn case(
    name: &'static str,
    pins: &'static str,
    ops: Vec<OpSpec>,
    inv: InvSpec,
    expect_valid: ExpectValid,
    expect_verdict: Verdict,
) -> Case {
    Case {
        name,
        pins,
        version: PROGRAM_VERSION,
        ops,
        inv,
        expect_valid,
        expect_verdict,
    }
}

/// Every conformance case. Ordering is stable — it is part of the frozen file.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn cases() -> Vec<Case> {
    use OpSpec as O;
    use Verdict::{False, True, Unknown};

    let mut sc0 = inv();
    sc0.signer_count = 0;
    let mut arg1_alice = inv();
    arg1_alice.args[1] = ValSpec::Address("alice");
    let mut arg3_overlong = inv();
    arg3_overlong.args[3] = ValSpec::Str(long(257));
    let mut arg3_max = inv();
    arg3_max.args[3] = ValSpec::Str(long(256));

    let mut v = vec![
        // --- single leaves: definite hits, definite misses, decode failures --
        case(
            "min-signers-met",
            "MinSigners is >= on the authenticated-signer count",
            vec![O::MinSigners(1)],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "min-signers-unmet",
            "one signer does not meet a floor of two",
            vec![O::MinSigners(2)],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "min-signers-zero-floor",
            "MinSigners(0) is vacuously true even with zero signers",
            vec![O::MinSigners(0)],
            sc0.clone(),
            Ok(()),
            True,
        ),
        case(
            "min-signers-non-contract",
            "MinSigners is context-independent: definite under a non-contract context",
            vec![O::MinSigners(1)],
            non_contract(),
            Ok(()),
            True,
        ),
        case(
            "fn-in-hit",
            "invoked function inside the allowlist",
            vec![O::FnIn(&["publish", "other"])],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "fn-in-miss",
            "invoked function outside the allowlist",
            vec![O::FnIn(&["other"])],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "fn-in-empty-is-false",
            "an empty allowlist is vacuously False (definite), not Unknown",
            vec![O::FnIn(&[])],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "fn-in-non-contract",
            "context leaf fails closed to Unknown outside a contract call",
            vec![O::FnIn(&["publish"])],
            non_contract(),
            Ok(()),
            Unknown,
        ),
        case(
            "arg-addr-eq-hit",
            "address equality on a matching argument",
            vec![O::ArgAddrEq(1, "self")],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-addr-eq-miss",
            "address equality on a differing argument",
            vec![O::ArgAddrEq(1, "alice")],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "arg-addr-eq-wrong-type",
            "decode failure (u32 argument read as address) is Unknown, never False",
            vec![O::ArgAddrEq(0, "alice")],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "arg-addr-eq-missing-index",
            "missing argument index is a decode failure",
            vec![O::ArgAddrEq(9, "alice")],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "arg-addr-is-self-hit",
            "argument is the protected account",
            vec![O::ArgAddrIsSelf(1)],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-addr-is-self-miss",
            "argument is some other address",
            vec![O::ArgAddrIsSelf(1)],
            arg1_alice,
            Ok(()),
            False,
        ),
        case(
            "arg-sym-eq-hit",
            "symbol equality hit",
            vec![O::ArgSymEq(2, "kind")],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-sym-eq-miss",
            "symbol equality miss",
            vec![O::ArgSymEq(2, "other")],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "arg-sym-eq-wrong-type",
            "string argument read as symbol is a decode failure",
            vec![O::ArgSymEq(3, "hello")],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "arg-str-in-hit",
            "string set membership hit",
            vec![O::ArgStrIn(3, vec![s("hello"), s("x")])],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-str-in-miss",
            "string set membership miss",
            vec![O::ArgStrIn(3, vec![s("x")])],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "arg-str-in-overlong-arg",
            "argument longer than MAX_STR_ARG_LEN fails closed even if the set matches textually",
            vec![O::ArgStrIn(3, vec![long(257)])],
            arg3_overlong.clone(),
            Ok(()),
            Unknown,
        ),
        case(
            "arg-str-in-overlong-candidate-skipped",
            "an over-long *candidate* is skipped, not fatal — a later match still hits",
            vec![O::ArgStrIn(3, vec![long(257), s("hello")])],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-str-in-only-overlong-candidates",
            "a set of only over-long candidates simply never matches: definite False",
            vec![O::ArgStrIn(3, vec![long(257)])],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "arg-str-in-256-boundary",
            "exactly MAX_STR_ARG_LEN (256) bytes is still comparable",
            vec![O::ArgStrIn(3, vec![long(256)])],
            arg3_max.clone(),
            Ok(()),
            True,
        ),
        case(
            "arg-str-prefix-hit",
            "prefix hit",
            vec![O::ArgStrPrefix(3, s("he"))],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-str-prefix-exact-equal",
            "a prefix equal to the whole argument matches (pn == sn)",
            vec![O::ArgStrPrefix(3, s("hello"))],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-str-prefix-longer-than-arg",
            "a prefix longer than the argument is a definite miss, not Unknown",
            vec![O::ArgStrPrefix(3, s("hello!"))],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "arg-str-prefix-miss",
            "prefix miss",
            vec![O::ArgStrPrefix(3, s("x"))],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "arg-str-prefix-empty-prefix",
            "the empty prefix matches any decodable string argument",
            vec![O::ArgStrPrefix(3, s(""))],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-str-prefix-overlong-arg",
            "over-long argument fails closed under prefix too",
            vec![O::ArgStrPrefix(3, s("a"))],
            arg3_overlong,
            Ok(()),
            Unknown,
        ),
        case(
            "arg-str-prefix-overlong-prefix",
            "an over-long *prefix* constant also fails closed (both sides are bounded)",
            vec![O::ArgStrPrefix(3, long(257))],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "arg-bytes-eq-hit",
            "bytes equality hit",
            vec![O::ArgBytesEq(4, &[1, 2])],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-bytes-eq-miss",
            "bytes equality miss",
            vec![O::ArgBytesEq(4, &[9, 9])],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "arg-bytes-eq-wrong-type",
            "u32 argument read as bytes is a decode failure",
            vec![O::ArgBytesEq(0, &[1, 2])],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "arg-i128-eq-hit",
            "i128 equality hit (negative value)",
            vec![O::ArgI128Eq(5, -42)],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-i128-eq-miss",
            "i128 equality miss",
            vec![O::ArgI128Eq(5, 42)],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "arg-i128-eq-wrong-type",
            "u32 argument is NOT implicitly widened to i128 — strict decode, Unknown",
            vec![O::ArgI128Eq(0, 7)],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "arg-u32-eq-hit",
            "u32 equality hit",
            vec![O::ArgU32Eq(0, 7)],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-u32-eq-miss",
            "u32 equality miss",
            vec![O::ArgU32Eq(0, 8)],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "arg-u32-eq-wrong-type",
            "i128 argument read as u32 is a decode failure",
            vec![O::ArgU32Eq(5, 7)],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "arg-u32-eq-void-arg",
            "an undecodable (void) argument is a decode failure",
            vec![O::ArgU32Eq(6, 0)],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "arg-count-exact",
            "ArgCount is exact equality on the argument count",
            vec![O::ArgCount(7)],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "arg-count-miss",
            "ArgCount misses on any other count",
            vec![O::ArgCount(3)],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "arg-count-non-contract",
            "ArgCount inspects the context: Unknown outside a contract call",
            vec![O::ArgCount(0)],
            non_contract(),
            Ok(()),
            Unknown,
        ),
        case(
            "ledger-before-true",
            "strictly-below window is open below the bound",
            vec![O::LedgerBefore(101)],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "ledger-before-boundary-false",
            "LedgerBefore is strict: closed exactly at the bound",
            vec![O::LedgerBefore(100)],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "ledger-at-or-after-boundary-true",
            "LedgerAtOrAfter is inclusive at the bound",
            vec![O::LedgerAtOrAfter(100)],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "ledger-at-or-after-false",
            "LedgerAtOrAfter below the bound is False",
            vec![O::LedgerAtOrAfter(101)],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "ledger-non-contract",
            "ledger leaves read the env, not the context: definite under non-contract",
            vec![O::LedgerBefore(101)],
            non_contract(),
            Ok(()),
            True,
        ),
        // --- Kleene composition ---------------------------------------------
        case(
            "all-true",
            "All folds True over definite-true leaves",
            vec![O::MinSigners(0), O::FnIn(&["publish"]), O::All(2)],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "all-false-wins",
            "All with one False is False",
            vec![O::MinSigners(2), O::FnIn(&["publish"]), O::All(2)],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "all-unknown-poisons-true",
            "All(Unknown, True) is Unknown — a decode failure can never help authorize",
            vec![O::ArgU32Eq(6, 0), O::MinSigners(0), O::All(2)],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "all-false-beats-unknown",
            "All(Unknown, False) is False — min under False < Unknown < True",
            vec![O::ArgU32Eq(6, 0), O::MinSigners(2), O::All(2)],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "any-true-beats-unknown",
            "Any(Unknown, True) is True — max under the same order",
            vec![O::ArgU32Eq(6, 0), O::MinSigners(0), O::Any(2)],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "any-all-false",
            "Any over definite-false leaves is False",
            vec![O::MinSigners(2), O::FnIn(&["other"]), O::Any(2)],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "any-unknown-beats-false",
            "Any(Unknown, False) is Unknown — an undecodable branch cannot be assumed False",
            vec![O::ArgU32Eq(6, 0), O::MinSigners(2), O::Any(2)],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "not-true",
            "Not(True) is False",
            vec![O::MinSigners(0), O::Not],
            inv(),
            Ok(()),
            False,
        ),
        case(
            "not-false",
            "Not(False) is True",
            vec![O::MinSigners(2), O::Not],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "not-unknown-stays-unknown",
            "THE fail-open trap: a decode failure under Not must deny, not satisfy the guardrail",
            vec![O::ArgU32Eq(6, 0), O::Not],
            inv(),
            Ok(()),
            Unknown,
        ),
        case(
            "double-not",
            "Not is an involution on definite verdicts",
            vec![O::MinSigners(0), O::Not, O::Not],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "ci-publish-shape-allows",
            "the motivating program: MinSigners + FnIn + ArgAddrIsSelf under All",
            vec![
                O::MinSigners(1),
                O::FnIn(&["publish", "publish_hash"]),
                O::ArgAddrIsSelf(1),
                O::All(3),
            ],
            inv(),
            Ok(()),
            True,
        ),
        case(
            "ci-publish-shape-denies-zero-signers",
            "the same program fails closed with zero authenticated signers (INV-1)",
            vec![
                O::MinSigners(1),
                O::FnIn(&["publish", "publish_hash"]),
                O::ArgAddrIsSelf(1),
                O::All(3),
            ],
            sc0,
            Ok(()),
            False,
        ),
        // --- structural guards: validate errors and eval's fail-closed twin --
        case(
            "empty-program",
            "no ops: rejected at install; eval yields no root verdict",
            vec![],
            inv(),
            Err("empty"),
            Unknown,
        ),
        case(
            "underflow-not",
            "Not with an empty stack underflows",
            vec![O::Not],
            inv(),
            Err("stack-underflow"),
            Unknown,
        ),
        case(
            "underflow-all",
            "All(2) over a single pushed verdict underflows",
            vec![O::MinSigners(0), O::All(2)],
            inv(),
            Err("stack-underflow"),
            Unknown,
        ),
        case(
            "zero-arity-all",
            "All(0) has no identity element on purpose — rejected, and eval fails closed",
            vec![O::All(0)],
            inv(),
            Err("arity-mismatch"),
            Unknown,
        ),
        case(
            "zero-arity-any",
            "Any(0) likewise",
            vec![O::Any(0)],
            inv(),
            Err("arity-mismatch"),
            Unknown,
        ),
        case(
            "multi-result",
            "two verdicts left on the stack is not a program",
            vec![O::MinSigners(0), O::MinSigners(0)],
            inv(),
            Err("not-single-result"),
            Unknown,
        ),
        case(
            "partial-consume-multi-result",
            "a fold that consumes only part of the stack still ends multi-result",
            vec![
                O::MinSigners(0),
                O::MinSigners(0),
                O::MinSigners(0),
                O::Any(2),
            ],
            inv(),
            Err("not-single-result"),
            Unknown,
        ),
    ];

    // Version-blindness of eval: validation rejects an unknown version, but a
    // program that somehow bypassed install-time validation still evaluates —
    // install-time validate is the only version gate. Pinned deliberately.
    let mut wrong_version = case(
        "wrong-version-eval-is-version-blind",
        "validate rejects version 2; eval itself never reads the version field",
        vec![OpSpec::MinSigners(0)],
        inv(),
        Err("unknown-version"),
        Verdict::True,
    );
    wrong_version.version = 2;
    v.push(wrong_version);

    // Depth boundary: 128 leaves then All(128) touches MAX_STACK_DEPTH exactly.
    let mut at_cap: Vec<OpSpec> = vec![OpSpec::MinSigners(0); 128];
    at_cap.push(OpSpec::All(128));
    v.push(case(
        "depth-at-cap-ok",
        "a simulated depth of exactly MAX_STACK_DEPTH validates and evaluates",
        at_cap,
        inv(),
        Ok(()),
        Verdict::True,
    ));

    // One leaf past the cap: rejected, and eval fails closed at the push guard.
    let over_cap: Vec<OpSpec> = vec![OpSpec::MinSigners(0); 129];
    v.push(case(
        "depth-overflow",
        "MAX_STACK_DEPTH + 1 unfolded leaves overflow the verdict stack",
        over_cap,
        inv(),
        Err("stack-overflow"),
        Verdict::Unknown,
    ));

    // One op past the program-length cap.
    let too_large: Vec<OpSpec> = vec![OpSpec::MinSigners(0); 257];
    v.push(case(
        "program-too-large",
        "MAX_PROGRAM_LEN + 1 ops are rejected at install",
        too_large,
        inv(),
        Err("too-large"),
        Verdict::Unknown,
    ));

    v
}

// --- building real soroban values from specs ---------------------------------

/// Maps symbolic address names to concrete generated addresses, consistently
/// within one run. `"self"` is the protected account.
pub struct AddrBook {
    entries: std::vec::Vec<(&'static str, Address)>,
}

impl AddrBook {
    #[must_use]
    pub fn new() -> AddrBook {
        AddrBook {
            entries: std::vec::Vec::new(),
        }
    }

    pub fn get(&mut self, env: &Env, name: &'static str) -> Address {
        if let Some((_, a)) = self.entries.iter().find(|(n, _)| *n == name) {
            return a.clone();
        }
        let a = Address::generate(env);
        self.entries.push((name, a.clone()));
        a
    }
}

impl Default for AddrBook {
    fn default() -> Self {
        AddrBook::new()
    }
}

fn val(env: &Env, book: &mut AddrBook, spec: &ValSpec) -> Val {
    match spec {
        ValSpec::U32(n) => (*n).into_val(env),
        ValSpec::I128(n) => (*n).into_val(env),
        ValSpec::Address(name) => book.get(env, name).into_val(env),
        ValSpec::Symbol(sym) => Symbol::new(env, sym).into_val(env),
        ValSpec::Str(text) => SString::from_str(env, text).into_val(env),
        ValSpec::Bytes(b) => Bytes::from_slice(env, b).into_val(env),
        ValSpec::Void => ().into_val(env),
    }
}

/// Build the real [`Op`] for an [`OpSpec`].
pub fn op(env: &Env, book: &mut AddrBook, spec: &OpSpec) -> Op {
    match spec {
        OpSpec::All(n) => Op::All(*n),
        OpSpec::Any(n) => Op::Any(*n),
        OpSpec::Not => Op::Not,
        OpSpec::MinSigners(n) => Op::MinSigners(*n),
        OpSpec::FnIn(fns) => {
            let mut v: SVec<Symbol> = SVec::new(env);
            for f in *fns {
                v.push_back(Symbol::new(env, f));
            }
            Op::FnIn(v)
        }
        OpSpec::ArgAddrEq(i, name) => Op::ArgAddrEq(*i, book.get(env, name)),
        OpSpec::ArgAddrIsSelf(i) => Op::ArgAddrIsSelf(*i),
        OpSpec::ArgSymEq(i, sym) => Op::ArgSymEq(*i, Symbol::new(env, sym)),
        OpSpec::ArgStrIn(i, values) => {
            let mut v: SVec<SString> = SVec::new(env);
            for x in values {
                v.push_back(SString::from_str(env, x));
            }
            Op::ArgStrIn(*i, v)
        }
        OpSpec::ArgStrPrefix(i, prefix) => Op::ArgStrPrefix(*i, SString::from_str(env, prefix)),
        OpSpec::ArgBytesEq(i, b) => Op::ArgBytesEq(*i, Bytes::from_slice(env, b)),
        OpSpec::ArgI128Eq(i, n) => Op::ArgI128Eq(*i, *n),
        OpSpec::ArgU32Eq(i, n) => Op::ArgU32Eq(*i, *n),
        OpSpec::ArgCount(n) => Op::ArgCount(*n),
        OpSpec::LedgerBefore(n) => Op::LedgerBefore(*n),
        OpSpec::LedgerAtOrAfter(n) => Op::LedgerAtOrAfter(*n),
    }
}

/// Build the real [`RpnProgram`] for a case.
pub fn program(env: &Env, book: &mut AddrBook, c: &Case) -> RpnProgram {
    let mut ops: SVec<Op> = SVec::new(env);
    for spec in &c.ops {
        ops.push_back(op(env, book, spec));
    }
    RpnProgram {
        version: c.version,
        ops,
    }
}

/// Run one case against the real evaluator, returning
/// `(validate outcome, verdict)`.
pub fn run(env: &Env, book: &mut AddrBook, c: &Case) -> (Result<(), ValidationError>, Verdict) {
    let (p, ctx, signer_count, self_addr) = materialize(env, book, c);
    let valid = rpn::validate(&p);
    let inputs = EvalInputs {
        context: &ctx,
        signer_count,
        self_addr: &self_addr,
    };
    (valid, rpn::eval(env, &p, &inputs))
}

/// Materialize a case into concrete soroban values: sets the env's ledger
/// sequence and returns the program plus the evaluator inputs' components.
/// Shared by the native leg ([`run`]) and the wasm leg (`tests/wasm_leg.rs`),
/// so both execute byte-identical inputs.
pub fn materialize(
    env: &Env,
    book: &mut AddrBook,
    c: &Case,
) -> (RpnProgram, Context, u32, Address) {
    use soroban_sdk::testutils::Ledger as _;
    env.ledger().with_mut(|li| {
        li.sequence_number = c.inv.ledger;
    });

    let p = program(env, book, c);
    let self_addr = book.get(env, "self");
    let ctx = match c.inv.ctx {
        CtxKind::Contract => {
            let mut args: SVec<Val> = SVec::new(env);
            for a in &c.inv.args {
                args.push_back(val(env, book, a));
            }
            Context::Contract(ContractContext {
                contract: book.get(env, "target-contract"),
                fn_name: Symbol::new(env, c.inv.fn_name),
                args,
            })
        }
        CtxKind::NonContract => non_contract_context(env),
    };
    (p, ctx, c.inv.signer_count, self_addr)
}

/// A concrete non-`Contract` authorization context: contract creation via the
/// host function. Every context-inspecting leaf must yield `Unknown` for it.
fn non_contract_context(env: &Env) -> Context {
    use soroban_sdk::auth::{ContractExecutable, CreateContractHostFnContext};
    use soroban_sdk::BytesN;
    Context::CreateContractHostFn(CreateContractHostFnContext {
        executable: ContractExecutable::Wasm(BytesN::from_array(env, &[0u8; 32])),
        salt: BytesN::from_array(env, &[0u8; 32]),
    })
}

// --- JSON serialization (hand-rolled; the workspace is serde-free) -----------

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_str_list(items: &[String]) -> String {
    let inner: std::vec::Vec<String> = items.iter().map(|x| format!("\"{}\"", esc(x))).collect();
    format!("[{}]", inner.join(","))
}

fn op_json(spec: &OpSpec) -> String {
    match spec {
        OpSpec::All(n) => format!("{{\"op\":\"all\",\"n\":{n}}}"),
        OpSpec::Any(n) => format!("{{\"op\":\"any\",\"n\":{n}}}"),
        OpSpec::Not => "{\"op\":\"not\"}".into(),
        OpSpec::MinSigners(n) => format!("{{\"op\":\"min-signers\",\"n\":{n}}}"),
        OpSpec::FnIn(fns) => {
            let owned: std::vec::Vec<String> = fns.iter().map(|f| s(f)).collect();
            format!("{{\"op\":\"fn-in\",\"fns\":{}}}", json_str_list(&owned))
        }
        OpSpec::ArgAddrEq(i, name) => {
            format!(
                "{{\"op\":\"arg-addr-eq\",\"i\":{i},\"address\":\"{}\"}}",
                esc(name)
            )
        }
        OpSpec::ArgAddrIsSelf(i) => format!("{{\"op\":\"arg-addr-is-self\",\"i\":{i}}}"),
        OpSpec::ArgSymEq(i, sym) => {
            format!(
                "{{\"op\":\"arg-sym-eq\",\"i\":{i},\"symbol\":\"{}\"}}",
                esc(sym)
            )
        }
        OpSpec::ArgStrIn(i, values) => {
            format!(
                "{{\"op\":\"arg-str-in\",\"i\":{i},\"values\":{}}}",
                json_str_list(values)
            )
        }
        OpSpec::ArgStrPrefix(i, prefix) => {
            format!(
                "{{\"op\":\"arg-str-prefix\",\"i\":{i},\"prefix\":\"{}\"}}",
                esc(prefix)
            )
        }
        OpSpec::ArgBytesEq(i, b) => {
            format!(
                "{{\"op\":\"arg-bytes-eq\",\"i\":{i},\"hex\":\"{}\"}}",
                hex_of(b)
            )
        }
        OpSpec::ArgI128Eq(i, n) => {
            format!("{{\"op\":\"arg-i128-eq\",\"i\":{i},\"value\":\"{n}\"}}")
        }
        OpSpec::ArgU32Eq(i, n) => format!("{{\"op\":\"arg-u32-eq\",\"i\":{i},\"value\":{n}}}"),
        OpSpec::ArgCount(n) => format!("{{\"op\":\"arg-count\",\"n\":{n}}}"),
        OpSpec::LedgerBefore(n) => format!("{{\"op\":\"ledger-before\",\"n\":{n}}}"),
        OpSpec::LedgerAtOrAfter(n) => format!("{{\"op\":\"ledger-at-or-after\",\"n\":{n}}}"),
    }
}

fn val_json(spec: &ValSpec) -> String {
    match spec {
        ValSpec::U32(n) => format!("{{\"type\":\"u32\",\"value\":{n}}}"),
        ValSpec::I128(n) => format!("{{\"type\":\"i128\",\"value\":\"{n}\"}}"),
        ValSpec::Address(name) => format!("{{\"type\":\"address\",\"value\":\"{}\"}}", esc(name)),
        ValSpec::Symbol(sym) => format!("{{\"type\":\"symbol\",\"value\":\"{}\"}}", esc(sym)),
        ValSpec::Str(text) => format!("{{\"type\":\"string\",\"value\":\"{}\"}}", esc(text)),
        ValSpec::Bytes(b) => format!("{{\"type\":\"bytes\",\"hex\":\"{}\"}}", hex_of(b)),
        ValSpec::Void => "{\"type\":\"void\"}".into(),
    }
}

fn hex_of(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for byte in b {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Serialize the whole case table to the frozen JSON form consumed by the
/// Lean model (`formal/`). One op / one arg per line keeps diffs reviewable.
#[must_use]
pub fn to_json(cases: &[Case]) -> String {
    let mut out = String::from("{\n  \"format\": 1,\n  \"cases\": [\n");
    for (ci, c) in cases.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", esc(c.name)));
        out.push_str(&format!("      \"pins\": \"{}\",\n", esc(c.pins)));
        out.push_str(&format!(
            "      \"program\": {{ \"version\": {}, \"ops\": [\n",
            c.version
        ));
        for (i, o) in c.ops.iter().enumerate() {
            let comma = if i + 1 < c.ops.len() { "," } else { "" };
            out.push_str(&format!("        {}{comma}\n", op_json(o)));
        }
        out.push_str("      ] },\n");
        match c.inv.ctx {
            CtxKind::Contract => {
                out.push_str("      \"invocation\": {\n");
                out.push_str("        \"context\": \"contract\",\n");
                out.push_str(&format!("        \"fn\": \"{}\",\n", esc(c.inv.fn_name)));
                out.push_str("        \"args\": [\n");
                for (i, a) in c.inv.args.iter().enumerate() {
                    let comma = if i + 1 < c.inv.args.len() { "," } else { "" };
                    out.push_str(&format!("          {}{comma}\n", val_json(a)));
                }
                out.push_str("        ],\n");
            }
            CtxKind::NonContract => {
                out.push_str("      \"invocation\": {\n");
                out.push_str("        \"context\": \"non-contract\",\n");
            }
        }
        out.push_str(&format!(
            "        \"signer_count\": {},\n",
            c.inv.signer_count
        ));
        out.push_str(&format!("        \"ledger\": {}\n", c.inv.ledger));
        out.push_str("      },\n");
        match c.expect_valid {
            Ok(()) => out.push_str("      \"valid\": true,\n"),
            Err(name) => out.push_str(&format!(
                "      \"valid\": false,\n      \"error\": \"{name}\",\n"
            )),
        }
        out.push_str(&format!(
            "      \"verdict\": \"{}\"\n",
            verdict_name(c.expect_verdict)
        ));
        let comma = if ci + 1 < cases.len() { "," } else { "" };
        out.push_str(&format!("    }}{comma}\n"));
    }
    out.push_str("  ]\n}\n");
    out
}
