//! Per-policy SMT prover (PLAN.md phase 4, the `cedar-policy-symcc` shape).
//!
//! Encodes the **doc-level meaning** of each rule — the same semantics the
//! Lean model states and the differential suite tests — as a quantifier-free
//! SMT formula over one symbolic invocation, and asks z3:
//!
//! - [`dead_rules`] — can this rule *ever* authorize an invocation? `unsat`
//!   is a proof of deadness (stronger than
//!   `perch_compile::can_ever_authorize`, which reads op shapes only);
//!   `sat` comes with a witness invocation to eyeball.
//! - [`only_calls`] — intent conformance: on a given contract scope, can the
//!   document authorize any function outside an allowlist? `unsat` per rule
//!   proves "this policy can only ever call these functions here" — the
//!   flagship CI-key question.
//! - [`narrows`] — semantic attenuation: does the child document authorize
//!   any invocation the parent would refuse, rule by rule? Catches arg-level
//!   widening that the coarse `(scope, function-set)` check in
//!   `perch_compile::attenuation` cannot see, plus expiry extensions and cap
//!   loosening (checked structurally).
//!
//! The encoding is decidable (booleans, bounded integers, and z3's string
//! theory restricted to equality/prefix/length over literals). Soundness
//! assumptions, stated once:
//!
//! - The smart account's own address (`is-self`) is distinct from every
//!   address literal in the documents (interning gives them distinct ids).
//! - String lengths are measured in *characters* by SMT `str.len` but in
//!   *bytes* by the on-chain `MAX_STR_ARG_LEN` cap; the two agree on ASCII.
//!   Non-ASCII constants near the 256 cap could diverge — kept honest by
//!   [`encode_doc_warnings`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::process::{Command, Stdio};

use perch_ir::{ArgPred, PolicyDoc, Principals, Rule, Scope};

/// On-chain string-argument cap (`perch_program::MAX_STR_ARG_LEN`), mirrored
/// here so the library stays soroban-free.
const MAX_STR_ARG_LEN: usize = 256;

// --- z3 driver ----------------------------------------------------------------

/// Outcome of one `(check-sat)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Z3Verdict {
    /// Satisfiable; carries the raw `(get-value …)` witness lines.
    Sat(String),
    Unsat,
    /// z3 gave up or errored; carries its output. Fail closed on this.
    Unknown(String),
}

/// Whether a z3 binary is available on `PATH`.
#[must_use]
pub fn z3_available() -> bool {
    Command::new("z3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run one SMT-LIB script through `z3 -in` and classify the result.
///
/// # Panics
/// Panics if z3 cannot be spawned — call [`z3_available`] first.
#[must_use]
pub fn run_z3(script: &str) -> Z3Verdict {
    let mut child = Command::new("z3")
        .args(["-in", "-smt2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn z3 — is it installed and on PATH?");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes())
        .expect("write to z3");
    let out = child.wait_with_output().expect("wait for z3");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    match lines.next() {
        Some("unsat") => Z3Verdict::Unsat,
        Some("sat") => Z3Verdict::Sat(lines.collect::<Vec<_>>().join("\n")),
        _ => Z3Verdict::Unknown(format!("{stdout}{}", String::from_utf8_lossy(&out.stderr))),
    }
}

// --- encoding ------------------------------------------------------------------

/// Argument type tags in the encoding.
const T_ADDR: u32 = 0;
const T_U32: u32 = 1;
const T_STR: u32 = 2;
/// Anything no doc-level predicate can decode (symbols, bytes, i128, void…).
const T_OTHER: u32 = 3;

/// Encodes one symbolic invocation plus the allow-conditions of rules from up
/// to two documents (two are needed for [`narrows`]).
pub struct Encoder {
    /// Address-literal interning; the account's own address is id 0.
    addr_ids: BTreeMap<String, u32>,
    /// Every argument index any encoded predicate inspects.
    arg_indexes: BTreeSet<u32>,
}

impl Default for Encoder {
    fn default() -> Self {
        Encoder::new()
    }
}

impl Encoder {
    #[must_use]
    pub fn new() -> Encoder {
        Encoder {
            addr_ids: BTreeMap::new(),
            arg_indexes: BTreeSet::new(),
        }
    }

    fn addr_id(&mut self, address: &str) -> u32 {
        if let Some(id) = self.addr_ids.get(address) {
            return *id;
        }
        let id = self.addr_ids.len() as u32 + 1; // 0 is reserved for self
        self.addr_ids.insert(address.to_string(), id);
        id
    }

    /// The SMT Bool term for "this rule's program-level semantics authorize
    /// the symbolic invocation" — the Kleene conjunction being definitely
    /// `True`: signer floor met, function in the allowlist (when present),
    /// every argument predicate definitely satisfied.
    ///
    /// Expiry and caps are deliberately absent: they lower outside the
    /// program (OZ `valid_until` / the stateful sibling policy) and are
    /// compared structurally by [`narrows`].
    pub fn rule_allows(&mut self, rule: &Rule) -> String {
        let mut conj: Vec<String> = Vec::new();

        let n = match &rule.principals {
            Principals::All(a) => a.signers.len().max(1),
            // M-of-N: the floor is the quorum `m`, matching the `MinSigners(m)`
            // the compiler emits (validation guarantees 1 <= m <= N).
            Principals::Threshold(t) => (t.m.max(1)) as usize,
            // Not lowerable in v1 (perch-compile rejects it); encode as the
            // signer floor 1 so analysis still says something sensible.
            Principals::SelfAuthenticating(_) => 1,
        };
        conj.push(format!("(>= signer_count {n})"));

        if let Some(fns) = &rule.functions {
            conj.push("ctx_contract".into());
            let alts: Vec<String> = fns
                .iter()
                .map(|f| format!("(= fn_name {})", smt_string(f)))
                .collect();
            conj.push(disj(&alts));
        }

        if let Some(args) = &rule.args {
            for c in args {
                conj.push("ctx_contract".into());
                conj.push(self.pred_holds(c.index, &c.pred));
            }
        }

        conj_term(&conj)
    }

    fn pred_holds(&mut self, i: u32, pred: &ArgPred) -> String {
        self.arg_indexes.insert(i);
        let present = format!("(< {i} arg_count)");
        let body = match pred {
            ArgPred::IsSelf(_) => {
                format!("(and (= arg{i}_type {T_ADDR}) (= arg{i}_addr 0))")
            }
            ArgPred::AddressEq(p) => {
                let id = self.addr_id(&p.address);
                format!("(and (= arg{i}_type {T_ADDR}) (= arg{i}_addr {id}))")
            }
            ArgPred::U32Eq(p) => {
                format!("(and (= arg{i}_type {T_U32}) (= arg{i}_u32 {}))", p.value)
            }
            ArgPred::StringIn(p) => {
                // Over-long candidates can never match a decodable argument
                // (the on-chain comparator skips them), so drop them here too.
                let alts: Vec<String> = p
                    .values
                    .iter()
                    .filter(|v| v.len() <= MAX_STR_ARG_LEN)
                    .map(|v| format!("(= arg{i}_str {})", smt_string(v)))
                    .collect();
                format!(
                    "(and (= arg{i}_type {T_STR}) (<= (str.len arg{i}_str) {MAX_STR_ARG_LEN}) {})",
                    disj(&alts)
                )
            }
            ArgPred::StringPrefix(p) => {
                if p.prefix.len() > MAX_STR_ARG_LEN {
                    // An over-long prefix constant fails closed on-chain.
                    "false".to_string()
                } else {
                    format!(
                        "(and (= arg{i}_type {T_STR}) (<= (str.len arg{i}_str) {MAX_STR_ARG_LEN}) \
                         (str.prefixof {} arg{i}_str))",
                        smt_string(&p.prefix)
                    )
                }
            }
        };
        format!("(and {present} {body})")
    }

    /// Declarations for the symbolic invocation, covering every argument
    /// index the encoded predicates inspect.
    #[must_use]
    pub fn declarations(&self) -> String {
        let mut out = String::new();
        out.push_str("(declare-const ctx_contract Bool)\n");
        out.push_str("(declare-const fn_name String)\n");
        out.push_str("(declare-const signer_count Int)\n(assert (>= signer_count 0))\n");
        out.push_str("(declare-const arg_count Int)\n(assert (>= arg_count 0))\n");
        for i in &self.arg_indexes {
            out.push_str(&format!(
                "(declare-const arg{i}_type Int)\n(assert (and (>= arg{i}_type 0) (<= arg{i}_type {T_OTHER})))\n"
            ));
            out.push_str(&format!("(declare-const arg{i}_addr Int)\n"));
            out.push_str(&format!(
                "(declare-const arg{i}_u32 Int)\n(assert (and (>= arg{i}_u32 0) (<= arg{i}_u32 4294967295)))\n"
            ));
            out.push_str(&format!("(declare-const arg{i}_str String)\n"));
        }
        out
    }

    /// The values worth showing a human when a query is `sat`.
    #[must_use]
    pub fn witness_query(&self) -> String {
        let mut vars = vec![
            "ctx_contract".to_string(),
            "fn_name".to_string(),
            "signer_count".to_string(),
            "arg_count".to_string(),
        ];
        for i in &self.arg_indexes {
            vars.push(format!("arg{i}_type"));
            vars.push(format!("arg{i}_addr"));
            vars.push(format!("arg{i}_u32"));
            vars.push(format!("arg{i}_str"));
        }
        format!("(get-value ({}))\n", vars.join(" "))
    }
}

fn conj_term(parts: &[String]) -> String {
    match parts.len() {
        0 => "true".into(),
        1 => parts[0].clone(),
        _ => format!("(and {})", parts.join(" ")),
    }
}

fn disj(parts: &[String]) -> String {
    match parts.len() {
        0 => "false".into(),
        1 => parts[0].clone(),
        _ => format!("(or {})", parts.join(" ")),
    }
}

/// SMT-LIB 2.6 string literal: only `"` needs escaping (doubled).
fn smt_string(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Length-cap caveats for the byte-vs-char divergence (see module docs).
#[must_use]
pub fn encode_doc_warnings(doc: &PolicyDoc) -> Vec<String> {
    let mut out = Vec::new();
    for rule in &doc.rules {
        for c in rule.args.iter().flatten() {
            let texts: Vec<&String> = match &c.pred {
                ArgPred::StringIn(p) => p.values.iter().collect(),
                ArgPred::StringPrefix(p) => vec![&p.prefix],
                _ => vec![],
            };
            for t in texts {
                if !t.is_ascii() && t.chars().count() != t.len() {
                    out.push(format!(
                        "rule `{}`: non-ASCII string constant — SMT char-length vs on-chain \
                         byte-length may diverge near the {MAX_STR_ARG_LEN} cap",
                        rule.name
                    ));
                }
            }
        }
    }
    out
}

// --- checks --------------------------------------------------------------------

/// Liveness of one rule.
#[derive(Clone, Debug)]
pub struct RuleLiveness {
    pub rule: String,
    pub verdict: Z3Verdict,
}

/// For each rule: can it ever authorize an invocation? `Unsat` proves the
/// rule dead (it can never yield a definite allow).
#[must_use]
pub fn dead_rules(doc: &PolicyDoc) -> Vec<RuleLiveness> {
    doc.rules
        .iter()
        .map(|rule| {
            let mut enc = Encoder::new();
            let allow = enc.rule_allows(rule);
            let script = format!(
                "{}(assert {allow})\n(check-sat)\n{}",
                enc.declarations(),
                enc.witness_query()
            );
            RuleLiveness {
                rule: rule.name.clone(),
                verdict: run_z3(&script),
            }
        })
        .collect()
}

/// A rule that can authorize a function outside the allowlist, with the
/// witness invocation.
#[derive(Clone, Debug)]
pub struct OnlyCallsViolation {
    pub rule: String,
    pub verdict: Z3Verdict,
}

/// Intent conformance: on `contract`, can any rule authorize a function
/// outside `allowed`? An empty result **proves** the policy can only ever
/// call `allowed` on that contract. Rules scoped elsewhere are ignored;
/// a function-unrestricted rule on the contract is always a violation.
#[must_use]
pub fn only_calls(doc: &PolicyDoc, contract: &str, allowed: &[String]) -> Vec<OnlyCallsViolation> {
    let mut violations = Vec::new();
    for rule in &doc.rules {
        let on_target = matches!(&rule.scope, Scope::Contract(c) if c.address == contract);
        if !on_target {
            continue;
        }
        let mut enc = Encoder::new();
        let allow = enc.rule_allows(rule);
        let outside: Vec<String> = allowed
            .iter()
            .map(|f| format!("(not (= fn_name {}))", smt_string(f)))
            .collect();
        let script = format!(
            "{}(assert {allow})\n(assert ctx_contract)\n(assert {})\n(check-sat)\n{}",
            enc.declarations(),
            conj_term(&outside),
            enc.witness_query()
        );
        match run_z3(&script) {
            Z3Verdict::Unsat => {}
            v => violations.push(OnlyCallsViolation {
                rule: rule.name.clone(),
                verdict: v,
            }),
        }
    }
    violations
}

/// Which contract-scoped rules can authorize calling `function`? `Sat`
/// verdicts carry a witness invocation.
#[must_use]
pub fn can_call(doc: &PolicyDoc, function: &str) -> Vec<RuleLiveness> {
    let mut out = Vec::new();
    for rule in &doc.rules {
        if !matches!(&rule.scope, Scope::Contract(_)) {
            continue;
        }
        let mut enc = Encoder::new();
        let allow = enc.rule_allows(rule);
        let script = format!(
            "{}(assert {allow})\n(assert ctx_contract)\n(assert (= fn_name {}))\n(check-sat)\n{}",
            enc.declarations(),
            smt_string(function),
            enc.witness_query()
        );
        out.push(RuleLiveness {
            rule: rule.name.clone(),
            verdict: run_z3(&script),
        });
    }
    out
}

/// One way a child document widens (or fails to provably narrow) its parent.
#[derive(Clone, Debug)]
pub enum WideningFinding {
    /// The child has a rule the parent lacks — new authority by definition.
    AddedRule { rule: String },
    /// Same rule name, different scope: different authority.
    ScopeChanged { rule: String },
    /// The child's program semantics admit an invocation the parent's refuse;
    /// carries the witness.
    SemanticWidening { rule: String, verdict: Z3Verdict },
    /// The child expires later than the parent (or dropped the expiry).
    ExpiryExtended { rule: String },
    /// The child loosened or dropped the parent's cumulative cap.
    CapLoosened { rule: String },
    /// z3 could not decide; fail closed.
    Undecided { rule: String, verdict: Z3Verdict },
}

/// Semantic attenuation check: every finding is a reason `child` is NOT a
/// pure narrowing of `parent`. Empty = proved narrowing (per matched rule
/// name), strictly stronger on program semantics than
/// `perch_compile::attenuation::is_narrowing` (which compares only
/// `(scope, function-set)` reachability and cannot see argument predicates).
#[must_use]
pub fn narrows(parent: &PolicyDoc, child: &PolicyDoc) -> Vec<WideningFinding> {
    let mut findings = Vec::new();
    for crule in &child.rules {
        let Some(prule) = parent.rules.iter().find(|r| r.name == crule.name) else {
            findings.push(WideningFinding::AddedRule {
                rule: crule.name.clone(),
            });
            continue;
        };
        if prule.scope != crule.scope {
            findings.push(WideningFinding::ScopeChanged {
                rule: crule.name.clone(),
            });
            continue;
        }

        // Program semantics: child-allows ∧ ¬parent-allows must be unsat.
        let mut enc = Encoder::new();
        let child_allow = enc.rule_allows(crule);
        let parent_allow = enc.rule_allows(prule);
        let script = format!(
            "{}(assert {child_allow})\n(assert (not {parent_allow}))\n(check-sat)\n{}",
            enc.declarations(),
            enc.witness_query()
        );
        match run_z3(&script) {
            Z3Verdict::Unsat => {}
            v @ Z3Verdict::Sat(_) => findings.push(WideningFinding::SemanticWidening {
                rule: crule.name.clone(),
                verdict: v,
            }),
            v @ Z3Verdict::Unknown(_) => findings.push(WideningFinding::Undecided {
                rule: crule.name.clone(),
                verdict: v,
            }),
        }

        // Expiry: dead-at-or-after X only narrows if X' ≤ X (None = never).
        let extended = match (prule.not_after_ledger, crule.not_after_ledger) {
            (Some(_), None) => true,
            (Some(p), Some(c)) => c > p,
            (None, _) => false,
        };
        if extended {
            findings.push(WideningFinding::ExpiryExtended {
                rule: crule.name.clone(),
            });
        }

        // Caps: a cap only narrows if it stays present with limit ≤ parent's
        // over a window ≥ parent's, on the same token.
        let loosened = match (&prule.cap, &crule.cap) {
            (Some(_), None) => true,
            (Some(p), Some(c)) => {
                let plimit = p.limit.parse::<i128>().unwrap_or(i128::MAX);
                let climit = c.limit.parse::<i128>().unwrap_or(i128::MAX);
                p.token != c.token || climit > plimit || c.period_ledgers < p.period_ledgers
            }
            (None, _) => false,
        };
        if loosened {
            findings.push(WideningFinding::CapLoosened {
                rule: crule.name.clone(),
            });
        }
    }
    findings
}
