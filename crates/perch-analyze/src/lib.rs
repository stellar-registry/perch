//! Per-policy SMT prover (the `cedar-policy-symcc` shape).
//!
//! Encodes a rule's stateless eligibility as `rule_eval::rule_allows_in`:
//! target, functions, arguments, authenticated signers, and an exact entry
//! root when required. The symbolic root and invocation describe one entry;
//! a satisfying assignment is a screening witness, not a complete authorized
//! transaction. Only `rule_eval::check_auth` checks the whole selection and charges caps.
//!
//! `dead_rules`, `only_calls` and `can_call` query that predicate. `narrows`
//! additionally compares expiry, caps and root implication structurally.
//! No query proves that all selected contexts execute, nor models ancestors.
//! The encoding assumes the account is distinct from every named address.
//! Account id 0 and the other address ids are interned without collisions.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::process::{Command, Stdio};

use perch_ir::{PolicyDoc, Scope};
use rule_eval::{Cond, Functions, Rule, Signer, Val};

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

// --- lowering ------------------------------------------------------------------

/// The account the rules are lowered on: a contract id no document names,
/// as its `ScAddress` XDR (the `SC_ADDRESS_TYPE_CONTRACT` discriminant, then
/// the id).
const ACCOUNT: [u8; 36] = {
    let mut x = [0xee; 36];
    x[0] = 0;
    x[1] = 0;
    x[2] = 0;
    x[3] = 1;
    x
};

/// One document rule and the rule-eval rule it lowers to.
pub struct LoweredRule {
    pub name: String,
    /// The document rule's scope contract, `None` for a self-admin rule.
    pub contract: Option<String>,
    pub rule: Rule,
}

/// The rules of `doc`, each with the rule-eval rule it lowers to on the
/// account: `rule_eval::lower` of the document's model, read as the doc
/// compiler and the account read it. The recovery rule a document with
/// recovery also gets is not listed: its controller decides its calls.
///
/// # Panics
/// Panics if `doc` is not valid (`perch_ir::validate`), which every caller
/// checks first, or has self-authenticating principals, which no Perch
/// account installs.
#[must_use]
pub fn lowered(doc: &PolicyDoc) -> Vec<LoweredRule> {
    let e = soroban_sdk::Env::default();
    let model = perch_rule_eval::model_of(&e, doc).expect("a document the doc compiler lowers");
    let model = perch_rule_eval::doc_of(&e, &model).expect("a model soroban-facade reads");
    doc.rules
        .iter()
        .zip(rule_eval::lower(&model, &ACCOUNT))
        .map(|(r, rule)| LoweredRule {
            name: r.name.clone(),
            contract: match &r.scope {
                Scope::Contract(c) => Some(c.address.clone()),
                Scope::SelfAdmin(_) => None,
            },
            rule,
        })
        .collect()
}

// --- encoding ------------------------------------------------------------------

/// Argument type tags in the encoding.
const T_ADDR: u32 = 0;
const T_U32: u32 = 1;
const T_STR: u32 = 2;
const T_I128: u32 = 3;
/// Every other value (symbols, bytes, `u64`, `bool`, vectors, …), compared
/// by interned identity.
const T_OTHER: u32 = 4;

/// The `ScVal` XDR discriminant of `u32` (`SCV_U32`).
const SCV_U32: [u8; 4] = [0, 0, 0, 3];

/// Encodes one symbolic invocation plus the allow-conditions of rules from up
/// to two documents (two are needed for [`narrows`]).
pub struct Encoder {
    /// Address interning; the account's own address is id 0.
    addr_ids: BTreeMap<Vec<u8>, u32>,
    /// Interning of every other value a condition compares with.
    other_ids: BTreeMap<Vec<u8>, u32>,
    /// Signer interning: one authentication flag per distinct signer.
    signer_ids: BTreeMap<Vec<u8>, u32>,
    /// Every argument index any encoded condition inspects.
    arg_indexes: BTreeSet<u32>,
}

impl Default for Encoder {
    fn default() -> Self {
        Encoder::new()
    }
}

fn intern(ids: &mut BTreeMap<Vec<u8>, u32>, key: Vec<u8>) -> u32 {
    let next = ids.len() as u32;
    *ids.entry(key).or_insert(next)
}

/// `bytes`, each prefixed with its length, after `tag`: an injective key.
fn key(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![tag];
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

impl Encoder {
    #[must_use]
    pub fn new() -> Encoder {
        let mut addr_ids = BTreeMap::new();
        addr_ids.insert(ACCOUNT.to_vec(), 0);
        Encoder {
            addr_ids,
            other_ids: BTreeMap::new(),
            signer_ids: BTreeMap::new(),
            arg_indexes: BTreeSet::new(),
        }
    }

    fn addr_id(&mut self, address: &[u8]) -> u32 {
        intern(&mut self.addr_ids, address.to_vec())
    }

    fn signer_id(&mut self, s: &Signer) -> u32 {
        let k = match s {
            Signer::Delegated(a) => key(0, &[a]),
            Signer::External(v, k) => key(1, &[v, k]),
        };
        intern(&mut self.signer_ids, k)
    }

    /// The SMT Bool term for `rule_eval::rule_allows(rule, ctx, signers)` on
    /// the symbolic invocation: a contract call to the rule's contract, its
    /// function matched, every condition holding on its arguments, and at
    /// least the rule's threshold of its distinct signers authenticated.
    pub fn rule_allows(&mut self, rule: &Rule) -> String {
        let contract = self.addr_id(&rule.contract);
        let mut conj = vec!["ctx_call".to_string(), format!("(= contract {contract})")];
        conj.push(match &rule.functions {
            Functions::AnyExcept(xs) => {
                let named: Vec<String> = xs
                    .iter()
                    .map(|f| format!("(= fn_name {})", smt_string(f)))
                    .collect();
                format!("(not {})", disj(&named))
            }
            Functions::Only(xs) => disj(
                &xs.iter()
                    .map(|f| format!("(= fn_name {})", smt_string(f)))
                    .collect::<Vec<_>>(),
            ),
        });
        for c in &rule.conds {
            conj.push(self.cond_holds(c));
        }
        conj.push(self.signers_met(rule));
        conj_term(&conj)
    }

    /// `rule_allows_in` for a symbolic entry root and invocation. This is
    /// stateless eligibility, not the complete `rule_eval::check_auth` decision.
    pub fn rule_allows_in(&mut self, rule: &Rule) -> String {
        let local = self.rule_allows(rule);
        match &rule.auth_root {
            None => local,
            Some(root) => {
                let contract = self.addr_id(&root.contract);
                format!(
                    "(and {local} root_call (= root_contract {contract}) (= root_fn {}))",
                    smt_string(&root.function)
                )
            }
        }
    }

    fn signers_met(&mut self, rule: &Rule) -> String {
        if rule.threshold == 0 {
            return "true".into();
        }
        let ids: BTreeSet<u32> = rule.signers.iter().map(|s| self.signer_id(s)).collect();
        let terms: Vec<String> = ids.iter().map(|k| format!("(ite signer{k} 1 0)")).collect();
        let sum = match terms.len() {
            0 => "0".to_string(),
            1 => terms[0].clone(),
            _ => format!("(+ {})", terms.join(" ")),
        };
        format!("(>= {sum} {})", rule.threshold)
    }

    fn cond_holds(&mut self, cond: &Cond) -> String {
        let (i, body) = match cond {
            Cond::ArgEq(i, v) => (*i, self.val_eq(*i, v)),
            Cond::ArgIn(i, vs) => (
                *i,
                disj(&vs.iter().map(|v| self.val_eq(*i, v)).collect::<Vec<_>>()),
            ),
            Cond::ArgStrPrefix(i, p) => (
                *i,
                format!(
                    "(and (= arg{i}_type {T_STR}) (str.prefixof {} arg{i}_str))",
                    smt_string(p)
                ),
            ),
            Cond::ArgI128AtMost(i, bound) => (
                *i,
                format!(
                    "(and (= arg{i}_type {T_I128}) (<= arg{i}_i128 {}))",
                    smt_int(*bound)
                ),
            ),
        };
        self.arg_indexes.insert(i);
        format!("(and (< {i} arg_count) {body})")
    }

    /// Argument `i` equals `v`: the same type and the same value.
    fn val_eq(&mut self, i: u32, v: &Val) -> String {
        match v {
            Val::Address(a) => {
                let id = self.addr_id(a);
                format!("(and (= arg{i}_type {T_ADDR}) (= arg{i}_addr {id}))")
            }
            Val::String(s) => format!(
                "(and (= arg{i}_type {T_STR}) (= arg{i}_str {}))",
                smt_string(s)
            ),
            Val::I128(x) => format!(
                "(and (= arg{i}_type {T_I128}) (= arg{i}_i128 {}))",
                smt_int(*x)
            ),
            Val::Other(x) if x.len() == 8 && x[..4] == SCV_U32 => {
                let value = u32::from_be_bytes([x[4], x[5], x[6], x[7]]);
                format!("(and (= arg{i}_type {T_U32}) (= arg{i}_u32 {value}))")
            }
            other => {
                let k = match other {
                    Val::U64(x) => key(0, &[&x.to_be_bytes()]),
                    Val::Bool(x) => key(1, &[&[u8::from(*x)]]),
                    Val::Bytes(x) => key(2, &[x]),
                    Val::Symbol(x) => key(3, &[x]),
                    Val::Other(x) => key(4, &[x]),
                    Val::Address(_) | Val::String(_) | Val::I128(_) => unreachable!(),
                };
                let id = intern(&mut self.other_ids, k);
                format!("(and (= arg{i}_type {T_OTHER}) (= arg{i}_other {id}))")
            }
        }
    }

    /// Declarations for the symbolic invocation, covering every argument
    /// index and signer the encoded rules inspect.
    #[must_use]
    pub fn declarations(&self) -> String {
        let mut out = String::new();
        out.push_str("(declare-const ctx_call Bool)\n");
        out.push_str("(declare-const root_call Bool)\n(declare-const root_contract Int)\n(declare-const root_fn String)\n");
        out.push_str("(declare-const contract Int)\n");
        out.push_str("(declare-const fn_name String)\n");
        out.push_str("(declare-const arg_count Int)\n(assert (>= arg_count 0))\n");
        for k in self.signer_ids.values() {
            out.push_str(&format!("(declare-const signer{k} Bool)\n"));
        }
        let (lo, hi) = (smt_int(i128::MIN), smt_int(i128::MAX));
        for i in &self.arg_indexes {
            out.push_str(&format!(
                "(declare-const arg{i}_type Int)\n(assert (and (>= arg{i}_type 0) (<= arg{i}_type {T_OTHER})))\n"
            ));
            out.push_str(&format!("(declare-const arg{i}_addr Int)\n"));
            out.push_str(&format!(
                "(declare-const arg{i}_u32 Int)\n(assert (and (>= arg{i}_u32 0) (<= arg{i}_u32 4294967295)))\n"
            ));
            out.push_str(&format!("(declare-const arg{i}_str String)\n"));
            out.push_str(&format!(
                "(declare-const arg{i}_i128 Int)\n(assert (and (>= arg{i}_i128 {lo}) (<= arg{i}_i128 {hi})))\n"
            ));
            out.push_str(&format!("(declare-const arg{i}_other Int)\n"));
        }
        out
    }

    /// The values worth showing a human when a query is `sat`.
    #[must_use]
    pub fn witness_query(&self) -> String {
        let mut vars = vec![
            "ctx_call".to_string(),
            "root_call".to_string(),
            "root_contract".to_string(),
            "root_fn".to_string(),
            "contract".to_string(),
            "fn_name".to_string(),
            "arg_count".to_string(),
        ];
        for k in self.signer_ids.values() {
            vars.push(format!("signer{k}"));
        }
        for i in &self.arg_indexes {
            vars.push(format!("arg{i}_type"));
            vars.push(format!("arg{i}_addr"));
            vars.push(format!("arg{i}_u32"));
            vars.push(format!("arg{i}_str"));
            vars.push(format!("arg{i}_i128"));
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

/// SMT-LIB 2.6 string literal of UTF-8 `bytes`: only `"` needs escaping
/// (doubled).
fn smt_string(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// SMT-LIB integer literal (negatives as `(- n)`).
fn smt_int(x: i128) -> String {
    if x < 0 {
        format!("(- {})", x.unsigned_abs())
    } else {
        x.to_string()
    }
}

// --- checks --------------------------------------------------------------------

/// Liveness of one rule.
#[derive(Clone, Debug)]
pub struct RuleLiveness {
    pub rule: String,
    pub verdict: Z3Verdict,
}

/// For each rule: can it ever authorize an invocation? `Unsat` proves the
/// rule dead (it can never allow one).
#[must_use]
pub fn dead_rules(doc: &PolicyDoc) -> Vec<RuleLiveness> {
    lowered(doc)
        .into_iter()
        .map(|l| {
            let mut enc = Encoder::new();
            let allow = enc.rule_allows_in(&l.rule);
            let script = format!(
                "{}(assert {allow})\n(check-sat)\n{}",
                enc.declarations(),
                enc.witness_query()
            );
            RuleLiveness {
                rule: l.name,
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
    for l in lowered(doc) {
        if l.contract.as_deref() != Some(contract) {
            continue;
        }
        let mut enc = Encoder::new();
        let allow = enc.rule_allows_in(&l.rule);
        let outside: Vec<String> = allowed
            .iter()
            .map(|f| format!("(not (= fn_name {}))", smt_string(f.as_bytes())))
            .collect();
        let script = format!(
            "{}(assert {allow})\n(assert {})\n(check-sat)\n{}",
            enc.declarations(),
            conj_term(&outside),
            enc.witness_query()
        );
        match run_z3(&script) {
            Z3Verdict::Unsat => {}
            v => violations.push(OnlyCallsViolation {
                rule: l.name,
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
    for l in lowered(doc) {
        if l.contract.is_none() {
            continue;
        }
        let mut enc = Encoder::new();
        let allow = enc.rule_allows_in(&l.rule);
        let script = format!(
            "{}(assert {allow})\n(assert (= fn_name {}))\n(check-sat)\n{}",
            enc.declarations(),
            smt_string(function.as_bytes()),
            enc.witness_query()
        );
        out.push(RuleLiveness {
            rule: l.name,
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
    /// Same rule name, different contract: different authority.
    ScopeChanged { rule: String },
    /// The child's rule allows an invocation the parent's refuses; carries
    /// the witness.
    SemanticWidening { rule: String, verdict: Z3Verdict },
    /// An exact root was erased or changed; root implication failed.
    AuthRootChanged { rule: String },
    /// The child expires later than the parent (or dropped the expiry).
    ExpiryExtended { rule: String },
    /// The child loosened or dropped the parent's cumulative cap.
    CapLoosened { rule: String },
    /// z3 could not decide; fail closed.
    Undecided { rule: String, verdict: Z3Verdict },
}

/// Semantic attenuation check: every finding is a reason `child` is NOT a
/// pure narrowing of `parent`. Empty = proved narrowing, per matched rule
/// name, of what the account's rules allow: functions, argument conditions
/// and signers alike.
#[must_use]
pub fn narrows(parent: &PolicyDoc, child: &PolicyDoc) -> Vec<WideningFinding> {
    let parents = lowered(parent);
    let mut findings = Vec::new();
    for c in lowered(child) {
        let Some(p) = parents.iter().find(|p| p.name == c.name) else {
            findings.push(WideningFinding::AddedRule { rule: c.name });
            continue;
        };
        if p.rule.contract != c.rule.contract {
            findings.push(WideningFinding::ScopeChanged { rule: c.name });
            continue;
        }

        if !rule_eval::auth_root_narrows(&c.rule.auth_root, &p.rule.auth_root) {
            findings.push(WideningFinding::AuthRootChanged {
                rule: c.name.clone(),
            });
        }

        // The local predicate must also narrow independently of the root.
        // child-allows ∧ ¬parent-allows must be unsat.
        let mut enc = Encoder::new();
        let child_allow = enc.rule_allows(&c.rule);
        let parent_allow = enc.rule_allows(&p.rule);
        let script = format!(
            "{}(assert {child_allow})\n(assert (not {parent_allow}))\n(check-sat)\n{}",
            enc.declarations(),
            enc.witness_query()
        );
        match run_z3(&script) {
            Z3Verdict::Unsat => {}
            v @ Z3Verdict::Sat(_) => findings.push(WideningFinding::SemanticWidening {
                rule: c.name.clone(),
                verdict: v,
            }),
            v @ Z3Verdict::Unknown(_) => findings.push(WideningFinding::Undecided {
                rule: c.name.clone(),
                verdict: v,
            }),
        }

        // The last ledger only narrows if it stays at or before the parent's
        // (None = never expires).
        let extended = match (p.rule.valid_until, c.rule.valid_until) {
            (Some(_), None) => true,
            (Some(p), Some(c)) => c > p,
            (None, _) => false,
        };
        if extended {
            findings.push(WideningFinding::ExpiryExtended {
                rule: c.name.clone(),
            });
        }

        // A cap only narrows if it stays present with limit ≤ the parent's
        // over a window ≥ the parent's. Its token is the rule's contract,
        // which is unchanged here.
        let loosened = match (&p.rule.cap, &c.rule.cap) {
            (Some(_), None) => true,
            (Some(p), Some(c)) => c.limit > p.limit || c.period < p.period,
            (None, _) => false,
        };
        if loosened {
            findings.push(WideningFinding::CapLoosened { rule: c.name });
        }
    }
    findings
}
