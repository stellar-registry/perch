//! Delta-apply harness: checks `apply_doc`'s delta reconciliation against
//! the full replace it replaced (`docs/recovery/spec.md` §7.5).
//!
//! - [`OracleAccount`] is the perch account with `apply_doc` swapped for the
//!   full replace ([`perch_smart_account::testutils::apply_doc_full_replace`]).
//!   Everything else (compile, revocation, recovery sync, and the desired
//!   rule set the reconcile is handed, expiry drop included) is the same
//!   code, so the oracle checks the reconcile only.
//! - [`DocModel::expected_rules`] is the independent check: the rules a
//!   document grants at the current ledger, computed from the model alone,
//!   compared with [`live_rules`], the grant read back from the account's
//!   context-rule views and the stored rule-eval rule each one's id selects.
//!   It shares no code with the compiler or the account, so it catches what
//!   the oracle cannot.
//! - [`DocModel`] is a generated policy document. [`DocModel::generate`]
//!   draws one from bytes, so proptest (shrinking over bytes) and cargo-fuzz
//!   share one generator. It reaches the document caps, draws signer lists
//!   in any order, spells keys in either hex case and cap limits with
//!   leading zeros or a sign, and [`DocModel::sequence`] advances the ledger
//!   between documents past the rule expiries it draws.
//! - After every accepted step of a [`GrantOp`] sequence, the stored
//!   rule-eval rule set of the document it applied equals the lowering of
//!   that document's model and the denotation of what it installed
//!   ([`crate::rule_set`]); a removed grant keeps none.
//! - [`DeltaWorld`] holds a delta account and an oracle account side by side
//!   in one `Env`, with the shared infra, controller, verifier, and address
//!   pools every generated document draws from.
//! - [`GrantOp::sequence`] interleaves admin `apply_doc` with `apply_grant`
//!   and `remove_grant` over a few grant ids (spec §7.6), and
//!   [`GrantModel::step`] checks each step against the documents the model
//!   says are applied: every grant grants exactly its own document's rules,
//!   grant operations leave the account document and the other grants alone,
//!   and a refused operation changes nothing.
//! - [`storage_state`] reads an account's complete storage from the ledger
//!   snapshot (its own entries, and every entry the interpreter, spending
//!   limit, controller, and pool keep for it), renaming the ids that differ
//!   by history: rule ids become rule names, and the policy ids of the OZ
//!   registry entries kept for the recovery rule become the policy. Two
//!   accounts whose rules grant the same authorization produce equal
//!   states.

use crate::fixture::AnyKeyVerifier;
use arbitrary::Unstructured;
use perch_account::{PerchAccount, PerchAccountClient};
use perch_account_types::{ContextRule, ContextRuleType, Signer};
use perch_doc_compiler::{PerchDocCompiler, MAX_DOC_RULES, MAX_DOC_SIGNERS};
use perch_interpreter::PerchInterpreter;
use perch_recovery::PerchRecovery;
use perch_smart_account::{infra, InstalledRule, StoredRule};
use perch_spending_limit::PerchSpendingLimit;
use soroban_sdk::testutils::EnvTestConfig;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::xdr::{ContractEventBody, LedgerEntryData, LedgerKey, ScAddress, ScVal};
use soroban_sdk::{vec, Address, Bytes, BytesN, Env};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::string::{String, ToString};
use std::vec::Vec;

pub use oracle::{OracleAccount, OracleAccountClient};

/// The oracle contract lives in its own module: soroban's macros name the
/// trait impls after the bare trait paths, which must be in scope.
mod oracle {
    use perch_account_types::{AuthPayload, ContextRule, Signer};
    use perch_smart_account::testutils::apply_doc_full_replace;
    use perch_smart_account::{
        check_auth, install_account_rules, AccountCapabilities, AccountConfiguration, FreezeGate,
        GrantRecord, InfraPins, InstalledRule, PerchAccountError, PerchSmartAccount, StoredRule,
        UpgradeRequest,
    };
    use soroban_sdk::auth::{Context, CustomAccountInterface};
    use soroban_sdk::crypto::Hash;
    use soroban_sdk::{
        contract, contractimpl, Address, Bytes, BytesN, Env, String, Symbol, Val, Vec,
    };

    /// The perch account with `apply_doc` swapped for the full replace.
    #[contract]
    pub struct OracleAccount;

    #[contractimpl]
    impl OracleAccount {
        pub fn __constructor(e: &Env, admin_signers: Vec<Signer>) {
            install_account_rules(e, &admin_signers);
        }
    }

    #[contractimpl]
    impl CustomAccountInterface for OracleAccount {
        type Error = soroban_sdk::Error;
        type Signature = AuthPayload;

        fn __check_auth(
            e: Env,
            signature_payload: Hash<32>,
            signatures: AuthPayload,
            auth_contexts: Vec<Context>,
        ) -> Result<(), soroban_sdk::Error> {
            check_auth(&e, &signature_payload, &signatures, &auth_contexts)
        }
    }

    #[contractimpl(contracttrait)]
    impl PerchSmartAccount for OracleAccount {
        fn apply_doc(
            e: &Env,
            doc_json: Bytes,
            approval_valid_until: u32,
            expected_revision: Option<u64>,
        ) -> Result<BytesN<32>, PerchAccountError> {
            apply_doc_full_replace(e, doc_json, approval_valid_until, expected_revision)
        }
    }
}

// ---------------------------------------------------------------------------
// Generated documents
// ---------------------------------------------------------------------------

/// Signer ids a generated document draws from. The first is always the
/// admin's (and the recovery's replaceable) `owner`.
pub const SIGNER_IDS: [&str; 16] = [
    "owner", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13",
    "s14", "s15",
];
/// Rule names after `admin`. `recovery` is deliberately absent, so a
/// document rule never shares the recovery rule's name.
pub const RULE_NAMES: [&str; 15] = [
    "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];
/// Function names a constrained rule may allow: none a grant document may
/// not list (a guardian approval or a token-admin function, spec §7.6).
pub const FUNCTIONS: [&str; 3] = ["transfer", "approve", "swap"];
/// Size of the key pool (delegated addresses and external keys).
pub const KEY_POOL: usize = 20;
/// Size of the scope pool (contracts rules are scoped to).
pub const SCOPE_POOL: usize = 4;

/// How a generated signer authenticates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyModel {
    /// `Signer::Delegated` to key-pool address `n`.
    Delegated(usize),
    /// `Signer::External` on the stand-in verifier, with key `n`.
    External(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerModel {
    pub id: &'static str,
    pub key: KeyModel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleModel {
    pub name: &'static str,
    /// `None`: self-admin. `Some(n)`: scope-pool contract `n`.
    pub scope: Option<usize>,
    /// Indices into the document's signers.
    pub signers: Vec<usize>,
    /// `Some(m)`: an m-of-n threshold (interpreter `MinSigners`).
    pub threshold: Option<u32>,
    pub functions: Option<Vec<&'static str>>,
    /// `not-after-ledger`: near the world's starting ledger (so a sequence
    /// that advances the ledger passes it) or far in the future.
    pub not_after: Option<u32>,
    /// `(limit, period_ledgers)`; contract scopes only.
    pub cap: Option<(u32, u32)>,
}

/// A `Loss`, guardian-only recovery member at the world's controller. Loss
/// needs only owner authorization to change, so generated sequences can
/// enroll, reconfigure, and remove recovery freely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryModel {
    pub quorum: u32,
    pub delay: u32,
    pub expiry: u32,
    pub max_cancels: u32,
}

/// How a document spells values that have more than one accepted spelling.
/// Every spelling of a document compiles to the same rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Spelling {
    /// External keys in uppercase hex.
    pub upper_hex: bool,
    /// Prepended to every cap limit: `""`, leading zeros, or a `+` sign.
    pub limit_prefix: &'static str,
}

/// A generated policy document. `rules[0]` is always the policy-free
/// self-admin rule `admin` (the anti-brick check needs one), except in a
/// grant document ([`DocModel::generate_grant`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocModel {
    pub signers: Vec<SignerModel>,
    pub rules: Vec<RuleModel>,
    pub recovery: Option<RecoveryModel>,
    pub spelling: Spelling,
}

/// The not-after ledgers a generated rule may carry: just past the world's
/// starting ledger (1,000, the last ledger a `1_001` rule is live at),
/// within reach of [`ADVANCE`], and out of reach.
const NOT_AFTER: [u32; 5] = [1_001, 1_050, 1_300, 2_000, 5_000_000];
/// Ledgers a sequence advances before each document: none, or past some of
/// the [`NOT_AFTER`] bounds, so rules expire between applies and documents
/// carry bounds already past.
const ADVANCE: [u32; 4] = [0, 0, 60, 400];
/// Cap-limit spellings: canonical, leading zeros, or an explicit sign.
const LIMIT_PREFIXES: [&str; 4] = ["", "0", "00", "+"];

impl DocModel {
    /// Draw a valid document from `u`. Every draw is in range, so running
    /// out of bytes yields the smallest choices: proptest shrinks toward
    /// one-signer, admin-only documents.
    pub fn generate(u: &mut Unstructured) -> arbitrary::Result<DocModel> {
        // Up to the compiler's document caps, so every draw compiles and the
        // caps themselves are reached.
        let n_signers = u.int_in_range(1..=MAX_DOC_SIGNERS as usize)?;
        let mut keys: Vec<usize> = (0..KEY_POOL).collect();
        let mut signers = Vec::new();
        for id in SIGNER_IDS.iter().take(n_signers) {
            let pick = u.choose_index(keys.len())?;
            let k = keys.remove(pick);
            let key = if u.ratio(1, 4)? {
                KeyModel::External(k)
            } else {
                KeyModel::Delegated(k)
            };
            signers.push(SignerModel { id, key });
        }
        let mut rules = std::vec![RuleModel {
            name: "admin",
            scope: None,
            signers: subset(u, n_signers, true)?,
            threshold: None,
            functions: None,
            not_after: None,
            cap: None,
        }];
        let n_rules = u.int_in_range(0..=MAX_DOC_RULES as usize - 1)?;
        let mut names: Vec<&'static str> = RULE_NAMES.to_vec();
        for _ in 0..n_rules {
            let name = names.remove(u.choose_index(names.len())?);
            let scope = if u.ratio(1, 4)? {
                None
            } else {
                Some(u.int_in_range(0..=SCOPE_POOL - 1)?)
            };
            let rule_signers = subset(u, n_signers, true)?;
            let threshold = if u.ratio(1, 4)? {
                Some(u.int_in_range(1..=rule_signers.len() as u32)?)
            } else {
                None
            };
            let functions = if u.ratio(1, 3)? {
                let n = u.int_in_range(1..=FUNCTIONS.len())?;
                Some(FUNCTIONS[..n].to_vec())
            } else {
                None
            };
            let not_after = if u.ratio(1, 4)? {
                Some(*u.choose(&NOT_AFTER)?)
            } else {
                None
            };
            let cap = if scope.is_some() && u.ratio(1, 4)? {
                Some((
                    u.int_in_range(1..=3u32)? * 1_000,
                    u.int_in_range(1..=2u32)? * 100,
                ))
            } else {
                None
            };
            rules.push(RuleModel {
                name,
                scope,
                signers: rule_signers,
                threshold,
                functions,
                not_after,
                cap,
            });
        }
        let recovery = if u.ratio(1, 3)? {
            Some(RecoveryModel {
                quorum: u.int_in_range(1..=2u32)?,
                delay: *u.choose(&[10, 20])?,
                expiry: *u.choose(&[100, 200])?,
                max_cancels: *u.choose(&[1, 3])?,
            })
        } else {
            None
        };
        let spelling = Spelling {
            upper_hex: u.ratio(1, 3)?,
            limit_prefix: u.choose(&LIMIT_PREFIXES)?,
        };
        Ok(DocModel {
            signers,
            rules,
            recovery,
            spelling,
        })
    }

    /// A sequence of `1..=max` documents drawn from `u`, each with the
    /// ledgers to advance ([`DeltaWorld::advance`]) before it is applied.
    pub fn sequence(u: &mut Unstructured, max: usize) -> arbitrary::Result<Vec<(u32, DocModel)>> {
        let n = u.int_in_range(1..=max)?;
        (0..n)
            .map(|_| Ok((*u.choose(&ADVANCE)?, DocModel::generate(u)?)))
            .collect()
    }

    /// Draw a grant document (`apply_grant`, spec §7.6): a generated
    /// document without its self-admin rules and recovery member, three
    /// draws in four in normal form ([`Self::normalize`]). One draw in six
    /// keeps the self-admin rules and recovery member, and one in four keeps
    /// its spellings, documents `apply_grant` must refuse.
    pub fn generate_grant(u: &mut Unstructured) -> arbitrary::Result<DocModel> {
        let mut d = DocModel::generate(u)?;
        if !u.ratio(1, 6)? {
            d.rules.retain(|r| r.scope.is_some());
            d.recovery = None;
        }
        if !u.ratio(1, 4)? {
            d.normalize();
        }
        Ok(d)
    }

    /// Rewrite this document into normal form (`perch_ir::normal_form`):
    /// keys in lowercase hex and limits without a prefix, `all` for a
    /// threshold asking every signer it names, `["transfer"]` for a capped
    /// rule's functions, and the signers the rules name declared in the
    /// order the rules first name them, the others dropped. Its rules'
    /// expiries are kept.
    pub fn normalize(&mut self) {
        self.spelling = Spelling::default();
        let mut order: Vec<usize> = Vec::new();
        for r in &mut self.rules {
            if r.threshold == Some(r.signers.len() as u32) {
                r.threshold = None;
            }
            if r.cap.is_some() {
                r.functions = Some(std::vec!["transfer"]);
            }
            for i in &r.signers {
                if !order.contains(i) {
                    order.push(*i);
                }
            }
        }
        for r in &mut self.rules {
            for i in &mut r.signers {
                *i = order.iter().position(|j| j == i).unwrap();
            }
        }
        self.signers = order.iter().map(|i| self.signers[*i].clone()).collect();
    }

    /// Whether `apply_grant` takes this document's form at ledger `ledger`,
    /// computed from the model alone: no rule's `not-after-ledger` reached,
    /// and in normal form (no uppercase hex digit in a key, no limit prefix,
    /// no threshold asking every signer it names, every capped rule's
    /// functions `["transfer"]`, and every signer declared in the order the
    /// rules first name it).
    pub fn normal_form(&self, ledger: u32) -> bool {
        let upper = self.signers.iter().any(|s| match s.key {
            KeyModel::External(k) => external_key(k) != external_key(k).to_uppercase(),
            KeyModel::Delegated(_) => false,
        });
        let capped = self.rules.iter().any(|r| r.cap.is_some());
        if (self.spelling.upper_hex && upper) || (capped && !self.spelling.limit_prefix.is_empty())
        {
            return false;
        }
        let mut order: Vec<usize> = Vec::new();
        for r in &self.rules {
            if r.not_after.is_some_and(|n| n <= ledger)
                || r.threshold == Some(r.signers.len() as u32)
                || (r.cap.is_some() && r.functions.as_deref() != Some(&["transfer"][..]))
            {
                return false;
            }
            for i in &r.signers {
                if !order.contains(i) {
                    order.push(*i);
                }
            }
        }
        order.iter().copied().eq(0..self.signers.len())
    }

    /// The rules this document grants `account` at the current ledger,
    /// rendered like [`live_rules`] and computed from the model alone (no
    /// compiler or account code): a rule whose `not-after-ledger` has been
    /// reached grants nothing; a rule's signers are a set, of which `m` must
    /// sign (n for `all`); a function list allows those functions and no
    /// list every one; a cap, at the limit's numeric value however it is
    /// spelled, allows only a `transfer` (when the functions cover it) whose
    /// argument 2 is an `i128`, and charges that argument; recovery adds a
    /// zero-signer self-scoped rule held by the controller.
    pub fn expected_rules(&self, w: &DeltaWorld, account: &Address) -> BTreeSet<String> {
        let seq = w.env.ledger().sequence();
        let mut out = BTreeSet::new();
        for r in &self.rules {
            if r.not_after.is_some_and(|n| n <= seq) {
                continue;
            }
            let ctx = match r.scope {
                None => account,
                Some(n) => &w.scopes[n],
            };
            let signers: BTreeSet<String> = r
                .signers
                .iter()
                .map(|i| match self.signers[*i].key {
                    KeyModel::Delegated(k) => strkey(&w.keys[k]),
                    KeyModel::External(k) => {
                        format!("{}:{}", strkey(&w.verifier), external_key(k))
                    }
                })
                .collect();
            let mut policies = BTreeSet::new();
            let m = r.threshold.unwrap_or(r.signers.len() as u32);
            policies.insert(format!("threshold:{m}"));
            let functions: BTreeSet<String> = match (&r.functions, r.cap) {
                (Some(f), None) => f.iter().map(|f| f.to_string()).collect(),
                (f, Some(_)) if f.as_ref().is_none_or(|f| f.contains(&"transfer")) => {
                    BTreeSet::from(["transfer".to_string()])
                }
                (_, Some(_)) => BTreeSet::new(),
                (None, None) => BTreeSet::new(),
            };
            let kind = if r.functions.is_none() && r.cap.is_none() {
                "any-except"
            } else {
                "only"
            };
            policies.insert(format!("functions:{kind}{functions:?}"));
            if let Some((limit, period)) = r.cap {
                policies.insert(format!("cond:arg2<={}", i128::MAX));
                policies.insert(format!("cap:{limit}/{period}@2"));
            }
            out.insert(rule_line(
                r.name,
                ctx,
                r.not_after.map(|n| n - 1),
                &signers,
                &policies,
            ));
        }
        if self.recovery.is_some() {
            out.insert(rule_line(
                "recovery",
                account,
                None,
                &BTreeSet::new(),
                &BTreeSet::from(["recovery".to_string()]),
            ));
        }
        out
    }

    /// The document's JSON, with every address from `w`'s pools.
    pub fn json(&self, w: &DeltaWorld) -> String {
        let signers: Vec<String> = self
            .signers
            .iter()
            .map(|s| match s.key {
                KeyModel::Delegated(k) => {
                    format!(r#"{{"id":"{}","address":"{}"}}"#, s.id, strkey(&w.keys[k]))
                }
                KeyModel::External(k) => format!(
                    r#"{{"id":"{}","verifier":"{}","verifier-name":"{VERIFIER_NAME}","key":"{}"}}"#,
                    s.id,
                    strkey(&w.verifier),
                    if self.spelling.upper_hex {
                        external_key(k).to_uppercase()
                    } else {
                        external_key(k)
                    }
                ),
            })
            .collect();
        let rules: Vec<String> = self.rules.iter().map(|r| self.rule_json(w, r)).collect();
        let recovery = match &self.recovery {
            None => String::new(),
            Some(r) => {
                let guardians: Vec<String> = w
                    .guardians
                    .iter()
                    .map(|g| format!(r#""{}""#, strkey(g)))
                    .collect();
                format!(
                    r#","recovery":{{"profile":"loss","mode":{{"type":"guardian-only","guardians":[{}],"quorum":{}}},"controller":"{}","replaceable":["owner"],"delay-ledgers":{},"expiry-ledgers":{},"max-cancels":{}}}"#,
                    guardians.join(","),
                    r.quorum,
                    strkey(&w.controller),
                    r.delay,
                    r.expiry,
                    r.max_cancels
                )
            }
        };
        format!(
            r#"{{"version":1,"network":"{}","signers":[{}],"rules":[{}]{}}}"#,
            crate::FIXTURE_NETWORK,
            signers.join(","),
            rules.join(","),
            recovery
        )
    }

    fn rule_json(&self, w: &DeltaWorld, r: &RuleModel) -> String {
        let ids: Vec<String> = r
            .signers
            .iter()
            .map(|i| format!(r#""{}""#, self.signers[*i].id))
            .collect();
        let principals = match r.threshold {
            None => format!(r#"{{"type":"all","signers":[{}]}}"#, ids.join(",")),
            Some(m) => format!(
                r#"{{"type":"threshold","signers":[{}],"m":{}}}"#,
                ids.join(","),
                m
            ),
        };
        let scope = match r.scope {
            None => r#"{"type":"self-admin"}"#.to_string(),
            Some(n) => format!(
                r#"{{"type":"contract","address":"{}"}}"#,
                strkey(&w.scopes[n])
            ),
        };
        let mut out = format!(
            r#"{{"name":"{}","scope":{},"principals":{}"#,
            r.name, scope, principals
        );
        if let Some(f) = &r.functions {
            let f: Vec<String> = f.iter().map(|f| format!(r#""{f}""#)).collect();
            let _ = write!(out, r#","functions":[{}]"#, f.join(","));
        }
        if let Some(n) = r.not_after {
            let _ = write!(out, r#","not-after-ledger":{n}"#);
        }
        if let Some((limit, period)) = r.cap {
            let _ = write!(
                out,
                r#","cap":{{"limit":"{}{limit}","period-ledgers":{period}}}"#,
                self.spelling.limit_prefix
            );
        }
        out.push('}');
        out
    }

    pub fn bytes(&self, w: &DeltaWorld) -> Bytes {
        Bytes::from_slice(&w.env, self.json(w).as_bytes())
    }
}

/// A non-empty subset of `0..n` (`all` and `threshold` reject an empty
/// list), in a drawn order: a rule's signers are a set, so their order in the
/// document must not change what is granted. Out of bytes, the order is
/// ascending.
fn subset(u: &mut Unstructured, n: usize, non_empty: bool) -> arbitrary::Result<Vec<usize>> {
    let mut out: Vec<usize> = (0..n).filter(|_| u.ratio(1, 2).unwrap_or(false)).collect();
    if out.is_empty() && non_empty {
        out.push(u.choose_index(n)?);
    }
    for i in (1..out.len()).rev() {
        let j = i - u.int_in_range(0..=i)?;
        out.swap(i, j);
    }
    Ok(out)
}

/// One granted rule, as [`DocModel::expected_rules`] and [`live_rules`]
/// render it.
fn rule_line(
    name: &str,
    ctx: &Address,
    valid_until: Option<u32>,
    signers: &BTreeSet<String>,
    policies: &BTreeSet<String>,
) -> String {
    format!(
        "{name} @{} until={valid_until:?} signers={signers:?} policies={policies:?}",
        strkey(ctx)
    )
}

/// The rules `account` grants at the current ledger, read from where they
/// are enforced: every OZ context rule not yet expired, its signers and
/// policies, and the stored rule-eval rule its id selects, from the account
/// document's set or its grant's.
pub fn live_rules(w: &DeltaWorld, account: &Address) -> BTreeSet<String> {
    let client = PerchAccountClient::new(&w.env, account);
    let count = client.get_context_rules_count();
    let stored = stored_rules(w, account);
    let mut out = BTreeSet::new();
    let (mut found, mut id) = (0, 0u32);
    while found < count {
        assert!(id < 100_000, "{count} context rules, not all found");
        let rule = client.try_get_context_rule(&id);
        id += 1;
        let Ok(Ok(rule)) = rule else {
            continue;
        };
        found += 1;
        out.extend(granted(w, &rule, stored.get(&rule.id)));
    }
    out
}

/// Every stored rule-eval rule of `account`, by the OZ id of the installed
/// rule it stands beside.
fn stored_rules(w: &DeltaWorld, account: &Address) -> BTreeMap<u32, StoredRule> {
    let client = PerchAccountClient::new(&w.env, account);
    let mut out: BTreeMap<u32, StoredRule> = client
        .installed_rules()
        .iter()
        .map(|r| r.id)
        .zip(client.rule_set().iter())
        .collect();
    for grant in client.grants(&0, &u32::MAX).iter() {
        if let Some(record) = client.grant(&grant) {
            out.extend(
                record
                    .rules
                    .iter()
                    .map(|r| r.id)
                    .zip(client.grant_rule_set(&grant).iter()),
            );
        }
    }
    out
}

/// [`live_rules`] restricted to the OZ rules `ids`: what one document's
/// records grant, the account document's (`installed_rules`) or a grant's.
pub fn rules_by_id(
    w: &DeltaWorld,
    account: &Address,
    ids: impl IntoIterator<Item = u32>,
) -> BTreeSet<String> {
    let client = PerchAccountClient::new(&w.env, account);
    let stored = stored_rules(w, account);
    ids.into_iter()
        .filter_map(|id| granted(w, &client.get_context_rule(&id), stored.get(&id)))
        .collect()
}

/// What `stored` allows beyond its contract, signers and last ledger,
/// rendered like [`DocModel::expected_rules`]: its threshold, functions,
/// conditions, and cap.
fn enforced(e: &Env, stored: &StoredRule) -> BTreeSet<String> {
    let rule = stored.to_rule(e).expect("a stored rule reads back");
    let names = |fs: &[std::vec::Vec<u8>]| -> BTreeSet<String> {
        fs.iter()
            .map(|f| String::from_utf8(f.clone()).unwrap())
            .collect()
    };
    let mut out = BTreeSet::from([
        format!("threshold:{}", rule.threshold),
        match &rule.functions {
            rule_eval::Functions::AnyExcept(fs) => format!("functions:any-except{:?}", names(fs)),
            rule_eval::Functions::Only(fs) => format!("functions:only{:?}", names(fs)),
        },
    ]);
    for c in &rule.conds {
        out.insert(match c {
            rule_eval::Cond::ArgI128AtMost(i, b) => format!("cond:arg{i}<={b}"),
            _ => "cond:other".to_string(),
        });
    }
    if let Some(cap) = &rule.cap {
        out.insert(format!(
            "cap:{}/{}@{}",
            cap.limit, cap.period, cap.amount_arg
        ));
    }
    out
}

/// `rule` rendered like [`DocModel::expected_rules`], or `None` once expired.
/// `stored` is the stored rule its id selects, which the recovery rule's
/// controller stands in for.
fn granted(w: &DeltaWorld, rule: &ContextRule, stored: Option<&StoredRule>) -> Option<String> {
    if rule
        .valid_until
        .is_some_and(|v| v < w.env.ledger().sequence())
    {
        return None;
    }
    let ctx = match &rule.context_type {
        ContextRuleType::CallContract(a) => a.clone(),
        other => panic!("unexpected context type {other:?}"),
    };
    let signers: BTreeSet<String> = rule
        .signers
        .iter()
        .map(|s| match s {
            Signer::Delegated(a) => strkey(&a),
            Signer::External(v, key) => {
                let mut buf = std::vec![0u8; key.len() as usize];
                key.copy_into_slice(&mut buf);
                format!("{}:{}", strkey(&v), hex::encode(buf))
            }
        })
        .collect();
    let mut policies: BTreeSet<String> = rule
        .policies
        .iter()
        .map(|p| {
            if p == w.controller {
                "recovery".to_string()
            } else {
                strkey(&p)
            }
        })
        .collect();
    if !policies.contains("recovery") {
        match stored {
            Some(s) => policies.extend(enforced(&w.env, s)),
            None => {
                policies.insert("unstored".to_string());
            }
        }
    }
    let mut name = std::vec![0u8; rule.name.len() as usize];
    rule.name.copy_into_slice(&mut name);
    Some(rule_line(
        &String::from_utf8(name).unwrap(),
        &ctx,
        rule.valid_until,
        &signers,
        &policies,
    ))
}

/// The `verifier-name` generated documents give [`DeltaWorld::verifier`].
pub const VERIFIER_NAME: &str = "delta-verifier@1.0.0";

/// External key `n`: 32 bytes, distinct per `n`.
pub fn external_key(n: usize) -> String {
    hex::encode([n as u8 + 1; 32])
}

/// The hex contract id events and [`raw_entries`] name a contract by.
pub fn contract_hex(a: &Address) -> String {
    let sc: ScAddress = a.clone().into();
    address_hex(&sc)
}

pub fn strkey(a: &Address) -> String {
    let s = a.to_string();
    let mut buf = std::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    String::from_utf8(buf).unwrap()
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

/// A delta account and an oracle account in one `Env`, with the pools every
/// generated document draws from. Authorization is mocked: this world checks
/// storage equivalence, not authorization (the enforcing-auth suites in
/// `crates/integration-tests` cover that).
pub struct DeltaWorld {
    pub env: Env,
    pub delta: Address,
    pub oracle: Address,
    pub keys: Vec<Address>,
    pub scopes: Vec<Address>,
    pub guardians: Vec<Address>,
    pub controller: Address,
    pub verifier: Address,
    pub interpreter: Address,
    pub spending_limit: Address,
}

impl Default for DeltaWorld {
    fn default() -> Self {
        Self::new()
    }
}

impl DeltaWorld {
    pub fn new() -> Self {
        Self::with_controller(None)
    }

    /// A world whose recovery controller runs `controller` (a wasm) instead
    /// of this source's, at the address `new` gives it: for an account build
    /// that calls an earlier controller's hooks (`oz_differential.rs`).
    pub fn with_controller(controller: Option<&[u8]>) -> Self {
        // Property tests build many worlds; none writes a test snapshot.
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let network_id = env
            .crypto()
            .sha256(&Bytes::from_slice(&env, crate::FIXTURE_NETWORK.as_bytes()))
            .to_array();
        env.ledger().with_mut(|l| {
            l.sequence_number = 1_000;
            l.network_id = network_id;
            l.min_persistent_entry_ttl = 1_000_000;
            l.min_temp_entry_ttl = 1_000_000;
            l.max_entry_ttl = 10_000_000;
        });
        env.mock_all_auths();
        // Documents near the caps are large; equivalence, not cost, is under
        // test here.
        env.cost_estimate().disable_resource_limits();
        env.cost_estimate().budget().reset_unlimited();
        let compiler = infra::perch_doc_compiler::address(&env);
        env.register_at(&compiler, PerchDocCompiler, ());
        let interpreter = infra::perch_interpreter::address(&env);
        env.register_at(&interpreter, PerchInterpreter, ());
        let spending_limit = infra::perch_spending_limit::address(&env);
        env.register_at(&spending_limit, PerchSpendingLimit, ());
        let verifier = crate::verifiers::deploy(&env, AnyKeyVerifier);
        crate::verifiers::name(&env, VERIFIER_NAME, &verifier);
        // A native contract registers at the next generated address; a wasm
        // is put there too, so both worlds name the same controller.
        let controller = match controller {
            Some(wasm) => env.register_at(&Address::generate(&env), wasm, ()),
            None => env.register(PerchRecovery, ()),
        };
        let keys: Vec<Address> = (0..KEY_POOL).map(|_| Address::generate(&env)).collect();
        let scopes: Vec<Address> = (0..SCOPE_POOL).map(|_| Address::generate(&env)).collect();
        let guardians: Vec<Address> = (0..2).map(|_| Address::generate(&env)).collect();
        let admin = vec![&env, Signer::Delegated(keys[0].clone())];
        let delta = env.register(PerchAccount, (admin.clone(),));
        let oracle = env.register(OracleAccount, (admin,));
        DeltaWorld {
            env,
            delta,
            oracle,
            keys,
            scopes,
            guardians,
            controller,
            verifier,
            interpreter,
            spending_limit,
        }
    }

    /// Advance the ledger by `ledgers` (a [`DocModel::sequence`] step's
    /// advance), once for both accounts.
    pub fn advance(&self, ledgers: u32) {
        self.env.ledger().with_mut(|l| l.sequence_number += ledgers);
    }

    /// Apply `doc` to `account` (either one). `Ok(doc_hash)` or the error,
    /// rendered so two accounts' outcomes compare.
    pub fn apply(&self, account: &Address, doc: &DocModel) -> Result<BytesN<32>, String> {
        let bytes = doc.bytes(self);
        self.env.cost_estimate().budget().reset_unlimited();
        let out = if *account == self.oracle {
            OracleAccountClient::new(&self.env, account)
                .try_apply_doc(&bytes, &0, &None)
                .map(|r| r.unwrap())
                .map_err(|e| format!("{e:?}"))
        } else {
            PerchAccountClient::new(&self.env, account)
                .try_apply_doc(&bytes, &0, &None)
                .map(|r| r.unwrap())
                .map_err(|e| format!("{e:?}"))
        };
        out
    }

    /// `apply_grant(grant, doc)` on `account`, rendered like [`Self::apply`].
    pub fn apply_grant(
        &self,
        account: &Address,
        grant: u32,
        doc: &DocModel,
    ) -> Result<BytesN<32>, String> {
        let bytes = doc.bytes(self);
        self.env.cost_estimate().budget().reset_unlimited();
        PerchAccountClient::new(&self.env, account)
            .try_apply_grant(&grant, &bytes)
            .map(|r| r.unwrap())
            .map_err(|e| format!("{e:?}"))
    }

    /// `remove_grant(grant)` on `account`.
    pub fn remove_grant(&self, account: &Address, grant: u32) -> Result<(), String> {
        self.env.cost_estimate().budget().reset_unlimited();
        PerchAccountClient::new(&self.env, account)
            .try_remove_grant(&grant)
            .map(|r| r.unwrap())
            .map_err(|e| format!("{e:?}"))
    }

    /// The account's rule records.
    pub fn installed(&self, account: &Address) -> soroban_sdk::Vec<InstalledRule> {
        PerchAccountClient::new(&self.env, account).installed_rules()
    }

    /// The events the last invocation emitted, as `(contract, name, topics,
    /// data)` renderings, for every contract.
    pub fn events(&self) -> Vec<Event> {
        events(&self.env)
    }
}

/// XDR bytes of the last invocation's contract events (the host's figure).
pub fn event_bytes(env: &Env) -> u32 {
    env.cost_estimate().resources().contract_events_size_bytes
}

/// One contract event, rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub contract: String,
    pub name: String,
    pub topics: Vec<String>,
    pub data: String,
}

/// The events of the last invocation.
pub fn events(env: &Env) -> Vec<Event> {
    env.events()
        .all()
        .events()
        .iter()
        .map(|e| {
            let ContractEventBody::V0(body) = &e.body;
            let topics: Vec<String> = body.topics.iter().map(|t| render(t, None)).collect();
            Event {
                contract: e
                    .contract_id
                    .as_ref()
                    .map(|c| hex::encode(c.0 .0))
                    .unwrap_or_default(),
                name: topics.first().cloned().unwrap_or_default(),
                topics,
                data: render(&body.data, None),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Grant documents
// ---------------------------------------------------------------------------

/// The grant ids a [`GrantOp`] sequence draws from: three, so each grant
/// has more than one neighbour to leave untouched and removals move entries
/// around the grant index, yet few enough that grants are re-applied,
/// removed, and created again over one another.
pub const GRANT_IDS: [u32; 3] = [0, 7, 1];

/// One step of a grant-document sequence on [`DeltaWorld::delta`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantOp {
    /// `apply_doc` of an account document.
    Admin(DocModel),
    /// `apply_grant(grant, doc)`.
    Apply(u32, DocModel),
    /// `remove_grant(grant)`.
    Remove(u32),
}

impl GrantOp {
    /// `1..=max` steps drawn from `u`, each with the ledgers to advance
    /// ([`DeltaWorld::advance`]) before it: half grant applications, a
    /// quarter removals (of live or unknown grants), and a quarter account
    /// documents, about one in ten of them without an admin rule (refused).
    pub fn sequence(u: &mut Unstructured, max: usize) -> arbitrary::Result<Vec<(u32, GrantOp)>> {
        let n = u.int_in_range(1..=max)?;
        (0..n)
            .map(|_| {
                let advance = *u.choose(&ADVANCE)?;
                let op = match u.int_in_range(0..=7u32)? {
                    0 | 1 if u.ratio(1, 8)? => GrantOp::Admin(DocModel::generate_grant(u)?),
                    0 | 1 => GrantOp::Admin(DocModel::generate(u)?),
                    6 | 7 => GrantOp::Remove(*u.choose(&GRANT_IDS)?),
                    _ => GrantOp::Apply(*u.choose(&GRANT_IDS)?, DocModel::generate_grant(u)?),
                };
                Ok((advance, op))
            })
            .collect()
    }

    /// The grant the step names, if any.
    fn grant(&self) -> Option<u32> {
        match self {
            GrantOp::Apply(s, _) | GrantOp::Remove(s) => Some(*s),
            GrantOp::Admin(_) => None,
        }
    }
}

/// The documents a [`GrantOp`] sequence has left applied to
/// [`DeltaWorld::delta`]: the account document (`None` while the
/// constructor's admin rule stands) and each live grant's.
#[derive(Clone, Debug, Default)]
pub struct GrantModel {
    pub admin: Option<DocModel>,
    pub grants: BTreeMap<u32, DocModel>,
}

impl GrantModel {
    /// Run `op` on the delta account and check, accepted or refused:
    ///
    /// - (a) every live grant grants exactly the rules the model computes
    ///   for its own document ([`DocModel::expected_rules`] against the OZ
    ///   rules its record names), and the grant index lists exactly the
    ///   model's grants;
    /// - (b) a grant operation leaves the account document as it was: its
    ///   records, the rules, signers, and policies they grant, the applied
    ///   document, the revision, and the recovery wiring;
    /// - (c) every operation leaves each grant it does not name as it was;
    /// - (d) a refused operation changes no ledger entry of any contract;
    ///
    /// and that the account grants nothing outside its documents. It also
    /// predicts the outcome before running `op`: an account document is
    /// accepted iff it keeps the `admin` rule, a grant document iff it has
    /// no self-admin rule and no recovery member and is in normal form at
    /// the current ledger ([`DocModel::normal_form`]), and a removal iff the
    /// grant is live. Nothing else can refuse in this world: generated
    /// documents always compile, recovery is a guardian-only `Loss` member
    /// with no ZK factor, and the scope pool never names the account. Panics
    /// on a violation; returns the operation's outcome.
    pub fn step(&mut self, w: &DeltaWorld, op: &GrantOp) -> Result<(), String> {
        let a = &w.delta;
        let named = op.grant();
        let expected = match op {
            GrantOp::Admin(d) => d.rules.iter().any(|r| r.name == "admin"),
            GrantOp::Apply(_, d) => {
                d.recovery.is_none()
                    && d.rules.iter().all(|r| r.scope.is_some())
                    && d.normal_form(w.env.ledger().sequence())
            }
            GrantOp::Remove(s) => self.grants.contains_key(s),
        };
        let entries = raw_entries(&w.env);
        let admin = admin_view(w, a);
        let grants: BTreeMap<u32, String> = GRANT_IDS
            .iter()
            .map(|s| (*s, grant_view(w, a, *s)))
            .collect();
        let out = match op {
            GrantOp::Admin(d) => w.apply(a, d).map(|_| ()),
            GrantOp::Apply(s, d) => w.apply_grant(a, *s, d).map(|_| ()),
            GrantOp::Remove(s) => w.remove_grant(a, *s),
        };
        assert_eq!(out.is_ok(), expected, "{op:?} returned {out:?}");
        match (&out, op) {
            (Err(e), _) => assert!(
                raw_entries(&w.env) == entries,
                "(d) the refused {op:?} changed the ledger ({e})"
            ),
            (Ok(()), GrantOp::Admin(d)) => {
                self.admin = Some(d.clone());
                if let Err(x) = crate::rule_set::check(&w.env, a) {
                    panic!("the admin rule set after {op:?}: {x}");
                }
            }
            (Ok(()), GrantOp::Apply(s, d)) => {
                self.grants.insert(*s, d.clone());
                if let Err(x) = crate::rule_set::check_grant(&w.env, a, *s) {
                    panic!("grant {s}'s rule set after {op:?}: {x}");
                }
            }
            (Ok(()), GrantOp::Remove(s)) => {
                self.grants.remove(s);
                assert!(
                    PerchAccountClient::new(&w.env, a)
                        .grant_rule_set(s)
                        .is_empty(),
                    "{op:?} left grant {s}'s rule set"
                );
            }
        }
        if named.is_some() {
            assert_eq!(
                admin_view(w, a),
                admin,
                "(b) {op:?} changed the account document"
            );
        }
        for s in GRANT_IDS {
            if Some(s) != named {
                assert_eq!(
                    grant_view(w, a, s),
                    grants[&s],
                    "(c) {op:?} changed grant {s}"
                );
            }
        }
        self.check(w);
        out
    }

    /// (a), the account document's grant, and that every live OZ rule belongs
    /// to the account document or a grant.
    pub fn check(&self, w: &DeltaWorld) {
        let a = &w.delta;
        let client = PerchAccountClient::new(&w.env, a);
        let admin = rules_by_id(w, a, client.installed_rules().iter().map(|r| r.id));
        if let Some(d) = &self.admin {
            assert_eq!(
                admin,
                d.expected_rules(w, a),
                "the account document's grant"
            );
        }
        let listed: BTreeSet<u32> = client.grants(&0, &u32::MAX).iter().collect();
        assert_eq!(
            listed,
            self.grants.keys().copied().collect(),
            "(a) the grant index"
        );
        let mut all = admin;
        for (s, d) in &self.grants {
            let record = client.grant(s).expect("a live grant has a record");
            let granted = rules_by_id(w, a, record.rules.iter().map(|r| r.id));
            assert_eq!(granted, d.expected_rules(w, a), "(a) grant {s}'s grant");
            all.extend(granted);
        }
        assert_eq!(
            live_rules(w, a),
            all,
            "a live context rule outside every document"
        );
    }
}

/// The account document as an account holds it: its configuration (records,
/// `doc_hash`, revision, recovery wiring), applied bytes, and what its
/// records grant.
fn admin_view(w: &DeltaWorld, account: &Address) -> String {
    let client = PerchAccountClient::new(&w.env, account);
    let configuration = client.configuration();
    let granted = rules_by_id(w, account, configuration.rules.iter().map(|r| r.id));
    format!("{configuration:?} {:?} {granted:?}", client.applied_doc())
}

/// Grant `grant` as an account holds it: its record, signer ids, and grant.
fn grant_view(w: &DeltaWorld, account: &Address, grant: u32) -> String {
    let client = PerchAccountClient::new(&w.env, account);
    let record = client.grant(&grant);
    let granted = record
        .as_ref()
        .map(|r| rules_by_id(w, account, r.rules.iter().map(|x| x.id)));
    format!(
        "{record:?} {:?} {granted:?}",
        client.grant_signer_ids(&grant)
    )
}

// ---------------------------------------------------------------------------
// Storage state
// ---------------------------------------------------------------------------

/// Whether [`storage_state`] keeps history counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum History {
    /// Everything, for accounts that went through the same sequence.
    Keep,
    /// Drop counters a different path legitimately leaves different: the
    /// account's recovery generation and configuration revision, and the
    /// controller's epoch. Used to compare `A -> B -> C` with `A -> C`.
    Ignore,
}

/// An account's complete storage, normalized (see the module docs), as
/// `"owner/key" -> value` renderings.
pub fn storage_state(env: &Env, account: &Address, history: History) -> BTreeMap<String, String> {
    let snapshot = env.to_ledger_snapshot();
    let me: ScAddress = account.clone().into();
    let ids = Ids::read(&snapshot.ledger_entries, &me);

    let mut out = BTreeMap::new();
    for (key, (entry, _ttl)) in snapshot.ledger_entries.iter() {
        let LedgerKey::ContractData(k) = &**key else {
            continue;
        };
        let LedgerEntryData::ContractData(d) = &entry.data else {
            continue;
        };
        if k.contract == me {
            if let ScVal::LedgerKeyContractInstance = &k.key {
                if let ScVal::ContractInstance(instance) = &d.val {
                    for e in instance.storage.iter().flat_map(|m| m.0.iter()) {
                        let name = render(&e.key, Some(&me));
                        // The id counter differs by history; ids are renamed.
                        if name == "NextRuleId"
                            || (history == History::Ignore
                                && ["RecoveryGeneration", "Revision"].contains(&name.as_str()))
                        {
                            continue;
                        }
                        let val = if name == "RecoveryRule" {
                            ids.rule(&e.val)
                        } else {
                            render(&e.val, Some(&me))
                        };
                        out.insert(format!("account/instance/{name}"), val);
                    }
                }
                continue;
            }
            if let ScVal::LedgerKeyNonce(_) = &k.key {
                continue;
            }
            let (name, val) = ids.account_entry(&k.key, &d.val, &me);
            out.insert(format!("account/{name}"), val);
        } else {
            // Another contract's entries for this account: the interpreter's
            // programs and the spending limit's state (per rule id), the
            // controller's and the pool's (per account).
            let key = render(&k.key, Some(&me));
            if !key.contains("SELF") {
                continue;
            }
            let owner = address_hex(&k.contract);
            if history == History::Ignore && key.contains("Epoch") {
                continue;
            }
            let key = ids.rule_ids_after_self(&k.key, &me).unwrap_or(key);
            out.insert(format!("{owner}/{key}"), render(&d.val, Some(&me)));
        }
    }
    out
}

/// The raw contract-data entries of every contract, for before/after diffs
/// (`"contract/key" -> value`, unnormalized; nonces excluded).
pub fn raw_entries(env: &Env) -> BTreeMap<String, String> {
    let snapshot = env.to_ledger_snapshot();
    let mut out = BTreeMap::new();
    for (key, (entry, _ttl)) in snapshot.ledger_entries.iter() {
        let LedgerKey::ContractData(k) = &**key else {
            continue;
        };
        if let ScVal::LedgerKeyNonce(_) = &k.key {
            continue;
        }
        let LedgerEntryData::ContractData(d) = &entry.data else {
            continue;
        };
        out.insert(
            format!("{}/{}", address_hex(&k.contract), render(&k.key, None)),
            render(&d.val, None),
        );
    }
    out
}

/// The [`raw_entries`] key of `contract`'s instance.
pub fn instance_key(contract: &Address) -> String {
    format!(
        "{}/{}",
        address_hex(&contract.clone().into()),
        render(&ScVal::LedgerKeyContractInstance, None)
    )
}

/// The keys whose entry was added, removed, or changed between two
/// [`raw_entries`] readings.
pub fn changed(before: &BTreeMap<String, String>, after: &BTreeMap<String, String>) -> Vec<String> {
    let mut keys: Vec<String> = before
        .iter()
        .filter(|(k, v)| after.get(*k) != Some(v))
        .map(|(k, _)| k.clone())
        .collect();
    keys.extend(after.keys().filter(|k| !before.contains_key(*k)).cloned());
    keys
}

/// One ledger snapshot entry: key, then entry and live-until ledger.
type SnapshotEntry = (
    Box<LedgerKey>,
    (Box<soroban_sdk::xdr::LedgerEntry>, Option<u32>),
);

/// Rule, signer, and policy ids of one account, read from its own entries:
/// its admin records (`RuleSet`), and any entry of OZ's registry.
struct Ids {
    rules: BTreeMap<u32, String>,
    signers: BTreeMap<u32, String>,
    policies: BTreeMap<u32, String>,
}

impl Ids {
    fn read(entries: &[SnapshotEntry], me: &ScAddress) -> Ids {
        let mut ids = Ids {
            rules: BTreeMap::new(),
            signers: BTreeMap::new(),
            policies: BTreeMap::new(),
        };
        for (key, (entry, _)) in entries {
            let LedgerKey::ContractData(k) = &**key else {
                continue;
            };
            if k.contract != *me {
                continue;
            }
            let LedgerEntryData::ContractData(d) = &entry.data else {
                continue;
            };
            // The account's records name its admin rules (the recovery
            // rule among them), each by its name and its stored rule's
            // contract.
            if let (ScVal::Symbol(s), ScVal::Vec(Some(records))) = (&k.key, &d.val) {
                if s.0.to_utf8_string_lossy() == "RuleSet" {
                    for r in records.iter() {
                        if let Some(ScVal::U32(id)) = field(r, "id") {
                            let name = field(r, "name").map(|v| render(v, Some(me)));
                            let contract = field(r, "rule")
                                .and_then(|rule| field(rule, "contract"))
                                .map(|v| render(v, Some(me)));
                            ids.rules.insert(
                                *id,
                                format!(
                                    "{}@{}",
                                    name.unwrap_or_default(),
                                    contract.unwrap_or_default()
                                ),
                            );
                        }
                    }
                }
                continue;
            }
            let Some((kind, id)) = oz_key(&k.key) else {
                continue;
            };
            match kind.as_str() {
                "ContextRuleData" => {
                    let name = field(&d.val, "name").map(|v| render(v, Some(me)));
                    let ty = field(&d.val, "context_type").map(|v| render(v, Some(me)));
                    ids.rules.insert(
                        id,
                        format!("{}@{}", name.unwrap_or_default(), ty.unwrap_or_default()),
                    );
                }
                "SignerData" => {
                    let signer = field(&d.val, "signer").map(|v| render(v, Some(me)));
                    ids.signers.insert(id, signer.unwrap_or_default());
                }
                "PolicyData" => {
                    let policy = field(&d.val, "policy").map(|v| render(v, Some(me)));
                    ids.policies.insert(id, policy.unwrap_or_default());
                }
                _ => {}
            }
        }
        ids
    }

    fn rule(&self, v: &ScVal) -> String {
        match v {
            ScVal::U32(id) => self.rules.get(id).cloned().unwrap_or(format!("?{id}")),
            other => render(other, None),
        }
    }

    /// The ids in `v` renamed through `map`; sorted unless `ordered`. OZ keeps a
    /// rule's signers in the order it was given, so that order is compared.
    fn named_list(&self, v: &ScVal, map: &BTreeMap<u32, String>, ordered: bool) -> String {
        let mut names: Vec<String> = match v {
            ScVal::Vec(Some(items)) => items
                .iter()
                .map(|i| match i {
                    ScVal::U32(id) => map.get(id).cloned().unwrap_or(format!("?{id}")),
                    other => render(other, None),
                })
                .collect(),
            other => std::vec![render(other, None)],
        };
        if !ordered {
            names.sort();
        }
        format!("[{}]", names.join(","))
    }

    /// One of the account's own entries, normalized.
    fn account_entry(&self, key: &ScVal, val: &ScVal, me: &ScAddress) -> (String, String) {
        if let Some((kind, id)) = oz_key(key) {
            return match kind.as_str() {
                "ContextRuleData" => {
                    let name = self.rules.get(&id).cloned().unwrap_or_default();
                    let mut fields = Vec::new();
                    if let ScVal::Map(Some(m)) = val {
                        for e in m.0.iter() {
                            let f = render(&e.key, Some(me));
                            let v = match f.as_str() {
                                "signer_ids" => self.named_list(&e.val, &self.signers, true),
                                "policy_ids" => self.named_list(&e.val, &self.policies, false),
                                _ => render(&e.val, Some(me)),
                            };
                            fields.push(format!("{f}={v}"));
                        }
                    }
                    (format!("rule/{name}"), fields.join(";"))
                }
                "SignerData" => (
                    format!(
                        "signer/{}",
                        self.signers.get(&id).cloned().unwrap_or_default()
                    ),
                    render(val, Some(me)),
                ),
                "PolicyData" => (
                    format!(
                        "policy/{}",
                        self.policies.get(&id).cloned().unwrap_or_default()
                    ),
                    render(val, Some(me)),
                ),
                _ => (render(key, Some(me)), render(val, Some(me))),
            };
        }
        let name = render(key, Some(me));
        let val = match (name.as_str(), val) {
            // Lookup values are ids.
            (n, ScVal::U32(id)) if n.starts_with("[SignerLookup") => {
                self.signers.get(id).cloned().unwrap_or_default()
            }
            (n, ScVal::U32(id)) if n.starts_with("[PolicyLookup") => {
                self.policies.get(id).cloned().unwrap_or_default()
            }
            // The rule records carry ids.
            ("RuleSet", ScVal::Vec(Some(rules))) => {
                let rendered: Vec<String> = rules
                    .iter()
                    .map(|r| match r {
                        ScVal::Map(Some(m)) => {
                            let fields: Vec<String> = m
                                .0
                                .iter()
                                .filter(|e| render(&e.key, None) != "id")
                                .map(|e| {
                                    format!("{}={}", render(&e.key, None), render(&e.val, Some(me)))
                                })
                                .collect();
                            format!("{{{}}}", fields.join(";"))
                        }
                        other => render(other, Some(me)),
                    })
                    .collect();
                format!("[{}]", rendered.join(","))
            }
            _ => render(val, Some(me)),
        };
        (name, val)
    }

    /// For another contract's key `[Tag, SELF, id, ...]`, the key with the
    /// rule id renamed (the interpreter's programs and the spending limit's
    /// state are keyed by rule id).
    fn rule_ids_after_self(&self, key: &ScVal, me: &ScAddress) -> Option<String> {
        let ScVal::Vec(Some(items)) = key else {
            return None;
        };
        let items: Vec<&ScVal> = items.iter().collect();
        let pos = items
            .iter()
            .position(|i| matches!(i, ScVal::Address(a) if a == me))?;
        let ScVal::U32(id) = items.get(pos + 1)? else {
            return None;
        };
        let mut parts: Vec<String> = items.iter().map(|i| render(i, Some(me))).collect();
        parts[pos + 1] = format!("rule:{}", self.rules.get(id).cloned().unwrap_or_default());
        Some(format!("[{}]", parts.join(",")))
    }
}

/// `[Kind, U32(id)]`, the shape of OZ's id-keyed entries.
fn oz_key(key: &ScVal) -> Option<(String, u32)> {
    let ScVal::Vec(Some(items)) = key else {
        return None;
    };
    match items.as_slice() {
        [ScVal::Symbol(kind), ScVal::U32(id)] => Some((kind.0.to_utf8_string_lossy(), *id)),
        _ => None,
    }
}

fn field<'a>(v: &'a ScVal, name: &str) -> Option<&'a ScVal> {
    let ScVal::Map(Some(m)) = v else {
        return None;
    };
    m.0.iter()
        .find(|e| matches!(&e.key, ScVal::Symbol(s) if s.0.to_utf8_string_lossy() == name))
        .map(|e| &e.val)
}

fn address_hex(a: &ScAddress) -> String {
    match a {
        ScAddress::Contract(c) => hex::encode(c.0 .0),
        other => format!("{other:?}"),
    }
}

/// A compact rendering of an `ScVal`; `me` renders as `SELF`.
pub fn render(v: &ScVal, me: Option<&ScAddress>) -> String {
    match v {
        ScVal::Address(a) if Some(a) == me => "SELF".into(),
        ScVal::Address(a) => address_hex(a),
        ScVal::Symbol(s) => s.0.to_utf8_string_lossy(),
        ScVal::U32(n) => n.to_string(),
        ScVal::I32(n) => n.to_string(),
        ScVal::U64(n) => n.to_string(),
        ScVal::I64(n) => n.to_string(),
        ScVal::Bool(b) => b.to_string(),
        ScVal::Void => "()".into(),
        ScVal::Bytes(b) => hex::encode(b.0.as_slice()),
        ScVal::String(s) => format!("{:?}", s.0.to_utf8_string_lossy()),
        ScVal::Vec(Some(items)) => {
            let parts: Vec<String> = items.iter().map(|i| render(i, me)).collect();
            format!("[{}]", parts.join(","))
        }
        ScVal::Map(Some(m)) => {
            let parts: Vec<String> =
                m.0.iter()
                    .map(|e| format!("{}:{}", render(&e.key, me), render(&e.val, me)))
                    .collect();
            format!("{{{}}}", parts.join(","))
        }
        other => format!("{other:?}"),
    }
}
