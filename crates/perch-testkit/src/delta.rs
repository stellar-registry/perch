//! Delta-apply harness: checks `apply_doc`'s delta reconciliation against
//! the full replace it replaced (`docs/recovery/spec.md` §7.5).
//!
//! - [`OracleAccount`] is the perch account with `apply_doc` swapped for the
//!   full replace ([`perch_smart_account::testutils::apply_doc_full_replace`]).
//!   Everything else (compile, revocation, recovery sync) is the same code.
//! - [`DocModel`] is a generated policy document. [`DocModel::generate`]
//!   draws one from bytes, so proptest (shrinking over bytes) and cargo-fuzz
//!   share one generator.
//! - [`DeltaWorld`] holds a delta account and an oracle account side by side
//!   in one `Env`, with the shared infra, controller, verifier, and address
//!   pools every generated document draws from.
//! - [`storage_state`] reads an account's complete storage from the ledger
//!   snapshot (its own entries, and every entry the interpreter, spending
//!   limit, controller, and pool keep for it), renaming the ids that differ
//!   by history: rule ids become rule names, signer and policy ids become the
//!   signer or policy. Two accounts whose rules grant the same authorization
//!   produce equal states.

use crate::fixture::AnyKeyVerifier;
use arbitrary::Unstructured;
use perch_account::{PerchAccount, PerchAccountClient};
use perch_doc_compiler::PerchDocCompiler;
use perch_interpreter::PerchInterpreter;
use perch_recovery::PerchRecovery;
use perch_smart_account::{infra, InstalledRule};
use perch_spending_limit::PerchSpendingLimit;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::xdr::{
    ContractEventBody, LedgerEntryData, LedgerKey, ScAddress, ScVal,
};
use soroban_sdk::testutils::EnvTestConfig;
use soroban_sdk::{vec, Address, Bytes, BytesN, Env};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::string::{String, ToString};
use std::vec::Vec;
use stellar_accounts::smart_account::Signer;

pub use oracle::{OracleAccount, OracleAccountClient};

/// The oracle contract lives in its own module: soroban's macros name the
/// trait impls after the bare trait paths, which must be in scope.
mod oracle {
    #![allow(unused_imports)]
    use perch_smart_account::testutils::apply_doc_full_replace;
    use perch_smart_account::{
        check_auth, install_admin, FreezeGate, InstalledRule, PerchAccountError,
        PerchSmartAccount, UpgradeRequest,
    };
    use soroban_sdk::auth::{Context, CustomAccountInterface};
    use soroban_sdk::crypto::Hash;
    use soroban_sdk::{
        contract, contractimpl, Address, Bytes, BytesN, Env, Symbol, Val, Vec,
    };
    use stellar_accounts::smart_account::{AuthPayload, ContextRule, Signer, SmartAccount};

    /// The perch account with `apply_doc` swapped for the full replace.
    #[contract]
    pub struct OracleAccount;

    #[contractimpl]
    impl OracleAccount {
        pub fn __constructor(e: &Env, admin_signers: Vec<Signer>) {
            install_admin(e, &admin_signers);
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

    impl SmartAccount for OracleAccount {}

    #[contractimpl(contracttrait)]
    impl PerchSmartAccount for OracleAccount {
        fn apply_doc(
            e: &Env,
            doc_json: Bytes,
            approval_valid_until: u32,
        ) -> Result<BytesN<32>, PerchAccountError> {
            apply_doc_full_replace(e, doc_json, approval_valid_until)
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
/// Function names a constrained rule may allow.
pub const FUNCTIONS: [&str; 3] = ["transfer", "approve", "mint"];
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
    /// `not-after-ledger`, far in the future.
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

/// A generated policy document. `rules[0]` is always the policy-free
/// self-admin rule `admin` (the anti-brick check needs one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocModel {
    pub signers: Vec<SignerModel>,
    pub rules: Vec<RuleModel>,
    pub recovery: Option<RecoveryModel>,
}

/// The not-after ledgers a generated rule may carry (all far past any ledger
/// a test reaches).
const NOT_AFTER: [u32; 3] = [5_000_000, 6_000_000, 7_000_000];

impl DocModel {
    /// Draw a valid document from `u`. Every draw is in range, so running
    /// out of bytes yields the smallest choices: proptest shrinks toward
    /// one-signer, admin-only documents.
    pub fn generate(u: &mut Unstructured) -> arbitrary::Result<DocModel> {
        let n_signers = u.int_in_range(1..=6usize)?;
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
        let n_rules = u.int_in_range(0..=6usize)?;
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
                Some((u.int_in_range(1..=3u32)? * 1_000, u.int_in_range(1..=2u32)? * 100))
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
        Ok(DocModel {
            signers,
            rules,
            recovery,
        })
    }

    /// A sequence of `1..=max` documents drawn from `u`.
    pub fn sequence(u: &mut Unstructured, max: usize) -> arbitrary::Result<Vec<DocModel>> {
        let n = u.int_in_range(1..=max)?;
        (0..n).map(|_| DocModel::generate(u)).collect()
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
                    r#"{{"id":"{}","verifier":"{}","key":"{}"}}"#,
                    s.id,
                    strkey(&w.verifier),
                    external_key(k)
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
                r#","cap":{{"limit":"{limit}","period-ledgers":{period}}}"#
            );
        }
        out.push('}');
        out
    }

    pub fn bytes(&self, w: &DeltaWorld) -> Bytes {
        Bytes::from_slice(&w.env, self.json(w).as_bytes())
    }
}

/// A non-empty, sorted subset of `0..n` (`all` and `threshold` reject an
/// empty list).
fn subset(u: &mut Unstructured, n: usize, non_empty: bool) -> arbitrary::Result<Vec<usize>> {
    let mut out: Vec<usize> = (0..n).filter(|_| u.ratio(1, 2).unwrap_or(false)).collect();
    if out.is_empty() && non_empty {
        out.push(u.choose_index(n)?);
    }
    Ok(out)
}

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
        let compiler = infra::perch_doc_compiler::address(&env);
        env.register_at(&compiler, PerchDocCompiler, ());
        let interpreter = infra::perch_interpreter::address(&env);
        env.register_at(&interpreter, PerchInterpreter, ());
        let spending_limit = infra::perch_spending_limit::address(&env);
        env.register_at(&spending_limit, PerchSpendingLimit, ());
        let verifier = env.register(AnyKeyVerifier, ());
        let controller = env.register(PerchRecovery, ());
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

    /// Apply `doc` to `account` (either one). `Ok(doc_hash)` or the error,
    /// rendered so two accounts' outcomes compare.
    pub fn apply(&self, account: &Address, doc: &DocModel) -> Result<BytesN<32>, String> {
        let bytes = doc.bytes(self);
        let out = if *account == self.oracle {
            OracleAccountClient::new(&self.env, account)
                .try_apply_doc(&bytes, &0)
                .map(|r| r.unwrap())
                .map_err(|e| format!("{e:?}"))
        } else {
            PerchAccountClient::new(&self.env, account)
                .try_apply_doc(&bytes, &0)
                .map(|r| r.unwrap())
                .map_err(|e| format!("{e:?}"))
        };
        out
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
// Storage state
// ---------------------------------------------------------------------------

/// Whether [`storage_state`] keeps history counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum History {
    /// Everything, for accounts that went through the same sequence.
    Keep,
    /// Drop counters a different path legitimately leaves different: the
    /// account's recovery generation and the controller's epoch. Used to
    /// compare `A -> B -> C` with `A -> C`.
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
                        if ["[NextId]", "[NextSignerId]", "[NextPolicyId]"].contains(&name.as_str())
                            || (history == History::Ignore && name == "RecoveryGeneration")
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

/// The keys whose entry was added, removed, or changed between two
/// [`raw_entries`] readings.
pub fn changed(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut keys: Vec<String> = before
        .iter()
        .filter(|(k, v)| after.get(*k) != Some(v))
        .map(|(k, _)| k.clone())
        .collect();
    keys.extend(after.keys().filter(|k| !before.contains_key(*k)).cloned());
    keys
}

/// Rule, signer, and policy ids of one account, read from its own entries.
struct Ids {
    rules: BTreeMap<u32, String>,
    signers: BTreeMap<u32, String>,
    policies: BTreeMap<u32, String>,
}

impl Ids {
    fn read(
        entries: &[(Box<LedgerKey>, (Box<soroban_sdk::xdr::LedgerEntry>, Option<u32>))],
        me: &ScAddress,
    ) -> Ids {
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

    fn named_list(&self, v: &ScVal, map: &BTreeMap<u32, String>) -> String {
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
        names.sort();
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
                                "signer_ids" => self.named_list(&e.val, &self.signers),
                                "policy_ids" => self.named_list(&e.val, &self.policies),
                                _ => render(&e.val, Some(me)),
                            };
                            fields.push(format!("{f}={v}"));
                        }
                    }
                    (format!("rule/{name}"), fields.join(";"))
                }
                "SignerData" => (
                    format!("signer/{}", self.signers.get(&id).cloned().unwrap_or_default()),
                    render(val, Some(me)),
                ),
                "PolicyData" => (
                    format!("policy/{}", self.policies.get(&id).cloned().unwrap_or_default()),
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
            // The rule records carry OZ ids.
            ("InstalledRules", ScVal::Vec(Some(rules))) => {
                let rendered: Vec<String> = rules
                    .iter()
                    .map(|r| match r {
                        ScVal::Map(Some(m)) => {
                            let fields: Vec<String> = m
                                .0
                                .iter()
                                .filter(|e| render(&e.key, None) != "id")
                                .map(|e| format!("{}={}", render(&e.key, None), render(&e.val, Some(me))))
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
            let parts: Vec<String> = m
                .0
                .iter()
                .map(|e| format!("{}:{}", render(&e.key, me), render(&e.val, me)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        other => format!("{other:?}"),
    }
}
