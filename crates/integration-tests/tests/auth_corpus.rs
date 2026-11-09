//! A recorded corpus of authorization outcomes, replayed against the build
//! under test: `tests/corpus/auth-outcomes.json`.
//!
//! Each scenario drives the real account, compiler, interpreter, spending
//! limit, and recovery controller under ENFORCING authorization (hand-built
//! auth entries through `set_auths`, so every account's real `__check_auth`
//! runs; see `support/mod.rs`). Every step records
//!
//! - the outcome: the returned value, or the error the host surfaced;
//! - the contract events the step published;
//! - for a refused authorization, every account whose `__check_auth` failed
//!   and its error (the host's "failed account authentication" diagnostic),
//!   since the host surfaces any such failure as one generic auth error;
//! - the contract storage it left: every contract-data entry it set or
//!   removed, with its `live_until` ledger.
//!
//! The corpus is the behaviour a dependency upgrade (soroban-sdk, the host,
//! `stellar-accounts`) must preserve. A difference the build is known to
//! have is declared, field by field and with its cause, in
//! `tests/corpus/declared-differences.json`; the test fails on any other
//! difference, naming the step and field, and on a declared one that no
//! longer occurs. Contract addresses are fixed
//! ([`support::fixed_address`]) and rendered by role, so the corpus does not
//! depend on the SDK's test address generator. Contract code entries and the
//! executable inside a contract instance are left out: natively registered
//! contracts carry an SDK-assigned code hash, which is not contract
//! behaviour.
//!
//! `PERCH_RECORD_CORPUS=1 cargo test -p perch-integration-tests --test
//! auth_corpus` rewrites the corpus from the current build.

mod support;

use perch_recovery::EvidenceDomain;
use perch_recovery_interface::RecoveryAction;
use perch_smart_account::infra;
use serde_json::{json, Map as JMap, Value as J};
use soroban_sdk::testutils::Events as _;
use soroban_sdk::xdr::{
    ContractEventBody, LedgerEntryData, ScAddress, ScMapEntry, ScVal, SorobanAddressCredentials,
    SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry, SorobanAuthorizedInvocation,
    SorobanCredentials, SorobanDelegateSignature, VecM,
};
use soroban_sdk::{
    contract, contractimpl, symbol_short, vec, Address, Bytes, Env, IntoVal, Symbol, TryFromVal,
    Val,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use stellar_accounts::smart_account::{AuthPayload, Signer};
use support::*;

const CORPUS: &str = "tests/corpus/auth-outcomes.json";
const DECLARED: &str = "tests/corpus/declared-differences.json";

// ---------------------------------------------------------------------------
// Stand-in token
// ---------------------------------------------------------------------------

/// A token's `transfer` shape: `from` authorizes, `to` is credited. Spending
/// limits and argument predicates meter exactly this call.
#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let key = (symbol_short!("bal"), to);
        let balance: i128 = e.storage().persistent().get(&key).unwrap_or(0);
        e.storage().persistent().set(&key, &(balance + amount));
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

struct Labels(std::vec::Vec<(ScAddress, String)>);

impl Labels {
    fn of(w: &World) -> Labels {
        let mut l = Labels(std::vec::Vec::new());
        l.add(&w.account, "account");
        l.add(&w.owner, "owner");
        l.add(&w.device, "device");
        for (i, g) in w.guardians.iter().enumerate() {
            l.add(g, &format!("guardian{i}"));
        }
        l.add(&w.controller, "controller");
        l.add(&w.adapter, "adapter");
        l.add(&w.pool, "pool");
        l.add(&w.compiler, "compiler");
        l.add(&w.target, "target");
        l.add(&infra::perch_interpreter::address(&w.env), "interpreter");
        l.add(
            &infra::perch_spending_limit::address(&w.env),
            "spending_limit",
        );
        l
    }

    fn add(&mut self, a: &Address, name: &str) {
        self.0.push((a.into(), name.into()));
    }

    fn name(&self, env: &Env, a: &ScAddress) -> String {
        match self.0.iter().find(|(x, _)| x == a) {
            Some((_, n)) => n.clone(),
            None => strkey(&Address::try_from_val(env, &ScVal::Address(a.clone())).unwrap()),
        }
    }
}

fn hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// A canonical, version-independent rendering of an `ScVal`, with contract
/// addresses by role.
fn render(env: &Env, l: &Labels, v: &ScVal) -> J {
    match v {
        ScVal::Bool(b) => json!(b),
        ScVal::Void => J::Null,
        ScVal::U32(n) => json!(format!("u32:{n}")),
        ScVal::I32(n) => json!(format!("i32:{n}")),
        ScVal::U64(n) => json!(format!("u64:{n}")),
        ScVal::I64(n) => json!(format!("i64:{n}")),
        ScVal::Timepoint(t) => json!(format!("timepoint:{}", t.0)),
        ScVal::Duration(d) => json!(format!("duration:{}", d.0)),
        ScVal::U128(p) => json!(format!("u128:{}", ((p.hi as u128) << 64) | p.lo as u128)),
        ScVal::I128(p) => json!(format!(
            "i128:{}",
            (((p.hi as i128) << 64) as u128 | p.lo as u128) as i128
        )),
        ScVal::U256(p) => json!(format!(
            "u256:{:016x}{:016x}{:016x}{:016x}",
            p.hi_hi, p.hi_lo, p.lo_hi, p.lo_lo
        )),
        ScVal::I256(p) => json!(format!(
            "i256:{:016x}{:016x}{:016x}{:016x}",
            p.hi_hi, p.hi_lo, p.lo_hi, p.lo_lo
        )),
        ScVal::Bytes(b) => json!(format!("bytes:{}", hex(b.as_slice()))),
        ScVal::String(s) => json!(format!("str:{}", String::from_utf8_lossy(s.as_slice()))),
        ScVal::Symbol(s) => json!(format!("sym:{}", String::from_utf8_lossy(s.as_slice()))),
        ScVal::Vec(None) => json!("vec:none"),
        ScVal::Vec(Some(items)) => J::Array(items.iter().map(|i| render(env, l, i)).collect()),
        ScVal::Map(None) => json!("map:none"),
        ScVal::Map(Some(m)) => J::Array(
            m.iter()
                .map(|e| json!([render(env, l, &e.key), render(env, l, &e.val)]))
                .collect(),
        ),
        ScVal::Address(a) => json!(format!("addr:{}", l.name(env, a))),
        ScVal::Error(e) => json!(format!("error:{e:?}")),
        // The executable of a natively registered contract is an SDK-assigned
        // code hash; only the instance's storage is contract state.
        ScVal::ContractInstance(i) => json!({
            "instance-storage": match &i.storage {
                None => J::Null,
                Some(m) => render(env, l, &ScVal::Map(Some(m.clone()))),
            }
        }),
        ScVal::LedgerKeyContractInstance => json!("instance"),
        ScVal::LedgerKeyNonce(n) => json!(format!("nonce:{}", n.nonce)),
        // A variant a newer XDR adds (`ExecutableTag`, CAP-0085): none of
        // the scenarios store or return one.
        #[allow(unreachable_patterns)]
        other => json!(format!("other:{other:?}")),
    }
}

/// Every contract-data entry in the ledger, keyed by
/// `<contract> <durability> <key>`.
fn storage(env: &Env, l: &Labels) -> BTreeMap<String, J> {
    let mut out = BTreeMap::new();
    for (_, (entry, live_until)) in env.to_ledger_snapshot().ledger_entries {
        if let LedgerEntryData::ContractData(d) = &entry.data {
            let key = format!(
                "{} {:?} {}",
                l.name(env, &d.contract),
                d.durability,
                render(env, l, &d.key)
            );
            out.insert(
                key,
                json!({ "val": render(env, l, &d.val), "live_until": live_until }),
            );
        }
    }
    out
}

fn sc(env: &Env, v: &Val) -> ScVal {
    ScVal::try_from_val(env, v).unwrap()
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

struct Recorder<'a> {
    w: &'a World,
    labels: Labels,
    prev: BTreeMap<String, J>,
    steps: std::vec::Vec<J>,
}

impl<'a> Recorder<'a> {
    fn new(w: &'a World) -> Recorder<'a> {
        let labels = Labels::of(w);
        let mut r = Recorder {
            w,
            labels,
            prev: BTreeMap::new(),
            steps: std::vec::Vec::new(),
        };
        r.checkpoint("setup");
        r
    }

    fn label(&mut self, a: &Address, name: &str) {
        self.labels.add(a, name);
    }

    /// The storage the scenario changed since the previous step.
    fn delta(&mut self) -> J {
        let now = storage(&self.w.env, &self.labels);
        let mut set = JMap::new();
        for (k, v) in &now {
            if self.prev.get(k) != Some(v) {
                set.insert(k.clone(), v.clone());
            }
        }
        let removed: std::vec::Vec<J> = self
            .prev
            .keys()
            .filter(|k| !now.contains_key(*k))
            .map(|k| json!(k))
            .collect();
        self.prev = now;
        json!({ "set": set, "removed": removed })
    }

    /// A storage-only step: setup, or a ledger advance.
    fn checkpoint(&mut self, step: &str) {
        let storage = self.delta();
        self.steps.push(json!({
            "step": step,
            "ledger": self.w.ledger(),
            "storage": storage,
        }));
    }

    fn advance(&mut self, ledgers: u32) {
        self.w.advance(ledgers);
        self.checkpoint(&format!("advance {ledgers}"));
    }

    /// Invoke `contract.f(args)` with exactly `auths` installed, and record
    /// the outcome, events, and storage it left.
    fn call(
        &mut self,
        step: &str,
        auths: &[SorobanAuthorizationEntry],
        contract: &Address,
        f: &str,
        args: soroban_sdk::Vec<Val>,
    ) -> Option<Val> {
        let env = &self.w.env;
        env.set_auths(auths);
        let out = env.try_invoke_contract::<Val, soroban_sdk::Error>(
            contract,
            &Symbol::new(env, f),
            args,
        );
        let events: std::vec::Vec<J> = env
            .events()
            .all()
            .events()
            .iter()
            .map(|e| {
                let ContractEventBody::V0(body) = &e.body;
                json!({
                    "contract": e.contract_id.as_ref().map(|c| {
                        self.labels.name(env, &ScAddress::Contract(c.clone()))
                    }),
                    "topics": body.topics.iter().map(|t| render(env, &self.labels, t)).collect::<std::vec::Vec<_>>(),
                    "data": render(env, &self.labels, &body.data),
                })
            })
            .collect();
        let auth_failures = self.auth_failures();
        env.set_auths(&[]);
        let (outcome, val) = match out {
            Ok(Ok(v)) => (
                json!({ "ok": render(env, &self.labels, &sc(env, &v)) }),
                Some(v),
            ),
            Ok(Err(e)) => (json!({ "unconvertible": format!("{e:?}") }), None),
            Err(Ok(e)) => {
                let e: soroban_sdk::xdr::ScError = e.try_into().unwrap();
                (json!({ "err": format!("{e:?}") }), None)
            }
            Err(Err(e)) => (json!({ "err": format!("{e:?}") }), None),
        };
        let storage = self.delta();
        self.steps.push(json!({
            "step": step,
            "ledger": self.w.ledger(),
            "outcome": outcome,
            "auth-failures": auth_failures,
            "events": events,
            "storage": storage,
        }));
        val
    }

    /// The last invocation's failed account authentications, as
    /// `<account>: <error>`.
    fn auth_failures(&self) -> std::vec::Vec<J> {
        let env = &self.w.env;
        let events = env.host().get_events().unwrap();
        events
            .0
            .iter()
            .filter_map(|e| {
                let ContractEventBody::V0(body) = &e.event.body;
                let ScVal::Vec(Some(data)) = &body.data else {
                    return None;
                };
                match data.as_slice() {
                    [ScVal::String(msg), ScVal::Address(account), ScVal::Error(err)]
                        if msg.to_utf8_string_lossy()
                            == "failed account authentication with error" =>
                    {
                        Some(json!(format!(
                            "{}: {err:?}",
                            self.labels.name(env, account)
                        )))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// `key`, the account's delegated signer, authorizes `contract.f(args)`
    /// through the rule named `rule`.
    fn call_as(
        &mut self,
        step: &str,
        key: &Address,
        rule: &str,
        contract: &Address,
        f: &str,
        args: soroban_sdk::Vec<Val>,
    ) -> Option<Val> {
        let entry = self.w.entry_as(key, rule, self.root(contract, f, &args));
        self.call(step, &[entry], contract, f, args)
    }

    fn root(
        &self,
        contract: &Address,
        f: &str,
        args: &soroban_sdk::Vec<Val>,
    ) -> SorobanAuthorizedInvocation {
        let env = &self.w.env;
        self.w
            .invocation(contract, f, args.iter().map(|a| sc(env, &a)).collect())
    }

    fn apply_args(&self, doc: &str, expected_revision: Option<u64>) -> soroban_sdk::Vec<Val> {
        let env = &self.w.env;
        vec![
            env,
            Bytes::from_slice(env, doc.as_bytes()).into_val(env),
            0u32.into_val(env),
            expected_revision.into_val(env),
        ]
    }

    /// `apply_doc(doc)` signed by `key` through the admin rule.
    fn apply_as(&mut self, step: &str, key: &Address, doc: &str) -> Option<Val> {
        let account = self.w.account.clone();
        let args = self.apply_args(doc, None);
        self.call_as(step, key, "admin", &account, "apply_doc", args)
    }

    fn finish(self) -> J {
        J::Array(self.steps)
    }
}

/// `account`'s authorization through `rule`, signed by every delegated key in
/// `keys` (one entry, CAP-0071 delegates in address order).
fn multi_delegated_entry(
    w: &World,
    keys: &[&Address],
    rule: u32,
    nonce: i64,
    root: SorobanAuthorizedInvocation,
) -> SorobanAuthorizationEntry {
    let mut sorted: std::vec::Vec<&Address> = keys.to_vec();
    sorted.sort();
    let mut signers = soroban_sdk::Map::new(&w.env);
    for k in &sorted {
        signers.set(Signer::Delegated((*k).clone()), Bytes::new(&w.env));
    }
    let delegates: std::vec::Vec<SorobanDelegateSignature> = sorted
        .iter()
        .map(|k| SorobanDelegateSignature {
            address: (*k).clone().into(),
            signature: ScVal::Void,
            nested_delegates: VecM::default(),
        })
        .collect();
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::AddressWithDelegates(
            SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address: w.account.clone().into(),
                    nonce,
                    signature_expiration_ledger: w.ledger() + 1_000_000,
                    signature: w.sc(AuthPayload {
                        signers,
                        context_rule_ids: vec![&w.env, rule],
                    }),
                },
                delegates: delegates.try_into().unwrap(),
            },
        ),
        root_invocation: root,
    }
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

fn signer(id: &str, a: &Address) -> String {
    format!(r#"{{"id":"{id}","address":"{}"}}"#, strkey(a))
}

const ADMIN_RULE: &str = r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#;

fn doc(signers: &[String], rules: &[String]) -> String {
    let mut all = std::vec![ADMIN_RULE.to_string()];
    all.extend(rules.iter().cloned());
    format!(
        r#"{{"version":1,"network":"{}","signers":[{}],"rules":[{}]}}"#,
        perch_testkit::FIXTURE_NETWORK,
        signers.join(","),
        all.join(",")
    )
}

fn world() -> World {
    world_with(Opts {
        fixed_addresses: true,
        // The corpus records the state this suite cares about.
        skip_snapshot: true,
        ..Opts::default()
    })
}

fn protected_args(w: &World) -> soroban_sdk::Vec<Val> {
    vec![&w.env, w.account.clone().into_val(&w.env)]
}

fn transfer_args(w: &World, to: &Address, amount: i128) -> soroban_sdk::Vec<Val> {
    vec![
        &w.env,
        w.account.clone().into_val(&w.env),
        to.clone().into_val(&w.env),
        amount.into_val(&w.env),
    ]
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Applying documents: who may, what a refused apply leaves, and the
/// installed rule set's storage.
fn documents() -> J {
    let w = world();
    let mut r = Recorder::new(&w);
    let s_owner = signer("owner", &w.owner);
    let s_device = signer("device", &w.device);
    let target_rule = format!(
        r#"{{"name":"target","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}}}}"#,
        strkey(&w.target)
    );
    let d1 = doc(
        &[s_owner.clone(), s_device.clone()],
        std::slice::from_ref(&target_rule),
    );

    r.apply_as("device cannot apply through the admin rule", &w.device, &d1);
    r.apply_as("owner applies the first document", &w.owner, &d1);
    r.apply_as("owner re-applies the same document", &w.owner, &d1);
    r.apply_as("malformed JSON is refused", &w.owner, "{\"version\":1,");
    r.apply_as(
        "a document for another network is refused",
        &w.owner,
        &d1.replace(
            perch_testkit::FIXTURE_NETWORK,
            "Public Global Stellar Network ; September 2015",
        ),
    );
    r.apply_as(
        "a document without an admin rule is refused",
        &w.owner,
        &format!(
            r#"{{"version":1,"network":"{}","signers":[{}],"rules":[{}]}}"#,
            perch_testkit::FIXTURE_NETWORK,
            s_owner,
            target_rule
        ),
    );
    let account = w.account.clone();
    let stale = r.apply_args(&d1, Some(99));
    r.call_as(
        "a stale expected revision is refused",
        &w.owner,
        "admin",
        &account,
        "apply_doc",
        stale,
    );
    let d2 = doc(
        std::slice::from_ref(&s_owner),
        &[target_rule.replace("\"target\"", "\"target2\"")],
    );
    r.apply_as(
        "owner replaces the rule set and drops device",
        &w.owner,
        &d2,
    );
    r.call(
        "views: applied document hash",
        &[],
        &account,
        "applied_doc_hash",
        vec![&w.env],
    );
    r.call(
        "views: context rule count",
        &[],
        &account,
        "get_context_rules_count",
        vec![&w.env],
    );
    r.finish()
}

/// Rule selection under `__check_auth`: scope, principals, rule ids, a
/// refusing delegate, and the auth payload's shape.
fn rule_selection() -> J {
    let w = world();
    let mut r = Recorder::new(&w);
    let target_rule = format!(
        r#"{{"name":"target","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}}}}"#,
        strkey(&w.target)
    );
    let d = doc(
        &[signer("owner", &w.owner), signer("device", &w.device)],
        &[target_rule],
    );
    r.apply_as("owner applies", &w.owner, &d);
    let target = w.target.clone();

    r.call_as(
        "owner through the target rule",
        &w.owner,
        "target",
        &target,
        "protected",
        protected_args(&w),
    );
    r.call_as(
        "owner through the admin rule on another contract",
        &w.owner,
        "admin",
        &target,
        "protected",
        protected_args(&w),
    );
    r.call_as(
        "device through the target rule",
        &w.device,
        "target",
        &target,
        "protected",
        protected_args(&w),
    );
    r.call_as(
        "owner through a rule id that does not exist",
        &w.owner,
        "no-such-rule",
        &target,
        "protected",
        protected_args(&w),
    );
    r.call(
        "no authorization at all",
        &[],
        &target,
        "protected",
        protected_args(&w),
    );

    // The auth payload with a key `AuthPayload` does not define.
    let root = r.root(&target, "protected", &protected_args(&w));
    let mut entry = w.entry_as(&w.owner, "target", root);
    if let SorobanCredentials::AddressWithDelegates(c) = &mut entry.credentials {
        if let ScVal::Map(Some(m)) = &mut c.address_credentials.signature {
            let mut entries: std::vec::Vec<ScMapEntry> = m.0.to_vec();
            entries.push(ScMapEntry {
                key: ScVal::Symbol("extra".try_into().unwrap()),
                val: ScVal::U32(1),
            });
            entries.sort_by(|a, b| a.key.cmp(&b.key));
            *m = soroban_sdk::xdr::ScMap(entries.try_into().unwrap());
        }
    }
    r.call(
        "an auth payload with an unknown field",
        &[entry],
        &target,
        "protected",
        protected_args(&w),
    );

    // The auth payload without `context_rule_ids`.
    let root = r.root(&target, "protected", &protected_args(&w));
    let mut entry = w.entry_as(&w.owner, "target", root);
    if let SorobanCredentials::AddressWithDelegates(c) = &mut entry.credentials {
        if let ScVal::Map(Some(m)) = &mut c.address_credentials.signature {
            let entries: std::vec::Vec<ScMapEntry> =
                m.0.iter()
                    .filter(|e| e.key != ScVal::Symbol("context_rule_ids".try_into().unwrap()))
                    .cloned()
                    .collect();
            *m = soroban_sdk::xdr::ScMap(entries.try_into().unwrap());
        }
    }
    r.call(
        "an auth payload without context_rule_ids",
        &[entry],
        &target,
        "protected",
        protected_args(&w),
    );

    r.call(
        "owner key refuses from now on",
        &[],
        &w.owner,
        "deny",
        vec![&w.env],
    );
    r.call_as(
        "a refusing delegate fails the account's authorization",
        &w.owner,
        "target",
        &target,
        "protected",
        protected_args(&w),
    );
    r.finish()
}

/// The interpreter policy: function allow-lists, argument predicates,
/// expiry, and threshold principals.
fn policies() -> J {
    let w = world();
    let token = w.env.register_at(&fixed_address(&w.env, 0xA0), Token, ());
    let payee = fixed_address(&w.env, 0xA1);
    let other = fixed_address(&w.env, 0xA2);
    let mut r = Recorder::new(&w);
    r.label(&token, "token");
    r.label(&payee, "payee");
    r.label(&other, "other");
    let pay_rule = format!(
        r#"{{"name":"pay","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}},"functions":["transfer"],"args":[{{"index":0,"pred":{{"type":"is-self"}}}},{{"index":1,"pred":{{"type":"address-eq","address":"{}"}}}}],"not-after-ledger":{}}}"#,
        strkey(&token),
        strkey(&payee),
        START + 50
    );
    let joint_rule = format!(
        r#"{{"name":"joint","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"threshold","signers":["owner","device"],"m":2}},"functions":["protected"]}}"#,
        strkey(&w.target)
    );
    let d = doc(
        &[signer("owner", &w.owner), signer("device", &w.device)],
        &[pay_rule, joint_rule],
    );
    r.apply_as("owner applies", &w.owner, &d);

    r.call_as(
        "transfer to the allowed payee",
        &w.owner,
        "pay",
        &token,
        "transfer",
        transfer_args(&w, &payee, 3),
    );
    r.call_as(
        "transfer to another address",
        &w.owner,
        "pay",
        &token,
        "transfer",
        transfer_args(&w, &other, 3),
    );
    let target = w.target.clone();
    r.call_as(
        "a function outside the allow-list",
        &w.owner,
        "joint",
        &target,
        "install",
        protected_args(&w),
    );
    r.call_as(
        "one of two threshold signers",
        &w.owner,
        "joint",
        &target,
        "protected",
        protected_args(&w),
    );
    let joint = w.rule_id(&w.account, "joint");
    let root = r.root(&target, "protected", &protected_args(&w));
    let both = multi_delegated_entry(&w, &[&w.owner, &w.device], joint, 9_001, root);
    r.call(
        "both threshold signers",
        &[both],
        &target,
        "protected",
        protected_args(&w),
    );
    r.advance(51);
    r.call_as(
        "transfer to the payee after the rule's last ledger",
        &w.owner,
        "pay",
        &token,
        "transfer",
        transfer_args(&w, &payee, 3),
    );
    r.finish()
}

/// The cumulative spending limit: within, at, and past the cap, and the
/// window rolling over.
fn spending_limit() -> J {
    let w = world();
    let token = w.env.register_at(&fixed_address(&w.env, 0xA0), Token, ());
    let payee = fixed_address(&w.env, 0xA1);
    let mut r = Recorder::new(&w);
    r.label(&token, "token");
    r.label(&payee, "payee");
    let spend_rule = format!(
        r#"{{"name":"spend","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}},"functions":["transfer"],"cap":{{"limit":"10","period-ledgers":100}}}}"#,
        strkey(&token)
    );
    let d = doc(&[signer("owner", &w.owner)], &[spend_rule]);
    r.apply_as("owner applies a capped rule", &w.owner, &d);
    for (step, amount) in [
        ("spend 6 of 10", 6),
        ("spend 4 more, reaching the cap", 4),
        ("spend 1 past the cap", 1),
    ] {
        r.call_as(
            step,
            &w.owner,
            "spend",
            &token,
            "transfer",
            transfer_args(&w, &payee, amount),
        );
    }
    r.advance(100);
    r.call_as(
        "spend 5 in the next window",
        &w.owner,
        "spend",
        &token,
        "transfer",
        transfer_args(&w, &payee, 5),
    );
    r.call_as(
        "a single transfer over the cap",
        &w.owner,
        "spend",
        &token,
        "transfer",
        transfer_args(&w, &payee, 11),
    );
    r.finish()
}

/// Guardian lost-key recovery: enrollment, evidence, the timelock,
/// completion through the zero-signer recovery rule, and the keys after.
fn recovery() -> J {
    let w = world();
    let mut r = Recorder::new(&w);
    let d = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    let json_doc = d.json(&w);
    r.apply_as("owner enrolls guardian recovery", &w.owner, &json_doc);

    let new_owner = w.new_key();
    r.label(&new_owner, "new_owner");
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let controller = w.controller.clone();
    let id = r
        .call(
            "anyone opens a lost-key attempt",
            &[],
            &controller,
            "begin_lost_key",
            vec![
                &w.env,
                w.account.clone().into_val(&w.env),
                replacements.clone().into_val(&w.env),
            ],
        )
        .map(|v| u64::try_from_val(&w.env, &v).unwrap())
        .expect("attempt opened");
    let target_bytes = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);

    for (step, g) in [
        ("guardian 0 approves", 0usize),
        ("guardian 0 again is not counted twice", 0),
        ("guardian 1 approves, reaching quorum", 1),
    ] {
        let guardian = w.guardians[g].clone();
        let digest = w.digest(&w.statement(id, EvidenceDomain::Initiate));
        let entry = w.guardian_entry(&guardian, "submit_guardian", &digest);
        r.call(
            step,
            &[entry],
            &controller,
            "submit_guardian",
            vec![
                &w.env,
                w.account.clone().into_val(&w.env),
                id.into_val(&w.env),
                EvidenceDomain::Initiate.into_val(&w.env),
                guardian.into_val(&w.env),
            ],
        );
    }

    let account = w.account.clone();
    let complete = |r: &mut Recorder, step: &str, bytes: &Bytes| {
        let args = vec![
            &w.env,
            bytes.clone().into_val(&w.env),
            0u32.into_val(&w.env),
            Option::<u64>::None.into_val(&w.env),
        ];
        let entry = w.recovery_rule_entry(r.root(&account, "apply_doc", &args));
        r.call(step, &[entry], &account, "apply_doc", args);
    };
    complete(&mut r, "completion before the timelock", &target_bytes);
    r.advance(DELAY);
    let current = w.client().applied_doc().unwrap();
    complete(&mut r, "completion with other bytes", &current);
    complete(&mut r, "completion with the derived target", &target_bytes);
    complete(&mut r, "completion replayed", &target_bytes);

    let target = w.target.clone();
    r.call_as(
        "the replaced key through the target rule",
        &w.owner,
        "target",
        &target,
        "protected",
        protected_args(&w),
    );
    r.call_as(
        "the new key through the target rule",
        &new_owner,
        "target",
        &target,
        "protected",
        protected_args(&w),
    );
    r.finish()
}

/// Removing recovery from the document: the controller drops the
/// configuration and publishes `EpochAdvanced` with no configuration hash.
fn recovery_removal() -> J {
    let w = world();
    let mut r = Recorder::new(&w);
    let with = w.doc(Some(w.recovery("loss", Mode::Guardian))).json(&w);
    let without = w.doc(None).json(&w);
    r.apply_as("owner enrolls guardian recovery", &w.owner, &with);
    r.apply_as("owner removes recovery", &w.owner, &without);
    r.apply_as("owner re-enrolls guardian recovery", &w.owner, &with);
    let controller = w.controller.clone();
    let none = vec![
        &w.env,
        w.account.clone().into_val(&w.env),
        w.replacements(&w.owner, None).into_val(&w.env),
    ];
    r.call(
        "a lost-key attempt that replaces a key with itself",
        &[],
        &controller,
        "begin_lost_key",
        none,
    );
    r.finish()
}

fn corpus() -> J {
    json!({
        "recovery-removal": recovery_removal(),
        "documents": documents(),
        "rule-selection": rule_selection(),
        "policies": policies(),
        "spending-limit": spending_limit(),
        "recovery": recovery(),
    })
}

/// One field that differs from the recorded corpus: its path, and its value
/// there and now (`None`: absent).
#[derive(Debug, PartialEq)]
struct Difference {
    path: String,
    recorded: Option<J>,
    now: Option<J>,
}

impl Difference {
    fn to_json(&self) -> J {
        let mut o = JMap::new();
        o.insert("path".into(), json!(self.path));
        if let Some(v) = &self.recorded {
            o.insert("recorded".into(), v.clone());
        }
        if let Some(v) = &self.now {
            o.insert("now".into(), v.clone());
        }
        J::Object(o)
    }
}

/// Every field where `want` and `got` differ.
fn differences(path: &str, want: &J, got: &J, out: &mut std::vec::Vec<Difference>) {
    match (want, got) {
        (J::Object(a), J::Object(b)) => {
            let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
            for k in keys {
                let p = format!("{path}.{k}");
                match (a.get(k), b.get(k)) {
                    (Some(x), Some(y)) => differences(&p, x, y, out),
                    (x, y) => out.push(Difference {
                        path: p,
                        recorded: x.cloned(),
                        now: y.cloned(),
                    }),
                }
            }
        }
        (J::Array(a), J::Array(b)) if a.len() == b.len() => {
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                let p = match x.get("step").and_then(J::as_str) {
                    Some(s) => format!("{path}[{i} \"{s}\"]"),
                    None => format!("{path}[{i}]"),
                };
                differences(&p, x, y, out);
            }
        }
        _ if want != got => out.push(Difference {
            path: path.into(),
            recorded: Some(want.clone()),
            now: Some(got.clone()),
        }),
        _ => {}
    }
}

/// The differences from the recorded corpus this build is known to have,
/// each with its cause (`tests/corpus/declared-differences.json`).
fn declared() -> std::vec::Vec<Difference> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DECLARED);
    let file: J = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut out = std::vec::Vec::new();
    for group in file["differences"].as_array().unwrap() {
        assert!(
            group["cause"].as_str().is_some_and(|c| !c.is_empty()),
            "every declared difference names its cause"
        );
        for f in group["fields"].as_array().unwrap() {
            out.push(Difference {
                path: f["path"].as_str().unwrap().into(),
                recorded: f.get("recorded").cloned(),
                now: f.get("now").cloned(),
            });
        }
    }
    out
}

/// The build reproduces the recorded corpus exactly, except for the declared
/// differences: an undeclared difference fails, and so does a declared one
/// that no longer occurs.
#[test]
fn authorization_outcomes_match_the_recorded_corpus() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CORPUS);
    let got = corpus();
    if std::env::var("PERCH_RECORD_CORPUS").as_deref() == Ok("1") {
        let text = serde_json::to_string_pretty(&got).unwrap() + "\n";
        std::fs::write(&path, text).unwrap();
        return;
    }
    let want: J = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let mut diffs = std::vec::Vec::new();
    differences("corpus", &want, &got, &mut diffs);
    let declared = declared();
    let undeclared: std::vec::Vec<J> = diffs
        .iter()
        .filter(|d| !declared.contains(d))
        .map(Difference::to_json)
        .collect();
    let unobserved: std::vec::Vec<J> = declared
        .iter()
        .filter(|d| !diffs.contains(d))
        .map(Difference::to_json)
        .collect();
    assert!(
        undeclared.is_empty() && unobserved.is_empty(),
        "differences from {CORPUS} not declared in {DECLARED}:\n{}\n\
         declared in {DECLARED} but not observed:\n{}",
        serde_json::to_string_pretty(&undeclared).unwrap(),
        serde_json::to_string_pretty(&unobserved).unwrap()
    );
}

#[test]
fn the_corpus_is_deterministic() {
    assert_eq!(corpus(), corpus());
}

/// The corpus exercises both outcomes in every scenario: a scenario where
/// everything passed (or everything failed) proves nothing about selection.
#[test]
fn every_scenario_records_both_accepts_and_refusals() {
    let c = corpus();
    for (name, steps) in c.as_object().unwrap() {
        let outcomes: std::vec::Vec<&J> = steps
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s.get("outcome"))
            .collect();
        assert!(
            outcomes.iter().any(|o| o.get("ok").is_some()),
            "{name}: no accepted step"
        );
        assert!(
            outcomes.iter().any(|o| o.get("err").is_some()),
            "{name}: no refused step"
        );
    }
}
