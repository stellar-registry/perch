//! `perch-review-core` against the account's real `__check_auth`.
//!
//! The core claims: for the ledger entries given and the ledger sequence
//! given, assuming every payload signer it is not told is unverified
//! authenticates, its verdict is what the account's `__check_auth` returns
//! on that state at that ledger. Each test here puts the account in a state,
//! reads the account's contract-data entries from the host exactly as
//! `getLedgerEntries` would return them (`rule_core::account_entries`), runs
//! the core on them and on the authorization entry, and then runs the same
//! authorization through the host natively, with real signatures:
//!
//! - rule-core's document traces and Perch's own (`rule_core::run_with`,
//!   the harness `rule_core_documents.rs` uses): each document applied with
//!   the real `apply_doc` or `apply_grant`, each authorization a real
//!   invocation under enforcing authorization (`set_auths`), with ed25519
//!   signatures and CAP-0071 delegates;
//! - rule-core's authorization traces: each trace's rules installed as the
//!   account's stored rules (`testutils::install_rule`) with its starting
//!   records, each authorization handed to `__check_auth` through
//!   `try_invoke_contract_check_auth` with real ed25519 signatures;
//! - Perch's own gate cases: reserved functions, the freeze, a stale grant
//!   generation, a wiped credential, guardian approvals and token-admin
//!   functions under a grant, the excluded set, and the rest of the gate's
//!   refusals.
//!
//! The core must give the account's verdict, the account's error code, and
//! after an accepted authorization the spending records the account stored.
//! A recovery completion the account's own checks pass is the controller's
//! to decide; the core says so, and those are counted apart. Every
//! difference is reported.

mod rule_core;
mod support;

use std::collections::BTreeMap;

use ed25519_dalek::{Signer as _, SigningKey};
use perch_account::PerchAccountError;
use perch_account_types::{AuthPayload, Signer};
use perch_ed25519_verifier::PerchEd25519Verifier;
use perch_recovery_interface::config::CompiledZkFactor;
use perch_review_core::{Claimed, Outcome, Request, Review, Snapshot, Verified};
use perch_rule_eval::StoredRule;
use perch_smart_account::testutils::{install_rule, set_grant_generation, spend_record};
use perch_smart_account::FreezeGate;
use rule_core::{account_entries, Seen, Start};
use rule_eval_conformance::{
    authorize, decode_context, decode_hex, decode_rules, documents, JsonContext, JsonSigner,
    JsonVal,
};
use sha2::{Digest as _, Sha256};
use soroban_sdk::auth::{Context, ContractContext, CreateContractHostFnContext};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::xdr::{
    ContractDataDurability, ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress,
    CreateContractArgs, Hash as XdrHash, InvokeContractArgs, LedgerEntryData, Limits, ReadXdr,
    ScAddress, ScError, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanDelegateSignature, StringM, Uint256,
    VecM, WriteXdr as _,
};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, BytesN, Env, IntoVal, Map, String as SString, Symbol,
    TryFromVal, Val, Vec as SVec,
};
use support::*;

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/// A verdict, as both sides are compared.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Verdict {
    Accepted,
    /// The error: a contract error code, or `None` for a host error.
    Refused(Option<u32>),
    /// A signer's own refusal, whose code is its verifier's or its own (the
    /// core's answer only): it matches any refusal.
    SignerRefused,
    /// The recovery controller decides (the core's answer only).
    Controller,
}

fn core_verdict(r: &Review) -> Verdict {
    match &r.outcome {
        Outcome::Accepted => Verdict::Accepted,
        Outcome::Refused(f) => match f.error() {
            perch_review_core::Error::Contract(c) => Verdict::Refused(Some(c)),
            perch_review_core::Error::Host => Verdict::Refused(None),
            perch_review_core::Error::Signer => Verdict::SignerRefused,
        },
        Outcome::Controller { .. } => Verdict::Controller,
    }
}

/// The account's verdict from an invocation's outcome.
fn host_verdict(outcome: &Result<(), Option<ScError>>) -> Verdict {
    match outcome {
        Ok(()) => Verdict::Accepted,
        Err(Some(ScError::Contract(c))) => Verdict::Refused(Some(*c)),
        Err(_) => Verdict::Refused(None),
    }
}

fn host_error(err: &soroban_sdk::Error) -> Verdict {
    match ScError::try_from(*err) {
        Ok(ScError::Contract(c)) => Verdict::Refused(Some(c)),
        _ => Verdict::Refused(None),
    }
}

/// The core's name for what it decided.
fn core_label(r: &Review) -> String {
    match &r.outcome {
        Outcome::Accepted => "accepted".into(),
        Outcome::Refused(f) => format!("refused: {} ({})", f.check.name(), f.error_name()),
        Outcome::Controller { .. } => "controller decides".into(),
    }
}

fn sc_address(a: &Address) -> Vec<u8> {
    ScAddress::from(a.clone())
        .to_xdr(Limits::none())
        .expect("address xdr")
}

/// The spending record the account keeps for `id`, as `(history, total)`.
fn stored_record(w: &World, id: u32) -> (Vec<(u32, i128)>, i128) {
    match w.env.as_contract(&w.account, || spend_record(&w.env, id)) {
        Some(r) => (
            r.history.iter().map(|x| (x.ledger, x.amount)).collect(),
            r.total,
        ),
        None => (vec![], 0),
    }
}

/// Every difference between the core's review and the account's outcome:
/// the verdict and error, and after an acceptance the record of each chosen
/// capped rule the core says changed.
fn compare(w: &World, review: &Review, host: &Verdict) -> Vec<String> {
    let core = core_verdict(review);
    let mut out = vec![];
    match (&core, host) {
        (Verdict::Controller, _) | (Verdict::SignerRefused, Verdict::Refused(_)) => {}
        (c, h) if c == h => {}
        (c, h) => out.push(format!(
            "core {c:?} ({}), account {h:?}",
            core_label(review)
        )),
    }
    if core == Verdict::Accepted && *host == Verdict::Accepted {
        for (id, rec) in &review.records {
            let want = (
                rec.history.iter().map(|e| (e.ledger, e.amount)).collect(),
                rec.total,
            );
            let got = stored_record(w, *id);
            if got != want {
                out.push(format!(
                    "rule {id}: the core's record {want:?}, the account's {got:?}"
                ));
            }
        }
    }
    out
}

/// What a run of comparisons found.
#[derive(Default)]
struct Tally {
    compared: usize,
    accepted: usize,
    refused: BTreeMap<String, usize>,
    controller: usize,
    /// Controller-decided completions, by the account's verdict.
    controller_host: BTreeMap<String, usize>,
    budgets: usize,
    records: usize,
    differences: Vec<String>,
}

impl Tally {
    fn add(&mut self, what: &str, w: &World, review: &Review, host: &Verdict) {
        self.compared += 1;
        self.budgets += review.budgets.len();
        match &review.outcome {
            Outcome::Accepted => {
                self.accepted += 1;
                self.records += review.records.len();
            }
            Outcome::Refused(f) => *self.refused.entry(f.check.name().into()).or_default() += 1,
            Outcome::Controller { .. } => {
                self.controller += 1;
                *self.controller_host.entry(format!("{host:?}")).or_default() += 1;
            }
        }
        for d in compare(w, review, host) {
            self.differences.push(format!("{what}: {d}"));
        }
    }

    fn summary(&self, kind: &str) -> String {
        format!(
            "{kind}: compared {} (agree {}), accepted {}, refused {:?}, deferred to the controller \
             {} (account: {:?}), budgets {}, records stored {}, differences {}",
            self.compared,
            self.compared.saturating_sub(self.differences.len()),
            self.accepted,
            self.refused,
            self.controller,
            self.controller_host,
            self.budgets,
            self.records,
            self.differences.len()
        )
    }
}

/// The core on one authorization the harness showed the account.
fn review_seen(seen: &Seen<'_>) -> Result<Review, String> {
    let entries = seen.before.iter().map(Vec::as_slice);
    match seen.entry {
        Some(entry) => {
            let xdr = entry.to_xdr(Limits::none()).expect("entry xdr");
            perch_review_core::review_entry(&xdr, entries, seen.ledger, &[])
                .map(|(_, r)| r)
                .map_err(|u| format!("the core cannot read the input: {u:?}"))
        }
        None => {
            let account = sc_address(&seen.world.account);
            let snapshot = Snapshot::from_ledger_entries(&account, entries)
                .map_err(|u| format!("the core cannot read the snapshot: {u:?}"))?;
            perch_review_core::review(
                &snapshot,
                &Request {
                    account,
                    contexts: vec![],
                    rule_ids: vec![],
                    signers: vec![],
                    delegates: None,
                    ledger: seen.ledger,
                },
            )
            .map_err(|u| format!("the core cannot read the snapshot: {u:?}"))
        }
    }
}

/// The rule ids an entry's payload chooses.
fn chosen_ids(entry: &[u8]) -> Vec<u32> {
    let e = perch_review_core::xdr::entry(entry).expect("an entry");
    let soroban_facade::Val::Map(fields) = e.payload else {
        panic!("a payload is a map")
    };
    let Some((_, soroban_facade::Val::Vec(ids))) = fields.first() else {
        panic!("a payload's first field is its rule ids")
    };
    ids.iter()
        .map(|v| match v {
            soroban_facade::Val::U32(x) => *x,
            _ => panic!("a rule id is a u32"),
        })
        .collect()
}

/// The entries of `before` a wallet fetches for `rule_ids`, as the core's
/// README tells it to: the instance entry, and the keys
/// `Snapshot::keys` and `Snapshot::grant_keys` name.
fn fetched(account: &[u8], before: &[Vec<u8>], rule_ids: &[u32]) -> Vec<Vec<u8>> {
    let all = Snapshot::from_ledger_entries(account, before.iter().map(Vec::as_slice))
        .expect("a snapshot");
    let mut keys = Snapshot::keys(rule_ids);
    keys.extend(all.grant_keys(rule_ids).expect("grant keys"));
    before
        .iter()
        .filter(|b| {
            let LedgerEntryData::ContractData(c) =
                LedgerEntryData::from_xdr(b, Limits::none()).unwrap()
            else {
                return false;
            };
            if c.key == ScVal::LedgerKeyContractInstance {
                return true;
            }
            c.durability == ContractDataDurability::Persistent
                && soroban_facade::xdr::decode(&c.key.to_xdr(Limits::none()).unwrap())
                    .is_some_and(|k| keys.contains(&k))
        })
        .cloned()
        .collect()
}

/// The core's byte interface's input (`perch_review_core::envelope`).
fn envelope(entry: &[u8], entries: &[Vec<u8>], ledger: u32, verified: &[Verified]) -> Vec<u8> {
    let mut out = vec![];
    let u32 = |out: &mut Vec<u8>, n: usize| out.extend((n as u32).to_be_bytes());
    u32(&mut out, 1);
    u32(&mut out, ledger as usize);
    u32(&mut out, entry.len());
    out.extend(entry);
    u32(&mut out, entries.len());
    for e in entries {
        u32(&mut out, e.len());
        out.extend(e);
    }
    u32(&mut out, verified.len());
    for v in verified {
        out.push(match v {
            Verified::No => 0,
            Verified::Yes => 1,
            Verified::Assumed => 2,
        });
    }
    out
}

thread_local! {
    /// Fixtures for the npm wrapper's tests, collected on the thread
    /// `write_npm_fixtures` runs the gate cases on.
    static FIXTURES: std::cell::RefCell<Option<Vec<serde_json::Value>>> =
        const { std::cell::RefCell::new(None) };
}

/// What the core must also do for an authorization it reviewed from
/// `entry`: give the same answer from only the entries a wallet fetches,
/// and through its byte interface. The differences, if any.
fn also(
    what: &str,
    entry: &[u8],
    before: &[Vec<u8>],
    ledger: u32,
    verified: &[Verified],
    review: &Review,
    host: &Verdict,
) -> Vec<String> {
    let ids = chosen_ids(entry);
    let account = perch_review_core::xdr::entry(entry).unwrap().account;
    let full = perch_review_core::json::review(&account, ledger, review);
    let subset = fetched(&account, before, &ids);
    let mut out = vec![];
    let input = envelope(entry, &subset, ledger, verified);
    let bytes = perch_review_core::envelope::review(&input);
    if bytes != full {
        out.push(format!(
            "{what}: from the fetched entries the core answers {}, from all of them {}",
            String::from_utf8_lossy(&bytes),
            String::from_utf8_lossy(&full)
        ));
    }
    let mut sink = FIXTURES.take();
    if let Some(sink) = sink.as_mut() {
        let keys: Vec<String> = std::iter::once(b64(&instance_key(&account)))
            .chain(
                Snapshot::keys(&ids)
                    .iter()
                    .map(|k| b64(&ledger_key(&account, k))),
            )
            .collect();
        sink.push(serde_json::json!({
            "name": what,
            "input": b64(&input),
            "output": serde_json::from_slice::<serde_json::Value>(&full).unwrap(),
            "account": format!("{host:?}"),
            "rule_ids": ids,
            "keys": keys,
        }));
    }
    FIXTURES.set(sink);
    out
}

/// `b` in standard base64, as `getLedgerEntries` and the wallets carry XDR.
fn b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// The `LedgerKey` XDR of the account's contract-data entry under `key`.
fn ledger_key(account: &[u8], key: &soroban_facade::Val) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 6];
    out.extend(account);
    out.extend(soroban_facade::xdr::encode(key));
    out.extend([0, 0, 0, 1]);
    out
}

/// The `LedgerKey` XDR of the account's instance entry.
fn instance_key(account: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 6];
    out.extend(account);
    out.extend([0, 0, 0, 20, 0, 0, 0, 1]);
    out
}

// ---------------------------------------------------------------------------
// Document traces
// ---------------------------------------------------------------------------

#[test]
fn the_core_agrees_with_the_account_on_every_document_trace() {
    let mut traces = documents::load_dir(&rule_core::vectors().join("documents"))
        .unwrap_or_else(|e| panic!("{e}"));
    let rule_core_traces = traces.len();
    traces
        .extend(documents::load_dir(&rule_core::perch_vectors()).unwrap_or_else(|e| panic!("{e}")));
    let mut tally = Tally::default();
    let mut runs = 0;
    for (_, t) in &traces {
        for start in [Start::Fresh, Start::AfterPredecessor] {
            let mut i = 0;
            let mut observe = |seen: Seen<'_>| {
                let what = format!("{} ({start:?}) authorization {i}", t.name);
                i += 1;
                match review_seen(&seen) {
                    Ok(review) => {
                        let host = host_verdict(&seen.outcome);
                        tally.add(&what, seen.world, &review, &host);
                        if let Some(entry) = seen.entry {
                            let xdr = entry.to_xdr(Limits::none()).unwrap();
                            let more =
                                also(&what, &xdr, &seen.before, seen.ledger, &[], &review, &host);
                            tally.differences.extend(more);
                        }
                    }
                    Err(e) => tally.differences.push(format!("{what}: {e}")),
                }
            };
            rule_core::run_with(t, start, &mut observe)
                .unwrap_or_else(|e| panic!("{} ({start:?}): {e}", t.name));
            runs += 1;
        }
    }
    println!(
        "document traces: {} ({rule_core_traces} rule-core's, {} Perch's), runs {runs}; {}",
        traces.len(),
        traces.len() - rule_core_traces,
        tally.summary("authorizations")
    );
    assert!(tally.accepted > 0 && !tally.refused.is_empty() && tally.records > 0);
    assert!(
        tally.differences.is_empty(),
        "{}",
        tally.differences.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Authorization traces
// ---------------------------------------------------------------------------

/// One authorization trace's renaming onto a world: abstract contracts,
/// addresses and signers onto real ones, injectively.
struct Lab<'w> {
    w: &'w World,
    addr: BTreeMap<Vec<u8>, Address>,
    keys: BTreeMap<Vec<u8>, SigningKey>,
    /// Symbols the host does not hold, renamed onto ones it does.
    syms: BTreeMap<Vec<u8>, Vec<u8>>,
    /// `Other` payloads that are no host value's XDR, renamed onto the XDR
    /// of an `i64`, which the facade reads as `Other` of that XDR.
    others: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl<'w> Lab<'w> {
    /// `account`: the abstract address renamed onto the account itself, if
    /// any; every abstract verifier onto a real ed25519 verifier.
    fn new(w: &'w World, t: &authorize::Trace, account: Option<Vec<u8>>) -> Lab<'w> {
        let mut lab = Lab {
            w,
            addr: BTreeMap::new(),
            keys: BTreeMap::new(),
            syms: BTreeMap::new(),
            others: BTreeMap::new(),
        };
        if let Some(a) = account {
            lab.addr.insert(a, w.account.clone());
        }
        let rules = decode_rules(&t.rules).expect("trace rules");
        let verifiers = rules
            .iter()
            .flat_map(|r| r.signers.iter())
            .filter_map(|s| match s {
                rule_eval::Signer::External(v, _) => Some(v.clone()),
                _ => None,
            })
            .chain(t.authorizations.iter().flat_map(|a| {
                a.authenticated.iter().filter_map(|s| match s {
                    JsonSigner::External { verifier, .. } => Some(decode_hex(verifier).unwrap()),
                    _ => None,
                })
            }));
        for v in verifiers {
            lab.addr.entry(v).or_insert_with(|| {
                perch_testkit::verifiers::deploy_auto(&w.env, PerchEd25519Verifier)
            });
        }
        lab
    }

    /// `b` as a symbol the host holds: itself when it is one, otherwise a
    /// fresh `zq…` name. rule-eval compares symbols only for equality, so
    /// an injective renaming keeps every verdict.
    fn sym(&mut self, b: &[u8]) -> Vec<u8> {
        if perch_rule_eval::convert::host_symbol(&self.w.env, b).is_some() && !b.starts_with(b"zq")
        {
            return b.to_vec();
        }
        let n = self.syms.len();
        self.syms
            .entry(b.to_vec())
            .or_insert_with(|| format!("zq{n}").into_bytes())
            .clone()
    }

    /// `b`, an `Other` payload, as the XDR of a host value the facade reads
    /// as `Other` of exactly that XDR: itself when it is one, otherwise an
    /// `i64` from a range no trace uses. rule-eval compares `Other` payloads
    /// only for equality.
    fn other(&mut self, b: &[u8]) -> Vec<u8> {
        let own = soroban_facade::xdr::decode(b).is_some_and(
            |v| matches!(soroban_facade::val_to_rule_eval(&v), rule_eval::Val::Other(x) if x == b),
        ) && ScVal::from_xdr(b, Limits::none()).is_ok();
        if own {
            return b.to_vec();
        }
        let n = self.others.len() as i64;
        self.others
            .entry(b.to_vec())
            .or_insert_with(|| {
                ScVal::I64(0x5eed_0000_0000 + n)
                    .to_xdr(Limits::none())
                    .unwrap()
            })
            .clone()
    }

    fn address(&mut self, abs: &[u8]) -> Address {
        let e = self.w.env.clone();
        self.addr
            .entry(abs.to_vec())
            .or_insert_with(|| <Address as soroban_sdk::testutils::Address>::generate(&e))
            .clone()
    }

    fn xdr(&mut self, abs: &[u8]) -> Vec<u8> {
        sc_address(&self.address(abs))
    }

    fn key(&mut self, abs: &[u8]) -> SigningKey {
        self.keys
            .entry(abs.to_vec())
            .or_insert_with(|| {
                let mut h = Sha256::new();
                h.update(b"perch review-core trace key\0");
                h.update(abs);
                SigningKey::from_bytes(&h.finalize().into())
            })
            .clone()
    }

    fn signer(&mut self, s: &rule_eval::Signer) -> rule_eval::Signer {
        match s {
            rule_eval::Signer::Delegated(a) => rule_eval::Signer::Delegated(self.xdr(a)),
            rule_eval::Signer::External(v, k) => rule_eval::Signer::External(
                self.xdr(v),
                self.key(k).verifying_key().to_bytes().to_vec(),
            ),
        }
    }

    fn val(&mut self, v: &rule_eval::Val) -> rule_eval::Val {
        match v {
            rule_eval::Val::Address(a) => rule_eval::Val::Address(self.xdr(a)),
            rule_eval::Val::I128(n) => rule_eval::Val::I128(*n),
            rule_eval::Val::U64(n) => rule_eval::Val::U64(*n),
            rule_eval::Val::Bool(b) => rule_eval::Val::Bool(*b),
            rule_eval::Val::Bytes(b) => rule_eval::Val::Bytes(b.clone()),
            rule_eval::Val::Symbol(b) => rule_eval::Val::Symbol(self.sym(b)),
            rule_eval::Val::String(b) => rule_eval::Val::String(b.clone()),
            rule_eval::Val::Other(b) => rule_eval::Val::Other(self.other(b)),
        }
    }

    /// A trace context renamed, as the account should read it.
    fn renamed(&mut self, c: &rule_eval::Context) -> Option<rule_eval::Context> {
        match c {
            rule_eval::Context::Call {
                contract,
                function,
                args,
            } => Some(rule_eval::Context::Call {
                contract: self.xdr(contract),
                function: self.sym(function),
                args: args.iter().map(|v| self.val(v)).collect(),
            }),
            rule_eval::Context::Create { .. } => None,
        }
    }

    /// The trace's rule with every abstract identifier renamed.
    fn rule(&mut self, r: &rule_eval::Rule) -> rule_eval::Rule {
        rule_eval::Rule {
            contract: self.xdr(&r.contract),
            functions: match &r.functions {
                rule_eval::Functions::Only(f) => {
                    rule_eval::Functions::Only(f.iter().map(|x| self.sym(x)).collect())
                }
                rule_eval::Functions::AnyExcept(f) => {
                    rule_eval::Functions::AnyExcept(f.iter().map(|x| self.sym(x)).collect())
                }
            },
            conds: r
                .conds
                .iter()
                .map(|c| match c {
                    rule_eval::Cond::ArgEq(i, v) => rule_eval::Cond::ArgEq(*i, self.val(v)),
                    rule_eval::Cond::ArgI128AtMost(i, n) => rule_eval::Cond::ArgI128AtMost(*i, *n),
                    rule_eval::Cond::ArgIn(i, vs) => {
                        rule_eval::Cond::ArgIn(*i, vs.iter().map(|v| self.val(v)).collect())
                    }
                    rule_eval::Cond::ArgStrPrefix(i, p) => {
                        rule_eval::Cond::ArgStrPrefix(*i, p.clone())
                    }
                })
                .collect(),
            signers: r.signers.iter().map(|s| self.signer(s)).collect(),
            threshold: r.threshold,
            cap: r.cap.as_ref().map(|c| rule_eval::Cap {
                limit: c.limit,
                period: c.period,
                amount_arg: c.amount_arg,
            }),
            valid_until: r.valid_until,
            generation: r.generation,
            auth_root: r.auth_root.as_ref().map(|root| rule_eval::AuthRoot {
                contract: self.xdr(&root.contract),
                function: self.sym(&root.function),
            }),
        }
    }

    fn host_val(&mut self, v: &JsonVal) -> Result<Val, String> {
        let e = self.w.env.clone();
        Ok(match v {
            JsonVal::I128(s) => s.parse::<i128>().map_err(|x| x.to_string())?.into_val(&e),
            JsonVal::U64(s) => s.parse::<u64>().map_err(|x| x.to_string())?.into_val(&e),
            JsonVal::Bool(b) => (*b).into_val(&e),
            JsonVal::Bytes(h) => Bytes::from_slice(&e, &decode_hex(h)?).into_val(&e),
            JsonVal::Address(h) => self.address(&decode_hex(h)?).into_val(&e),
            JsonVal::Symbol(h) => {
                let s = self.sym(&decode_hex(h)?);
                perch_rule_eval::convert::host_symbol(&e, &s)
                    .expect("a renamed symbol")
                    .into_val(&e)
            }
            JsonVal::String(h) => SString::from_bytes(&e, &decode_hex(h)?).into_val(&e),
            // rule-eval holds `Other` as opaque bytes; only the XDR of a
            // value the host holds can be a context's argument.
            JsonVal::Other(h) => {
                let x = self.other(&decode_hex(h)?);
                let sc = ScVal::from_xdr(x, Limits::none()).expect("a renamed payload");
                Val::try_from_val(&e, &sc).map_err(|_| format!("no host value for {h}"))?
            }
        })
    }

    fn context(&mut self, c: &JsonContext) -> Result<Context, String> {
        let e = self.w.env.clone();
        Ok(match c {
            JsonContext::Call {
                contract,
                function,
                args,
            } => {
                let f = self.sym(&decode_hex(function)?);
                let fn_name =
                    perch_rule_eval::convert::host_symbol(&e, &f).expect("a renamed symbol");
                let mut a: SVec<Val> = SVec::new(&e);
                for v in args {
                    let v = self.host_val(v)?;
                    a.push_back(v);
                }
                Context::Contract(ContractContext {
                    contract: self.address(&decode_hex(contract)?),
                    fn_name,
                    args: a,
                })
            }
            JsonContext::Create { wasm_hash } => {
                let hash: [u8; 32] = Sha256::digest(decode_hex(wasm_hash)?).into();
                Context::CreateContractHostFn(CreateContractHostFnContext {
                    executable: soroban_sdk::auth::ContractExecutable::Wasm(BytesN::from_array(
                        &e, &hash,
                    )),
                    salt: BytesN::from_array(&e, &[7; 32]),
                })
            }
        })
    }
}

/// The invocation tree whose preorder is `contexts`: the first context with
/// the rest as its sub-invocations, in order.
fn invocation_of(w: &World, contexts: &[Context]) -> SorobanAuthorizedInvocation {
    let node = |c: &Context| -> SorobanAuthorizedInvocation {
        let function = match c {
            Context::Contract(c) => SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: c.contract.clone().into(),
                function_name: ScSymbol(
                    StringM::try_from(c.fn_name.to_string().into_bytes()).unwrap(),
                ),
                args: c
                    .args
                    .iter()
                    .map(|v| w.sc(v))
                    .collect::<std::vec::Vec<_>>()
                    .try_into()
                    .unwrap(),
            }),
            Context::CreateContractHostFn(c) => {
                SorobanAuthorizedFunction::CreateContractHostFn(CreateContractArgs {
                    contract_id_preimage: ContractIdPreimage::Address(
                        ContractIdPreimageFromAddress {
                            address: w.account.clone().into(),
                            salt: Uint256(c.salt.to_array()),
                        },
                    ),
                    executable: match &c.executable {
                        soroban_sdk::auth::ContractExecutable::Wasm(h) => {
                            ContractExecutable::Wasm(XdrHash(h.to_array()))
                        }
                        _ => unreachable!("no case makes another executable"),
                    },
                })
            }
            Context::CreateContractWithCtorHostFn(_) => unreachable!("no trace makes one"),
        };
        SorobanAuthorizedInvocation {
            function,
            sub_invocations: VecM::default(),
        }
    };
    let mut root = node(&contexts[0]);
    root.sub_invocations = contexts[1..]
        .iter()
        .map(node)
        .collect::<std::vec::Vec<_>>()
        .try_into()
        .unwrap();
    root
}

/// The account's entry for `contexts` under `payload`, with plain address
/// credentials (`try_invoke_contract_check_auth` carries no delegates).
fn entry_of(w: &World, contexts: &[Context], payload: &AuthPayload) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: w.account.clone().into(),
            nonce: 1,
            signature_expiration_ledger: u32::MAX,
            signature: w.sc(payload.clone()),
        }),
        root_invocation: invocation_of(w, contexts),
    }
}

/// The core on `contexts` and `payload` over the account's entries `before`
/// at `ledger`, with each payload signer's `verified` flag (none: assumed).
fn review_direct(
    w: &World,
    contexts: &[Context],
    payload: &AuthPayload,
    before: &[Vec<u8>],
    ledger: u32,
    verified: &[Verified],
) -> Review {
    LAST_ENTRY.with(|l| *l.borrow_mut() = None);
    let entries = before.iter().map(Vec::as_slice);
    if contexts.is_empty() {
        let account = sc_address(&w.account);
        let snapshot = Snapshot::from_ledger_entries(&account, entries).expect("a snapshot");
        let signers = payload
            .signers
            .keys()
            .iter()
            .enumerate()
            .map(|(i, s)| Claimed {
                signer: perch_rule_eval::convert::signer(&w.env, &s).unwrap(),
                verified: verified.get(i).copied().unwrap_or(Verified::Assumed),
            })
            .collect();
        return perch_review_core::review(
            &snapshot,
            &Request {
                account,
                contexts: vec![],
                rule_ids: payload.context_rule_ids.iter().collect(),
                signers,
                delegates: None,
                ledger,
            },
        )
        .expect("a review");
    }
    let xdr = entry_of(w, contexts, payload)
        .to_xdr(Limits::none())
        .unwrap();
    let review = perch_review_core::review_entry(&xdr, entries, ledger, verified)
        .expect("a review")
        .1;
    LAST_ENTRY.with(|l| *l.borrow_mut() = Some(xdr));
    review
}

thread_local! {
    /// The entry [`review_direct`] last built, for [`also`].
    static LAST_ENTRY: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// The entry [`review_direct`] built for its last call, if it built one.
fn last_entry() -> Option<Vec<u8>> {
    LAST_ENTRY.with(|l| l.borrow_mut().take())
}

/// The abstract address renamed onto the account: the one most often
/// argument 0 of a call chosen under a capped rule, so the account's own
/// calls reach the caps (a capped rule acts only on them), unless it is a
/// signer's address.
fn account_of(t: &authorize::Trace) -> Option<Vec<u8>> {
    let rules = decode_rules(&t.rules).ok()?;
    let mut count: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    for a in &t.authorizations {
        for (c, j) in a.batch.iter().zip(&a.choices) {
            let capped = rules.get(*j as usize).is_some_and(|r| r.cap.is_some());
            if let (true, Ok(rule_eval::Context::Call { args, .. })) = (capped, decode_context(c)) {
                if let Some(rule_eval::Val::Address(x)) = args.first() {
                    *count.entry(x.clone()).or_default() += 1;
                }
            }
        }
    }
    let signer_ids: Vec<Vec<u8>> = rules
        .iter()
        .flat_map(|r| r.signers.iter())
        .map(|s| match s {
            rule_eval::Signer::Delegated(a) | rule_eval::Signer::External(a, _) => a.clone(),
        })
        .collect();
    count
        .into_iter()
        .filter(|(a, _)| !signer_ids.contains(a))
        .max_by_key(|(_, n)| *n)
        .map(|(a, _)| a)
}

/// What an authorization trace's run compared with the trace's own
/// expectations (rule-eval alone, as the Lean model computes it).
#[derive(Default)]
struct ModelTally {
    agree: usize,
    /// The account refused where the model accepts, by the check the core
    /// names: Perch's checks outside rule-eval.
    refined: BTreeMap<String, usize>,
    /// Authorizations after the first difference, whose records the model
    /// computes from a charge the account never made.
    after_divergence: usize,
    /// The account accepted where the model refuses: no Perch check can.
    widened: Vec<String>,
    /// Authorizations at a ledger within the host's entry TTL of
    /// `u32::MAX`, which no world can run (`run_authorize_trace`).
    beyond_ttl: usize,
    /// Authorizations of a trace whose records do not align with its rules.
    misaligned: usize,
}

fn run_authorize_trace(
    t: &authorize::Trace,
    tally: &mut Tally,
    model: &mut ModelTally,
) -> Result<(), String> {
    let w = support::world_with(Opts {
        skip_snapshot: true,
        ..Opts::default()
    });
    let e = w.env.clone();
    e.cost_estimate().budget().reset_unlimited();
    let rules = decode_rules(&t.rules)?;
    let mut lab = Lab::new(&w, t, account_of(t));
    let mut ids = vec![];
    for (i, r) in rules.iter().enumerate() {
        let renamed = lab.rule(r);
        if non_string_set(&renamed) {
            return Err(format!(
                "{NOT_PERCH}rule {i} has a set of values that are not strings"
            ));
        }
        let mut table = SVec::new(&e);
        let stored = StoredRule::from_rule(&e, &renamed, &mut table)
            .ok_or(format!("rule {i} has no stored form"))?;
        ids.push(e.as_contract(&w.account, || {
            install_rule(&e, &format!("r{i}"), &stored, &table)
        }));
    }
    for (j, start) in t.start.iter().enumerate() {
        if rules[j].cap.is_none() || start.history.is_empty() {
            continue;
        }
        let record = perch_rule_eval::StoredRecord {
            history: SVec::from_iter(
                &e,
                start.history.iter().map(|x| perch_rule_eval::StoredEntry {
                    ledger: x.ledger,
                    amount: x.amount.parse().unwrap(),
                }),
            ),
            total: start.total.parse().unwrap(),
        };
        // No ledger holds a contract-data entry over the network's 64 KiB
        // limit: such a starting record is no state an account can be in.
        let size = w.sc(record.clone()).to_xdr(Limits::none()).unwrap().len();
        if size > 65_536 {
            return Err(format!(
                "a starting record of {size} bytes, over the 64 KiB contract-data entry limit"
            ));
        }
        e.as_contract(&w.account, || {
            e.storage()
                .persistent()
                .set(&(Symbol::new(&e, "SpendRecords"), ids[j]), &record)
        });
        let got = e.as_contract(&w.account, || spend_record(&e, ids[j]));
        assert_eq!(
            got.as_ref(),
            Some(&record),
            "the record's key is the account's"
        );
    }
    // A trace whose records do not align with its rules tests rule-eval's
    // `RecordsMismatch`, which no account state can reach: the account
    // reads one record per chosen rule. Its expectations are not the
    // account's to meet.
    let mut diverged = t.start.len() != t.rules.len();
    if diverged {
        model.misaligned += t.authorizations.len();
    }
    for (i, a) in t.authorizations.iter().enumerate() {
        let what = format!("{} authorization {i}", t.name);
        // The host extends every entry it reads to the ledger plus its TTL,
        // which must fit in a `u32`: a ledger this close to `u32::MAX` is no
        // ledger the world can run.
        if a.now > u32::MAX - 20_000_000 {
            model.beyond_ttl += 1;
            diverged = true;
            continue;
        }
        e.ledger().with_mut(|l| l.sequence_number = a.now);
        let generation: u64 = a.generation.parse().map_err(|x| format!("{x}"))?;
        e.as_contract(&w.account, || set_grant_generation(&e, generation));
        let contexts: Vec<Context> = a
            .batch
            .iter()
            .map(|c| lab.context(c))
            .collect::<Result<_, _>>()?;
        // The account is shown exactly the trace's batch, renamed.
        let want: Option<Vec<rule_eval::Context>> = a
            .batch
            .iter()
            .map(|c| lab.renamed(&decode_context(c).unwrap()))
            .collect();
        if let Some(want) = want {
            let read = perch_rule_eval::convert::calls(&e, &SVec::from_slice(&e, &contexts))
                .ok_or(format!("{what}: the account cannot read the batch"))?;
            if !rule_eval_conformance::soroban::contexts_eq(&read, &want) {
                return Err(format!(
                    "{what}: the account reads another batch than the trace's"
                ));
            }
        }
        let rule_ids: SVec<u32> = SVec::from_iter(
            &e,
            a.choices
                .iter()
                .map(|&j| ids.get(j as usize).copied().unwrap_or(u32::MAX - j)),
        );
        let payload_hash = BytesN::from_array(&e, &[i as u8 + 1; 32]);
        let digest = perch_testkit::auth_digest(&e, &w.account, &payload_hash, &rule_ids);
        let mut signers: Map<Signer, Bytes> = Map::new(&e);
        for s in &a.authenticated {
            let (signer, signature) = match s {
                JsonSigner::External { verifier, key } => {
                    let k = lab.key(&decode_hex(key)?);
                    (
                        Signer::External(
                            lab.address(&decode_hex(verifier)?),
                            Bytes::from_array(&e, &k.verifying_key().to_bytes()),
                        ),
                        Bytes::from_array(&e, &k.sign(&digest).to_bytes()),
                    )
                }
                JsonSigner::Delegated { address } => (
                    Signer::Delegated(lab.address(&decode_hex(address)?)),
                    Bytes::new(&e),
                ),
            };
            signers.set(signer, signature);
        }
        let payload = AuthPayload {
            signers,
            context_rule_ids: rule_ids,
        };
        let before = account_entries(&e, &w.account);
        let review = review_direct(&w, &contexts, &payload, &before, a.now, &[]);
        let outcome = e.try_invoke_contract_check_auth::<soroban_sdk::Error>(
            &w.account,
            &payload_hash,
            payload.clone().into_val(&e),
            &SVec::from_slice(&e, &contexts),
        );
        let host = match &outcome {
            Ok(()) => Verdict::Accepted,
            Err(Ok(err)) => host_error(err),
            Err(Err(_)) => Verdict::Refused(None),
        };
        tally.add(&what, &w, &review, &host);
        if let Some(entry) = last_entry() {
            let more = also(&what, &entry, &before, a.now, &[], &review, &host);
            tally.differences.extend(more);
        }
        // The trace's expectation is rule-eval's alone.
        let model_ok = matches!(a.expected, authorize::Outcome::Ok(_));
        if diverged {
            model.after_divergence += usize::from(t.start.len() == t.rules.len());
        } else if model_ok == (host == Verdict::Accepted) {
            model.agree += 1;
        } else if model_ok {
            *model.refined.entry(core_label(&review)).or_default() += 1;
            diverged = true;
        } else {
            model.widened.push(what.clone());
        }
    }
    Ok(())
}

/// The prefix of a skipped trace's reason when one of its rules is no rule a
/// Perch document lowers to, so no account can hold it.
const NOT_PERCH: &str = "not a Perch rule: ";

/// Whether `rule` has a set condition holding a value that is not a string:
/// rule-eval reads one, but only `string-in` lowers to a set, so an account
/// stores sets of strings alone (`StoredCond::ArgIn`).
fn non_string_set(rule: &rule_eval::Rule) -> bool {
    rule.conds.iter().any(|c| {
        matches!(c, rule_eval::Cond::ArgIn(_, vs)
            if vs.iter().any(|v| !matches!(v, rule_eval::Val::String(_))))
    })
}

#[test]
fn the_core_agrees_with_the_account_on_every_authorization_trace() {
    let traces = authorize::load_dir(&rule_core::vectors().join("authorize"))
        .unwrap_or_else(|e| panic!("{e}"));
    let mut tally = Tally::default();
    let mut model = ModelTally::default();
    let mut skipped = vec![];
    for (_, t) in &traces {
        if let Err(e) = run_authorize_trace(t, &mut tally, &mut model) {
            skipped.push(format!("{}: {e}", t.name));
        }
    }
    println!(
        "authorization traces: {} (skipped {}: {:?}); {}",
        traces.len(),
        skipped.len(),
        skipped,
        tally.summary("authorizations")
    );
    println!(
        "against the traces' rule-eval expectations: agree {}, refined by Perch's checks {:?}, \
         not compared after the first refinement {}, widened {}; of a trace whose records do \
         not align with its rules {}; not run, a ledger within the host's TTL of u32::MAX: {}",
        model.agree,
        model.refined,
        model.after_divergence,
        model.widened.len(),
        model.misaligned,
        model.beyond_ttl
    );
    // A trace whose rules no account can hold has nothing to compare; every
    // other skip counts against the budget.
    let not_perch = skipped.iter().filter(|s| s.contains(NOT_PERCH)).count();
    assert!(
        (skipped.len() - not_perch) * 10 < traces.len(),
        "too many traces skipped"
    );
    assert!(
        (traces.len() - skipped.len()) * 4 > traces.len() * 3,
        "too few traces run"
    );
    assert!(tally.accepted > 0 && tally.records > 0);
    assert!(model.widened.is_empty(), "{:?}", model.widened);
    assert!(
        tally.differences.is_empty(),
        "{}",
        tally.differences.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Perch's gate cases
// ---------------------------------------------------------------------------

/// A contract whose every entry point asks for `account`'s authorization of
/// exactly its arguments: the calls the gate cases authorize.
#[contract]
pub struct GateStandIn;

#[contractimpl]
impl GateStandIn {
    pub fn rcv_sync(_e: Env, account: Address, args: soroban_sdk::Vec<Val>) {
        account.require_auth_for_args(args);
    }
    pub fn submit_guardian(_e: Env, account: Address, args: soroban_sdk::Vec<Val>) {
        account.require_auth_for_args(args);
    }
    pub fn approve_change(_e: Env, account: Address, args: soroban_sdk::Vec<Val>) {
        account.require_auth_for_args(args);
    }
    pub fn mint(_e: Env, account: Address, args: soroban_sdk::Vec<Val>) {
        account.require_auth_for_args(args);
    }
    pub fn transfer(_e: Env, account: Address, args: soroban_sdk::Vec<Val>) {
        account.require_auth_for_args(args);
    }
    pub fn f(_e: Env, account: Address, args: soroban_sdk::Vec<Val>) {
        account.require_auth_for_args(args);
    }
}

/// One gate case's world: the account document with a recovery member, an
/// owner rule on `app`, and a capped owner rule on `token`.
struct Gate {
    w: World,
    app: Address,
    token: Address,
    key: Address,
    tally: Tally,
    nonce: i64,
}

const GRANT: u32 = 3;

impl Gate {
    fn new() -> Gate {
        let w = world_with(Opts {
            skip_snapshot: true,
            ..Opts::default()
        });
        w.env.cost_estimate().budget().reset_unlimited();
        let app = w.env.register(GateStandIn, ());
        let token = w.env.register(GateStandIn, ());
        let key = w.new_key();
        let recovery = w.recovery("loss", Mode::Guardian).json(&w);
        let doc = format!(
            r#"{{"version":1,"network":"{}","signers":[{{"id":"owner","address":"{}"}},{{"id":"device","address":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}},{{"name":"app","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}}}},{{"name":"pay","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}},"functions":["transfer"],"cap":{{"limit":"100","period-ledgers":50}}}}],"recovery":{recovery}}}"#,
            perch_testkit::FIXTURE_NETWORK,
            strkey(&w.owner),
            strkey(&w.device),
            strkey(&app),
            strkey(&token),
        );
        w.apply_bytes(&w.json(doc), 0)
            .expect("the account document");
        Gate {
            w,
            app,
            token,
            key,
            tally: Tally::default(),
            nonce: 10_000,
        }
    }

    fn id(&self, name: &str) -> u32 {
        self.w.rule_id(&self.w.account, name)
    }

    fn grant_id(&self, name: &str) -> u32 {
        let record = self.w.client().grant(&GRANT).expect("the grant");
        let name = SString::from_str(&self.w.env, name);
        record
            .rules
            .iter()
            .find(|r| r.name == name)
            .expect("the grant rule")
            .id
    }

    /// `apply_grant(GRANT)` of one rule `name` on `scope`, signed by `key`,
    /// with `extra` JSON members (functions, cap).
    fn grant(
        &self,
        name: &str,
        scope: &Address,
        key: &Address,
        extra: &str,
    ) -> Result<(), PerchAccountError> {
        let w = &self.w;
        let doc = w.json(format!(
            r#"{{"version":1,"network":"{}","signers":[{{"id":"app","address":"{}"}}],"rules":[{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["app"]}}{extra}}}]}}"#,
            perch_testkit::FIXTURE_NETWORK,
            strkey(key),
            strkey(scope),
        ));
        w.as_owner(
            &w.account,
            &w.owner,
            w.invocation(
                &w.account,
                "apply_grant",
                vec![w.sc(GRANT), w.sc(doc.clone())],
            ),
        );
        let out = w.client().try_apply_grant(&GRANT, &doc);
        w.env.set_auths(&[]);
        match out {
            Ok(_) => Ok(()),
            Err(Ok(e)) => Err(e),
            Err(Err(e)) => panic!("invoke error {e:?}"),
        }
    }

    /// Authorize `calls` (each `(contract, function, args)`, the first the
    /// invocation made, the rest its sub-invocations) through `ids`, signed
    /// by the delegated `keys`, under enforcing authorization; compare the
    /// core with the account and return the account's verdict.
    fn call(
        &mut self,
        what: &str,
        calls: &[(&Address, &str, std::vec::Vec<Val>)],
        ids: &[u32],
        keys: &[&Address],
    ) -> Verdict {
        let w = &self.w;
        let e = &w.env;
        self.nonce += 1;
        let contexts: Vec<Context> = calls
            .iter()
            .map(|(c, f, args)| {
                Context::Contract(ContractContext {
                    contract: (*c).clone(),
                    fn_name: Symbol::new(e, f),
                    args: SVec::from_slice(e, args),
                })
            })
            .collect();
        let mut signers: Map<Signer, Bytes> = Map::new(e);
        let mut delegates: std::vec::Vec<ScAddress> = vec![];
        for k in keys {
            signers.set(Signer::Delegated((*k).clone()), Bytes::new(e));
            delegates.push((*k).clone().into());
        }
        delegates.sort();
        let payload = AuthPayload {
            signers,
            context_rule_ids: SVec::from_slice(e, ids),
        };
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::AddressWithDelegates(
                SorobanAddressCredentialsWithDelegates {
                    address_credentials: SorobanAddressCredentials {
                        address: w.account.clone().into(),
                        nonce: self.nonce,
                        signature_expiration_ledger: w.ledger() + 1_000,
                        signature: w.sc(payload),
                    },
                    delegates: delegates
                        .into_iter()
                        .map(|address| SorobanDelegateSignature {
                            address,
                            signature: ScVal::Void,
                            nested_delegates: VecM::default(),
                        })
                        .collect::<std::vec::Vec<_>>()
                        .try_into()
                        .unwrap(),
                },
            ),
            root_invocation: invocation_of(w, &contexts),
        };
        let before = account_entries(e, &w.account);
        let xdr = entry.to_xdr(Limits::none()).unwrap();
        let review = perch_review_core::review_entry(
            &xdr,
            before.iter().map(Vec::as_slice),
            w.ledger(),
            &[],
        )
        .expect("a review")
        .1;
        e.set_auths(std::slice::from_ref(&entry));
        let (contract, function, args) = &calls[0];
        let outcome = e.try_invoke_contract::<(), soroban_sdk::Error>(
            contract,
            &Symbol::new(e, function),
            soroban_sdk::vec![e, w.account.to_val(), SVec::from_slice(e, args).to_val()],
        );
        e.set_auths(&[]);
        let host = match outcome {
            Ok(Ok(())) => Verdict::Accepted,
            _ => host_verdict(&Err(rule_core::account_refusal(w))),
        };
        self.tally.add(what, w, &review, &host);
        let more = also(what, &xdr, &before, w.ledger(), &[], &review, &host);
        self.tally.differences.extend(more);
        host
    }

    /// Hand `contexts` to `__check_auth` directly, through `ids`, with the
    /// payload `signers` (and their signatures) and the core's `verified`
    /// flags; compare and return the account's verdict.
    fn direct(
        &mut self,
        what: &str,
        contexts: &[Context],
        ids: &[u32],
        signers: Map<Signer, Bytes>,
        verified: &[Verified],
    ) -> Verdict {
        let w = &self.w;
        let e = &w.env;
        let payload = AuthPayload {
            signers,
            context_rule_ids: SVec::from_slice(e, ids),
        };
        let before = account_entries(e, &w.account);
        let review = review_direct(w, contexts, &payload, &before, w.ledger(), verified);
        let outcome = e.try_invoke_contract_check_auth::<soroban_sdk::Error>(
            &w.account,
            &BytesN::from_array(e, &[9; 32]),
            payload.into_val(e),
            &SVec::from_slice(e, contexts),
        );
        let host = match &outcome {
            Ok(()) => Verdict::Accepted,
            Err(Ok(err)) => host_error(err),
            Err(Err(_)) => Verdict::Refused(None),
        };
        self.tally.add(what, w, &review, &host);
        if let Some(entry) = last_entry() {
            let more = also(what, &entry, &before, w.ledger(), verified, &review, &host);
            self.tally.differences.extend(more);
        }
        host
    }

    fn val<T: IntoVal<Env, Val>>(&self, v: T) -> Val {
        v.into_val(&self.w.env)
    }

    fn ctx(&self, contract: &Address, f: &str, args: std::vec::Vec<Val>) -> Context {
        Context::Contract(ContractContext {
            contract: contract.clone(),
            fn_name: Symbol::new(&self.w.env, f),
            args: SVec::from_slice(&self.w.env, &args),
        })
    }
}

fn code(e: impl Into<soroban_sdk::Error>) -> Verdict {
    host_error(&e.into())
}

#[test]
fn the_core_agrees_with_the_account_on_perchs_gate_cases() {
    let (cases, all) = gate_cases();
    println!("gate cases: {cases:?}; {}", all.summary("authorizations"));
    assert!(all.differences.is_empty(), "{}", all.differences.join("\n"));
}

/// Perch's gate cases, each compared: the cases run and what they found.
fn gate_cases() -> (Vec<String>, Tally) {
    use perch_account::PerchAuthError as A;
    use perch_account_types::SmartAccountError as S;
    let mut all = Tally::default();
    let mut cases = vec![];
    let mut done = |g: Gate, name: &str| {
        cases.push(format!("{name}: {}", g.tally.compared));
        all.compared += g.tally.compared;
        all.accepted += g.tally.accepted;
        all.controller += g.tally.controller;
        all.budgets += g.tally.budgets;
        all.records += g.tally.records;
        for (k, v) in g.tally.refused {
            *all.refused.entry(k).or_default() += v;
        }
        for (k, v) in g.tally.controller_host {
            *all.controller_host.entry(k).or_default() += v;
        }
        all.differences.extend(g.tally.differences);
    };

    // The account's own rules authorize, as a baseline.
    let mut g = Gate::new();
    let (app, owner) = (g.app.clone(), g.w.owner.clone());
    let a = g.val(1u32);
    assert_eq!(
        g.call(
            "owner on app",
            &[(&app, "f", vec![a])],
            &[g.id("app")],
            &[&owner]
        ),
        Verdict::Accepted
    );

    // 1. Reserved functions: every invoker-only name, on any contract,
    // under any rule.
    for name in perch_recovery_interface::account::RESERVED_INVOKER_ONLY_FNS {
        let ctx = g.ctx(&app, name, vec![]);
        let v = g.direct(
            &format!("reserved {name}"),
            &[ctx],
            &[g.id("app")],
            Map::new(&g.w.env),
            &[],
        );
        assert_eq!(v, code(A::ReservedFunction));
    }
    let a = g.val(1u32);
    let v = g.call(
        "reserved rcv_sync, enforced",
        &[(&app, "rcv_sync", vec![a])],
        &[g.id("app")],
        &[&owner],
    );
    assert_eq!(v, code(A::ReservedFunction));
    done(g, "reserved functions");

    // 2. The freeze: only a completion while `ledger < until`.
    let mut g = Gate::new();
    let (app, owner) = (g.app.clone(), g.w.owner.clone());
    let until = g.w.ledger() + 20;
    let e = g.w.env.clone();
    e.as_contract(&g.w.account, || {
        e.storage().instance().set(
            &Symbol::new(&e, "Gate"),
            &FreezeGate {
                attempt_id: 1,
                until,
            },
        )
    });
    let a = g.val(1u32);
    assert_eq!(
        g.call("frozen", &[(&app, "f", vec![a])], &[g.id("app")], &[&owner]),
        code(A::AccountFrozen)
    );
    let recovery =
        g.w.client()
            .configuration()
            .recovery_rule
            .expect("a recovery rule");
    let account = g.w.account.clone();
    let doc = g.val(Bytes::new(&e));
    let completion = g.ctx(&account, "apply_doc", vec![doc]);
    let v = g.direct(
        "frozen, a completion",
        std::slice::from_ref(&completion),
        &[recovery],
        Map::new(&e),
        &[],
    );
    assert!(matches!(v, Verdict::Refused(_) | Verdict::Accepted));
    let mut one = Map::new(&e);
    one.set(Signer::Delegated(owner.clone()), Bytes::new(&e));
    assert_eq!(
        g.direct(
            "frozen, a completion naming a signer",
            std::slice::from_ref(&completion),
            &[recovery],
            one,
            &[]
        ),
        code(S::UnauthorizedSigner)
    );
    let other = g.ctx(&app, "apply_doc", vec![]);
    assert_eq!(
        g.direct(
            "a completion's context off the account",
            &[other],
            &[recovery],
            Map::new(&e),
            &[]
        ),
        code(A::AccountFrozen)
    );
    g.w.env.ledger().with_mut(|l| l.sequence_number = until - 1);
    let a = g.val(1u32);
    assert_eq!(
        g.call(
            "frozen, its last ledger",
            &[(&app, "f", vec![a])],
            &[g.id("app")],
            &[&owner]
        ),
        code(A::AccountFrozen)
    );
    g.w.env.ledger().with_mut(|l| l.sequence_number = until);
    let a = g.val(1u32);
    assert_eq!(
        g.call(
            "the freeze over",
            &[(&app, "f", vec![a])],
            &[g.id("app")],
            &[&owner]
        ),
        Verdict::Accepted
    );
    // Without the freeze: the recovery rule outside a completion, and a
    // completion with two contexts.
    let a = g.val(1u32);
    assert_eq!(
        g.direct(
            "the recovery rule chosen for a call",
            &[g.ctx(&app, "f", vec![a])],
            &[recovery],
            Map::new(&e),
            &[]
        ),
        code(A::RuleEvalRefused)
    );
    let doc = g.val(Bytes::new(&e));
    let twice = [completion.clone(), g.ctx(&account, "apply_doc", vec![doc])];
    assert_eq!(
        g.direct(
            "two apply_doc contexts on the recovery rule",
            &twice,
            &[recovery, recovery],
            Map::new(&e),
            &[]
        ),
        code(A::RuleEvalRefused)
    );
    done(g, "the freeze and completions");

    // 3. A stale grant generation, and 4. a wiped credential.
    let mut g = Gate::new();
    let (app, key) = (g.app.clone(), g.key.clone());
    g.grant("g", &app, &key, "").expect("a grant");
    let id = g.grant_id("g");
    let a = g.val(1u32);
    assert_eq!(
        g.call("a grant rule", &[(&app, "f", vec![a])], &[id], &[&key]),
        Verdict::Accepted
    );
    let e = g.w.env.clone();
    e.as_contract(&g.w.account, || set_grant_generation(&e, 1));
    let a = g.val(1u32);
    assert_eq!(
        g.call(
            "a wiped grant's rule",
            &[(&app, "f", vec![a])],
            &[id],
            &[&key]
        ),
        code(A::StaleGrant)
    );
    // The credential its grant named cannot come back under the new
    // generation: `apply_grant` refuses it, so no snapshot holds it.
    let token = g.token.clone();
    assert_eq!(
        g.grant("again", &token, &key, ""),
        Err(PerchAccountError::WipedCredential)
    );
    let a = g.val(1u32);
    assert_eq!(
        g.call(
            "the wiped credential, still",
            &[(&app, "f", vec![a])],
            &[id],
            &[&key]
        ),
        code(A::StaleGrant)
    );
    let fresh = g.w.new_key();
    g.grant("g2", &app, &fresh, "")
        .expect("a grant under the new generation");
    let id2 = g.grant_id("g2");
    let a = g.val(1u32);
    assert_eq!(
        g.call(
            "a new grant's rule",
            &[(&app, "f", vec![a])],
            &[id2],
            &[&fresh]
        ),
        Verdict::Accepted
    );
    done(g, "stale generation and wiped credential");

    // 5. Guardian approvals and token-admin functions under a grant, on a
    // grant rule that leaves its functions unrestricted.
    let mut g = Gate::new();
    let (app, key, owner) = (g.app.clone(), g.key.clone(), g.w.owner.clone());
    g.grant("g", &app, &key, "").expect("a grant");
    let id = g.grant_id("g");
    for f in perch_recovery_interface::account::GUARDIAN_APPROVAL_FNS
        .into_iter()
        .chain(["mint"])
    {
        let a = g.val(1u32);
        assert_eq!(
            g.call(
                &format!("a grant casting {f}"),
                &[(&app, f, vec![a])],
                &[id],
                &[&key]
            ),
            code(A::GrantEscalation)
        );
        let a = g.val(1u32);
        assert_eq!(
            g.call(
                &format!("the account document's rule casting {f}"),
                &[(&app, f, vec![a])],
                &[g.id("app")],
                &[&owner]
            ),
            Verdict::Accepted
        );
    }
    for f in perch_smart_account::TOKEN_ADMIN_FNS {
        let ctx = g.ctx(&app, f, vec![]);
        assert_eq!(
            g.direct(
                &format!("a grant calling {f}"),
                &[ctx],
                &[id],
                Map::new(&g.w.env),
                &[]
            ),
            code(A::GrantEscalation)
        );
    }
    // The grant's escalation is checked at its own context only.
    let a = g.val(1u32);
    let b = g.val(1u32);
    assert_eq!(
        g.call(
            "a grant rule beside an account rule's guardian approval",
            &[(&app, "f", vec![a]), (&app, "submit_guardian", vec![b])],
            &[id, g.id("app")],
            &[&key, &owner]
        ),
        Verdict::Accepted
    );
    done(g, "guardian approvals and token admin under grants");

    // 6. The excluded set, adopted after the grant: the recovery controller,
    // and the ZK factor's adapter and pool.
    for which in ["controller", "adapter", "pool"] {
        let mut g = Gate::new();
        let (app, key) = (g.app.clone(), g.key.clone());
        g.grant("g", &app, &key, "").expect("a grant");
        let id = g.grant_id("g");
        let e = g.w.env.clone();
        e.as_contract(&g.w.account, || match which {
            "controller" => e
                .storage()
                .instance()
                .set(&Symbol::new(&e, "RecoveryController"), &app),
            _ => {
                let other = g.w.adapter.clone();
                let (adapter, pool) = if which == "adapter" {
                    (app.clone(), other)
                } else {
                    (other, app.clone())
                };
                e.storage().instance().set(
                    &Symbol::new(&e, "CurrentZk"),
                    &CompiledZkFactor {
                        adapter,
                        circuit_id: BytesN::from_array(&e, &[1; 32]),
                        pool,
                        enrollment_id: BytesN::from_array(&e, &[2; 32]),
                        commitment: BytesN::from_array(&e, &[3; 32]),
                    },
                )
            }
        });
        let a = g.val(1u32);
        assert_eq!(
            g.call(
                &format!("a grant on the {which}"),
                &[(&app, "f", vec![a])],
                &[id],
                &[&key]
            ),
            code(A::GrantEscalation)
        );
        done(g, &format!("the excluded set: {which}"));
    }

    // 7. The rest of the gate: an unknown id, own funds under a cap and
    // under a grant, a creation, signatures.
    let mut g = Gate::new();
    let (app, token, key, owner) = (
        g.app.clone(),
        g.token.clone(),
        g.key.clone(),
        g.w.owner.clone(),
    );
    let account = g.w.account.clone();
    let a = g.val(1u32);
    assert_eq!(
        g.call(
            "an unknown rule id",
            &[(&app, "f", vec![a])],
            &[999],
            &[&owner]
        ),
        code(S::ContextRuleNotFound)
    );
    let pay = g.id("pay");
    let send = |g: &Gate, from: &Address, amount: i128| -> std::vec::Vec<Val> {
        vec![
            g.val(from.clone()),
            g.val(g.w.target.clone()),
            g.val(amount),
        ]
    };
    let other = g.w.new_key();
    let args = send(&g, &other, 10);
    assert_eq!(
        g.call(
            "a capped rule, another's transfer",
            &[(&token, "transfer", args)],
            &[pay],
            &[&owner]
        ),
        code(A::RuleEvalRefused)
    );
    let args = send(&g, &account, 60);
    assert_eq!(
        g.call(
            "a capped rule, 60 of 100",
            &[(&token, "transfer", args)],
            &[pay],
            &[&owner]
        ),
        Verdict::Accepted
    );
    let (x, y) = (send(&g, &account, 30), send(&g, &account, 30));
    assert_eq!(
        g.call(
            "two transfers of 30 on 40 left",
            &[(&token, "transfer", x), (&token, "transfer", y)],
            &[pay, pay],
            &[&owner]
        ),
        code(A::RuleEvalRefused)
    );
    let args = send(&g, &account, 40);
    assert_eq!(
        g.call(
            "the 40 left",
            &[(&token, "transfer", args)],
            &[pay],
            &[&owner]
        ),
        Verdict::Accepted
    );
    let ledger = g.w.ledger();
    g.w.env
        .ledger()
        .with_mut(|l| l.sequence_number = ledger + 49);
    let args = send(&g, &account, 1);
    assert_eq!(
        g.call(
            "the window's last ledger",
            &[(&token, "transfer", args)],
            &[pay],
            &[&owner]
        ),
        code(A::RuleEvalRefused)
    );
    g.w.env
        .ledger()
        .with_mut(|l| l.sequence_number = ledger + 50);
    let args = send(&g, &account, 100);
    assert_eq!(
        g.call(
            "the window over",
            &[(&token, "transfer", args)],
            &[pay],
            &[&owner]
        ),
        Verdict::Accepted
    );
    g.grant("g", &token, &key, r#","functions":["f","transfer"]"#)
        .expect("a grant");
    let id = g.grant_id("g");
    let args = send(&g, &other, 5);
    assert_eq!(
        g.call(
            "a grant, another's transfer",
            &[(&token, "transfer", args)],
            &[id],
            &[&key]
        ),
        code(A::RuleEvalRefused)
    );
    let args = send(&g, &account, 5);
    assert_eq!(
        g.call(
            "a grant, the account's transfer",
            &[(&token, "transfer", args)],
            &[id],
            &[&key]
        ),
        Verdict::Accepted
    );
    let args = send(&g, &other, 5);
    assert_eq!(
        g.call(
            "a grant, another non-owner function",
            &[(&token, "f", args)],
            &[id],
            &[&key]
        ),
        Verdict::Accepted
    );
    let e = g.w.env.clone();
    let creation = Context::CreateContractHostFn(CreateContractHostFnContext {
        executable: soroban_sdk::auth::ContractExecutable::Wasm(BytesN::from_array(&e, &[5; 32])),
        salt: BytesN::from_array(&e, &[6; 32]),
    });
    let a = g.val(1u32);
    let call = g.ctx(&app, "f", vec![a]);
    assert_eq!(
        g.direct(
            "a creation in the batch",
            &[call.clone(), creation],
            &[g.id("app"), g.id("app")],
            Map::new(&e),
            &[]
        ),
        code(A::RuleEvalRefused)
    );
    let mut one = Map::new(&e);
    one.set(Signer::Delegated(owner.clone()), Bytes::new(&e));
    assert_eq!(
        g.direct(
            "a delegated signer with no delegate",
            std::slice::from_ref(&call),
            &[g.id("app")],
            one,
            &[]
        ),
        Verdict::Refused(None)
    );
    done(g, "the rest of the gate");

    // 8. An external signer: a signature that verifies, one that does not,
    // and the core told which.
    let mut g = Gate::new();
    let app = g.app.clone();
    let e = g.w.env.clone();
    let verifier = perch_testkit::verifiers::deploy_auto(&e, PerchEd25519Verifier);
    let sk = SigningKey::from_bytes(&[42; 32]);
    let pk = Bytes::from_array(&e, &sk.verifying_key().to_bytes());
    let signer = Signer::External(verifier.clone(), pk);
    let rule = StoredRule(
        app.clone(),
        perch_rule_eval::StoredFunctions::AnyExcept(SVec::new(&e)),
        SVec::new(&e),
        SVec::from_array(&e, [0u32]),
        1,
        SVec::new(&e),
        None,
        None,
        None,
    );
    let table = SVec::from_array(&e, [signer.clone()]);
    let ext = e.as_contract(&g.w.account, || install_rule(&e, "ext", &rule, &table));
    let a = g.val(1u32);
    let call = g.ctx(&app, "f", vec![a]);
    let ids = SVec::from_array(&e, [ext]);
    let digest =
        perch_testkit::auth_digest(&e, &g.w.account, &BytesN::from_array(&e, &[9; 32]), &ids);
    let mut good = Map::new(&e);
    good.set(
        signer.clone(),
        Bytes::from_array(&e, &sk.sign(&digest).to_bytes()),
    );
    assert_eq!(
        g.direct(
            "an external signature that verifies",
            std::slice::from_ref(&call),
            &[ext],
            good,
            &[Verified::Yes]
        ),
        Verdict::Accepted
    );
    let mut bad = Map::new(&e);
    bad.set(signer.clone(), Bytes::from_array(&e, &[0; 64]));
    // The ed25519 verifier traps on a bad signature rather than returning
    // `false`, so the account fails with the verifier's error: the core
    // knows the refusal, not its code.
    assert!(matches!(
        g.direct(
            "an external signature that does not",
            std::slice::from_ref(&call),
            &[ext],
            bad.clone(),
            &[Verified::No]
        ),
        Verdict::Refused(_)
    ));
    // Told nothing, the core assumes it verifies: its verdict is the
    // account's only under that assumption, which it names.
    let before = account_entries(&e, &g.w.account);
    let payload = AuthPayload {
        signers: bad,
        context_rule_ids: ids,
    };
    let assumed = review_direct(&g.w, &[call], &payload, &before, g.w.ledger(), &[]);
    assert_eq!(core_verdict(&assumed), Verdict::Accepted);
    assert_eq!(assumed.assumed, vec![0]);
    done(g, "external signatures");

    (cases, all)
}

// ---------------------------------------------------------------------------
// The npm wrapper's fixtures
// ---------------------------------------------------------------------------

/// The committed fixtures of the npm wrapper's tests.
fn fixtures_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../perch-review-core/npm/test/fixtures.json")
}

/// Regenerate the npm wrapper's fixtures (`fixtures_path`): every gate
/// case's input with the native core's answer and the account's verdict,
/// and witness and budget inputs with the native core's answers. Run with
/// `cargo test -p perch-integration-tests --test review_core_differential
/// write_npm_fixtures -- --ignored`. `perch-review-core`'s
/// `tests/fixtures.rs` checks the committed file against the native core,
/// and the npm tests run the wasm builds on it.
#[test]
#[ignore = "regenerates committed fixtures"]
fn write_npm_fixtures() {
    FIXTURES.set(Some(vec![]));
    let (_, all) = gate_cases();
    assert!(all.differences.is_empty(), "{}", all.differences.join("\n"));
    // At most three cases of each answer: every verdict and check the gate
    // cases reach, without their repeats.
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let reviews: Vec<serde_json::Value> = FIXTURES
        .take()
        .unwrap()
        .into_iter()
        .filter(|f| {
            let o = &f["output"];
            let budgets = o["budgets"].as_array().is_some_and(|b| !b.is_empty());
            let kind = format!(
                "{} {} {} {budgets}",
                o["status"], o["refusal"]["check"], f["account"]
            );
            let n = seen.entry(kind).or_default();
            *n += 1;
            *n <= 3
        })
        .collect();
    let out = serde_json::json!({
        "about": "Generated by perch-integration-tests (review_core_differential.rs, write_npm_fixtures): each review input is a gate case the account decided, with the native core's answer and the account's verdict; checked against the native core by perch-review-core's tests/fixtures.rs.",
        "review": reviews,
        "witness": witness_fixtures(),
        "budget": budget_fixtures(),
    });
    std::fs::write(
        fixtures_path(),
        serde_json::to_string_pretty(&out).unwrap() + "\n",
    )
    .unwrap();
}

/// A host value's XDR.
fn host_xdr<T: IntoVal<Env, Val>>(e: &Env, v: T) -> Vec<u8> {
    let v: Val = v.into_val(e);
    soroban_sdk::xdr::ToXdr::to_xdr(v, e).to_alloc_vec()
}

/// A host value's XDR, read by the facade.
fn facade_of<T: IntoVal<Env, Val>>(e: &Env, v: T) -> soroban_facade::Val {
    soroban_facade::xdr::decode(&host_xdr(e, v)).unwrap()
}

/// Witness inputs from rule-core's attenuation vectors: a vector's rule
/// set as stored rules (its abstract addresses renamed onto host ones), a
/// step list, and the child the vector reaches (or the parent, where a step
/// is refused), then the same with the child's first threshold raised.
fn witness_fixtures() -> Vec<serde_json::Value> {
    use perch_rule_eval::{StoredCond, StoredRule};
    use rule_eval_conformance::{decode_step, Outcome as VOutcome, Step as VStep};
    use soroban_facade::Val as F;
    let e = Env::default();
    e.cost_estimate().budget().reset_unlimited();
    let mut names = Renamer {
        e: e.clone(),
        names: BTreeMap::new(),
    };
    // Rules as the views give them: a signer table, and the stored rules
    // naming signers by position in it.
    let stored = |rules: &[rule_eval::Rule]| -> Option<Vec<u8>> {
        let mut table = SVec::new(&e);
        let mut v: SVec<StoredRule> = SVec::new(&e);
        for r in rules {
            v.push_back(StoredRule::from_rule(&e, r, &mut table)?);
        }
        Some(host_xdr(&e, (table, v)))
    };
    let sym = |s: &str| F::Symbol(s.as_bytes().to_vec());
    let symbols = |fs: &[Vec<u8>]| F::Vec(fs.iter().map(|f| F::Symbol(f.clone())).collect());
    let mut out = vec![];
    let vectors = rule_eval_conformance::load_dir(&rule_eval_conformance::vectors_dir()).unwrap();
    for (_, v) in vectors.iter().filter(|(_, v)| !v.attenuations.is_empty()) {
        let parent: Vec<rule_eval::Rule> = decode_rules(&v.rules)
            .unwrap()
            .iter()
            .map(|r| names.rule(r))
            .collect();
        let Some(parent_xdr) = stored(&parent) else {
            continue;
        };
        for case in v.attenuations.iter().take(2) {
            let mut steps = vec![];
            let mut ok = true;
            for s in &case.steps {
                let step = match decode_step(s).unwrap() {
                    VStep::DropRule(i) => F::Vec(vec![sym("DropRule"), F::U32(i)]),
                    VStep::AddCond(i, c) => {
                        let renamed = names.rule(&rule_eval::Rule {
                            contract: vec![],
                            functions: rule_eval::Functions::Only(vec![]),
                            conds: vec![c],
                            signers: vec![],
                            threshold: 0,
                            cap: None,
                            valid_until: None,
                            generation: None,
                            auth_root: None,
                        });
                        let Some(c) = StoredCond::from_cond(&e, &renamed.conds[0]) else {
                            ok = false;
                            break;
                        };
                        F::Vec(vec![sym("AddCond"), F::U32(i), facade_of(&e, c)])
                    }
                    VStep::RemoveFunctions(i, f) => {
                        F::Vec(vec![sym("RemoveFunctions"), F::U32(i), symbols(&f)])
                    }
                    VStep::RestrictFunctions(i, f) => {
                        F::Vec(vec![sym("RestrictFunctions"), F::U32(i), symbols(&f)])
                    }
                    VStep::RemoveSigners(i, ss) => {
                        let mut list = vec![];
                        for s in ss {
                            let renamed = match s {
                                rule_eval::Signer::Delegated(a) => {
                                    rule_eval::Signer::Delegated(names.xdr(&a))
                                }
                                rule_eval::Signer::External(v, k) => {
                                    rule_eval::Signer::External(names.xdr(&v), k)
                                }
                            };
                            let host = perch_rule_eval::convert::host_signer(&e, &renamed).unwrap();
                            list.push(facade_of(&e, host));
                        }
                        F::Vec(vec![sym("RemoveSigners"), F::U32(i), F::Vec(list)])
                    }
                    VStep::RaiseThreshold(i, t) => {
                        F::Vec(vec![sym("RaiseThreshold"), F::U32(i), F::U32(t)])
                    }
                    // A `StoredCap`: the tuple of its limit, period and
                    // amount argument.
                    VStep::AddCap(i, c) => F::Vec(vec![
                        sym("AddCap"),
                        F::U32(i),
                        F::Vec(vec![
                            F::I128(c.limit),
                            F::U32(c.period),
                            F::U32(c.amount_arg),
                        ]),
                    ]),
                    VStep::LowerCapLimit(i, l) => {
                        F::Vec(vec![sym("LowerCapLimit"), F::U32(i), F::I128(l)])
                    }
                    VStep::LengthenCapPeriod(i, p) => {
                        F::Vec(vec![sym("LengthenCapPeriod"), F::U32(i), F::U32(p)])
                    }
                    VStep::LowerValidUntil(i, u) => {
                        F::Vec(vec![sym("LowerValidUntil"), F::U32(i), F::U32(u)])
                    }
                };
                steps.push(step);
            }
            if !ok {
                continue;
            }
            let child: Vec<rule_eval::Rule> = match &case.expected {
                VOutcome::Ok { rules, .. } => decode_rules(rules)
                    .unwrap()
                    .iter()
                    .map(|r| names.rule(r))
                    .collect(),
                VOutcome::Error(_) => parent.iter().map(rename_identity).collect(),
            };
            let Some(child_xdr) = stored(&child) else {
                continue;
            };
            let steps_xdr = soroban_facade::xdr::encode(&F::Vec(steps));
            let mut tampered = child;
            if let Some(first) = tampered.first_mut() {
                first.threshold = first.threshold.wrapping_add(1);
            }
            let tampered_xdr = stored(&tampered);
            for (label, child_xdr) in [("", Some(child_xdr)), (", the child changed", tampered_xdr)]
            {
                let Some(child_xdr) = child_xdr else { continue };
                let mut input = vec![];
                input.extend(1u32.to_be_bytes());
                for b in [&parent_xdr, &steps_xdr, &child_xdr] {
                    input.extend((b.len() as u32).to_be_bytes());
                    input.extend(b);
                }
                let output = perch_review_core::envelope::witness(&input);
                out.push(serde_json::json!({
                    "name": format!("{}{label}", v.name),
                    "input": b64(&input),
                    "output": serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
                }));
            }
        }
        if out.len() >= 16 {
            break;
        }
    }
    out
}

/// Abstract addresses renamed onto host ones, injectively.
struct Renamer {
    e: Env,
    names: BTreeMap<Vec<u8>, Address>,
}

impl Renamer {
    fn xdr(&mut self, a: &[u8]) -> Vec<u8> {
        let e = self.e.clone();
        let host = self
            .names
            .entry(a.to_vec())
            .or_insert_with(|| <Address as soroban_sdk::testutils::Address>::generate(&e))
            .clone();
        sc_address(&host)
    }

    fn val(&mut self, v: &rule_eval::Val) -> rule_eval::Val {
        match v {
            rule_eval::Val::Address(a) => rule_eval::Val::Address(self.xdr(a)),
            rule_eval::Val::I128(n) => rule_eval::Val::I128(*n),
            rule_eval::Val::U64(n) => rule_eval::Val::U64(*n),
            rule_eval::Val::Bool(b) => rule_eval::Val::Bool(*b),
            rule_eval::Val::Bytes(b) => rule_eval::Val::Bytes(b.clone()),
            rule_eval::Val::Symbol(b) => rule_eval::Val::Symbol(b.clone()),
            rule_eval::Val::String(b) => rule_eval::Val::String(b.clone()),
            rule_eval::Val::Other(b) => rule_eval::Val::Other(b.clone()),
        }
    }

    fn rule(&mut self, r: &rule_eval::Rule) -> rule_eval::Rule {
        rule_eval::Rule {
            contract: self.xdr(&r.contract),
            functions: match &r.functions {
                rule_eval::Functions::Only(f) => rule_eval::Functions::Only(f.clone()),
                rule_eval::Functions::AnyExcept(f) => rule_eval::Functions::AnyExcept(f.clone()),
            },
            conds: r
                .conds
                .iter()
                .map(|c| match c {
                    rule_eval::Cond::ArgEq(i, v) => rule_eval::Cond::ArgEq(*i, self.val(v)),
                    rule_eval::Cond::ArgI128AtMost(i, n) => rule_eval::Cond::ArgI128AtMost(*i, *n),
                    rule_eval::Cond::ArgIn(i, vs) => {
                        rule_eval::Cond::ArgIn(*i, vs.iter().map(|v| self.val(v)).collect())
                    }
                    rule_eval::Cond::ArgStrPrefix(i, p) => {
                        rule_eval::Cond::ArgStrPrefix(*i, p.clone())
                    }
                })
                .collect(),
            signers: r
                .signers
                .iter()
                .map(|s| match s {
                    rule_eval::Signer::Delegated(a) => rule_eval::Signer::Delegated(self.xdr(a)),
                    rule_eval::Signer::External(v, k) => {
                        rule_eval::Signer::External(self.xdr(v), k.clone())
                    }
                })
                .collect(),
            threshold: r.threshold,
            cap: r.cap.as_ref().map(|c| rule_eval::Cap {
                limit: c.limit,
                period: c.period,
                amount_arg: c.amount_arg,
            }),
            valid_until: r.valid_until,
            generation: r.generation,
            auth_root: r.auth_root.as_ref().map(|root| rule_eval::AuthRoot {
                contract: self.xdr(&root.contract),
                function: root.function.clone(),
            }),
        }
    }
}

/// A copy of a rule already renamed.
fn rename_identity(r: &rule_eval::Rule) -> rule_eval::Rule {
    let e = Env::default();
    let mut table = SVec::new(&e);
    let v: Val = StoredRule::from_rule(&e, r, &mut table)
        .unwrap()
        .into_val(&e);
    let table = perch_rule_eval::convert::signers(&e, &table).unwrap();
    perch_rule_eval::mirror::rule(&e, v, &table).unwrap()
}

/// Budget inputs: records and caps around the window's edges, with the
/// native core's answers.
fn budget_fixtures() -> Vec<serde_json::Value> {
    use perch_rule_eval::{StoredCap, StoredEntry, StoredRecord};
    let e = Env::default();
    let record = |spends: &[(u32, i128)]| StoredRecord {
        history: SVec::from_iter(
            &e,
            spends
                .iter()
                .map(|&(ledger, amount)| StoredEntry { ledger, amount }),
        ),
        total: spends.iter().map(|s| s.1).sum(),
    };
    let cap = |limit: i128, period: u32| StoredCap(limit, period, 2);
    let cases = [
        ("an empty record", record(&[]), cap(100, 50), 1000),
        (
            "a spend in its window",
            record(&[(1000, 40)]),
            cap(100, 100),
            1099,
        ),
        (
            "a spend leaving its window",
            record(&[(1000, 40)]),
            cap(100, 100),
            1100,
        ),
        (
            "spends leaving one at a time",
            record(&[(10, 5), (20, 7), (30, 11)]),
            cap(30, 15),
            35,
        ),
        (
            "the record ahead of the ledger",
            record(&[(500, 1)]),
            cap(100, 10),
            499,
        ),
        ("over the limit", record(&[(10, 150)]), cap(100, 50), 20),
        ("a huge limit", record(&[(10, 1)]), cap(i128::MAX, 50), 20),
    ];
    cases
        .into_iter()
        .map(|(name, rec, cap, now)| {
            let mut input = vec![];
            input.extend(1u32.to_be_bytes());
            for b in [host_xdr(&e, rec), host_xdr(&e, cap)] {
                input.extend((b.len() as u32).to_be_bytes());
                input.extend(b);
            }
            input.extend((now as u32).to_be_bytes());
            let output = perch_review_core::envelope::budget(&input);
            serde_json::json!({
                "name": name,
                "input": b64(&input),
                "output": serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The core's copies of the account's constants
// ---------------------------------------------------------------------------

#[test]
fn the_core_names_the_accounts_functions_and_errors() {
    use perch_account::PerchAuthError as A;
    use perch_account_types::SmartAccountError as S;
    use perch_review_core::gate;
    use perch_review_core::{Check, Error};
    assert_eq!(
        gate::RESERVED_INVOKER_ONLY_FNS,
        perch_recovery_interface::account::RESERVED_INVOKER_ONLY_FNS
    );
    assert_eq!(
        gate::GUARDIAN_APPROVAL_FNS,
        perch_recovery_interface::account::GUARDIAN_APPROVAL_FNS
    );
    assert_eq!(gate::TOKEN_ADMIN_FNS, perch_smart_account::TOKEN_ADMIN_FNS);
    assert_eq!(gate::OWNER_FNS, perch_smart_account::OWNER_FNS);
    let contract = |e: soroban_sdk::Error| match ScError::try_from(e) {
        Ok(ScError::Contract(c)) => Error::Contract(c),
        other => panic!("not a contract error: {other:?}"),
    };
    let cases: [(Check, soroban_sdk::Error); 10] = [
        (Check::ReservedFunction, A::ReservedFunction.into()),
        (Check::Frozen, A::AccountFrozen.into()),
        (Check::StaleGrant, A::StaleGrant.into()),
        (Check::GrantEscalation, A::GrantEscalation.into()),
        (Check::NotOwnFunds, A::RuleEvalRefused.into()),
        (Check::RuleNotFound, S::ContextRuleNotFound.into()),
        (Check::CompletionUnvalidated, S::UnvalidatedContext.into()),
        (Check::Signature, S::ExternalVerificationFailed.into()),
        (
            Check::CompletionLength,
            S::ContextRuleIdsLengthMismatch.into(),
        ),
        (Check::CompletionSigner, S::UnauthorizedSigner.into()),
    ];
    for (check, err) in cases {
        assert_eq!(check.error(), contract(err), "{check:?}");
    }
    // Every name the core gives a code is the account's error's name.
    for (check, err) in cases {
        let name = format!("{:?}", ScError::try_from(err).unwrap());
        assert!(name.contains("Contract"), "{name}");
        assert!(!check.error_name().is_empty());
    }
}

// ---------------------------------------------------------------------------
// The comparison is not vacuous
// ---------------------------------------------------------------------------

/// The core's verdict holds for the snapshot and ledger it is given: given
/// a snapshot missing an entry the account reads, or another ledger, it
/// answers for that state, and the comparison reports the difference.
#[test]
fn a_wrong_snapshot_or_ledger_is_reported() {
    let g = Gate::new();
    let w = &g.w;
    let e = &w.env;
    let until = w.ledger() + 20;
    e.as_contract(&w.account, || {
        e.storage().instance().set(
            &Symbol::new(e, "Gate"),
            &FreezeGate {
                attempt_id: 1,
                until,
            },
        )
    });
    let context = g.ctx(&g.app, "f", vec![g.val(1u32)]);
    let mut signers = Map::new(e);
    signers.set(Signer::Delegated(w.owner.clone()), Bytes::new(e));
    let payload = AuthPayload {
        signers,
        context_rule_ids: SVec::from_array(e, [g.id("app")]),
    };
    let before = account_entries(e, &w.account);
    let host = match e.try_invoke_contract_check_auth::<soroban_sdk::Error>(
        &w.account,
        &BytesN::from_array(e, &[9; 32]),
        payload.clone().into_val(e),
        &SVec::from_array(e, [context.clone()]),
    ) {
        Ok(()) => Verdict::Accepted,
        Err(Ok(err)) => host_error(&err),
        Err(Err(_)) => Verdict::Refused(None),
    };
    assert_eq!(host, code(perch_account::PerchAuthError::AccountFrozen));
    let right = review_direct(
        w,
        std::slice::from_ref(&context),
        &payload,
        &before,
        w.ledger(),
        &[],
    );
    assert!(compare(w, &right, &host).is_empty());
    // At the freeze's end the core answers for that ledger: the frozen
    // account's verdict is not its.
    let later = review_direct(
        w,
        std::slice::from_ref(&context),
        &payload,
        &before,
        until,
        &[],
    );
    assert!(
        !compare(w, &later, &host).is_empty(),
        "another ledger passed"
    );
    // Without the instance entry's freeze the core does not see it.
    let without: Vec<Vec<u8>> = before
        .iter()
        .map(|b| {
            let mut d = <soroban_sdk::xdr::LedgerEntryData as ReadXdr>::from_xdr(b, Limits::none())
                .unwrap();
            if let soroban_sdk::xdr::LedgerEntryData::ContractData(c) = &mut d {
                if let ScVal::ContractInstance(i) = &mut c.val {
                    if let Some(storage) = &mut i.storage {
                        let kept: std::vec::Vec<_> = storage
                            .iter()
                            .filter(|m| m.key != ScVal::Symbol("Gate".try_into().unwrap()))
                            .cloned()
                            .collect();
                        *storage = soroban_sdk::xdr::ScMap(kept.try_into().unwrap());
                    }
                }
            }
            d.to_xdr(Limits::none()).unwrap()
        })
        .collect();
    assert_ne!(without, before);
    let missing = review_direct(
        w,
        std::slice::from_ref(&context),
        &payload,
        &without,
        w.ledger(),
        &[],
    );
    assert!(
        !compare(w, &missing, &host).is_empty(),
        "a missing entry passed"
    );
}
