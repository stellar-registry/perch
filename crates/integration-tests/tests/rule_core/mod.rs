//! Document traces in rule-core's format (`conformance/vectors/documents`)
//! run through Perch's real pipeline.
//!
//! A trace names its signers, verifiers, keys and contracts by abstract
//! identifiers. [`run`] renames them injectively onto real addresses and
//! ed25519 keys in a [`support::world`](crate::support), writes the trace's
//! document as a Perch document, applies it with the account's real
//! `apply_doc` (the doc compiler at its pinned address, the delta
//! reconcile, the interpreter and spending-limit policies, and, for a
//! document with recovery, the support module's real controller and pool),
//! and then drives every authorization through the account's real
//! `__check_auth` under enforcing authorization:
//!
//! - an `External` signer signs OZ's digest with its ed25519 key, checked by
//!   the real `PerchEd25519Verifier`;
//! - a `Delegated` signer is a [`support::Key`](crate::support::Key)
//!   stand-in authenticated by CAP-0071 `delegate_account_auth`, so it rides
//!   in the account's own auth entry, delegates sorted by address as the host
//!   requires;
//! - the batch's first context is the invocation actually made, and the rest
//!   ride as its sub-invocations, so the host hands `__check_auth` the whole
//!   batch in order. A context on another contract is made by a [`StandIn`]
//!   there; a context on the account itself is made by the account, whose
//!   code is swapped after `apply_doc` (as an upgrade swaps it, storage kept)
//!   for [`TraceAccount`]: Perch's `check_auth` as `__check_auth`, exactly as
//!   `impl_perch_smart_account!` expands it, and one entry point per trace
//!   function name.
//!
//! Before each authorization, `soroban-facade` reads the contexts the
//! harness built and they must equal the trace's batch under the renaming,
//! so the account is shown exactly the trace's authorization.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use ed25519_dalek::{Signer as _, SigningKey};
use perch_compile::{compile, CompileConfig, LoweredRule, ScopeSpec, SignerSpec};
use perch_ed25519_verifier::PerchEd25519Verifier;
use perch_ir::{
    AddressEqPred, AllPrincipals, ArgConstraint, ArgPred, CapConstraint, GuardianSet, IsSelfPred,
    PolicyDoc, Principals, RecoveryConfig, RecoveryMode, RecoveryProfile, Rule, Scope, SignerDecl,
    SignerMethod, StringInPred, StringPrefixPred, ThresholdPrincipals, U32EqPred, ZkFactor,
};
use perch_program::Op;
use perch_smart_account::infra;
use perch_testkit::{auth_digest, FIXTURE_NETWORK};
use rule_eval::{Cap, Cond, Functions, Rule as ERule, Signer as ESigner, Val as EVal};
use rule_eval_conformance::documents::{
    JsonDoc, JsonPred, JsonPrincipals, JsonScope, Lowered, Trace, Verdict,
};
use rule_eval_conformance::{
    decode_context, decode_hex, decode_rules, rules_eq, soroban, JsonContext, JsonSigner, JsonVal,
};
use sha2::{Digest as _, Sha256};
use soroban_facade::SdkHost;
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::xdr::{
    ContractEventBody, FromXdr, Hash as XdrHash, HashIdPreimage,
    HashIdPreimageSorobanAuthorizationWithAddress, Limits, ScAddress, ScVal,
    SorobanAddressCredentials, SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanDelegateSignature, VecM, WriteXdr as _,
};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, BytesN, Env, IntoVal, Map, String as SString, Symbol,
    Val, Vec as SVec,
};
use stellar_accounts::policies::spending_limit::get_spending_limit_data;
use stellar_accounts::smart_account::{AuthPayload, Signer};

use crate::support::{self, Key, Opts, World};

// ---------------------------------------------------------------------------
// Where the vectors are
// ---------------------------------------------------------------------------

/// The conformance vectors at the rev the workspace pins
/// (`rule_eval_conformance::vectors_dir()`, which `CONFORMANCE_VECTORS`
/// overrides).
pub fn vectors() -> PathBuf {
    rule_eval_conformance::vectors_dir()
}

// ---------------------------------------------------------------------------
// Stand-in contracts
// ---------------------------------------------------------------------------

macro_rules! stand_ins {
    ($($f:ident),* $(,)?) => {
        /// Every function name a trace context may name.
        pub const FUNCTIONS: &[&str] = &[$(stringify!($f)),*];

        /// The account's code while authorizations run: Perch's `check_auth`
        /// and one entry point per trace function name, each asking for the
        /// account's authorization of exactly its arguments.
        #[contract]
        pub struct TraceAccount;

        #[contractimpl]
        impl TraceAccount {
            $(pub fn $f(e: Env, args: soroban_sdk::Vec<Val>) {
                e.current_contract_address().require_auth_for_args(args);
            })*
        }

        /// Any other contract a trace calls: each entry point asks for
        /// `account`'s authorization of exactly its arguments.
        #[contract]
        pub struct StandIn;

        #[contractimpl]
        impl StandIn {
            $(pub fn $f(_e: Env, account: Address, args: soroban_sdk::Vec<Val>) {
                account.require_auth_for_args(args);
            })*
        }
    };
}

stand_ins!(
    approve,
    anything_at_all,
    apply_doc,
    burn,
    execute,
    f,
    g,
    publish,
    send,
    transfer
);

#[contractimpl]
impl CustomAccountInterface for TraceAccount {
    type Error = soroban_sdk::Error;
    type Signature = AuthPayload;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: soroban_sdk::Vec<Context>,
    ) -> Result<(), soroban_sdk::Error> {
        perch_smart_account::check_auth(&e, &signature_payload, &signatures, &auth_contexts)
    }
}

// ---------------------------------------------------------------------------
// What a run produced
// ---------------------------------------------------------------------------

/// Which account a trace's document is applied to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    /// The constructor's account, holding only its admin rule.
    Fresh,
    /// An account whose applied document has other rule names, a capped rule
    /// and a constrained one, so applying the trace's document adds every
    /// rule and removes every earlier one.
    AfterPredecessor,
}

/// A spending record: `(ledger, amount)` history and the total.
pub type Record = (Vec<(u32, i128)>, i128);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Got {
    Refused,
    /// The records after the authorization, one per rule the trace lowers to.
    Accepted(Vec<Record>),
}

/// What Perch did with one trace.
pub struct Run {
    /// Perch's lowering of the document's rules, as rule-eval rules over the
    /// trace's abstract identifiers.
    pub lowered: Vec<ERule>,
    /// Whether the account installed a recovery rule.
    pub recovery_rule: bool,
    pub verdicts: Vec<Got>,
    /// Authorizations with a `Delegated` / an `External` authenticated signer.
    pub delegated: usize,
    pub external: usize,
}

// ---------------------------------------------------------------------------
// Renaming
// ---------------------------------------------------------------------------

fn utf8(hex: &str) -> Result<String, String> {
    String::from_utf8(decode_hex(hex)?).map_err(|e| format!("not utf-8: {e}"))
}

fn unhex(hex: &str) -> Vec<u8> {
    decode_hex(hex).expect("trace hex")
}

/// One trace's renaming: every abstract identifier onto a real address or
/// key, injectively.
struct Lab<'w> {
    w: &'w World,
    account_abs: Vec<u8>,
    addr: BTreeMap<Vec<u8>, Address>,
    keys: BTreeMap<Vec<u8>, SigningKey>,
}

impl<'w> Lab<'w> {
    fn new(w: &'w World, t: &Trace) -> Result<Lab<'w>, String> {
        let e = &w.env;
        let account_abs = unhex(&t.account);
        let mut lab = Lab {
            w,
            account_abs: account_abs.clone(),
            addr: BTreeMap::new(),
            keys: BTreeMap::new(),
        };
        lab.addr.insert(account_abs.clone(), w.account.clone());
        let mut roles: BTreeMap<Vec<u8>, &'static str> = BTreeMap::new();
        let mut note = |id: Vec<u8>, role: &'static str| -> Result<(), String> {
            if id == account_abs {
                return Err(format!("{} is the account and a {role}", hex::encode(&id)));
            }
            match roles.insert(id.clone(), role) {
                Some(prev) if prev != role => Err(format!(
                    "{} is both a {prev} and a {role}",
                    hex::encode(&id)
                )),
                _ => Ok(()),
            }
        };
        if let Some(r) = &t.document.recovery {
            note(unhex(&r.controller), "controller")?;
            if let Some(z) = &r.zk {
                note(unhex(&z.adapter), "adapter")?;
                note(unhex(&z.pool), "pool")?;
            }
        }
        let signers = t
            .document
            .signers
            .iter()
            .map(|d| &d.signer)
            .chain(t.authorizations.iter().flat_map(|a| a.authenticated.iter()));
        for s in signers {
            match s {
                JsonSigner::External { verifier, .. } => note(unhex(verifier), "verifier")?,
                JsonSigner::Delegated { address } => note(unhex(address), "delegate")?,
            }
        }
        for a in &t.authorizations {
            for c in &a.batch {
                match c {
                    JsonContext::Call { contract, .. } => {
                        let id = unhex(contract);
                        if id != lab.account_abs {
                            note(id, "called contract")?;
                        }
                    }
                    JsonContext::Create { .. } => {
                        return Err(
                            "a creation context (Perch documents have no creation rule)".into()
                        )
                    }
                }
            }
        }
        for (id, role) in roles {
            let a = match role {
                "controller" => w.controller.clone(),
                "adapter" => w.adapter.clone(),
                "pool" => w.pool.clone(),
                "verifier" => e.register(PerchEd25519Verifier, ()),
                "delegate" => e.register(Key, ()),
                _ => e.register(StandIn, ()),
            };
            lab.addr.insert(id, a);
        }
        Ok(lab)
    }

    fn address(&mut self, abs: &[u8]) -> Address {
        if let Some(a) = self.addr.get(abs) {
            return a.clone();
        }
        let a = <Address as soroban_sdk::testutils::Address>::generate(&self.w.env);
        self.addr.insert(abs.to_vec(), a.clone());
        a
    }

    fn abs_of(&self, a: &Address) -> Vec<u8> {
        self.addr
            .iter()
            .find(|(_, v)| *v == a)
            .map(|(k, _)| k.clone())
            .expect("a renamed address")
    }

    /// The abstract key's ed25519 key: a function of its identifier alone.
    fn key(&mut self, abs: &[u8]) -> SigningKey {
        self.keys
            .entry(abs.to_vec())
            .or_insert_with(|| {
                let mut h = Sha256::new();
                h.update(b"perch rule-core trace key\0");
                h.update(abs);
                SigningKey::from_bytes(&h.finalize().into())
            })
            .clone()
    }

    fn key_abs(&self, pubhex: &str) -> Vec<u8> {
        self.keys
            .iter()
            .find(|(_, k)| hex::encode(k.verifying_key().to_bytes()) == pubhex)
            .map(|(a, _)| a.clone())
            .expect("a renamed key")
    }

    fn strkey(&mut self, abs: &[u8]) -> String {
        support::strkey(&self.address(abs))
    }

    fn signer(&mut self, s: &JsonSigner) -> Signer {
        let e = self.w.env.clone();
        match s {
            JsonSigner::Delegated { address } => Signer::Delegated(self.address(&unhex(address))),
            JsonSigner::External { verifier, key } => {
                let v = self.address(&unhex(verifier));
                let k = self.key(&unhex(key));
                Signer::External(v, Bytes::from_array(&e, &k.verifying_key().to_bytes()))
            }
        }
    }

    fn val(&mut self, v: &JsonVal) -> Result<Val, String> {
        let e = self.w.env.clone();
        Ok(match v {
            JsonVal::I128(s) => s.parse::<i128>().map_err(|x| x.to_string())?.into_val(&e),
            JsonVal::U64(s) => s.parse::<u64>().map_err(|x| x.to_string())?.into_val(&e),
            JsonVal::Bool(b) => (*b).into_val(&e),
            JsonVal::Bytes(h) => Bytes::from_slice(&e, &decode_hex(h)?).into_val(&e),
            JsonVal::Address(h) => self.address(&decode_hex(h)?).into_val(&e),
            JsonVal::Symbol(h) => Symbol::new(&e, &utf8(h)?).into_val(&e),
            JsonVal::String(h) => SString::from_bytes(&e, &decode_hex(h)?).into_val(&e),
            JsonVal::Other(h) => Val::from_xdr(&e, &Bytes::from_slice(&e, &decode_hex(h)?))
                .map_err(|_| format!("not an ScVal: {h}"))?,
        })
    }

    fn context(&mut self, c: &JsonContext) -> Result<ContractContext, String> {
        let JsonContext::Call {
            contract,
            function,
            args,
        } = c
        else {
            return Err("a creation context".into());
        };
        let function = utf8(function)?;
        if !FUNCTIONS.contains(&function.as_str()) {
            return Err(format!("no stand-in entry point named {function:?}"));
        }
        let mut a: SVec<Val> = SVec::new(&self.w.env);
        for v in args {
            let v = self.val(v)?;
            a.push_back(v);
        }
        Ok(ContractContext {
            contract: self.address(&decode_hex(contract)?),
            fn_name: Symbol::new(&self.w.env, &function),
            args: a,
        })
    }

    /// The trace's document as a Perch document: signer ids `s<i>`, rule
    /// names `r<i>`. Its recovery member, if any, names the world's real
    /// controller (and, for ZK, its adapter and pool); its other fields,
    /// which the trace does not carry, are the support module's defaults.
    fn doc(&mut self, d: &JsonDoc) -> Result<PolicyDoc, String> {
        let mut ids: BTreeMap<String, String> = BTreeMap::new();
        let mut signers = vec![];
        for (i, s) in d.signers.iter().enumerate() {
            let name = format!("s{i}");
            ids.insert(s.id.clone(), name.clone());
            let method = match &s.signer {
                JsonSigner::Delegated { address } => SignerMethod::Delegated {
                    address: self.strkey(&decode_hex(address)?),
                },
                JsonSigner::External { verifier, key } => {
                    let v = self.strkey(&decode_hex(verifier)?);
                    let k = self.key(&decode_hex(key)?);
                    SignerMethod::External {
                        verifier: v,
                        key: hex::encode(k.verifying_key().to_bytes()),
                    }
                }
            };
            signers.push(SignerDecl { id: name, method });
        }
        let name_of = |id: &String| {
            ids.get(id)
                .cloned()
                .unwrap_or_else(|| format!("undeclared-{id}"))
        };
        let mut rules = vec![];
        for (i, r) in d.rules.iter().enumerate() {
            let scope = match &r.scope {
                JsonScope::SelfAdmin => Scope::self_admin(),
                JsonScope::Contract(h) => Scope::contract(self.strkey(&decode_hex(h)?)),
            };
            let principals = match &r.principals {
                JsonPrincipals::All(xs) => Principals::All(AllPrincipals {
                    signers: xs.iter().map(name_of).collect(),
                }),
                JsonPrincipals::Threshold { ids: xs, m } => {
                    Principals::Threshold(ThresholdPrincipals {
                        signers: xs.iter().map(name_of).collect(),
                        m: *m,
                    })
                }
            };
            let args = match &r.args {
                None => None,
                Some(args) => {
                    let mut out = vec![];
                    for a in args {
                        let pred = match &a.pred {
                            JsonPred::IsSelf => ArgPred::IsSelf(IsSelfPred {}),
                            JsonPred::AddressEq(h) => ArgPred::AddressEq(AddressEqPred {
                                address: self.strkey(&decode_hex(h)?),
                            }),
                            JsonPred::StringIn(vs) => ArgPred::StringIn(StringInPred {
                                values: vs.iter().map(|v| utf8(v)).collect::<Result<_, _>>()?,
                            }),
                            JsonPred::StringPrefix(p) => {
                                ArgPred::StringPrefix(StringPrefixPred { prefix: utf8(p)? })
                            }
                            JsonPred::U32Eq(v) => ArgPred::U32Eq(U32EqPred { value: *v }),
                        };
                        out.push(ArgConstraint {
                            index: a.index,
                            pred,
                        });
                    }
                    Some(out)
                }
            };
            let functions = match &r.functions {
                None => None,
                Some(fs) => Some(fs.iter().map(|f| utf8(f)).collect::<Result<_, _>>()?),
            };
            rules.push(Rule {
                name: format!("r{i}"),
                scope,
                principals,
                functions,
                args,
                not_after_ledger: r.not_after_ledger,
                cap: r.cap.as_ref().map(|c| CapConstraint {
                    token: None,
                    limit: c.limit.clone(),
                    period_ledgers: c.period_ledgers,
                }),
            });
        }
        let recovery = match &d.recovery {
            None => None,
            Some(r) => {
                let w = self.w;
                let mode = match &r.zk {
                    None => RecoveryMode::GuardianOnly(GuardianSet {
                        guardians: w.guardians.iter().map(support::strkey).collect(),
                        quorum: 2,
                    }),
                    Some(_) => {
                        let z = support::enrollment(&w.env, 1);
                        RecoveryMode::ZkOnly(ZkFactor {
                            adapter: support::strkey(&w.adapter),
                            circuit_id: hex::encode(support::CIRCUIT),
                            pool: support::strkey(&w.pool),
                            enrollment_id: support::hex32(&z.id),
                            commitment: support::hex32(&z.commitment),
                        })
                    }
                };
                Some(RecoveryConfig {
                    profile: RecoveryProfile::Loss,
                    mode,
                    controller: self.strkey(&decode_hex(&r.controller)?),
                    baseline: None,
                    replaceable: vec!["s0".into()],
                    delay_ledgers: support::DELAY,
                    expiry_ledgers: support::EXPIRY,
                    max_cancels: 3,
                })
            }
        };
        Ok(PolicyDoc {
            version: 1,
            network: Some(FIXTURE_NETWORK.into()),
            signers,
            rules,
            recovery,
        })
    }

    /// The document applied before the trace's under [`Start::AfterPredecessor`]:
    /// the world's owner as admin, and a capped rule and a constrained rule
    /// on a contract the trace calls, none named like a trace rule.
    fn predecessor(&mut self, t: &Trace) -> PolicyDoc {
        let contract = t
            .authorizations
            .iter()
            .flat_map(|a| a.batch.iter())
            .find_map(|c| match c {
                JsonContext::Call { contract, .. } if unhex(contract) != self.account_abs => {
                    Some(unhex(contract))
                }
                _ => None,
            });
        let contract = match contract {
            Some(abs) => self.strkey(&abs),
            None => support::strkey(&self.w.target),
        };
        let owner = || Principals::all(["owner"]);
        PolicyDoc {
            version: 1,
            network: Some(FIXTURE_NETWORK.into()),
            signers: vec![SignerDecl {
                id: "owner".into(),
                method: SignerMethod::Delegated {
                    address: support::strkey(&self.w.owner),
                },
            }],
            rules: vec![
                Rule {
                    name: "admin".into(),
                    scope: Scope::self_admin(),
                    principals: owner(),
                    functions: None,
                    args: None,
                    not_after_ledger: None,
                    cap: None,
                },
                Rule {
                    name: "predecessor-cap".into(),
                    scope: Scope::contract(contract.clone()),
                    principals: Principals::threshold(["owner"], 1),
                    functions: Some(vec!["transfer".into()]),
                    args: None,
                    not_after_ledger: None,
                    cap: Some(CapConstraint {
                        token: None,
                        limit: "5".into(),
                        period_ledgers: 100,
                    }),
                },
                Rule {
                    name: "predecessor-args".into(),
                    scope: Scope::contract(contract),
                    principals: owner(),
                    functions: Some(vec!["approve".into(), "publish".into()]),
                    args: Some(vec![ArgConstraint {
                        index: 0,
                        pred: ArgPred::IsSelf(IsSelfPred {}),
                    }]),
                    not_after_ledger: Some(10_000),
                    cap: None,
                },
            ],
            recovery: None,
        }
    }

    /// The `rule_eval::Rule` a Perch lowered rule denotes once installed: OZ
    /// `CallContract` + expiry + signers, the interpreter program's leaves,
    /// and OZ's spending-limit policy (`transfer` only, the amount at
    /// argument 2).
    fn denote(&self, l: &LoweredRule) -> ERule {
        let e = &self.w.env;
        let contract = match &l.scope {
            ScopeSpec::SelfAdmin => self.account_abs.clone(),
            ScopeSpec::Contract(s) => self.abs_of(&Address::from_str(e, s)),
        };
        let signers: Vec<ESigner> = l
            .signers
            .iter()
            .map(|s| match s {
                SignerSpec::Delegated { address } => {
                    ESigner::Delegated(self.abs_of(&Address::from_str(e, address)))
                }
                SignerSpec::External { verifier, key_hex } => ESigner::External(
                    self.abs_of(&Address::from_str(e, verifier)),
                    self.key_abs(key_hex),
                ),
            })
            .collect();
        let mut functions = Functions::AnyExcept(vec![]);
        let mut conds = vec![];
        let mut threshold = signers.len() as u32;
        let mut fns: Option<Vec<Vec<u8>>> = None;
        if let Some(install) = &l.install {
            for op in install.program.ops.iter() {
                match op {
                    Op::MinSigners(n) => threshold = n,
                    Op::FnIn(fs) => {
                        let names: Vec<Vec<u8>> =
                            fs.iter().map(|f| f.to_string().into_bytes()).collect();
                        fns = Some(names.clone());
                        functions = Functions::Only(names);
                    }
                    Op::ArgAddrIsSelf(i) => {
                        conds.push(Cond::ArgEq(i, EVal::Address(self.account_abs.clone())))
                    }
                    Op::ArgAddrEq(i, a) => {
                        conds.push(Cond::ArgEq(i, EVal::Address(self.abs_of(&a))))
                    }
                    Op::ArgU32Eq(i, v) => {
                        conds.push(Cond::ArgEq(i, EVal::Other(rule_eval::u32_xdr(v))))
                    }
                    Op::ArgStrIn(i, set) => {
                        // The interpreter never matches a string over 256
                        // bytes, so such a value is no member.
                        let mut vs = vec![];
                        for s in set.iter() {
                            if s.len() <= 256 {
                                let mut b = vec![0u8; s.len() as usize];
                                s.copy_into_slice(&mut b);
                                vs.push(EVal::String(b));
                            }
                        }
                        conds.push(Cond::ArgIn(i, vs));
                    }
                    Op::ArgStrPrefix(i, p) => {
                        let mut b = vec![0u8; p.len() as usize];
                        p.copy_into_slice(&mut b);
                        conds.push(Cond::ArgStrPrefix(i, b));
                    }
                    Op::All(_) => {}
                    other => panic!("an op Perch's lowering never emits: {other:?}"),
                }
            }
        }
        let cap = l.cap.as_ref().map(|c| {
            let covers = fns
                .as_ref()
                .is_none_or(|fs| fs.iter().any(|f| f.as_slice() == b"transfer"));
            functions = Functions::Only(if covers {
                vec![b"transfer".to_vec()]
            } else {
                vec![]
            });
            conds.push(Cond::ArgI128AtMost(2, i128::MAX));
            Cap {
                limit: c.limit,
                period: c.period_ledgers,
                amount_arg: 2,
            }
        });
        ERule {
            contract,
            functions,
            conds,
            signers,
            threshold,
            cap,
            valid_until: l.valid_until,
            generation: None,
        }
    }

    /// The `ScAddress` XDR soroban-facade reads `a` as.
    fn xdr(&self, host: &SdkHost, a: &Address) -> Vec<u8> {
        match host
            .from_sdk(a.to_val())
            .map(|v| soroban_facade::val_to_rule_eval(&v))
        {
            Some(EVal::Address(x)) => x,
            _ => panic!("the facade reads an address as another value"),
        }
    }

    /// `c` with every abstract address replaced by its renamed address's XDR.
    fn renamed(&mut self, host: &SdkHost, c: rule_eval::Context) -> rule_eval::Context {
        let rule_eval::Context::Call {
            contract,
            function,
            args,
        } = c
        else {
            return c;
        };
        let contract = self.address(&contract);
        let args = args
            .into_iter()
            .map(|v| match v {
                EVal::Address(abs) => {
                    let a = self.address(&abs);
                    EVal::Address(self.xdr(host, &a))
                }
                v => v,
            })
            .collect();
        rule_eval::Context::Call {
            contract: self.xdr(host, &contract),
            function,
            args,
        }
    }
}

// ---------------------------------------------------------------------------
// Running a trace
// ---------------------------------------------------------------------------

fn invocation(w: &World, c: &ContractContext) -> SorobanAuthorizedInvocation {
    let args: std::vec::Vec<ScVal> = c.args.iter().map(|v| w.sc(v)).collect();
    w.invocation(&c.contract, &c.fn_name.to_string(), args)
}

fn spending_record(w: &World, id: u32) -> Record {
    let spending = infra::perch_spending_limit::address(&w.env);
    let d = w.env.as_contract(&spending, || {
        get_spending_limit_data(&w.env, id, &w.account)
    });
    (
        d.spending_history
            .iter()
            .map(|x| (x.ledger_sequence, x.amount))
            .collect(),
        d.cached_total_spent,
    )
}

/// The `signature_payload` the host hands the account's `__check_auth` for
/// an entry: with delegates (CAP-0071 `AddressWithDelegates`) its preimage
/// also binds the account's address.
fn signature_payload(
    w: &World,
    nonce: i64,
    expiration: u32,
    root: &SorobanAuthorizedInvocation,
    delegates: bool,
) -> [u8; 32] {
    if !delegates {
        return perch_testkit::passkey::signature_payload(&w.env, nonce, expiration, root);
    }
    let preimage = HashIdPreimage::SorobanAuthorizationWithAddress(
        HashIdPreimageSorobanAuthorizationWithAddress {
            network_id: XdrHash(w.env.ledger().network_id().to_array()),
            address: w.account.clone().into(),
            nonce,
            signature_expiration_ledger: expiration,
            invocation: root.clone(),
        },
    );
    Sha256::digest(preimage.to_xdr(Limits::none()).expect("preimage xdr")).into()
}

/// Whether the last invocation failed because the account's `__check_auth`
/// refused: the host's "failed account authentication" diagnostic names it.
fn account_refused(w: &World) -> bool {
    let account: ScAddress = w.account.clone().into();
    w.env.host().get_events().unwrap().0.iter().any(|ev| {
        let ContractEventBody::V0(body) = &ev.event.body;
        let ScVal::Vec(Some(data)) = &body.data else {
            return false;
        };
        matches!(
            data.as_slice(),
            [ScVal::String(msg), ScVal::Address(a), ScVal::Error(_)]
                if msg.to_utf8_string_lossy() == "failed account authentication with error"
                    && *a == account
        )
    })
}

/// Apply `t`'s document to an account and run every authorization through
/// it. An `Err` is a step that did not complete: the harness could not set
/// the trace up, or Perch refused the document.
pub fn run(t: &Trace, start: Start) -> Result<Run, String> {
    let w = support::world_with(Opts {
        skip_snapshot: true,
        ..Opts::default()
    });
    let e = w.env.clone();
    e.cost_estimate().budget().reset_unlimited();
    let mut lab = Lab::new(&w, t)?;
    let doc = lab.doc(&t.document)?;
    perch_ir::validate(&doc).map_err(|es| format!("perch_ir::validate refuses: {es:?}"))?;
    let plan = compile(
        &e,
        &doc,
        &CompileConfig {
            interpreter_wasm_hash: BytesN::from_array(&e, &[0; 32]),
        },
    )
    .map_err(|x| format!("perch_compile::compile refuses: {x:?}"))?;
    let lowered: Vec<ERule> = plan.rules.iter().map(|l| lab.denote(l)).collect();

    // Every rule is installed at ledger 0, before any authorization's ledger.
    e.ledger().with_mut(|l| l.sequence_number = 0);
    if start == Start::AfterPredecessor {
        let p = lab.predecessor(t);
        let bytes = Bytes::from_slice(&e, perch_ir::canonical_json(&p).as_bytes());
        w.apply_bytes(&bytes, 0)
            .map_err(|x| format!("apply_doc refuses the predecessor: {x:?}"))?;
    }
    let bytes = Bytes::from_slice(&e, perch_ir::canonical_json(&doc).as_bytes());
    w.apply_bytes(&bytes, 0)
        .map_err(|x| format!("apply_doc refuses the document: {x:?}"))?;

    // Rule index (the document's, then the recovery rule) to OZ id, while the
    // account still serves its views.
    let missing = u32::MAX;
    let mut ids: Vec<u32> = (0..doc.rules.len())
        .map(|i| w.rule_id(&w.account, &format!("r{i}")))
        .collect();
    let recovery_id = w.rule_id(&w.account, "recovery");
    let recovery_rule = recovery_id != missing;
    if t.document.recovery.is_some() {
        ids.push(recovery_id);
    }
    let capped: Vec<bool> = plan.rules.iter().map(|l| l.cap.is_some()).collect();

    let code = e.upload(TraceAccount);
    e.as_contract(&w.account, || {
        e.deployer()
            .update_current_contract(soroban_sdk::ContractExecutable::Wasm(code))
    });

    let host = SdkHost::new(&e);
    let mut run = Run {
        lowered,
        recovery_rule,
        verdicts: vec![],
        delegated: 0,
        external: 0,
    };
    for (i, a) in t.authorizations.iter().enumerate() {
        e.ledger().with_mut(|l| l.sequence_number = a.now);
        let contexts: std::vec::Vec<ContractContext> = a
            .batch
            .iter()
            .map(|c| lab.context(c))
            .collect::<Result<_, _>>()
            .map_err(|x| format!("authorization {i}: {x}"))?;
        let Some(first) = contexts.first() else {
            return Err(format!("authorization {i}: an empty batch"));
        };

        // The account is shown exactly the trace's batch.
        let sdk_contexts: SVec<Context> =
            SVec::from_iter(&e, contexts.iter().map(|c| Context::Contract(c.clone())));
        let read = host
            .auth_contexts(sdk_contexts.to_val())
            .map(|cs| soroban_facade::contexts_to_rule_eval(&cs))
            .ok_or_else(|| format!("authorization {i}: the facade refuses the batch"))?;
        let mut want = vec![];
        for c in &a.batch {
            let c = decode_context(c).map_err(|x| format!("authorization {i}: {x}"))?;
            want.push(lab.renamed(&host, c));
        }
        if !soroban::contexts_eq(&read, &want) {
            return Err(format!(
                "authorization {i}: the harness built another batch than the trace's"
            ));
        }

        let rule_ids: SVec<u32> = SVec::from_iter(
            &e,
            a.choices
                .iter()
                .map(|&j| ids.get(j as usize).copied().unwrap_or(missing)),
        );
        let mut root = invocation(&w, first);
        root.sub_invocations = contexts[1..]
            .iter()
            .map(|c| invocation(&w, c))
            .collect::<std::vec::Vec<_>>()
            .try_into()
            .unwrap();
        // Above the nonces the world's own `apply_doc` entries use.
        let nonce = 1_000_000 + i as i64;
        let expiration = a.now + 1_000;
        let delegated = a
            .authenticated
            .iter()
            .any(|s| matches!(s, JsonSigner::Delegated { .. }));
        let payload = signature_payload(&w, nonce, expiration, &root, delegated);
        let digest = auth_digest(&e, &w.account, &BytesN::from_array(&e, &payload), &rule_ids);
        let mut signatures: Map<Signer, Bytes> = Map::new(&e);
        let mut delegates: std::vec::Vec<ScAddress> = vec![];
        let mut external = false;
        for s in &a.authenticated {
            let signer = lab.signer(s);
            let signature = match s {
                JsonSigner::External { key, .. } => {
                    external = true;
                    let k = lab.key(&unhex(key));
                    Bytes::from_array(&e, &k.sign(&digest).to_bytes())
                }
                JsonSigner::Delegated { address } => {
                    let d: ScAddress = lab.address(&unhex(address)).into();
                    if !delegates.contains(&d) {
                        delegates.push(d);
                    }
                    Bytes::new(&e)
                }
            };
            signatures.set(signer, signature);
        }
        delegates.sort();
        run.delegated += usize::from(!delegates.is_empty());
        run.external += usize::from(external);
        let credentials = SorobanAddressCredentials {
            address: w.account.clone().into(),
            nonce,
            signature_expiration_ledger: expiration,
            signature: w.sc(AuthPayload {
                signers: signatures,
                context_rule_ids: rule_ids,
            }),
        };
        let credentials = if delegates.is_empty() {
            SorobanCredentials::Address(credentials)
        } else {
            SorobanCredentials::AddressWithDelegates(SorobanAddressCredentialsWithDelegates {
                address_credentials: credentials,
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
            })
        };
        e.set_auths(&[SorobanAuthorizationEntry {
            credentials,
            root_invocation: root,
        }]);
        let mut call_args: SVec<Val> = SVec::new(&e);
        if first.contract != w.account {
            call_args.push_back(w.account.to_val());
        }
        call_args.push_back(first.args.to_val());
        let outcome = e.try_invoke_contract::<(), soroban_sdk::Error>(
            &first.contract,
            &first.fn_name,
            call_args,
        );
        e.set_auths(&[]);
        let got = match outcome {
            Ok(Ok(())) => {
                let records = (0..ids.len())
                    .map(|j| match (capped.get(j), ids[j]) {
                        (Some(true), id) if id != missing => spending_record(&w, id),
                        _ => (vec![], 0),
                    })
                    .collect();
                Got::Accepted(records)
            }
            Err(_) if account_refused(&w) => Got::Refused,
            other => {
                return Err(format!(
                    "authorization {i}: the call failed other than in authorization: {other:?}"
                ))
            }
        };
        run.verdicts.push(got);
    }
    Ok(run)
}

// ---------------------------------------------------------------------------
// Comparing with the trace
// ---------------------------------------------------------------------------

/// The trace's expected records as [`Record`]s.
pub fn expected(v: &Verdict) -> Got {
    match v {
        Verdict::Refused => Got::Refused,
        Verdict::Ok(records) => Got::Accepted(
            records
                .iter()
                .map(|r| {
                    (
                        r.history
                            .iter()
                            .map(|x| (x.ledger, x.amount.parse().expect("decimal amount")))
                            .collect(),
                        r.total.parse().expect("decimal total"),
                    )
                })
                .collect(),
        ),
    }
}

/// Every way `run` differs from what `t` states: the lowering of the
/// document's own rules (the recovery rule, which Perch installs from its
/// recovery member rather than lowers, only by presence), each verdict, and
/// each accepted authorization's records.
pub fn differences(t: &Trace, run: &Run) -> Vec<String> {
    let mut out = vec![];
    let want = match &t.lowered {
        Lowered::Ok(rules) => decode_rules(rules).expect("trace rules"),
        Lowered::Error(e) => return vec![format!("the trace's lowering refuses ({e:?})")],
    };
    let documented = t.document.rules.len();
    if !rules_eq(&run.lowered, &want[..documented.min(want.len())]) {
        out.push("lowering: Perch's rules differ from the trace's".into());
    }
    let recovery_wanted = want.len() > documented;
    if run.recovery_rule != recovery_wanted {
        out.push(format!(
            "lowering: Perch {} a recovery rule, the trace {}",
            if run.recovery_rule {
                "installs"
            } else {
                "has no"
            },
            if recovery_wanted {
                "has one"
            } else {
                "has none"
            },
        ));
    }
    for (i, (a, got)) in t.authorizations.iter().zip(&run.verdicts).enumerate() {
        let want = expected(&a.expected);
        if *got != want {
            let delegated = a
                .authenticated
                .iter()
                .any(|s| matches!(s, JsonSigner::Delegated { .. }));
            let tag = if delegated { " (delegated signer)" } else { "" };
            out.push(match (&want, got) {
                (Got::Refused, Got::Accepted(_)) => {
                    format!("authorization {i}{tag}: Perch accepts, the trace refuses")
                }
                (Got::Accepted(_), Got::Refused) => {
                    format!("authorization {i}{tag}: Perch refuses, the trace accepts")
                }
                _ => format!("authorization {i}{tag}: records: Perch {got:?}, the trace {want:?}"),
            });
        }
    }
    out
}
