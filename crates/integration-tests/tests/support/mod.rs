//! A recovery-enabled world under ENFORCING authorization, shared by the
//! recovery and account-capability suites.
//!
//! Every account path here runs the account's real `__check_auth` with auth
//! entries built by hand and installed with `set_auths`: `mock_all_auths`
//! never invokes a custom account's `__check_auth` (AGENTS.md), so it could
//! prove none of the freeze, reserved-name, or recovery-rule properties.
//!
//! The contracts are the real ones (`PerchAccount`, the doc compiler and
//! interpreter at their pinned content addresses, the `PerchRecovery`
//! controller, the WS2 membership pool), except:
//!
//! - the owner's key and the guardians are [`Key`] stand-ins: custom
//!   accounts whose `__check_auth` approves until [`Key::deny`] is called.
//!   The owner signs as `Signer::Delegated(owner)`, so the account's own
//!   `__check_auth` and OZ rule selection run exactly as on-chain;
//! - the ZK adapter is [`MockAdapter`], which accepts a proof only if it is
//!   [`mock_proof`] of the exact statement digest, enrollment id, and
//!   nullifier, against a root the enrolled pool knows. Real proofs are the
//!   integration layer's job; this boundary is the adapter interface.
#![allow(dead_code)]

extern crate std;

use perch_account::{PerchAccount, PerchAccountClient};
use perch_doc_compiler::{PerchDocCompiler, PerchDocCompilerClient};
use perch_interpreter::PerchInterpreter;
use perch_recovery::{EvidenceDomain, PerchRecovery, PerchRecoveryClient};
use perch_recovery_interface::credential::{Credential, Replacement, ReplacementSet, ZkEnrollment};
use perch_recovery_interface::zk::{
    is_canonical_field, MembershipPoolClient, ZkAdapterError, ZkBinding, ZkEvidence,
};
use perch_recovery_interface::{RecoveryAction, RecoveryStatement, StatementSubject};
use perch_smart_account::infra;
use perch_spending_limit::PerchSpendingLimit;
use perch_testkit::FIXTURE_NETWORK;
use perch_zk_pool::{PerchZkPool, PerchZkPoolClient};
use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::xdr::{
    InvokeContractArgs, ScVal, SorobanAddressCredentials, SorobanAddressCredentialsWithDelegates,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, SorobanDelegateSignature, StringM, VecM,
};
use soroban_sdk::{
    contract, contracterror, contractimpl, map, symbol_short, vec, Address, Bytes, BytesN, Env,
    IntoVal, Map, Symbol, TryFromVal, Val, Vec,
};
use std::cell::Cell;
use std::format;
use std::string::String;
use stellar_accounts::smart_account::{AuthPayload, Signer, SmartAccountStorageKey};

// ---------------------------------------------------------------------------
// Stand-in contracts
// ---------------------------------------------------------------------------

const DENY: Symbol = symbol_short!("deny");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum KeyError {
    Denied = 1,
}

/// A key's stand-in: approves every authorization until [`Key::deny`]
/// (a lost or revoked key).
#[contract]
pub struct Key;

#[contractimpl]
impl CustomAccountInterface for Key {
    type Error = KeyError;
    type Signature = Val;

    fn __check_auth(
        e: Env,
        _signature_payload: Hash<32>,
        _signature: Val,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), KeyError> {
        if e.storage().instance().has(&DENY) {
            return Err(KeyError::Denied);
        }
        Ok(())
    }
}

#[contractimpl]
impl Key {
    pub fn deny(e: Env) {
        e.storage().instance().set(&DENY, &true);
    }
}

/// Something that needs the account's authorization: ordinary activity.
#[contract]
pub struct Target;

const HITS: Symbol = symbol_short!("hits");

#[contractimpl]
impl Target {
    pub fn protected(e: Env, account: Address) -> u32 {
        account.require_auth();
        let hits: u32 = e.storage().instance().get(&HITS).unwrap_or(0) + 1;
        e.storage().instance().set(&HITS, &hits);
        hits
    }

    /// The `install` name with an `account.require_auth()`, like an OZ
    /// policy hook.
    pub fn install(_e: Env, account: Address) {
        account.require_auth();
    }
}

/// A policy whose `install` always fails: stands in for a policy install
/// that fails partway through an `apply_doc`.
#[contract]
pub struct FailingPolicy;

#[contractimpl]
impl stellar_accounts::policies::Policy for FailingPolicy {
    type AccountParams = Val;

    fn enforce(
        _e: &Env,
        _context: Context,
        _authenticated_signers: Vec<Signer>,
        _context_rule: stellar_accounts::smart_account::ContextRule,
        _smart_account: Address,
    ) {
    }

    fn install(
        e: &Env,
        _install_params: Val,
        _context_rule: stellar_accounts::smart_account::ContextRule,
        _smart_account: Address,
    ) {
        soroban_sdk::panic_with_error!(e, KeyError::Denied);
    }

    fn uninstall(
        _e: &Env,
        _context_rule: stellar_accounts::smart_account::ContextRule,
        _smart_account: Address,
    ) {
    }
}

/// The mock adapter's circuit id.
pub const CIRCUIT: [u8; 32] = [0xc1; 32];

/// A ZK adapter that accepts exactly [`mock_proof`] of the statement it is
/// handed, and only against a root the binding's pool knows.
#[contract]
pub struct MockAdapter;

#[contractimpl]
impl MockAdapter {
    pub fn circuit_id(e: Env) -> BytesN<32> {
        BytesN::from_array(&e, &CIRCUIT)
    }

    pub fn tree_depth(_e: Env) -> u32 {
        perch_zk_pool::TREE_DEPTH
    }

    pub fn verify(
        e: Env,
        statement: RecoveryStatement,
        binding: ZkBinding,
        evidence: ZkEvidence,
    ) -> Result<(), ZkAdapterError> {
        if binding.circuit_id != BytesN::from_array(&e, &CIRCUIT) {
            return Err(ZkAdapterError::CircuitMismatch);
        }
        if !is_canonical_field(&evidence.root.to_array())
            || !is_canonical_field(&evidence.nullifier.to_array())
        {
            return Err(ZkAdapterError::NonCanonicalField);
        }
        if !MembershipPoolClient::new(&e, &binding.pool)
            .is_known_root(&evidence.tree_id, &evidence.root)
        {
            return Err(ZkAdapterError::UnknownRoot);
        }
        let digest = statement
            .digest(&e)
            .map_err(|_| ZkAdapterError::InvalidStatement)?;
        if evidence.proof != mock_proof(&e, &digest, &binding.enrollment_id, &evidence.nullifier) {
            return Err(ZkAdapterError::ProofRejected);
        }
        Ok(())
    }
}

/// The only proof [`MockAdapter`] accepts for a statement digest.
pub fn mock_proof(
    e: &Env,
    digest: &BytesN<32>,
    enrollment_id: &BytesN<32>,
    nullifier: &BytesN<32>,
) -> Bytes {
    let mut pre = Bytes::from_slice(e, b"mock-proof");
    pre.extend_from_array(&digest.to_array());
    pre.extend_from_array(&enrollment_id.to_array());
    pre.extend_from_array(&nullifier.to_array());
    e.crypto().sha256(&pre).to_bytes().into()
}

/// A credential's nullifier stand-in: one per enrollment, canonical.
pub fn nullifier(e: &Env, enrollment_id: &BytesN<32>) -> BytesN<32> {
    let mut pre = Bytes::from_slice(e, b"nullifier");
    pre.extend_from_array(&enrollment_id.to_array());
    let mut out = e.crypto().sha256(&pre).to_array();
    out[0] = 0;
    BytesN::from_array(e, &out)
}

/// A fresh enrollment: id `[n; 32]`, a canonical commitment.
pub fn enrollment(e: &Env, n: u8) -> ZkEnrollment {
    let mut commitment = [n; 32];
    commitment[0] = 0x01;
    ZkEnrollment {
        id: BytesN::from_array(e, &[n; 32]),
        commitment: BytesN::from_array(e, &commitment),
    }
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

pub fn strkey(a: &Address) -> String {
    let s = a.to_string();
    let mut buf = std::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    String::from_utf8(buf).unwrap()
}

pub fn hex32(b: &BytesN<32>) -> String {
    hex::encode(b.to_array())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Guardian,
    Zk,
    Combined,
}

/// What a test document enrolls.
#[derive(Clone)]
pub struct Recovery {
    pub profile: &'static str,
    pub mode: Mode,
    /// Guardian quorum (guardian modes; the guardian set is the world's).
    pub quorum: u32,
    pub controller: Address,
    pub adapter: Address,
    pub enrollment: Option<ZkEnrollment>,
    pub baseline: Option<BytesN<32>>,
    pub replaceable: std::vec::Vec<&'static str>,
    pub delay: u32,
    pub expiry: u32,
    pub max_cancels: u32,
    /// Overrides the world's guardian set.
    pub guardians: Option<std::vec::Vec<Address>>,
}

/// A test document: `signers` are delegated stand-in keys (the first is the
/// admin); `rules` are extra rule objects, each scoped to a contract and
/// signed by `owner`.
#[derive(Clone)]
pub struct Doc {
    pub signers: std::vec::Vec<(&'static str, Address)>,
    pub rules: std::vec::Vec<(&'static str, Address)>,
    pub recovery: Option<Recovery>,
}

impl Doc {
    pub fn json(&self, w: &World) -> String {
        let signers: std::vec::Vec<String> = self
            .signers
            .iter()
            .map(|(id, a)| format!(r#"{{"id":"{id}","address":"{}"}}"#, strkey(a)))
            .collect();
        let admin = self.signers[0].0;
        let mut rules = std::vec![format!(
            r#"{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["{admin}"]}}}}"#
        )];
        for (name, scope) in &self.rules {
            rules.push(format!(
                r#"{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["{admin}"]}}}}"#,
                strkey(scope)
            ));
        }
        let recovery = match &self.recovery {
            None => String::new(),
            Some(r) => format!(r#","recovery":{}"#, r.json(w)),
        };
        format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]{recovery}}}"#,
            signers.join(","),
            rules.join(",")
        )
    }

    pub fn bytes(&self, w: &World) -> Bytes {
        Bytes::from_slice(&w.env, self.json(w).as_bytes())
    }
}

impl Recovery {
    pub fn json(&self, w: &World) -> String {
        let guardians: std::vec::Vec<String> = self
            .guardians
            .as_ref()
            .unwrap_or(&w.guardians)
            .iter()
            .map(|g| format!(r#""{}""#, strkey(g)))
            .collect();
        let guardian_fields = format!(
            r#""guardians":[{}],"quorum":{}"#,
            guardians.join(","),
            self.quorum
        );
        let zk_fields = || {
            let z = self
                .enrollment
                .as_ref()
                .expect("zk mode needs an enrollment");
            format!(
                r#""adapter":"{}","circuit-id":"{}","pool":"{}","enrollment-id":"{}","commitment":"{}""#,
                strkey(&self.adapter),
                hex::encode(CIRCUIT),
                strkey(&w.pool),
                hex32(&z.id),
                hex32(&z.commitment)
            )
        };
        let mode = match self.mode {
            Mode::Guardian => format!(r#"{{"type":"guardian-only",{guardian_fields}}}"#),
            Mode::Zk => format!(r#"{{"type":"zk-only",{}}}"#, zk_fields()),
            Mode::Combined => format!(r#"{{"type":"combined",{guardian_fields},{}}}"#, zk_fields()),
        };
        let baseline = self
            .baseline
            .as_ref()
            .map(|b| format!(r#","baseline":{{"doc-hash":"{}"}}"#, hex32(b)))
            .unwrap_or_default();
        let replaceable: std::vec::Vec<String> = self
            .replaceable
            .iter()
            .map(|id| format!(r#""{id}""#))
            .collect();
        format!(
            r#"{{"profile":"{}","mode":{mode},"controller":"{}"{baseline},"replaceable":[{}],"delay-ledgers":{},"expiry-ledgers":{},"max-cancels":{}}}"#,
            self.profile,
            strkey(&self.controller),
            replaceable.join(","),
            self.delay,
            self.expiry,
            self.max_cancels
        )
    }
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

pub const START: u32 = 1_000;
pub const DELAY: u32 = 10;
pub const EXPIRY: u32 = 100;

pub struct World {
    pub env: Env,
    pub account: Address,
    /// The owner's key (the admin signer).
    pub owner: Address,
    /// A second, replaceable signer of every default document.
    pub device: Address,
    pub controller: Address,
    pub adapter: Address,
    pub pool: Address,
    pub compiler: Address,
    pub target: Address,
    pub guardians: std::vec::Vec<Address>,
    nonce: Cell<i64>,
}

/// How [`world_with`] departs from the default world.
#[derive(Clone, Copy, Default)]
pub struct Opts {
    /// The account is the full-replace oracle (`perch_testkit::delta`).
    pub oracle: bool,
    /// [`FailingPolicy`] sits at the spending-limit address: any capped
    /// rule's install fails.
    pub failing_spending_limit: bool,
    /// Which compiler sits at the compiler's address.
    pub compiler: TestCompiler,
}

/// The compiler a world runs (`perch_doc_compiler::testutils`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TestCompiler {
    /// The real one: CANON v1, identity = `sha256(canonical)`.
    #[default]
    Real,
    /// Identities are a different function of the canonical document, as a
    /// CANON v2 root would be.
    StandInIdentity,
    /// `derive_target` returns an identity that does not name its bytes.
    InconsistentPair,
}

impl TestCompiler {
    pub fn from_env() -> TestCompiler {
        match std::env::var("PERCH_TEST_COMPILER").as_deref() {
            Ok("stand-in") => TestCompiler::StandInIdentity,
            Ok("inconsistent-pair") => TestCompiler::InconsistentPair,
            _ => TestCompiler::Real,
        }
    }
}

/// A world with the compiler `PERCH_TEST_COMPILER` names (`stand-in` or
/// `inconsistent-pair`; the real one otherwise), so a whole suite can be run
/// under another identity scheme.
pub fn world() -> World {
    world_with(Opts {
        compiler: TestCompiler::from_env(),
        ..Opts::default()
    })
}

pub fn world_with(opts: Opts) -> World {
    let env = Env::default();
    let network_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, FIXTURE_NETWORK.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| {
        l.sequence_number = START;
        l.network_id = network_id;
        l.min_persistent_entry_ttl = 1_000_000;
        l.min_temp_entry_ttl = 1_000_000;
        l.max_entry_ttl = 10_000_000;
    });
    // The infra at exactly the content addresses the account derives.
    let compiler = infra::perch_doc_compiler::address(&env);
    match opts.compiler {
        TestCompiler::Real => env.register_at(&compiler, PerchDocCompiler, ()),
        TestCompiler::StandInIdentity => env.register_at(
            &compiler,
            perch_doc_compiler::testutils::StandInIdentityCompiler,
            (),
        ),
        TestCompiler::InconsistentPair => env.register_at(
            &compiler,
            perch_doc_compiler::testutils::InconsistentPairCompiler,
            (),
        ),
    };
    env.register_at(
        &infra::perch_interpreter::address(&env),
        PerchInterpreter,
        (),
    );
    if opts.failing_spending_limit {
        env.register_at(
            &infra::perch_spending_limit::address(&env),
            FailingPolicy,
            (),
        );
    } else {
        env.register_at(
            &infra::perch_spending_limit::address(&env),
            PerchSpendingLimit,
            (),
        );
    }

    let owner = env.register(Key, ());
    let device = env.register(Key, ());
    let guardians = (0..3).map(|_| env.register(Key, ())).collect();
    let controller = env.register(PerchRecovery, ());
    let adapter = env.register(MockAdapter, ());
    let pool = env.register(PerchZkPool, ());
    let target = env.register(Target, ());
    let admin = vec![&env, Signer::Delegated(owner.clone())];
    let account = if opts.oracle {
        env.register(perch_testkit::delta::OracleAccount, (admin,))
    } else {
        env.register(PerchAccount, (admin,))
    };

    // Enforcing authorization from here on: only explicit entries pass.
    env.set_auths(&[]);
    World {
        env,
        account,
        owner,
        device,
        controller,
        adapter,
        pool,
        compiler,
        target,
        guardians,
        nonce: Cell::new(0),
    }
}

impl World {
    pub fn client(&self) -> PerchAccountClient<'_> {
        PerchAccountClient::new(&self.env, &self.account)
    }

    pub fn ctl(&self) -> PerchRecoveryClient<'_> {
        PerchRecoveryClient::new(&self.env, &self.controller)
    }

    pub fn compiler(&self) -> PerchDocCompilerClient<'_> {
        PerchDocCompilerClient::new(&self.env, &self.compiler)
    }

    pub fn pool_client(&self) -> PerchZkPoolClient<'_> {
        PerchZkPoolClient::new(&self.env, &self.pool)
    }

    pub fn ledger(&self) -> u32 {
        self.env.ledger().sequence()
    }

    pub fn advance(&self, ledgers: u32) {
        self.env.ledger().with_mut(|l| l.sequence_number += ledgers);
    }

    /// The default recovery member: guardian-only 2-of-3 over `owner`.
    pub fn recovery(&self, profile: &'static str, mode: Mode) -> Recovery {
        Recovery {
            profile,
            mode,
            quorum: 2,
            controller: self.controller.clone(),
            adapter: self.adapter.clone(),
            enrollment: (mode != Mode::Guardian).then(|| enrollment(&self.env, 1)),
            baseline: None,
            replaceable: std::vec!["owner"],
            delay: DELAY,
            expiry: EXPIRY,
            max_cancels: 3,
            guardians: None,
        }
    }

    /// The default document: `owner` (admin) and `device`, a rule letting
    /// the owner call [`Target`], and `recovery`.
    pub fn doc(&self, recovery: Option<Recovery>) -> Doc {
        Doc {
            signers: std::vec![
                ("owner", self.owner.clone()),
                ("device", self.device.clone())
            ],
            rules: std::vec![("target", self.target.clone())],
            recovery,
        }
    }

    // --- auth entries ------------------------------------------------------

    fn next_nonce(&self) -> i64 {
        let n = self.nonce.get() + 1;
        self.nonce.set(n);
        n
    }

    pub fn sc<T: IntoVal<Env, Val>>(&self, v: T) -> ScVal {
        let val: Val = v.into_val(&self.env);
        ScVal::try_from_val(&self.env, &val).unwrap()
    }

    pub fn invocation(
        &self,
        contract: &Address,
        fn_name: &str,
        args: std::vec::Vec<ScVal>,
    ) -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: contract.clone().into(),
                function_name: StringM::try_from(fn_name).unwrap().into(),
                args: args.try_into().unwrap(),
            }),
            sub_invocations: VecM::default(),
        }
    }

    fn payload(&self, signers: Map<Signer, Bytes>, rule: u32) -> ScVal {
        self.sc(AuthPayload {
            signers,
            context_rule_ids: vec![&self.env, rule],
        })
    }

    /// `account`'s authorization through `rule`, signed by the delegated
    /// `key` (which rides in the account's own entry, CAP-0071).
    pub fn delegated_entry(
        &self,
        account: &Address,
        key: &Address,
        rule: u32,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::AddressWithDelegates(
                SorobanAddressCredentialsWithDelegates {
                    address_credentials: SorobanAddressCredentials {
                        address: account.clone().into(),
                        nonce: self.next_nonce(),
                        signature_expiration_ledger: self.ledger() + 1_000_000,
                        signature: self.payload(
                            map![
                                &self.env,
                                (Signer::Delegated(key.clone()), Bytes::new(&self.env))
                            ],
                            rule,
                        ),
                    },
                    delegates: std::vec![SorobanDelegateSignature {
                        address: key.clone().into(),
                        signature: ScVal::Void,
                        nested_delegates: VecM::default(),
                    }]
                    .try_into()
                    .unwrap(),
                },
            ),
            root_invocation: root,
        }
    }

    /// The owner's authorization of `root` through the rule named `rule`.
    pub fn owner_entry(
        &self,
        rule: &str,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        self.entry_as(&self.owner, rule, root)
    }

    /// `key`'s authorization, as the account's delegated signer, of `root`
    /// through the rule named `rule`.
    pub fn entry_as(
        &self,
        key: &Address,
        rule: &str,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        self.delegated_entry(&self.account, key, self.rule_id(&self.account, rule), root)
    }

    /// Anyone's selection of the zero-signer recovery rule for `root`.
    pub fn recovery_rule_entry(
        &self,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        self.recovery_rule_entry_for(&self.account, root)
    }

    /// Anyone's selection of `account`'s zero-signer recovery rule.
    pub fn recovery_rule_entry_for(
        &self,
        account: &Address,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: account.clone().into(),
                nonce: self.next_nonce(),
                signature_expiration_ledger: self.ledger() + 1_000_000,
                signature: self.payload(Map::new(&self.env), self.rule_id(account, "recovery")),
            }),
            root_invocation: root,
        }
    }

    /// A stand-in guardian's authorization of `digest` collected in the
    /// controller's `fn_name`.
    pub fn guardian_entry(
        &self,
        guardian: &Address,
        fn_name: &str,
        digest: &BytesN<32>,
    ) -> SorobanAuthorizationEntry {
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: guardian.clone().into(),
                nonce: self.next_nonce(),
                signature_expiration_ledger: self.ledger() + 1_000_000,
                signature: ScVal::Void,
            }),
            root_invocation: self.invocation(
                &self.controller,
                fn_name,
                std::vec![self.sc(digest.clone())],
            ),
        }
    }

    /// The id of `account`'s live rule named `name`. `apply_doc` keeps a rule
    /// it edits in place under its id, but a rule it replaces whole gets a
    /// new one, so ids can move; the newest match wins.
    pub fn rule_id(&self, account: &Address, name: &str) -> u32 {
        let next: u32 = self.env.as_contract(account, || {
            self.env
                .storage()
                .instance()
                .get(&SmartAccountStorageKey::NextId)
                .unwrap_or(0)
        });
        let client = PerchAccountClient::new(&self.env, account);
        let wanted = soroban_sdk::String::from_str(&self.env, name);
        (0..next)
            .rev()
            .find(|id| matches!(client.try_get_context_rule(id), Ok(Ok(r)) if r.name == wanted))
            .unwrap_or(u32::MAX)
    }

    // --- account calls -----------------------------------------------------

    /// `apply_doc` under the owner's authorization.
    pub fn apply(
        &self,
        doc: &Doc,
        approval_valid_until: u32,
    ) -> Result<BytesN<32>, Result<perch_account::PerchAccountError, soroban_sdk::InvokeError>>
    {
        let bytes = doc.bytes(self);
        self.apply_bytes(&bytes, approval_valid_until)
    }

    pub fn apply_bytes(
        &self,
        bytes: &Bytes,
        approval_valid_until: u32,
    ) -> Result<BytesN<32>, Result<perch_account::PerchAccountError, soroban_sdk::InvokeError>>
    {
        self.apply_as(&self.owner, bytes, approval_valid_until)
    }

    /// `apply_doc` signed by `key` through the admin rule.
    pub fn apply_as(
        &self,
        key: &Address,
        bytes: &Bytes,
        approval_valid_until: u32,
    ) -> Result<BytesN<32>, Result<perch_account::PerchAccountError, soroban_sdk::InvokeError>>
    {
        let root = self.invocation(
            &self.account,
            "apply_doc",
            std::vec![self.sc(bytes.clone()), self.sc(approval_valid_until)],
        );
        self.env.set_auths(&[self.entry_as(key, "admin", root)]);
        let out = self.client().try_apply_doc(bytes, &approval_valid_until);
        self.env.set_auths(&[]);
        out.map(|r| r.unwrap())
    }

    /// Owner-authorized `apply_doc` that must succeed.
    pub fn enroll(&self, doc: &Doc) -> BytesN<32> {
        self.apply(doc, 0).expect("owner apply_doc")
    }

    /// Ordinary activity: the owner authorizes `Target::protected`.
    pub fn activity(&self) -> bool {
        self.activity_as(&self.owner)
    }

    /// Ordinary activity signed by `key`.
    pub fn activity_as(&self, key: &Address) -> bool {
        let root = self.invocation(
            &self.target,
            "protected",
            std::vec![self.sc(self.account.clone())],
        );
        self.env.set_auths(&[self.entry_as(key, "target", root)]);
        let ok = TargetClient::new(&self.env, &self.target)
            .try_protected(&self.account)
            .is_ok();
        self.env.set_auths(&[]);
        ok
    }

    /// Complete through the recovery rule: anyone may submit.
    pub fn complete(
        &self,
        target: &Bytes,
    ) -> Result<BytesN<32>, Result<perch_account::PerchAccountError, soroban_sdk::InvokeError>>
    {
        let root = self.invocation(
            &self.account,
            "apply_doc",
            std::vec![self.sc(target.clone()), self.sc(0u32)],
        );
        self.env.set_auths(&[self.recovery_rule_entry(root)]);
        let out = self.client().try_apply_doc(target, &0);
        self.env.set_auths(&[]);
        out.map(|r| r.unwrap())
    }

    // --- recovery helpers --------------------------------------------------

    /// Replace `owner` with a fresh [`Key`]; with `zk` a fresh enrollment.
    pub fn replacements(&self, new_owner: &Address, zk: Option<ZkEnrollment>) -> ReplacementSet {
        ReplacementSet {
            signers: vec![
                &self.env,
                Replacement {
                    signer_id: soroban_sdk::String::from_str(&self.env, "owner"),
                    credential: Credential::Delegated(new_owner.clone()),
                },
            ],
            zk_enrollment: match zk {
                Some(z) => vec![&self.env, z],
                None => Vec::new(&self.env),
            },
        }
    }

    /// The canonical target an attempt installs, by simulating the account
    /// compiler's `derive_target` like a completer would.
    pub fn target_bytes(
        &self,
        action: RecoveryAction,
        source: &Bytes,
        replacements: &ReplacementSet,
    ) -> Bytes {
        let current = self.client().applied_doc().unwrap();
        self.compiler()
            .derive_target(source, &current, &action, replacements)
            .canonical
    }

    pub fn statement(&self, attempt: u64, domain: EvidenceDomain) -> RecoveryStatement {
        self.ctl().statement(&self.account, &attempt, &domain)
    }

    pub fn digest(&self, statement: &RecoveryStatement) -> BytesN<32> {
        statement.digest(&self.env).unwrap()
    }

    /// One guardian's approval of an attempt statement.
    pub fn try_guardian(
        &self,
        guardian: usize,
        attempt: u64,
        domain: EvidenceDomain,
    ) -> Result<(), Result<perch_recovery::RecoveryError, soroban_sdk::InvokeError>> {
        let g = self.guardians[guardian].clone();
        let digest = self.digest(&self.statement(attempt, domain));
        self.env
            .set_auths(&[self.guardian_entry(&g, "submit_guardian", &digest)]);
        let out = self
            .ctl()
            .try_submit_guardian(&self.account, &attempt, &domain, &g);
        self.env.set_auths(&[]);
        out.map(|r| r.unwrap())
    }

    pub fn guardian(&self, guardian: usize, attempt: u64, domain: EvidenceDomain) {
        self.try_guardian(guardian, attempt, domain)
            .expect("guardian evidence");
    }

    /// A proof for `statement` from the credential `enrollment_id` of this
    /// account, against that leaf's tree's current root.
    pub fn proof(&self, statement: &RecoveryStatement, enrollment_id: &BytesN<32>) -> ZkEvidence {
        let pool = self.pool_client();
        let at = pool
            .enrollment(&self.account, enrollment_id)
            .expect("the leaf was inserted");
        let root = pool.tree(&at.tree_id).root;
        let n = nullifier(&self.env, enrollment_id);
        ZkEvidence {
            tree_id: at.tree_id,
            root,
            nullifier: n.clone(),
            proof: mock_proof(&self.env, &self.digest(statement), enrollment_id, &n),
        }
    }

    pub fn try_zk(
        &self,
        attempt: u64,
        domain: EvidenceDomain,
        enrollment_id: &BytesN<32>,
    ) -> Result<(), Result<perch_recovery::RecoveryError, soroban_sdk::InvokeError>> {
        let evidence = self.proof(&self.statement(attempt, domain), enrollment_id);
        self.ctl()
            .try_submit_zk(&self.account, &attempt, &domain, &evidence)
            .map(|r| r.unwrap())
    }

    /// One guardian's approval of a change statement.
    pub fn approve_change(&self, guardian: usize, subject: &StatementSubject, valid_until: u32) {
        let g = self.guardians[guardian].clone();
        let statement = self
            .ctl()
            .change_statement(&self.account, subject, &valid_until);
        let digest = self.digest(&statement);
        self.env
            .set_auths(&[self.guardian_entry(&g, "approve_change", &digest)]);
        self.ctl()
            .approve_change(&self.account, subject, &valid_until, &g);
        self.env.set_auths(&[]);
    }

    /// The config hash a document's recovery member compiles to.
    pub fn config_hash(&self, doc: &Doc) -> BytesN<32> {
        self.compiler()
            .compile_doc(&doc.bytes(self))
            .recovery
            .get(0)
            .unwrap()
            .config_hash
    }

    pub fn doc_hash(&self, doc: &Doc) -> BytesN<32> {
        self.compiler().compile_doc(&doc.bytes(self)).doc_hash
    }

    pub fn new_key(&self) -> Address {
        self.env.register(Key, ())
    }
}

/// Unwrap the inner contract error of a failed `try_` call.
pub fn err<T: core::fmt::Debug, E: core::fmt::Debug + Clone>(
    r: Result<T, Result<E, soroban_sdk::InvokeError>>,
) -> E {
    match r {
        Err(Ok(e)) => e,
        other => panic!("expected a contract error, got {other:?}"),
    }
}
