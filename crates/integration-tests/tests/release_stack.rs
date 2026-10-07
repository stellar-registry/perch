//! The release stack end to end: the exact wasm `scripts/build-stack.sh`
//! built (or `scripts/fetch-infra-wasm.sh --stack` fetched from a deployment
//! manifest), real UltraHonk proofs from the pinned nargo/bb, real WebAuthn
//! signatures, and enforcing authorization throughout.
//!
//! Every contract is registered from its release wasm at the address the
//! deployment gives it: tier-0 contracts at their content addresses under the
//! stack's registry, accounts through the factory. Owners are passkeys
//! (`perch-webauthn-verifier`, verifying real secp256r1 assertions); the
//! only stand-ins are guardian keys ([`support::Key`]), whose real G-account
//! signatures the testnet exercise covers.
//!
//! `#[ignore]`d because it needs the stack and the proving toolchain:
//!
//! ```text
//! scripts/build-stack.sh --registry <C...>      # or fetch-infra-wasm.sh --stack
//! eval "$(scripts/zk-toolchain.sh)"
//! cargo test -p perch-integration-tests --test release_stack -- --ignored --nocapture
//! ```
//!
//! Each transaction-shaped call prints one `{"case": ...}` JSON line with its
//! metered resources (the in-process estimate of the on-chain cost), and is
//! asserted to fit within the budget rule's 75% of the per-transaction limits
//! (`docs/recovery/budgets.md` §2). The `worst_case_*` tests do the same for
//! the costliest document the compiler's caps admit, and `cap_sweep` measures
//! any other shape (`budgets.md`, "Document caps").

mod support;

use perch_account::PerchAccountClient;
use perch_account_factory::PerchAccountFactoryClient;
use perch_doc_compiler::{
    PerchDocCompilerClient, MAX_DOC_CANONICAL_BYTES, MAX_DOC_RULES, MAX_DOC_SIGNERS,
};
use perch_recovery::{EvidenceDomain, PerchRecoveryClient, RecoveryError};
use perch_recovery_interface::credential::{Credential, Replacement, ReplacementSet, ZkEnrollment};
use perch_recovery_interface::zk::{ZkAdapterClient, ZkEvidence};
use perch_recovery_interface::{
    ConfigChange, RecoveryAction, RecoveryStatement, StatementSubject, UpgradeSubject,
};
use perch_testkit::delta::raw_entries;
use perch_testkit::passkey::{auth_entry, SoftPasskey};
use perch_testkit::FIXTURE_NETWORK;
use perch_zk_pool::{PerchZkPoolClient, PoolKey, TreeState};
use perch_zk_primitives::{contract_id, ZERO_HASHES};
use perch_zk_prover::{Inputs, Toolchain, Tree};
use soroban_sdk::testutils::{EnvTestConfig, Ledger as _};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::xdr::{
    AccountId, HostFunction, InvokeContractArgs, PublicKey, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, StringM, Uint256, VecM,
};
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol, TryFromVal, Val, Vec};
use std::cell::Cell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use stellar_accounts::policies::spending_limit::{SpendingLimitData, SpendingLimitStorageKey};
use stellar_accounts::smart_account::{
    AuthPayload, Signer, SmartAccountStorageKey, MAX_NAME_SIZE, MAX_SIGNERS as OZ_MAX_SIGNERS,
};
use support::{strkey, Key, TargetClient};

// ---------------------------------------------------------------------------
// Limits and the budget rule
// ---------------------------------------------------------------------------

/// Protocol-29 per-transaction limits (`stellar network settings` on
/// testnet, 2026-10-03; identical on mainnet).
const TX_MAX_INSTRUCTIONS: u64 = 400_000_000;
const TX_MEMORY_LIMIT: u64 = 41_943_040;
const TX_MAX_WRITE_BYTES: u64 = 132_096;
const TX_MAX_WRITE_ENTRIES: u64 = 200;
/// `tx_max_footprint_entries`: every entry read or written.
const TX_MAX_FOOTPRINT_ENTRIES: u64 = 400;
const TX_MAX_EVENTS_BYTES: u64 = 16_384;
/// `docs/recovery/budgets.md` §2: every row within 75% of each limit.
const BUDGET_PCT: u64 = 75;

thread_local! {
    /// Set by [`cap_sweep`] only: report rows without asserting the budget.
    static UNBUDGETED: Cell<bool> = const { Cell::new(false) };
    /// While set, [`World::shaped_json`] changes every interpreter program
    /// (`.0`) and every spending cap (`.1`): the keep-names thieves.
    static REPARAM: Cell<(bool, bool)> = const { Cell::new((false, false)) };
    /// While set, every `apply_doc` is first simulated the way RPC simulation
    /// runs it, and its metered footprint checked against the simulated one
    /// ([`World::check_footprint`]).
    static SIMULATE: Cell<bool> = const { Cell::new(false) };
    /// How many `apply_doc` calls were checked that way.
    static SIMULATED: Cell<u32> = const { Cell::new(0) };
}

fn report(label: &str, e: &Env) {
    let r = e.cost_estimate().resources();
    let fee = e.cost_estimate().fee();
    let read_entries = r.memory_read_entries + r.disk_read_entries;
    // The footprint the network limits is the transaction's distinct ledger
    // keys, read-only plus read-write (stellar-core:
    // `readOnly.size() + readWrite.size()`). The host meters one read entry
    // per footprint key of either kind, and one write entry more per
    // read-write key, so the reads alone are the footprint, and the writes
    // are its read-write part, limited separately (200). The host's own
    // in-process check adds the two, counting a read-write key twice.
    // `the_metered_footprint_is_the_simulated_transactions` checks both
    // against a simulated transaction's footprint.
    let footprint_entries = read_entries;
    println!(
        "\n{{\"case\":\"{label}\",\"instructions\":{},\"instructions_pct_of_tx_limit\":{:.1},\"mem_bytes\":{},\"read_entries\":{},\"write_entries\":{},\"footprint_entries\":{},\"write_bytes\":{},\"events_bytes\":{},\"fee_resource_stroops\":{},\"fee_rent_stroops\":{}}}",
        r.instructions,
        r.instructions as f64 * 100.0 / TX_MAX_INSTRUCTIONS as f64,
        r.mem_bytes,
        read_entries,
        r.write_entries,
        footprint_entries,
        r.write_bytes,
        r.contract_events_size_bytes,
        fee.total - fee.persistent_entry_rent - fee.temporary_entry_rent,
        fee.persistent_entry_rent + fee.temporary_entry_rent,
    );
    if std::env::var_os("PERCH_EVENTS").is_some() {
        use soroban_sdk::testutils::Events as _;
        let mut by: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
        for ev in e.events().all().events() {
            let soroban_sdk::xdr::ContractEventBody::V0(body) = &ev.body;
            let topic = match body.topics.first() {
                Some(ScVal::Symbol(s)) => s.to_string(),
                other => format!("{other:?}"),
            };
            let size = soroban_sdk::xdr::WriteXdr::to_xdr(ev, soroban_sdk::xdr::Limits::none())
                .map(|b| b.len())
                .unwrap_or(0);
            let slot = by.entry(topic).or_default();
            slot.0 += 1;
            slot.1 += size;
        }
        println!("\n{{\"events_of\":\"{label}\",\"by_topic\":\"{by:?}\"}}");
    }
    if UNBUDGETED.with(Cell::get) {
        return;
    }
    let within = |used: u64, limit: u64| used * 100 <= limit * BUDGET_PCT;
    assert!(
        within(r.instructions as u64, TX_MAX_INSTRUCTIONS),
        "{label}: instructions over budget"
    );
    assert!(
        within(r.mem_bytes as u64, TX_MEMORY_LIMIT),
        "{label}: memory over budget"
    );
    assert!(
        within(r.write_bytes as u64, TX_MAX_WRITE_BYTES),
        "{label}: write bytes over budget"
    );
    assert!(
        within(r.write_entries as u64, TX_MAX_WRITE_ENTRIES),
        "{label}: write entries over budget"
    );
    assert!(
        within(footprint_entries as u64, TX_MAX_FOOTPRINT_ENTRIES),
        "{label}: footprint entries over budget"
    );
    assert!(
        within(r.contract_events_size_bytes as u64, TX_MAX_EVENTS_BYTES),
        "{label}: events over budget"
    );
}

// ---------------------------------------------------------------------------
// The stack
// ---------------------------------------------------------------------------

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The built (or fetched) stack: `build.json` and the wasm it names.
struct Stack {
    registry: String,
    wasm: HashMap<String, std::vec::Vec<u8>>,
    pins: HashMap<String, HashMap<String, String>>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(b))
}

fn load_stack() -> Stack {
    // Relative to the repository root, like the scripts that write it.
    let dir = repo().join(
        std::env::var_os("PERCH_STACK_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| "target/stack".into()),
    );
    let build: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("build.json")).unwrap_or_else(|e| {
            panic!(
                "{}/build.json: {e} (run scripts/build-stack.sh)",
                dir.display()
            )
        }))
        .expect("build.json");
    let mut wasm = HashMap::new();
    let mut pins = HashMap::new();
    for a in build["artifacts"].as_array().expect("artifacts") {
        let package = a["package"].as_str().unwrap().to_string();
        let bytes = std::fs::read(dir.join(a["wasm"].as_str().unwrap())).expect("artifact wasm");
        assert_eq!(
            sha256_hex(&bytes),
            a["sha256"].as_str().unwrap(),
            "{package}: the wasm on disk is not the one build.json records"
        );
        let p: HashMap<String, String> = a["pins"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        pins.insert(package.clone(), p);
        wasm.insert(package, bytes);
    }
    let stack = Stack {
        registry: build["registry"].as_str().unwrap().to_string(),
        wasm,
        pins,
    };
    // Every consumer was built against the exact bytes this stack carries.
    for (consumer, pins) in &stack.pins {
        for (dep, hash) in pins {
            assert_eq!(
                &sha256_hex(&stack.wasm[dep]),
                hash,
                "{consumer} pins a {dep} other than the one in the stack"
            );
        }
    }
    stack
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

const DELAY: u32 = 10;
const EXPIRY: u32 = 100;

struct World {
    env: Env,
    stack: Stack,
    factory: Address,
    webauthn: Address,
    compiler: Address,
    controller: Address,
    adapter: Address,
    pool: Address,
    target: Address,
    spending_limit: Address,
    guardians: std::vec::Vec<Address>,
    circuit_id: BytesN<32>,
    nonce: Cell<i64>,
    salt: Cell<u8>,
}

/// One passkey-owned account and what its recovery member enrolled.
struct Acct {
    address: Address,
    owner: SoftPasskey,
}

#[derive(Clone)]
struct Zk {
    secret: [u8; 32],
    id: [u8; 32],
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Guardian,
    Zk,
    Combined,
}

#[derive(Clone)]
struct Rec {
    profile: &'static str,
    mode: Mode,
    zk: Option<Zk>,
    delay: u32,
    baseline: Option<BytesN<32>>,
}

fn world() -> World {
    let stack = load_stack();
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    // The network's per-transaction limits are the SDK's default invocation
    // resource limits (mainnet's, checked after every call), and the budget
    // rule is `report`'s. A budget limit would also cap the test host's own
    // shadow bookkeeping (diagnostic events and auth observation, over 8 KiB
    // documents at the caps), which no network charges.
    env.cost_estimate().budget().reset_unlimited();
    let network_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, FIXTURE_NETWORK.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| {
        l.sequence_number = 1_000;
        l.network_id = network_id;
        l.min_persistent_entry_ttl = 1_000_000;
        l.min_temp_entry_ttl = 1_000_000;
        l.max_entry_ttl = 10_000_000;
    });

    // Every tier-0 contract at its content address: deployer(registry,
    // sha256(wasm)), exactly what deploy_stateless gives it on-chain.
    let registry = Address::from_str(&env, &stack.registry);
    let content = |pkg: &str| -> Address {
        let hash = env
            .crypto()
            .sha256(&Bytes::from_slice(&env, &stack.wasm[pkg]))
            .to_bytes();
        let addr = env
            .deployer()
            .with_address(registry.clone(), hash)
            .deployed_address();
        env.register_at(&addr, stack.wasm[pkg].as_slice(), ());
        addr
    };
    let compiler = content("perch-doc-compiler");
    content("perch-interpreter");
    let spending_limit = content("perch-spending-limit");
    let webauthn = content("perch-webauthn-verifier");
    let pool = content("perch-zk-pool");
    let adapter = content("perch-zk-adapter");
    let controller = content("perch-recovery");
    let factory = content("perch-account-factory");
    env.deployer()
        .upload_contract_wasm(stack.wasm["perch-account"].as_slice());

    let guardians = (0..3).map(|_| env.register(Key, ())).collect();
    let target = env.register(support::Target, ());
    let circuit_id = ZkAdapterClient::new(&env, &adapter).circuit_id();
    env.set_auths(&[]);
    World {
        env,
        stack,
        factory,
        webauthn,
        compiler,
        controller,
        adapter,
        pool,
        target,
        spending_limit,
        guardians,
        circuit_id,
        nonce: Cell::new(0),
        salt: Cell::new(0),
    }
}

/// A random canonical field element (top byte zero).
fn field(tag: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out: [u8; 32] = Sha256::digest(tag.as_bytes()).into();
    out[0] = 0;
    out
}

impl World {
    fn ctl(&self) -> PerchRecoveryClient<'_> {
        PerchRecoveryClient::new(&self.env, &self.controller)
    }

    fn pool(&self) -> PerchZkPoolClient<'_> {
        PerchZkPoolClient::new(&self.env, &self.pool)
    }

    fn factory(&self) -> PerchAccountFactoryClient<'_> {
        PerchAccountFactoryClient::new(&self.env, &self.factory)
    }

    fn account(&self, a: &Acct) -> PerchAccountClient<'_> {
        PerchAccountClient::new(&self.env, &a.address)
    }

    fn ledger(&self) -> u32 {
        self.env.ledger().sequence()
    }

    fn advance(&self, ledgers: u32) {
        self.env.ledger().with_mut(|l| l.sequence_number += ledgers);
    }

    fn next_nonce(&self) -> i64 {
        self.nonce.set(self.nonce.get() + 1);
        self.nonce.get()
    }

    fn sc<T: IntoVal<Env, Val>>(&self, v: T) -> ScVal {
        let val: Val = v.into_val(&self.env);
        ScVal::try_from_val(&self.env, &val).unwrap()
    }

    fn invocation(
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

    /// A fresh passkey account from the factory.
    fn new_account(&self, owner: SoftPasskey) -> Acct {
        self.salt.set(self.salt.get() + 1);
        let salt = BytesN::from_array(&self.env, &[self.salt.get(); 32]);
        let address = self
            .factory()
            .create_passkey(&salt, &Bytes::from_slice(&self.env, &owner.key_data()));
        report("factory create_passkey", &self.env);
        Acct { address, owner }
    }

    /// The id of the account's live rule named `name`.
    fn rule_id(&self, account: &Address, name: &str) -> u32 {
        self.find_rule(account, name).expect("rule exists")
    }

    fn find_rule(&self, account: &Address, name: &str) -> Option<u32> {
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
    }

    /// `key`'s passkey authorization of `root` through the rule `rule`.
    fn passkey_entry(
        &self,
        account: &Address,
        key: &SoftPasskey,
        rule: &str,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        auth_entry(
            &self.env,
            account,
            &self.webauthn,
            key,
            self.rule_id(account, rule),
            self.next_nonce(),
            self.ledger() + 1_000_000,
            root,
        )
    }

    /// Anyone's selection of the zero-signer recovery rule.
    fn recovery_rule_entry(
        &self,
        account: &Address,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        let payload = AuthPayload {
            signers: Map::new(&self.env),
            context_rule_ids: vec![&self.env, self.rule_id(account, "recovery")],
        };
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: account.clone().into(),
                nonce: self.next_nonce(),
                signature_expiration_ledger: self.ledger() + 1_000_000,
                signature: self.sc(payload),
            }),
            root_invocation: root,
        }
    }

    fn guardian_entry(
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

    // --- documents ----------------------------------------------------------

    fn commitment(&self, zk: &Zk) -> [u8; 32] {
        perch_zk_prover::commitment(&perch_zk_prover::host(), &zk.secret)
    }

    fn recovery_json(&self, r: &Rec) -> String {
        self.recovery_json_replacing(r, &["owner"])
    }

    fn recovery_json_replacing(&self, r: &Rec, replaceable: &[&str]) -> String {
        let guardians: std::vec::Vec<String> = self
            .guardians
            .iter()
            .map(|g| format!(r#""{}""#, strkey(g)))
            .collect();
        let guardian_fields = format!(r#""guardians":[{}],"quorum":2"#, guardians.join(","));
        let zk_fields = || {
            let z = r.zk.as_ref().expect("zk mode needs an enrollment");
            format!(
                r#""adapter":"{}","circuit-id":"{}","pool":"{}","enrollment-id":"{}","commitment":"{}""#,
                strkey(&self.adapter),
                hex(&self.circuit_id.to_array()),
                strkey(&self.pool),
                hex(&z.id),
                hex(&self.commitment(z)),
            )
        };
        let mode = match r.mode {
            Mode::Guardian => format!(r#"{{"type":"guardian-only",{guardian_fields}}}"#),
            Mode::Zk => format!(r#"{{"type":"zk-only",{}}}"#, zk_fields()),
            Mode::Combined => {
                format!(r#"{{"type":"combined",{guardian_fields},{}}}"#, zk_fields())
            }
        };
        let baseline = r
            .baseline
            .as_ref()
            .map(|b| format!(r#","baseline":{{"doc-hash":"{}"}}"#, hex(&b.to_array())))
            .unwrap_or_default();
        let replaceable: std::vec::Vec<String> =
            replaceable.iter().map(|id| format!(r#""{id}""#)).collect();
        format!(
            r#"{{"profile":"{}","mode":{mode},"controller":"{}"{baseline},"replaceable":[{}],"delay-ledgers":{},"expiry-ledgers":{EXPIRY},"max-cancels":3}}"#,
            r.profile,
            strkey(&self.controller),
            replaceable.join(","),
            r.delay,
        )
    }

    /// The owner passkey as admin, a rule letting it call the target, and
    /// `recovery`.
    fn doc(&self, owner: &SoftPasskey, recovery: Option<&Rec>) -> Bytes {
        self.doc_with(owner, None, recovery)
    }

    /// [`World::doc`] plus, with `extra`, a second passkey signer "thief"
    /// and a rule letting it call the target.
    fn doc_with(
        &self,
        owner: &SoftPasskey,
        extra: Option<&SoftPasskey>,
        recovery: Option<&Rec>,
    ) -> Bytes {
        let recovery = recovery
            .map(|r| format!(r#","recovery":{}"#, self.recovery_json(r)))
            .unwrap_or_default();
        let signer = |id: &str, key: &SoftPasskey| {
            format!(
                r#"{{"id":"{id}","verifier":"{}","key":"{}"}}"#,
                strkey(&self.webauthn),
                hex(&key.key_data())
            )
        };
        let target_rule = |name: &str, signer: &str| {
            format!(
                r#"{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["{signer}"]}}}}"#,
                strkey(&self.target)
            )
        };
        let mut signers = std::vec![signer("owner", owner)];
        let mut rules = std::vec![
            r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#.to_string(),
            target_rule("target", "owner"),
        ];
        if let Some(thief) = extra {
            signers.push(signer("thief", thief));
            rules.push(target_rule("thief", "thief"));
        }
        let json = format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]{recovery}}}"#,
            signers.join(","),
            rules.join(","),
        );
        Bytes::from_slice(&self.env, json.as_bytes())
    }

    fn doc_hash(&self, doc: &Bytes) -> BytesN<32> {
        PerchDocCompilerClient::new(&self.env, &self.compiler)
            .compile_doc(doc)
            .doc_hash
    }

    fn config_hash(&self, doc: &Bytes) -> BytesN<32> {
        PerchDocCompilerClient::new(&self.env, &self.compiler)
            .compile_doc(doc)
            .recovery
            .get(0)
            .unwrap()
            .config_hash
    }

    // --- account calls ------------------------------------------------------

    /// `apply_doc` signed by `key` through the admin rule.
    fn try_apply(
        &self,
        a: &Acct,
        key: &SoftPasskey,
        doc: &Bytes,
        approval_valid_until: u32,
    ) -> bool {
        let root = self.invocation(
            &a.address,
            "apply_doc",
            std::vec![self.sc(doc.clone()), self.sc(approval_valid_until)],
        );
        let entry = self.passkey_entry(&a.address, key, "admin", root.clone());
        let simulated = SIMULATE
            .with(Cell::get)
            .then(|| self.simulated_footprint(&root, &entry));
        self.env.set_auths(&[entry]);
        let ok = matches!(
            self.account(a).try_apply_doc(doc, &approval_valid_until),
            Ok(Ok(_))
        );
        self.env.set_auths(&[]);
        if let (true, Some(simulated)) = (ok, simulated) {
            self.check_footprint(simulated);
        }
        ok
    }

    /// Ordinary activity: `key` authorizes the target's `protected`.
    fn activity(&self, a: &Acct, key: &SoftPasskey) -> bool {
        self.activity_via(a, key, "target")
    }

    /// Ordinary activity through the rule named `rule`. No such rule: no
    /// way to authorize.
    fn activity_via(&self, a: &Acct, key: &SoftPasskey, rule: &str) -> bool {
        if self.find_rule(&a.address, rule).is_none() {
            return false;
        }
        let root = self.invocation(
            &self.target,
            "protected",
            std::vec![self.sc(a.address.clone())],
        );
        self.env
            .set_auths(&[self.passkey_entry(&a.address, key, rule, root)]);
        let ok = TargetClient::new(&self.env, &self.target)
            .try_protected(&a.address)
            .is_ok();
        self.env.set_auths(&[]);
        ok
    }

    /// `execute(target, protected, [account])` signed by `key` via the
    /// admin rule (the self-scoped rule authorizes calls on the account).
    fn execute(&self, a: &Acct, key: &SoftPasskey) -> bool {
        let fn_name = Symbol::new(&self.env, "protected");
        let args: Vec<Val> = vec![&self.env, a.address.clone().into_val(&self.env)];
        // The target's `account.require_auth()` passes by invoker
        // authorization, so the entry covers `execute` alone.
        let root = self.invocation(
            &a.address,
            "execute",
            std::vec![
                self.sc(self.target.clone()),
                self.sc(fn_name.clone()),
                self.sc(args.clone()),
            ],
        );
        self.env
            .set_auths(&[self.passkey_entry(&a.address, key, "admin", root)]);
        let ok = matches!(
            self.account(a).try_execute(&self.target, &fn_name, &args),
            Ok(Ok(_))
        );
        self.env.set_auths(&[]);
        ok
    }

    /// The footprint RPC simulation declares for `root` authorized by
    /// `entry`, on the current ledger: its read-only and read-write key
    /// counts, or why the simulated call failed. Runs the call in recording mode on a fresh host over a
    /// snapshot of this ledger (`e2e_invoke`, what simulation runs), so the
    /// test environment's own metering plays no part.
    fn simulated_footprint(
        &self,
        root: &SorobanAuthorizedInvocation,
        entry: &SorobanAuthorizationEntry,
    ) -> Result<(usize, usize), String> {
        use soroban_env_host::{budget::Budget, e2e_invoke, storage::SnapshotSource};
        let SorobanAuthorizedFunction::ContractFn(call) = &root.function else {
            unreachable!("apply_doc is a contract call")
        };
        let budget = Budget::default();
        budget.reset_unlimited().unwrap();
        let snapshot: std::rc::Rc<dyn SnapshotSource> =
            std::rc::Rc::new(self.env.to_ledger_snapshot());
        let mut diagnostics = std::vec::Vec::new();
        let out = e2e_invoke::invoke_host_function_in_recording_mode(
            &budget,
            false,
            &HostFunction::InvokeContract(call.clone()),
            &AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32]))),
            e2e_invoke::RecordingInvocationAuthMode::Enforcing(std::vec![entry.clone()]),
            self.env.ledger().get(),
            snapshot,
            [0; 32],
            &mut diagnostics,
        )
        .expect("the simulation runs");
        if let Err(e) = &out.invoke_result {
            return Err(format!("{e:?}"));
        }
        let footprint = out.resources.footprint;
        Ok((footprint.read_only.len(), footprint.read_write.len()))
    }

    /// The `apply_doc` just metered, which succeeded, against its simulation:
    /// the simulation succeeds too, the metered footprint is its read-only
    /// plus read-write keys, and the written entries are the read-write keys.
    fn check_footprint(&self, simulated: Result<(usize, usize), String>) {
        let (read_only, read_write) =
            simulated.unwrap_or_else(|e| panic!("the call succeeded, its simulation failed: {e}"));
        let r = self.env.cost_estimate().resources();
        let reads = (r.memory_read_entries + r.disk_read_entries) as usize;
        assert_eq!(
            reads,
            read_only + read_write,
            "metered footprint = simulated read-only + read-write keys"
        );
        assert_eq!(
            r.write_entries as usize, read_write,
            "metered written entries = simulated read-write keys"
        );
        SIMULATED.with(|n| n.set(n.get() + 1));
        println!(
            "\n{{\"footprint_check\":{{\"read_only\":{read_only},\"read_write\":{read_write},\"metered_footprint\":{reads},\"metered_written\":{}}}}}",
            r.write_entries
        );
    }

    /// Complete through the recovery rule: anyone may submit.
    fn try_complete(&self, a: &Acct, target: &Bytes) -> bool {
        let root = self.invocation(
            &a.address,
            "apply_doc",
            std::vec![self.sc(target.clone()), self.sc(0u32)],
        );
        let entry = self.recovery_rule_entry(&a.address, root.clone());
        let simulated = SIMULATE
            .with(Cell::get)
            .then(|| self.simulated_footprint(&root, &entry));
        self.env.set_auths(&[entry]);
        let ok = matches!(self.account(a).try_apply_doc(target, &0), Ok(Ok(_)));
        self.env.set_auths(&[]);
        if let (true, Some(simulated)) = (ok, simulated) {
            self.check_footprint(simulated);
        }
        ok
    }

    // --- recovery -----------------------------------------------------------

    fn replacements(&self, new_owner: &SoftPasskey, zk: Option<&Zk>) -> ReplacementSet {
        ReplacementSet {
            signers: vec![
                &self.env,
                Replacement {
                    signer_id: soroban_sdk::String::from_str(&self.env, "owner"),
                    credential: Credential::External(
                        self.webauthn.clone(),
                        Bytes::from_slice(&self.env, &new_owner.key_data()),
                    ),
                },
            ],
            zk_enrollment: match zk {
                Some(z) => vec![
                    &self.env,
                    ZkEnrollment {
                        id: BytesN::from_array(&self.env, &z.id),
                        commitment: BytesN::from_array(&self.env, &self.commitment(z)),
                    },
                ],
                None => Vec::new(&self.env),
            },
        }
    }

    /// What a completer simulates: the attempt's canonical target bytes.
    fn target_bytes(&self, a: &Acct, replacements: &ReplacementSet) -> Bytes {
        let current = self.account(a).applied_doc().unwrap();
        PerchDocCompilerClient::new(&self.env, &self.compiler)
            .derive_target(&current, &current, &RecoveryAction::LostKey, replacements)
            .canonical
    }

    /// A compromise attempt's target: the published baseline with the
    /// current recovery member and `replacements`.
    fn compromise_target(&self, a: &Acct, replacements: &ReplacementSet) -> Bytes {
        let current = self.account(a).applied_doc().unwrap();
        let baseline = self.ctl().baseline(&a.address).unwrap();
        PerchDocCompilerClient::new(&self.env, &self.compiler)
            .derive_target(
                &baseline,
                &current,
                &RecoveryAction::Compromise,
                replacements,
            )
            .canonical
    }

    fn statement(&self, a: &Acct, attempt: u64, domain: EvidenceDomain) -> RecoveryStatement {
        self.ctl().statement(&a.address, &attempt, &domain)
    }

    fn guardian(&self, i: usize, a: &Acct, attempt: u64, domain: EvidenceDomain) {
        let g = self.guardians[i].clone();
        let digest = self
            .statement(a, attempt, domain)
            .digest(&self.env)
            .unwrap();
        self.env
            .set_auths(&[self.guardian_entry(&g, "submit_guardian", &digest)]);
        self.ctl()
            .submit_guardian(&a.address, &attempt, &domain, &g);
        self.env.set_auths(&[]);
    }

    fn approve_change(&self, i: usize, a: &Acct, subject: &StatementSubject, valid_until: u32) {
        let g = self.guardians[i].clone();
        let digest = self
            .ctl()
            .change_statement(&a.address, subject, &valid_until)
            .digest(&self.env)
            .unwrap();
        self.env
            .set_auths(&[self.guardian_entry(&g, "approve_change", &digest)]);
        self.ctl()
            .approve_change(&a.address, subject, &valid_until, &g);
        self.env.set_auths(&[]);
    }

    /// Every leaf of `tree_id`, read from the pool's storage pages.
    fn leaves(&self, tree_id: u32) -> std::vec::Vec<[u8; 32]> {
        let size = self.pool().tree(&tree_id).size;
        let mut out = std::vec::Vec::new();
        let mut start = 0u64;
        while start < size {
            let count = (size - start).min(perch_zk_pool::MAX_PAGE as u64) as u32;
            for leaf in self.pool().leaves(&tree_id, &start, &count).iter() {
                out.push(leaf.to_array());
            }
            start += count as u64;
        }
        out
    }

    /// A real proof of `statement` by the credential `zk` enrolled for `a`,
    /// against the root of its tree rebuilt from the pool's leaves (or, for
    /// a synthesized full tree, the zero-subtree path the frontier implies).
    fn prove(&self, a: &Acct, zk: &Zk, statement: &RecoveryStatement) -> ZkEvidence {
        let at = self
            .pool()
            .enrollment(&a.address, &BytesN::from_array(&self.env, &zk.id))
            .expect("the leaf was inserted");
        let info = self.pool().tree(&at.tree_id);
        let host = perch_zk_prover::host();
        let siblings = if info.capacity == info.size && at.index == info.capacity - 1 {
            ZERO_HASHES[..perch_zk_pool::TREE_DEPTH as usize].to_vec()
        } else {
            Tree::new(&host, perch_zk_pool::TREE_DEPTH, &self.leaves(at.tree_id)).path(at.index)
        };
        let inputs = Inputs::new(
            &host,
            zk.secret,
            contract_id(&self.env, &a.address).unwrap().to_array(),
            zk.id,
            statement.digest(&self.env).unwrap().to_array(),
            at.index,
            siblings,
        );
        assert!(
            self.pool()
                .is_known_root(&at.tree_id, &BytesN::from_array(&self.env, &inputs.root)),
            "the rebuilt root is not one the pool recorded"
        );
        let proof = prove_inputs(&inputs);
        ZkEvidence {
            tree_id: at.tree_id,
            root: BytesN::from_array(&self.env, &inputs.root),
            nullifier: BytesN::from_array(&self.env, &inputs.nullifier),
            proof: Bytes::from_slice(&self.env, &proof),
        }
    }
}

// ---------------------------------------------------------------------------
// Documents at the caps
// ---------------------------------------------------------------------------

/// A document's shape: `signers` passkey signers (the owner first), then
/// the rules: `admin`, `target` (the owner's activity rule, with the
/// interpreter), `both` rules with both policies (the interpreter, from a
/// 1-of-1 threshold and an argument constraint, and a spending cap),
/// `interp` with the interpreter alone, and `plain` with none.
#[derive(Clone, Copy, Debug)]
struct Shape {
    signers: usize,
    both: u32,
    interp: u32,
    plain: u32,
    /// How many signers each rule with the interpreter names (1-of-N).
    fan: usize,
    /// Prefixed to every rule name but `admin`'s: documents with different
    /// tags share no rule, so `apply_doc`'s diff replaces every one.
    tag: &'static str,
}

impl Shape {
    fn rules(&self) -> u32 {
        2 + self.both + self.interp + self.plain
    }
}

/// The ids of `n` signers: the owner, then `s01`, ..., in canonical order.
fn signer_ids(n: usize) -> std::vec::Vec<String> {
    let mut ids = std::vec!["owner".to_string()];
    ids.extend((1..n).map(|i| format!("s{i:02}")));
    ids
}

/// `n` fresh passkeys, the owner's first.
fn passkeys(seed: u8, n: usize) -> std::vec::Vec<SoftPasskey> {
    (0..n as u8)
        .map(|i| {
            let mut s = [seed; 32];
            s[1] = i;
            SoftPasskey::from_seed(s)
        })
        .collect()
}

fn canonical_len(json: &str) -> usize {
    perch_ir::canonical_json(&perch_ir::from_json(json).expect("a valid document")).len()
}

impl World {
    /// The document of `shape` over `keys`, recovery replacing every
    /// signer, with `values` strings in a second argument constraint of the
    /// first rule after `target`, and `pad` bytes spread over the names of
    /// the rules after `target` (each at most OZ's `MAX_NAME_SIZE`). With `with_recovery`
    /// false: the same document
    /// without its recovery member (a compromise baseline, to which the
    /// target adds the member back).
    fn shaped_json(
        &self,
        keys: &[SoftPasskey],
        recovery: &Rec,
        shape: Shape,
        values: usize,
        pad: usize,
        with_recovery: bool,
    ) -> String {
        let ids = signer_ids(shape.signers);
        let id_refs: std::vec::Vec<&str> = ids.iter().map(String::as_str).collect();
        let (reprogram, recap) = REPARAM.with(Cell::get);
        let function = if reprogram { "protectee" } else { "protected" };
        let limit = if recap { "11" } else { "10" };
        let scope = format!(
            r#""scope":{{"type":"contract","address":"{}"}}"#,
            strkey(&self.target)
        );
        // Rule `k` (0 is `target`) names `fan` signers starting at
        // `k * fan`, wrapping, so every signer is some rule's, and
        // `target` starts with the owner.
        let interpreted = |k: usize| {
            let mut named: std::vec::Vec<&String> = (0..shape.fan)
                .map(|i| &ids[(k * shape.fan + i) % shape.signers])
                .collect();
            named.sort();
            named.dedup();
            let named: std::vec::Vec<String> =
                named.iter().map(|id| format!(r#""{id}""#)).collect();
            format!(
                r#""principals":{{"type":"threshold","m":1,"signers":[{}]}},"functions":["{function}"],"args":[{{"index":0,"pred":{{"type":"is-self"}}}}]"#,
                named.join(",")
            )
        };
        let signers: std::vec::Vec<String> = ids
            .iter()
            .zip(keys)
            .map(|(id, key)| {
                format!(
                    r#"{{"id":"{id}","verifier":"{}","key":"{}"}}"#,
                    strkey(&self.webauthn),
                    hex(&key.key_data())
                )
            })
            .collect();
        let mut pad = pad;
        let mut name_of = |base: String| {
            let grow = pad.min(MAX_NAME_SIZE as usize - base.len());
            pad -= grow;
            format!("{base}{}", "x".repeat(grow))
        };
        let mut rules = std::vec![
            r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#.to_string(),
            format!(
                r#"{{"name":"{}target",{scope},{}}}"#,
                shape.tag,
                interpreted(0)
            ),
        ];
        for j in 0..shape.both + shape.interp + shape.plain {
            let name = name_of(format!("{}r{:02}", shape.tag, j + 2));
            let mut interpreted = interpreted(1 + j as usize);
            if j == 0 && values > 0 {
                // Spare bytes as a second argument constraint: a larger
                // interpreter program to compile, store, and install.
                let values: std::vec::Vec<String> =
                    (0..values).map(|v| format!(r#""v{v:04}""#)).collect();
                interpreted = interpreted.replacen(
                    r#"}}]"#,
                    &format!(
                        r#"}}}},{{"index":1,"pred":{{"type":"string-in","values":[{}]}}}}]"#,
                        values.join(",")
                    ),
                    1,
                );
            }
            rules.push(if j < shape.both {
                format!(
                    r#"{{"name":"{name}",{scope},{interpreted},"cap":{{"limit":"{limit}","period-ledgers":1000}}}}"#
                )
            } else if j < shape.both + shape.interp {
                format!(r#"{{"name":"{name}",{scope},{interpreted}}}"#)
            } else {
                format!(
                    r#"{{"name":"{name}",{scope},"principals":{{"type":"all","signers":["owner"]}}}}"#
                )
            });
        }
        assert_eq!(pad, 0, "the rule names cannot absorb the padding");
        let recovery = if with_recovery {
            format!(
                r#","recovery":{}"#,
                self.recovery_json_replacing(recovery, &id_refs)
            )
        } else {
            String::new()
        };
        format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]{recovery}}}"#,
            signers.join(","),
            rules.join(","),
        )
    }

    /// The document of `shape`, padded to exactly `bytes` (with its
    /// recovery member): first a second argument constraint with as many
    /// strings as fit, then the rule names.
    fn shaped_doc(
        &self,
        keys: &[SoftPasskey],
        recovery: &Rec,
        shape: Shape,
        bytes: usize,
        with_recovery: bool,
    ) -> Bytes {
        let len = |values: usize, pad: usize| {
            canonical_len(&self.shaped_json(keys, recovery, shape, values, pad, true))
        };
        assert!(len(0, 0) <= bytes, "{shape:?} does not fit {bytes} bytes");
        // What the names after `target` can grow by, from three bytes each.
        let room = (shape.rules() as usize - 2) * (MAX_NAME_SIZE as usize - 3 - shape.tag.len());
        let values = if shape.rules() > 2 && len(0, 0) + room < bytes {
            (1..)
                .take_while(|&v| len(v, 0) <= bytes)
                .last()
                .unwrap_or(0)
        } else {
            0
        };
        let pad = (bytes - len(values, 0)).min(room);
        let size = len(values, pad);
        assert_eq!(
            size, bytes,
            "{shape:?}: the padding cannot reach {bytes} bytes"
        );
        println!(
            "\n{{\"case\":\"document\",\"signers\":{},\"rules\":{},\"both_policies\":{},\"signers_per_rule\":{},\"string_values\":{values},\"canonical_bytes\":{size}}}",
            shape.signers,
            shape.rules(),
            shape.both,
            shape.fan,
        );
        Bytes::from_slice(
            &self.env,
            self.shaped_json(keys, recovery, shape, values, pad, with_recovery)
                .as_bytes(),
        )
    }

    /// A derived target has `shape`'s signers and rules, within the byte
    /// cap.
    fn assert_shape(&self, doc: &Bytes, shape: Shape) {
        let compiled = PerchDocCompilerClient::new(&self.env, &self.compiler).compile_doc(doc);
        assert_eq!(compiled.fingerprints.len() as usize, shape.signers);
        assert_eq!(compiled.rules.len(), shape.rules());
        assert!(compiled.canonical.len() <= MAX_DOC_CANONICAL_BYTES);
    }

    /// Every signer replaced with `keys` (in [`signer_ids`] order), and
    /// with `zk` a new ZK enrollment.
    fn replacing_all(&self, keys: &[SoftPasskey], zk: Option<&Zk>) -> ReplacementSet {
        let mut r = self.replacements(&keys[0], zk);
        r.signers = Vec::new(&self.env);
        for (id, key) in signer_ids(keys.len()).iter().zip(keys) {
            r.signers.push_back(Replacement {
                signer_id: soroban_sdk::String::from_str(&self.env, id),
                credential: self.passkey_credential(key),
            });
        }
        r
    }

    fn passkey_credential(&self, key: &SoftPasskey) -> Credential {
        Credential::External(
            self.webauthn.clone(),
            Bytes::from_slice(&self.env, &key.key_data()),
        )
    }

    /// Whether `a` has revoked every one of `keys`. A fingerprint is over
    /// the verifier's canonical key: the WebAuthn verifier drops the
    /// credential id, leaving the public key.
    fn all_revoked(&self, a: &Acct, keys: &[SoftPasskey]) -> bool {
        keys.iter().all(|k| {
            let canonical = Credential::External(
                self.webauthn.clone(),
                Bytes::from_slice(&self.env, &k.public_key()),
            );
            self.account(a)
                .is_revoked(&canonical.fingerprint(&self.env).unwrap())
        })
    }
}

/// `nargo execute` + `bb prove` writes into the shared circuit target dir,
/// keyed by process id: serialize the tests' proving.
static PROVING: Mutex<()> = Mutex::new(());

fn prove_inputs(inputs: &Inputs) -> std::vec::Vec<u8> {
    let _guard = PROVING.lock().unwrap_or_else(|p| p.into_inner());
    let tc = Toolchain::from_env().expect("pinned nargo/bb (eval \"$(scripts/zk-toolchain.sh)\")");
    // `PERCH_PROOF_DIR` separates concurrent runs (each writes Prover.toml).
    let work = repo().join(
        std::env::var_os("PERCH_PROOF_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| "target/release-stack-proofs".into()),
    );
    let proof = perch_zk_prover::prove(
        &tc,
        &repo().join("circuits"),
        "perch_zk_recovery",
        inputs,
        &work,
    )
    .expect("prove");
    println!(
        "\n{{\"case\":\"native prove\",\"execute_ms\":{},\"prove_ms\":{},\"peak_rss_bytes\":{}}}",
        proof.execute_ms,
        proof.prove_ms,
        proof.prove_peak_rss_bytes.unwrap_or(0)
    );
    proof.proof
}

fn zk_err(
    r: Result<
        Result<(), soroban_sdk::ConversionError>,
        Result<RecoveryError, soroban_sdk::InvokeError>,
    >,
) -> RecoveryError {
    match r {
        Err(Ok(e)) => e,
        other => panic!("expected a recovery error, got {other:?}"),
    }
}

fn tamper(e: &Env, ev: &ZkEvidence) -> ZkEvidence {
    let mut proof = std::vec![0u8; ev.proof.len() as usize];
    ev.proof.copy_into_slice(&mut proof);
    proof[1000] ^= 1;
    ZkEvidence {
        proof: Bytes::from_slice(e, &proof),
        ..ev.clone()
    }
}

// ---------------------------------------------------------------------------
// The flows
// ---------------------------------------------------------------------------

/// `ZkOnly` under `Loss`: a lost passkey is replaced with a real proof.
///
/// The account enrolls into the last slot of a full tree (synthesized
/// frontier, so the tree is full without 2^32 inserts); its completion's
/// rotation then opens the next tree. Every rejection along the way is
/// a real verifier, pool, or controller refusal.
#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn zk_lost_key_recovery_with_real_proofs_across_a_rollover() {
    let w = world();
    let a = w.new_account(SoftPasskey::from_seed([11; 32]));

    // The pool's tree 0 has one slot left.
    let depth = perch_zk_pool::TREE_DEPTH;
    w.env.as_contract(&w.pool, || {
        let mut frontier = Vec::new(&w.env);
        for z in &ZERO_HASHES[..depth as usize] {
            frontier.push_back(BytesN::from_array(&w.env, z));
        }
        w.env.storage().persistent().set(
            &PoolKey::Tree(0),
            &TreeState {
                size: (1u64 << depth) - 1,
                root: BytesN::from_array(&w.env, &ZERO_HASHES[depth as usize]),
                frontier,
            },
        );
    });

    let zk1 = Zk {
        secret: field("lost-key secret 1"),
        id: field("lost-key enrollment 1"),
    };
    let rec = Rec {
        profile: "loss",
        mode: Mode::Zk,
        zk: Some(zk1.clone()),
        delay: DELAY,
        baseline: None,
    };
    let doc = w.doc(&a.owner, Some(&rec));
    assert!(w.try_apply(&a, &a.owner, &doc, 0), "enrollment apply_doc");
    report("enroll ZK through apply_doc (seals tree 0)", &w.env);
    assert!(w.pool().tree(&0).sealed);
    assert!(
        w.activity(&a, &a.owner),
        "ordinary activity before recovery"
    );

    // The passkey is lost. A new passkey and a new ZK credential replace it.
    let new_owner = SoftPasskey::from_seed([12; 32]);
    let zk2 = Zk {
        secret: field("lost-key secret 2"),
        id: field("lost-key enrollment 2"),
    };
    let replacements = w.replacements(&new_owner, Some(&zk2));
    let attempt = w.ctl().begin_lost_key(&a.address, &replacements);
    report("begin_lost_key", &w.env);
    let decoy = w.ctl().begin_lost_key(&a.address, &replacements);

    let statement = w.statement(&a, attempt, EvidenceDomain::Initiate);
    let evidence = w.prove(&a, &zk1, &statement);

    // Refused: a proof of another attempt's statement, of this attempt's
    // cancellation, a tampered proof, and a root the pool never had.
    let decoy_proof = w.prove(&a, &zk1, &w.statement(&a, decoy, EvidenceDomain::Initiate));
    assert_eq!(
        zk_err(w.ctl().try_submit_zk(
            &a.address,
            &attempt,
            &EvidenceDomain::Initiate,
            &decoy_proof
        )),
        RecoveryError::ZkEvidenceRejected
    );
    let cancel_proof = w.prove(&a, &zk1, &w.statement(&a, attempt, EvidenceDomain::Cancel));
    assert_eq!(
        zk_err(w.ctl().try_submit_zk(
            &a.address,
            &attempt,
            &EvidenceDomain::Initiate,
            &cancel_proof
        )),
        RecoveryError::ZkEvidenceRejected
    );
    assert_eq!(
        zk_err(w.ctl().try_submit_zk(
            &a.address,
            &attempt,
            &EvidenceDomain::Initiate,
            &tamper(&w.env, &evidence)
        )),
        RecoveryError::ZkEvidenceRejected
    );
    let mut wrong_root = evidence.clone();
    wrong_root.root = BytesN::from_array(&w.env, &field("not a root"));
    assert_eq!(
        zk_err(
            w.ctl()
                .try_submit_zk(&a.address, &attempt, &EvidenceDomain::Initiate, &wrong_root)
        ),
        RecoveryError::ZkEvidenceRejected
    );

    w.ctl()
        .submit_zk(&a.address, &attempt, &EvidenceDomain::Initiate, &evidence);
    report("submit_zk (promoting, ZkOnly)", &w.env);
    assert!(w.ctl().activity_gate(&a.address).authorized_attempt == Some(attempt));
    // Replay refused; the sibling attempt died when this one was authorized.
    assert_eq!(
        zk_err(
            w.ctl()
                .try_submit_zk(&a.address, &attempt, &EvidenceDomain::Initiate, &evidence)
        ),
        RecoveryError::AttemptNotCollecting
    );
    assert!(!w.ctl().attempt_live(&a.address, &decoy));

    // Loss: ordinary activity continues, conflicting policy changes do not.
    assert!(w.activity(&a, &a.owner));
    assert!(!w.try_apply(&a, &a.owner, &w.doc(&a.owner, None), 0));

    let target = w.target_bytes(&a, &replacements);
    assert!(!w.try_complete(&a, &target), "completion before the delay");
    w.advance(DELAY);
    assert!(w.try_complete(&a, &target));
    report("completion apply_doc (ZK rotation opens tree 1)", &w.env);

    assert_eq!(
        w.account(&a).applied_doc_hash().unwrap(),
        w.env.crypto().sha256(&target).to_bytes()
    );
    assert!(w.ctl().nullifier_spent(&a.address, &evidence.nullifier));
    let rotated = w
        .pool()
        .enrollment(&a.address, &BytesN::from_array(&w.env, &zk2.id))
        .unwrap();
    assert_eq!(rotated.tree_id, 1, "the rotation opened the next tree");

    // The lost passkey is revoked; the new one runs the account.
    assert!(!w.activity(&a, &a.owner));
    assert!(!w.try_apply(&a, &a.owner, &doc, 0));
    assert!(w.activity(&a, &new_owner));

    // The spent credential can never recover again, and the rotated one can,
    // from the new tree.
    let next_owner = SoftPasskey::from_seed([13; 32]);
    let zk3 = Zk {
        secret: field("lost-key secret 3"),
        id: field("lost-key enrollment 3"),
    };
    let again = w
        .ctl()
        .begin_lost_key(&a.address, &w.replacements(&next_owner, Some(&zk3)));
    let stale = w.prove(&a, &zk1, &w.statement(&a, again, EvidenceDomain::Initiate));
    assert_eq!(
        zk_err(
            w.ctl()
                .try_submit_zk(&a.address, &again, &EvidenceDomain::Initiate, &stale)
        ),
        RecoveryError::ZkEvidenceRejected,
        "the consumed credential is no longer the enrolled binding"
    );
    let fresh = w.prove(&a, &zk2, &w.statement(&a, again, EvidenceDomain::Initiate));
    w.ctl()
        .submit_zk(&a.address, &again, &EvidenceDomain::Initiate, &fresh);
    report("submit_zk (proof from the rolled-over tree)", &w.env);
}

/// `Combined` under `Protected`: guardians and a real proof authorize an
/// attempt, the account freezes on every path, and the enrolled condition's
/// cancellation (guardian quorum and a real `Cancel` proof) lifts it.
#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn protected_combined_freeze_and_cancellation_with_real_proofs() {
    let w = world();
    let a = w.new_account(SoftPasskey::from_seed([21; 32]));
    let zk = Zk {
        secret: field("combined secret"),
        id: field("combined enrollment"),
    };
    let rec = Rec {
        profile: "protected",
        mode: Mode::Combined,
        zk: Some(zk.clone()),
        delay: DELAY,
        baseline: None,
    };
    assert!(w.try_apply(&a, &a.owner, &w.doc(&a.owner, Some(&rec)), 0));
    report("enroll Combined through apply_doc", &w.env);

    let thief_key = SoftPasskey::from_seed([22; 32]);
    let zk2 = Zk {
        secret: field("combined thief secret"),
        id: field("combined thief enrollment"),
    };
    let attempt = w
        .ctl()
        .begin_lost_key(&a.address, &w.replacements(&thief_key, Some(&zk2)));
    // Collecting attempts freeze nothing.
    assert!(w.activity(&a, &a.owner));

    w.guardian(0, &a, attempt, EvidenceDomain::Initiate);
    report("submit_guardian (Combined, not promoting)", &w.env);
    w.guardian(1, &a, attempt, EvidenceDomain::Initiate);
    let evidence = w.prove(&a, &zk, &w.statement(&a, attempt, EvidenceDomain::Initiate));
    w.ctl()
        .submit_zk(&a.address, &attempt, &EvidenceDomain::Initiate, &evidence);
    report("submit_zk (promoting, Combined, sets the freeze)", &w.env);

    // Frozen on every path: direct authorization, execute, apply_doc.
    assert!(
        !w.activity(&a, &a.owner),
        "direct authorization while frozen"
    );
    assert!(!w.execute(&a, &a.owner), "execute while frozen");
    assert!(
        !w.try_apply(&a, &a.owner, &w.doc(&a.owner, None), 0),
        "apply_doc while frozen"
    );

    // An initiation proof is not a cancellation proof.
    assert_eq!(
        zk_err(
            w.ctl()
                .try_submit_zk(&a.address, &attempt, &EvidenceDomain::Cancel, &evidence)
        ),
        RecoveryError::ZkEvidenceRejected
    );
    w.guardian(0, &a, attempt, EvidenceDomain::Cancel);
    w.guardian(2, &a, attempt, EvidenceDomain::Cancel);
    let cancel = w.prove(&a, &zk, &w.statement(&a, attempt, EvidenceDomain::Cancel));
    w.ctl()
        .submit_zk(&a.address, &attempt, &EvidenceDomain::Cancel, &cancel);
    report(
        "cancellation (Combined: ZK last, clears the freeze)",
        &w.env,
    );

    assert!(!w.ctl().attempt_live(&a.address, &attempt));
    assert!(w.activity(&a, &a.owner), "the freeze is lifted");
    assert!(w.execute(&a, &a.owner));

    // Reconfiguring a Combined account needs both factors' evidence.
    let next = Rec {
        delay: DELAY * 2,
        ..rec.clone()
    };
    let next_doc = w.doc(&a.owner, Some(&next));
    let valid_until = w.ledger() + EXPIRY;
    let subject = StatementSubject::Reconfigure(ConfigChange::Set(w.config_hash(&next_doc)));
    let proof = w.prove(
        &a,
        &zk,
        &w.ctl().change_statement(&a.address, &subject, &valid_until),
    );
    w.ctl()
        .submit_zk_change(&a.address, &subject, &valid_until, &proof);
    assert!(
        !w.try_apply(&a, &a.owner, &next_doc, valid_until),
        "ZK alone"
    );
    w.approve_change(0, &a, &subject, valid_until);
    assert!(
        !w.try_apply(&a, &a.owner, &next_doc, valid_until),
        "one approval short of the quorum"
    );
    w.approve_change(1, &a, &subject, valid_until);
    report("approve_change (Reconfigure, one guardian)", &w.env);
    assert!(w.try_apply(&a, &a.owner, &next_doc, valid_until));
    report("Protected Combined reconfiguration apply_doc", &w.env);
}

/// `ZkOnly` under `Protected`: reconfiguration and an upgrade each need a
/// real proof over their own `Reconfigure`/`Upgrade` statement.
#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn protected_reconfiguration_and_upgrade_need_real_proofs() {
    let w = world();
    let a = w.new_account(SoftPasskey::from_seed([31; 32]));
    let zk = Zk {
        secret: field("protected secret"),
        id: field("protected enrollment"),
    };
    let rec = Rec {
        profile: "protected",
        mode: Mode::Zk,
        zk: Some(zk.clone()),
        delay: DELAY,
        baseline: None,
    };
    assert!(w.try_apply(&a, &a.owner, &w.doc(&a.owner, Some(&rec)), 0));

    // A longer delay: a reconfiguration.
    let next = Rec {
        delay: DELAY * 2,
        ..rec.clone()
    };
    let next_doc = w.doc(&a.owner, Some(&next));
    let valid_until = w.ledger() + EXPIRY;
    assert!(
        !w.try_apply(&a, &a.owner, &next_doc, valid_until),
        "owner alone cannot reconfigure under Protected"
    );

    // A proof for some other configuration does not count.
    let other = Rec {
        delay: DELAY * 3,
        ..rec.clone()
    };
    let other_subject = StatementSubject::Reconfigure(ConfigChange::Set(
        w.config_hash(&w.doc(&a.owner, Some(&other))),
    ));
    let other_statement = w
        .ctl()
        .change_statement(&a.address, &other_subject, &valid_until);
    let other_proof = w.prove(&a, &zk, &other_statement);
    let subject = StatementSubject::Reconfigure(ConfigChange::Set(w.config_hash(&next_doc)));
    assert_eq!(
        zk_err(
            w.ctl()
                .try_submit_zk_change(&a.address, &subject, &valid_until, &other_proof)
        ),
        RecoveryError::ZkEvidenceRejected
    );
    // Recording the other configuration's proof approves only that one.
    w.ctl()
        .submit_zk_change(&a.address, &other_subject, &valid_until, &other_proof);
    assert!(!w.try_apply(&a, &a.owner, &next_doc, valid_until));

    let statement = w.ctl().change_statement(&a.address, &subject, &valid_until);
    let proof = w.prove(&a, &zk, &statement);
    w.ctl()
        .submit_zk_change(&a.address, &subject, &valid_until, &proof);
    report("submit_zk_change (Reconfigure)", &w.env);
    assert!(w.try_apply(&a, &a.owner, &next_doc, valid_until));
    report("Protected reconfiguration apply_doc", &w.env);
    assert_eq!(w.ctl().config(&a.address).unwrap().delay_ledgers, DELAY * 2);

    // An upgrade to the stack's own account wasm: the condition approves
    // the exact request id and wasm hash.
    let wasm_hash = w
        .env
        .crypto()
        .sha256(&Bytes::from_slice(&w.env, &w.stack.wasm["perch-account"]))
        .to_bytes();
    let request_id = w.account(&a).next_upgrade_request_id();
    let valid_until = w.ledger() + EXPIRY;
    let subject = StatementSubject::Upgrade(UpgradeSubject {
        request_id,
        wasm_hash: wasm_hash.clone(),
    });
    let schedule = |w: &World| -> bool {
        let root = w.invocation(
            &a.address,
            "schedule_upgrade",
            std::vec![w.sc(wasm_hash.clone()), w.sc(valid_until)],
        );
        w.env
            .set_auths(&[w.passkey_entry(&a.address, &a.owner, "admin", root)]);
        let ok = matches!(
            w.account(&a).try_schedule_upgrade(&wasm_hash, &valid_until),
            Ok(Ok(_))
        );
        w.env.set_auths(&[]);
        ok
    };
    assert!(!schedule(&w), "owner alone cannot schedule under Protected");
    let proof = w.prove(
        &a,
        &zk,
        &w.ctl().change_statement(&a.address, &subject, &valid_until),
    );
    w.ctl()
        .submit_zk_change(&a.address, &subject, &valid_until, &proof);
    report("submit_zk_change (Upgrade)", &w.env);
    assert!(schedule(&w));
    report("Protected schedule_upgrade", &w.env);

    let execute = |w: &World| -> Result<(), Option<perch_account::PerchAccountError>> {
        let root = w.invocation(&a.address, "execute_upgrade", std::vec![w.sc(request_id)]);
        w.env
            .set_auths(&[w.passkey_entry(&a.address, &a.owner, "admin", root)]);
        let out = w.account(&a).try_execute_upgrade(&request_id);
        w.env.set_auths(&[]);
        match out {
            Ok(Ok(())) => Ok(()),
            Err(Ok(e)) => Err(Some(e)),
            _ => Err(None),
        }
    };
    assert_eq!(
        execute(&w),
        Err(Some(perch_account::PerchAccountError::UpgradeNotReady)),
        "the seven-day delay has not elapsed"
    );
    w.advance(perch_recovery_interface::account::ACCOUNT_UPGRADE_DELAY_LEDGERS);
    assert_eq!(execute(&w), Ok(()));
    report("execute_upgrade (bumps the epoch)", &w.env);
    // The upgrade bumped the epoch: the reconfiguration approvals are dead.
    assert_eq!(w.ctl().epoch(&a.address), 3);
}

/// `GuardianOnly` under `Loss`: no ZK enrollment, proof, or pool access
/// anywhere on the path, and the owner can always veto.
#[test]
#[ignore = "needs the built stack"]
fn guardian_only_recovery_needs_no_zk_and_the_loss_owner_can_veto() {
    let w = world();
    let a = w.new_account(SoftPasskey::from_seed([41; 32]));
    let rec = Rec {
        profile: "loss",
        mode: Mode::Guardian,
        zk: None,
        delay: DELAY,
        baseline: None,
    };
    assert!(w.try_apply(&a, &a.owner, &w.doc(&a.owner, Some(&rec)), 0));
    report("enroll GuardianOnly through apply_doc", &w.env);

    let new_owner = SoftPasskey::from_seed([42; 32]);
    let replacements = w.replacements(&new_owner, None);

    // The owner vetoes a quorum-authorized attempt.
    let vetoed = w.ctl().begin_lost_key(&a.address, &replacements);
    w.guardian(0, &a, vetoed, EvidenceDomain::Initiate);
    w.guardian(1, &a, vetoed, EvidenceDomain::Initiate);
    report("submit_guardian (promoting, GuardianOnly)", &w.env);
    let root = w.invocation(&a.address, "cancel_recovery", std::vec![w.sc(vetoed)]);
    w.env
        .set_auths(&[w.passkey_entry(&a.address, &a.owner, "admin", root)]);
    w.account(&a).cancel_recovery(&vetoed);
    w.env.set_auths(&[]);
    report("Loss owner cancel_recovery", &w.env);

    let attempt = w.ctl().begin_lost_key(&a.address, &replacements);
    w.guardian(1, &a, attempt, EvidenceDomain::Initiate);
    w.guardian(2, &a, attempt, EvidenceDomain::Initiate);
    w.advance(DELAY);
    assert!(w.try_complete(&a, &w.target_bytes(&a, &replacements)));
    report("completion apply_doc (GuardianOnly)", &w.env);
    assert!(w.activity(&a, &new_owner));
    assert!(!w.activity(&a, &a.owner));
}

/// `Combined` under `Loss`: guardians and a real proof authorize, ordinary
/// activity continues, and the completion spends the nullifier and rotates
/// the ZK credential.
#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn combined_loss_lost_key_recovery_rotates_the_zk_credential() {
    let w = world();
    let a = w.new_account(SoftPasskey::from_seed([51; 32]));
    let zk1 = Zk {
        secret: field("combined loss secret 1"),
        id: field("combined loss enrollment 1"),
    };
    let rec = Rec {
        profile: "loss",
        mode: Mode::Combined,
        zk: Some(zk1.clone()),
        delay: DELAY,
        baseline: None,
    };
    assert!(w.try_apply(&a, &a.owner, &w.doc(&a.owner, Some(&rec)), 0));

    let new_owner = SoftPasskey::from_seed([52; 32]);
    let zk2 = Zk {
        secret: field("combined loss secret 2"),
        id: field("combined loss enrollment 2"),
    };
    let replacements = w.replacements(&new_owner, Some(&zk2));
    let attempt = w.ctl().begin_lost_key(&a.address, &replacements);
    w.guardian(0, &a, attempt, EvidenceDomain::Initiate);
    let evidence = w.prove(
        &a,
        &zk1,
        &w.statement(&a, attempt, EvidenceDomain::Initiate),
    );
    w.ctl()
        .submit_zk(&a.address, &attempt, &EvidenceDomain::Initiate, &evidence);
    assert_eq!(
        w.ctl().activity_gate(&a.address).authorized_attempt,
        None,
        "one guardian short"
    );
    w.guardian(1, &a, attempt, EvidenceDomain::Initiate);
    report(
        "submit_guardian (promoting, Combined: ZK already in)",
        &w.env,
    );
    assert!(w.activity(&a, &a.owner), "Loss keeps ordinary activity");

    w.advance(DELAY);
    assert!(w.try_complete(&a, &w.target_bytes(&a, &replacements)));
    report("completion apply_doc (Combined, ZK rotation)", &w.env);
    assert!(w.ctl().nullifier_spent(&a.address, &evidence.nullifier));
    assert!(w
        .pool()
        .enrollment(&a.address, &BytesN::from_array(&w.env, &zk2.id))
        .is_some());
    assert!(w.activity(&a, &new_owner));
    assert!(!w.activity(&a, &a.owner));
}

/// `GuardianOnly` under `Protected`, compromise recovery: a thief holding
/// the owner key adds a signer; the guardians restore the enrolled baseline
/// with a new owner key, and both the stolen key and the thief's signer are
/// revoked for good.
#[test]
#[ignore = "needs the built stack"]
fn guardian_protected_compromise_restores_the_baseline_and_revokes_the_thief() {
    let w = world();
    let a = w.new_account(SoftPasskey::from_seed([61; 32]));
    let baseline = w.doc(&a.owner, None);
    let rec = Rec {
        profile: "protected",
        mode: Mode::Guardian,
        zk: None,
        delay: DELAY,
        baseline: Some(w.doc_hash(&baseline)),
    };
    assert!(w.try_apply(&a, &a.owner, &w.doc(&a.owner, Some(&rec)), 0));

    // The thief signs with the stolen owner key. Adding a signer changes no
    // recovery text, so Protected asks for no condition.
    let thief = SoftPasskey::from_seed([62; 32]);
    let stolen = w.doc_with(&a.owner, Some(&thief), Some(&rec));
    assert!(w.try_apply(&a, &a.owner, &stolen, 0));
    assert!(w.activity_via(&a, &thief, "thief"));

    let new_owner = SoftPasskey::from_seed([63; 32]);
    let replacements = w.replacements(&new_owner, None);
    assert_eq!(
        w.ctl().try_begin_compromise(&a.address, &replacements),
        Err(Ok(RecoveryError::BaselineNotPublished))
    );
    assert_eq!(
        w.ctl().try_publish_baseline(&a.address, &stolen),
        Err(Ok(RecoveryError::BaselineMismatch))
    );
    w.ctl().publish_baseline(&a.address, &baseline);
    report("publish_baseline", &w.env);
    let attempt = w.ctl().begin_compromise(&a.address, &replacements);
    report("begin_compromise", &w.env);
    w.guardian(0, &a, attempt, EvidenceDomain::Initiate);
    w.guardian(1, &a, attempt, EvidenceDomain::Initiate);
    report(
        "submit_guardian (promoting, Protected: sets the freeze)",
        &w.env,
    );
    assert!(
        !w.activity_via(&a, &thief, "thief"),
        "frozen for the thief too"
    );

    w.advance(DELAY);
    assert!(w.try_complete(&a, &w.compromise_target(&a, &replacements)));
    report(
        "completion apply_doc (compromise: revokes the stolen and added keys)",
        &w.env,
    );

    assert!(w.activity(&a, &new_owner));
    assert!(!w.activity(&a, &a.owner));
    assert!(
        w.find_rule(&a.address, "thief").is_none(),
        "the baseline has no thief rule"
    );
    assert!(!w.activity(&a, &thief));
    // Neither revoked credential can come back, even signed by the new owner.
    assert!(!w.try_apply(
        &a,
        &new_owner,
        &w.doc_with(&new_owner, Some(&thief), Some(&rec)),
        0
    ));
    assert!(!w.try_apply(&a, &new_owner, &w.doc(&a.owner, Some(&rec)), 0));
}

// ---------------------------------------------------------------------------
// Worst cases at the document caps (docs/recovery/budgets.md §2)
// ---------------------------------------------------------------------------

/// The costliest document the caps admit: every signer a passkey some rule
/// names (as many per rule as OZ allows), and every rule but `admin` and
/// `target` carrying both policies. Each named signer is an OZ registry
/// entry and a registration event, each policy an install and an
/// uninstall: what a completion's footprint, events, and memory grow with.
fn worst_shape() -> Shape {
    Shape {
        signers: MAX_DOC_SIGNERS as usize,
        both: MAX_DOC_RULES - 2,
        interp: 0,
        plain: 0,
        fan: (MAX_DOC_SIGNERS as usize).min(OZ_MAX_SIGNERS as usize),
        tag: "",
    }
}

fn label(shape: Shape, what: &str) -> String {
    format!(
        "{what} [{} signers, {} rules, {} with both policies, {} per rule]",
        shape.signers,
        shape.rules(),
        shape.both,
        shape.fan
    )
}

/// `Combined` lost-key recovery of a `shape` document under `Loss`, every
/// signer replaced: enrollment, `begin_lost_key`, and the completion that
/// compiles the target, replaces every rule with its policies, revokes
/// every replaced credential, and rotates the ZK credential.
fn worst_lost_key(w: &World, shape: Shape, bytes: usize, seed: u8) {
    let keys = passkeys(seed, shape.signers);
    let a = w.new_account(passkeys(seed, 1).swap_remove(0));
    let zk1 = Zk {
        secret: field(&format!("worst lost-key {seed} 1")),
        id: field(&format!("worst lost-key id {seed} 1")),
    };
    let rec = Rec {
        profile: "loss",
        mode: Mode::Combined,
        zk: Some(zk1.clone()),
        delay: DELAY,
        baseline: None,
    };
    let doc = w.shaped_doc(&keys, &rec, shape, bytes, true);
    assert!(w.try_apply(&a, &keys[0], &doc, 0));
    report(&label(shape, "enroll Combined through apply_doc"), &w.env);

    let new_keys = passkeys(seed + 1, shape.signers);
    let zk2 = Zk {
        secret: field(&format!("worst lost-key {seed} 2")),
        id: field(&format!("worst lost-key id {seed} 2")),
    };
    let replacements = w.replacing_all(&new_keys, Some(&zk2));
    let attempt = w.ctl().begin_lost_key(&a.address, &replacements);
    report(&label(shape, "begin_lost_key"), &w.env);
    let target = w.target_bytes(&a, &replacements);
    w.assert_shape(&target, shape);

    let evidence = w.prove(
        &a,
        &zk1,
        &w.statement(&a, attempt, EvidenceDomain::Initiate),
    );
    w.ctl()
        .submit_zk(&a.address, &attempt, &EvidenceDomain::Initiate, &evidence);
    w.guardian(0, &a, attempt, EvidenceDomain::Initiate);
    w.guardian(1, &a, attempt, EvidenceDomain::Initiate);
    w.advance(DELAY);
    assert!(w.try_complete(&a, &target));
    report(
        &label(
            shape,
            "completion apply_doc (Combined, ZK rotation, every signer revoked)",
        ),
        &w.env,
    );
    assert!(w.all_revoked(&a, &keys));
    assert!(w.ctl().nullifier_spent(&a.address, &evidence.nullifier));
    assert!(w
        .pool()
        .enrollment(&a.address, &BytesN::from_array(&w.env, &zk2.id))
        .is_some());
    assert!(w.activity(&a, &new_keys[0]));
    assert!(!w.activity(&a, &keys[0]));
}

/// What a compromise thief changes besides every signer's key, which
/// decides how the completion's diff goes.
#[derive(Clone, Copy)]
enum Thief {
    /// Nothing else: every rule keeps its slot, and the reconcile takes each
    /// rule's cheaper path.
    KeepNames,
    /// Every rule's name: every rule is removed and added.
    Rename,
    /// Every interpreter program and every spending cap, names kept.
    Reparam,
    /// Every interpreter program, names kept.
    Reprogram,
    /// Every spending cap, names kept.
    Recap,
}

impl Thief {
    fn tag(self) -> &'static str {
        match self {
            Thief::Rename => "t",
            _ => "",
        }
    }

    /// What [`REPARAM`] is set to while the thief's document is built.
    fn edits(self) -> (bool, bool) {
        match self {
            Thief::Reparam => (true, true),
            Thief::Reprogram => (true, false),
            Thief::Recap => (false, true),
            Thief::KeepNames | Thief::Rename => (false, false),
        }
    }

    fn how(self) -> &'static str {
        match self {
            Thief::KeepNames => "the thief kept every rule",
            Thief::Rename => "the thief renamed every rule",
            Thief::Reparam => "the thief kept every name, changed every program and cap",
            Thief::Reprogram => "the thief kept every name, changed every program",
            Thief::Recap => "the thief kept every name, changed every cap",
        }
    }
}

/// `Combined` compromise recovery of a `shape` document under `Protected`,
/// revoking the most a completion can: a thief holding the owner key swaps
/// every signer's key (no recovery text changes, so no condition), and the
/// completion restores the baseline with new keys, revoking the replaced
/// baseline credentials and every key the thief added. The thief chooses
/// how the completion's diff goes ([`Thief`]): keeping every rule's name
/// leaves each rule's path to the reconcile; renaming every rule forces
/// every rule to be removed and added; keeping names while changing every
/// program, cap, or both forces every policy to be reinstalled whichever
/// path the reconcile takes. All are measured.
fn worst_compromise(w: &World, shape: Shape, bytes: usize, seed: u8, variant: Thief) {
    let thief_tag = variant.tag();
    let keys = passkeys(seed, shape.signers);
    let a = w.new_account(passkeys(seed, 1).swap_remove(0));
    let zk1 = Zk {
        secret: field(&format!("worst compromise {seed} 1")),
        id: field(&format!("worst compromise id {seed} 1")),
    };
    let mut rec = Rec {
        profile: "protected",
        mode: Mode::Combined,
        zk: Some(zk1.clone()),
        delay: DELAY,
        // Sized with a baseline hash of the real one's length.
        baseline: Some(BytesN::from_array(&w.env, &[0; 32])),
    };
    let baseline = w.shaped_doc(&keys, &rec, shape, bytes, false);
    rec.baseline = Some(w.doc_hash(&baseline));
    assert!(w.try_apply(
        &a,
        &keys[0],
        &w.shaped_doc(&keys, &rec, shape, bytes, true),
        0
    ));

    let thief = passkeys(seed + 1, shape.signers);
    let stolen = Shape {
        tag: thief_tag,
        ..shape
    };
    let thief_rule = format!("{thief_tag}target");
    let how = variant.how();
    REPARAM.with(|r| r.set(variant.edits()));
    let stolen_doc = w.shaped_doc(&thief, &rec, stolen, bytes, true);
    REPARAM.with(|r| r.set((false, false)));
    assert!(w.try_apply(&a, &keys[0], &stolen_doc, 0));
    report(
        &label(
            shape,
            &format!("Protected apply_doc (every key swapped, no condition; {how})"),
        ),
        &w.env,
    );
    w.ctl().publish_baseline(&a.address, &baseline);
    report(&label(shape, "publish_baseline"), &w.env);

    let new_keys = passkeys(seed + 2, shape.signers);
    let zk2 = Zk {
        secret: field(&format!("worst compromise {seed} 2")),
        id: field(&format!("worst compromise id {seed} 2")),
    };
    let replacements = w.replacing_all(&new_keys, Some(&zk2));
    let attempt = w.ctl().begin_compromise(&a.address, &replacements);
    report(&label(shape, "begin_compromise"), &w.env);
    let target = w.compromise_target(&a, &replacements);
    w.assert_shape(&target, shape);

    let evidence = w.prove(
        &a,
        &zk1,
        &w.statement(&a, attempt, EvidenceDomain::Initiate),
    );
    w.ctl()
        .submit_zk(&a.address, &attempt, &EvidenceDomain::Initiate, &evidence);
    w.guardian(0, &a, attempt, EvidenceDomain::Initiate);
    w.guardian(1, &a, attempt, EvidenceDomain::Initiate);
    assert!(!w.activity_via(&a, &thief[0], &thief_rule), "frozen");
    w.advance(DELAY);
    assert!(w.try_complete(&a, &target));
    report(
        &label(
            shape,
            &format!("completion apply_doc (compromise, Combined, ZK rotation, both key sets revoked; {how})"),
        ),
        &w.env,
    );
    assert!(w.all_revoked(&a, &keys), "every replaced baseline key");
    assert!(w.all_revoked(&a, &thief), "every key the thief added");
    assert!(w.activity(&a, &new_keys[0]));
    assert!(!w.activity(&a, &keys[0]));
    assert!(!w.activity_via(&a, &thief[0], &thief_rule));
}

/// A `Protected` `Combined` reconfiguration of a `shape` document: the
/// recorded guardian quorum and proof are read, every signer's key changes
/// (so `apply_doc`'s diff keeps nothing) and, with `next_tag`, every rule's
/// name too (so it replaces every rule instead of editing it), and the new
/// configuration enrolls a new ZK credential (a pool insert).
fn worst_reconfiguration(w: &World, shape: Shape, bytes: usize, seed: u8, next_tag: &'static str) {
    let keys = passkeys(seed, shape.signers);
    let a = w.new_account(passkeys(seed, 1).swap_remove(0));
    let zk1 = Zk {
        secret: field(&format!("worst reconfiguration {seed} 1")),
        id: field(&format!("worst reconfiguration id {seed} 1")),
    };
    let rec = Rec {
        profile: "protected",
        mode: Mode::Combined,
        zk: Some(zk1.clone()),
        delay: DELAY,
        baseline: None,
    };
    assert!(w.try_apply(
        &a,
        &keys[0],
        &w.shaped_doc(&keys, &rec, shape, bytes, true),
        0
    ));

    let zk2 = Zk {
        secret: field(&format!("worst reconfiguration {seed} 2")),
        id: field(&format!("worst reconfiguration id {seed} 2")),
    };
    let next = Rec {
        zk: Some(zk2.clone()),
        delay: DELAY * 2,
        ..rec.clone()
    };
    let next_doc = w.shaped_doc(
        &passkeys(seed + 1, shape.signers),
        &next,
        Shape {
            tag: next_tag,
            ..shape
        },
        bytes,
        true,
    );
    let valid_until = w.ledger() + EXPIRY;
    assert!(!w.try_apply(&a, &keys[0], &next_doc, valid_until));
    let subject = StatementSubject::Reconfigure(ConfigChange::Set(w.config_hash(&next_doc)));
    w.approve_change(0, &a, &subject, valid_until);
    w.approve_change(1, &a, &subject, valid_until);
    let statement = w.ctl().change_statement(&a.address, &subject, &valid_until);
    let proof = w.prove(&a, &zk1, &statement);
    w.ctl()
        .submit_zk_change(&a.address, &subject, &valid_until, &proof);
    assert!(w.try_apply(&a, &keys[0], &next_doc, valid_until));
    report(
        &label(
            shape,
            &format!(
                "Protected reconfiguration apply_doc (Combined: recorded quorum and proof, a new enrollment; {})",
                if next_tag.is_empty() { "every rule edited" } else { "every rule replaced" }
            ),
        ),
        &w.env,
    );
    assert_eq!(w.ctl().config(&a.address).unwrap().delay_ledgers, DELAY * 2);
    assert!(w
        .pool()
        .enrollment(&a.address, &BytesN::from_array(&w.env, &zk2.id))
        .is_some());
}

#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn worst_case_lost_key_recovery_at_the_document_caps() {
    worst_lost_key(
        &world(),
        worst_shape(),
        MAX_DOC_CANONICAL_BYTES as usize,
        70,
    );
}

fn worst_compromise_in_place(w: &World, shape: Shape, bytes: usize, seed: u8) {
    worst_compromise(w, shape, bytes, seed, Thief::KeepNames)
}

fn worst_compromise_renamed(w: &World, shape: Shape, bytes: usize, seed: u8) {
    worst_compromise(w, shape, bytes, seed, Thief::Rename)
}

fn worst_compromise_reparam(w: &World, shape: Shape, bytes: usize, seed: u8) {
    worst_compromise(w, shape, bytes, seed, Thief::Reparam)
}

fn worst_compromise_reprogram(w: &World, shape: Shape, bytes: usize, seed: u8) {
    worst_compromise(w, shape, bytes, seed, Thief::Reprogram)
}

fn worst_compromise_recap(w: &World, shape: Shape, bytes: usize, seed: u8) {
    worst_compromise(w, shape, bytes, seed, Thief::Recap)
}

fn worst_reconfiguration_in_place(w: &World, shape: Shape, bytes: usize, seed: u8) {
    worst_reconfiguration(w, shape, bytes, seed, "")
}

fn worst_reconfiguration_renamed(w: &World, shape: Shape, bytes: usize, seed: u8) {
    worst_reconfiguration(w, shape, bytes, seed, "n")
}

/// A worst-case flow over a document shape, padded to some bytes, from a seed.
type Flow = fn(&World, Shape, usize, u8);

/// Every worst-case flow: both ways a diff can go, and the keep-names
/// thieves that force every policy to be reinstalled. `PERCH_FLOWS` selects
/// by index in [`cap_sweep`].
const WORST_FLOWS: [Flow; 8] = [
    worst_lost_key,
    worst_compromise_in_place,
    worst_compromise_renamed,
    worst_reconfiguration_in_place,
    worst_reconfiguration_renamed,
    worst_compromise_reparam,
    worst_compromise_reprogram,
    worst_compromise_recap,
];

#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn worst_case_compromise_at_the_document_caps_edits_every_rule() {
    worst_compromise_in_place(
        &world(),
        worst_shape(),
        MAX_DOC_CANONICAL_BYTES as usize,
        80,
    );
}

#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn worst_case_compromise_at_the_document_caps_replaces_every_rule() {
    worst_compromise_renamed(
        &world(),
        worst_shape(),
        MAX_DOC_CANONICAL_BYTES as usize,
        85,
    );
}

#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn worst_case_compromise_at_the_document_caps_reparameterizes_every_rule() {
    worst_compromise_reparam(
        &world(),
        worst_shape(),
        MAX_DOC_CANONICAL_BYTES as usize,
        100,
    );
}

#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn worst_case_compromise_at_the_document_caps_reprograms_every_rule() {
    worst_compromise_reprogram(
        &world(),
        worst_shape(),
        MAX_DOC_CANONICAL_BYTES as usize,
        105,
    );
}

#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn worst_case_compromise_at_the_document_caps_recaps_every_rule() {
    worst_compromise_recap(
        &world(),
        worst_shape(),
        MAX_DOC_CANONICAL_BYTES as usize,
        110,
    );
}

/// The footprint `report` counts is the transaction's: every `apply_doc` of
/// the binding flows at the caps (enrollment, the thief's, and the
/// completion) is first simulated the way RPC simulation runs it, and its
/// metered footprint must equal the simulated read-only plus read-write
/// keys, its written entries the read-write keys.
#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn the_metered_footprint_is_the_simulated_transactions() {
    SIMULATE.with(|s| s.set(true));
    let flows: [(Flow, u8); 4] = [
        (worst_lost_key, 120),
        (worst_compromise_renamed, 125),
        (worst_compromise_reprogram, 130),
        (worst_reconfiguration_renamed, 135),
    ];
    for (flow, seed) in flows {
        flow(
            &world(),
            worst_shape(),
            MAX_DOC_CANONICAL_BYTES as usize,
            seed,
        );
    }
    SIMULATE.with(|s| s.set(false));
    // Each flow applies at least two documents through `apply_doc`.
    assert!(SIMULATED.with(Cell::get) >= 8);
}

#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn worst_case_protected_reconfiguration_at_the_document_caps_edits_every_rule() {
    worst_reconfiguration_in_place(
        &world(),
        worst_shape(),
        MAX_DOC_CANONICAL_BYTES as usize,
        90,
    );
}

#[test]
#[ignore = "needs the built stack and the pinned proving toolchain"]
fn worst_case_protected_reconfiguration_at_the_document_caps_replaces_every_rule() {
    worst_reconfiguration_renamed(
        &world(),
        worst_shape(),
        MAX_DOC_CANONICAL_BYTES as usize,
        95,
    );
}

// ---------------------------------------------------------------------------
// Signer transitions: one `apply_doc` that changes a rule's signers
// ---------------------------------------------------------------------------

/// One `apply_doc` that changes `pay`'s signers (passkeys by index), with
/// `admin` naming `owner` and, when given, a second rule `work` that keeps
/// its signers throughout.
struct Transition {
    name: &'static str,
    owner: (usize, usize),
    pay: (&'static [usize], &'static [usize]),
    work: Option<&'static [usize]>,
    /// `pay` is scoped to a token with a spending cap, part of which is spent
    /// before the transition.
    capped: bool,
}

const TRANSITIONS: &[Transition] = &[
    Transition {
        name: "single addition",
        owner: (0, 0),
        pay: (&[0, 1, 2], &[0, 1, 2, 3]),
        work: None,
        capped: false,
    },
    Transition {
        name: "several additions",
        owner: (0, 0),
        pay: (&[0, 1], &[0, 1, 2, 3, 4]),
        work: None,
        capped: false,
    },
    Transition {
        name: "full six-key rotation",
        owner: (0, 6),
        pay: (&[0, 1, 2, 3, 4, 5], &[6, 7, 8, 9, 10, 11]),
        work: None,
        capped: false,
    },
    Transition {
        name: "one swap at the signer cap",
        owner: (0, 0),
        pay: (&[0, 1, 2, 3, 4, 5], &[0, 1, 2, 3, 4, 6]),
        work: None,
        capped: false,
    },
    Transition {
        name: "five swaps at the signer cap",
        owner: (0, 0),
        pay: (&[0, 1, 2, 3, 4, 5], &[0, 6, 7, 8, 9, 10]),
        work: None,
        capped: false,
    },
    Transition {
        name: "shared signers",
        owner: (0, 0),
        pay: (&[0, 1, 2], &[0, 1, 3, 4]),
        work: Some(&[1, 2, 3]),
        capped: false,
    },
    Transition {
        name: "full rotation with an active spending cap",
        owner: (0, 6),
        pay: (&[0, 1, 2, 3, 4, 5], &[6, 7, 8, 9, 10, 11]),
        work: None,
        capped: true,
    },
    Transition {
        name: "one swap at OZ's 15",
        owner: (0, 0),
        pay: (
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15],
        ),
        work: None,
        capped: false,
    },
    Transition {
        name: "seven swaps at OZ's 15",
        owner: (0, 0),
        pay: (
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
            &[0, 1, 2, 3, 4, 5, 6, 7, 15, 16, 17, 18, 19, 20, 21],
        ),
        work: None,
        capped: false,
    },
];

fn tkey(i: usize) -> SoftPasskey {
    let mut s = [0x61; 32];
    s[1] = i as u8;
    SoftPasskey::from_seed(s)
}

impl Transition {
    /// Every key the document declares before (`false`) or after (`true`).
    fn declared(&self, after: bool) -> std::vec::Vec<usize> {
        let (owner, pay) = if after {
            (self.owner.1, self.pay.1)
        } else {
            (self.owner.0, self.pay.0)
        };
        let mut ids: std::vec::Vec<usize> = std::iter::once(owner)
            .chain(pay.iter().copied())
            .chain(self.work.into_iter().flatten().copied())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    fn doc(&self, w: &World, token: &Address, after: bool) -> Bytes {
        let (owner, pay) = if after {
            (self.owner.1, self.pay.1)
        } else {
            (self.owner.0, self.pay.0)
        };
        let signers: std::vec::Vec<(String, std::vec::Vec<u8>)> = self
            .declared(after)
            .into_iter()
            .map(|i| (format!("k{i}"), tkey(i).key_data()))
            .collect();
        let ids = |set: &[usize]| -> std::vec::Vec<String> {
            set.iter().map(|i| format!("k{i}")).collect()
        };
        w.transition_doc(
            token,
            &signers,
            &format!("k{owner}"),
            &ids(pay),
            self.work.map(ids).as_deref(),
            self.capped,
        )
    }
}

/// The signer `key` is as the account installs it.
fn passkey_signer(w: &World, key: &[u8]) -> Signer {
    Signer::External(w.webauthn.clone(), Bytes::from_slice(&w.env, key))
}

impl World {
    /// A document declaring `signers` (id, passkey key data), with `admin`
    /// naming `owner` and 1-of-n rules `pay` (scoped to `token` with a
    /// spending cap when `capped`, else to the target) and `work` (the
    /// target).
    fn transition_doc(
        &self,
        token: &Address,
        signers: &[(String, std::vec::Vec<u8>)],
        owner: &str,
        pay: &[String],
        work: Option<&[String]>,
        capped: bool,
    ) -> Bytes {
        let declared: std::vec::Vec<String> = signers
            .iter()
            .map(|(id, key)| {
                format!(
                    r#"{{"id":"{id}","verifier":"{}","key":"{}"}}"#,
                    strkey(&self.webauthn),
                    hex(key)
                )
            })
            .collect();
        let named = |set: &[String]| -> String {
            set.iter()
                .map(|id| format!(r#""{id}""#))
                .collect::<std::vec::Vec<_>>()
                .join(",")
        };
        let scope =
            |a: &Address| format!(r#""scope":{{"type":"contract","address":"{}"}}"#, strkey(a));
        let mut rules = std::vec![format!(
            r#"{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["{owner}"]}}}}"#
        )];
        let (pay_scope, cap) = if capped {
            (
                scope(token),
                r#","cap":{"limit":"100","period-ledgers":1000}"#,
            )
        } else {
            (scope(&self.target), "")
        };
        rules.push(format!(
            r#"{{"name":"pay",{pay_scope},"principals":{{"type":"threshold","m":1,"signers":[{}]}}{cap}}}"#,
            named(pay)
        ));
        if let Some(work) = work {
            rules.push(format!(
                r#"{{"name":"work",{},"principals":{{"type":"threshold","m":1,"signers":[{}]}}}}"#,
                scope(&self.target),
                named(work)
            ));
        }
        let json = format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
            declared.join(","),
            rules.join(","),
        );
        Bytes::from_slice(&self.env, json.as_bytes())
    }

    /// A token the account holds 1 000 of.
    fn funded_token(&self, a: &Acct) -> Address {
        let token = self
            .env
            .register_stellar_asset_contract_v2(self.guardians[0].clone())
            .address();
        self.env.mock_all_auths();
        StellarAssetClient::new(&self.env, &token).mint(&a.address, &1_000);
        self.env.set_auths(&[]);
        token
    }

    /// `key` authorizes a transfer of `amount` of `token` through `pay`.
    fn spend(&self, a: &Acct, key: &SoftPasskey, token: &Address, amount: i128) -> bool {
        let to = self.guardians[1].clone();
        let root = self.invocation(
            token,
            "transfer",
            std::vec![
                self.sc(a.address.clone()),
                self.sc(to.clone()),
                self.sc(amount)
            ],
        );
        self.env
            .set_auths(&[self.passkey_entry(&a.address, key, "pay", root)]);
        let ok = TokenClient::new(&self.env, token)
            .try_transfer(&a.address, &to, &amount)
            .is_ok();
        self.env.set_auths(&[]);
        ok
    }

    /// The spending-limit policy's window for rule `id`, if it has one.
    fn window(&self, a: &Acct, id: u32) -> Option<SpendingLimitData> {
        self.env.as_contract(&self.spending_limit, || {
            self.env
                .storage()
                .persistent()
                .get(&SpendingLimitStorageKey::AccountContext(
                    a.address.clone(),
                    id,
                ))
        })
    }

    /// `pay`'s id and its signers with their registry ids.
    fn pay_rule(&self, a: &Acct) -> (u32, std::vec::Vec<(Signer, u32)>) {
        let id = self.rule_id(&a.address, "pay");
        let rule = self.account(a).get_context_rule(&id);
        let signers = rule.signers.iter().zip(rule.signer_ids.iter()).collect();
        (id, signers)
    }
}

/// Run `t` on a fresh world: enroll its first document, spend part of the
/// cap when it has one, apply its second, and report the second's cost and
/// what it preserved.
fn run_transition(t: &Transition) {
    if t.declared(false).len().max(t.declared(true).len()) > MAX_DOC_SIGNERS as usize {
        println!(
            "\n{{\"transition\":\"{}\",\"skipped\":\"more than the build's {} signers\"}}",
            t.name, MAX_DOC_SIGNERS
        );
        return;
    }
    let w = world();
    let a = w.new_account(tkey(t.owner.0));
    let token = w.funded_token(&a);
    assert!(w.try_apply(&a, &tkey(t.owner.0), &t.doc(&w, &token, false), 0));
    if t.capped {
        assert!(w.spend(&a, &tkey(t.pay.0[0]), &token, 40));
    }
    let (id, before) = w.pay_rule(&a);
    let window = w.window(&a, id);

    assert!(w.try_apply(&a, &tkey(t.owner.0), &t.doc(&w, &token, true), 0));
    report(&format!("signer transition: {}", t.name), &w.env);

    // What the rule now authorizes is exactly the target set, however the
    // account got there.
    let (new_id, after) = w.pay_rule(&a);
    let mut got: std::vec::Vec<Signer> = after.iter().map(|(s, _)| s.clone()).collect();
    let mut want: std::vec::Vec<Signer> = t
        .pay
        .1
        .iter()
        .map(|&i| passkey_signer(&w, &tkey(i).key_data()))
        .collect();
    got.sort();
    want.sort();
    assert_eq!(got, want, "{}: pay's signers", t.name);
    // What the transition preserved.
    let retained: std::vec::Vec<&(Signer, u32)> = before
        .iter()
        .filter(|(s, _)| after.iter().any(|(t, _)| t == s))
        .collect();
    let ids_kept = retained
        .iter()
        .all(|(s, i)| after.iter().any(|(t, j)| t == s && j == i));
    let window_kept = match &window {
        Some(before) => w.window(&a, new_id).as_ref() == Some(before),
        None => true,
    };
    let joined = *t.pay.1.iter().rev().find(|i| !t.pay.0.contains(i)).unwrap();
    let left = t.pay.0.iter().find(|i| !t.pay.1.contains(i));
    if t.capped {
        assert!(
            w.spend(&a, &tkey(joined), &token, 1),
            "{}: a new key spends",
            t.name
        );
        if let Some(&left) = left {
            assert!(
                !w.spend(&a, &tkey(left), &token, 1),
                "{}: a removed key cannot",
                t.name
            );
        }
    } else {
        assert!(
            w.activity_via(&a, &tkey(joined), "pay"),
            "{}: a new key acts",
            t.name
        );
        if let Some(&left) = left {
            assert!(
                !w.activity_via(&a, &tkey(left), "pay"),
                "{}: a removed key cannot",
                t.name
            );
        }
    }

    println!(
        "\n{{\"transition\":\"{}\",\"path\":\"{}\",\"rule_id_kept\":{},\"retained_signers\":{},\"retained_signer_ids_kept\":{},\"spending_window\":\"{}\"}}",
        t.name,
        if new_id == id { "in place" } else { "replaced" },
        new_id == id,
        retained.len(),
        ids_kept,
        match (&window, window_kept) {
            (None, _) => "none",
            (Some(_), true) => "kept",
            (Some(_), false) => "reset",
        },
    );
}

/// Every [`TRANSITIONS`] entry the build's caps admit (the OZ-limit ones
/// need a stack built with `MAX_DOC_SIGNERS` raised to 15).
#[test]
#[ignore = "needs the built stack"]
fn signer_transitions() {
    for t in TRANSITIONS {
        run_transition(t);
    }
}

/// A transition the account refuses leaves every ledger entry as it was:
/// a duplicate key (one passkey under a second credential id), and the
/// budget running out part-way through a full rotation.
#[test]
#[ignore = "needs the built stack"]
fn a_rejected_signer_transition_changes_nothing() {
    let rotation = &TRANSITIONS[2];
    let setup = || {
        let w = world();
        let a = w.new_account(tkey(rotation.owner.0));
        let token = w.funded_token(&a);
        assert!(w.try_apply(&a, &tkey(0), &rotation.doc(&w, &token, false), 0));
        (w, a, token)
    };

    // The same passkey twice.
    let (w, a, token) = setup();
    let mut dup = tkey(1);
    dup.credential_id = std::vec![0xd0; 16];
    let signers: std::vec::Vec<(String, std::vec::Vec<u8>)> = [0, 1, 2]
        .iter()
        .map(|&i| (format!("k{i}"), tkey(i).key_data()))
        .chain(std::iter::once(("dup".to_string(), dup.key_data())))
        .collect();
    let ids: std::vec::Vec<String> = signers.iter().map(|(id, _)| id.clone()).collect();
    let duplicate = w.transition_doc(&token, &signers, "k0", &ids, None, false);
    let before = raw_entries(&w.env);
    assert!(!w.try_apply(&a, &tkey(0), &duplicate, 0));
    assert_eq!(
        raw_entries(&w.env),
        before,
        "a duplicate key changes nothing"
    );

    // The rotation's full cost, then a fresh world for each fraction of it
    // (AGENTS.md: don't chain recovered panics in one `Env`).
    let (twin, a, token) = setup();
    assert!(twin.try_apply(&a, &tkey(0), &rotation.doc(&twin, &token, true), 0));
    let cost = twin.env.cost_estimate().resources().instructions as u64;
    for percent in [25u64, 50, 75, 95] {
        let (w, a, token) = setup();
        let doc = rotation.doc(&w, &token, true);
        let before = raw_entries(&w.env);
        let root = w.invocation(
            &a.address,
            "apply_doc",
            std::vec![w.sc(doc.clone()), w.sc(0u32)],
        );
        w.env
            .set_auths(&[w.passkey_entry(&a.address, &tkey(0), "admin", root)]);
        w.env
            .cost_estimate()
            .budget()
            .reset_limits(cost * percent / 100, 1 << 30);
        let client = w.account(&a);
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.try_apply_doc(&doc, &0)
        }));
        w.env.cost_estimate().budget().reset_unlimited();
        w.env.set_auths(&[]);
        assert!(
            out.is_err() || out.as_ref().is_ok_and(|r| r.is_err()),
            "{percent}% of the budget"
        );
        assert_eq!(raw_entries(&w.env), before, "{percent}%: nothing changed");
        assert!(
            w.try_apply(&a, &tkey(0), &doc, 0),
            "{percent}%: the account still applies it"
        );
    }
}

/// Sizing the caps: every worst-case flow over the shapes in
/// `PERCH_CAP_SWEEP` (`signers,both,interp,plain,fan[,bytes];...`, bytes
/// defaulting to the byte cap; `0` is the larger of 8 192 and the shape's
/// own size rounded up to 1 KiB), with the budget and the network limits
/// lifted so a row past them still prints. A shape past this build's caps
/// or its byte target is reported and skipped: measure larger shapes on a
/// stack built with the compiler's caps raised. `scripts/cap-sweep.py`
/// runs it and tabulates the frontier.
#[test]
#[ignore = "sizing tool: PERCH_CAP_SWEEP=..."]
fn cap_sweep() {
    let spec = std::env::var("PERCH_CAP_SWEEP").unwrap_or_default();
    for (n, item) in spec.split(';').filter(|s| !s.is_empty()).enumerate() {
        let v: std::vec::Vec<usize> = item.split(',').map(|x| x.trim().parse().unwrap()).collect();
        let shape = Shape {
            signers: v[0],
            both: v[1] as u32,
            interp: v[2] as u32,
            plain: v[3] as u32,
            fan: v[4],
            tag: "",
        };
        let seed = 100 + 10 * (n % 15) as u8;
        let w = world();
        let rec = Rec {
            profile: "protected",
            mode: Mode::Combined,
            zk: Some(Zk {
                secret: field("fit"),
                id: field("fit id"),
            }),
            delay: DELAY,
            baseline: Some(BytesN::from_array(&w.env, &[0; 32])),
        };
        // Sized with a one-byte tag, as the thief's and the reconfiguration's
        // documents are.
        let own = canonical_len(&w.shaped_json(
            &passkeys(seed, shape.signers),
            &rec,
            Shape { tag: "t", ..shape },
            0,
            0,
            true,
        ));
        let bytes = match v.get(5).copied() {
            None => MAX_DOC_CANONICAL_BYTES as usize,
            Some(0) => own.div_ceil(1024).max(8) * 1024,
            Some(b) => b,
        };
        let skip = |why: &str| {
            println!(
                "\n{{\"case\":\"skipped\",\"signers\":{},\"rules\":{},\"bytes\":{bytes},\"why\":\"{why}\"}}",
                shape.signers,
                shape.rules()
            )
        };
        if shape.signers > MAX_DOC_SIGNERS as usize
            || shape.rules() > MAX_DOC_RULES
            || bytes > MAX_DOC_CANONICAL_BYTES as usize
        {
            skip("past this build's caps");
            continue;
        }
        if own > bytes {
            skip("does not fit the byte target");
            continue;
        }
        let flows = std::env::var("PERCH_FLOWS").ok();
        SIMULATE.with(|s| s.set(std::env::var_os("PERCH_SIMULATE").is_some()));
        for (i, flow) in WORST_FLOWS.iter().enumerate() {
            if let Some(flows) = &flows {
                if !flows.split(',').any(|f| f.trim().parse() == Ok(i)) {
                    continue;
                }
            }
            let w = world();
            w.env.cost_estimate().disable_resource_limits();
            UNBUDGETED.with(|u| u.set(true));
            flow(&w, shape, bytes, seed);
        }
    }
}
