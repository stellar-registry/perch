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
//! A rehearsal's stack, built from dev registry paths, adds `--skip
//! one_build_resolves_each_networks_own_registry`, which checks the canonical
//! registries.
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
use perch_account_types::{AuthPayload, Signer};
use perch_doc_compiler::{
    PerchDocCompilerClient, MAX_DOC_CANONICAL_BYTES, MAX_DOC_RULES, MAX_DOC_SIGNERS,
    MAX_GRANT_CANONICAL_BYTES, MAX_GRANT_RULES, MAX_GRANT_SIGNERS, MAX_GRANT_STORED_BYTES,
    MAX_RULE_CONSTRAINTS,
};
use perch_recovery::{EvidenceDomain, PerchRecoveryClient, RecoveryError};
use perch_recovery_interface::credential::{Credential, Replacement, ReplacementSet, ZkEnrollment};
use perch_recovery_interface::zk::{ZkAdapterClient, ZkEvidence};
use perch_recovery_interface::{
    ConfigChange, RecoveryAction, RecoveryStatement, StatementSubject, UpgradeSubject,
};
use perch_smart_account::{MAX_NAME_SIZE, MAX_SIGNERS};
use perch_testkit::delta::raw_entries;
use perch_testkit::passkey::{auth_entry, auth_entry_for_keys, SoftPasskey};
use perch_testkit::FIXTURE_NETWORK;
use perch_zk_pool::{PerchZkPoolClient, PoolKey, TreeState};
use perch_zk_primitives::{contract_id, ZERO_HASHES};
use perch_zk_prover::{Inputs, Toolchain, Tree};
use soroban_sdk::testutils::{Address as _, EnvTestConfig, Ledger as _};
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
    /// Include the maximum-size exact root on every ordinary sizing rule.
    static ROOT_CONDITIONS: Cell<bool> = const { Cell::new(false) };
    /// While set, every `apply_doc` is first simulated the way RPC simulation
    /// runs it, and its metered footprint checked against the simulated one
    /// ([`World::check_footprint`]).
    static SIMULATE: Cell<bool> = const { Cell::new(false) };
    /// How many `apply_doc` calls were checked that way.
    static SIMULATED: Cell<u32> = const { Cell::new(0) };
    /// How many grant documents a [`worst_compromise`] thief installs
    /// before the attempt, and of how many own-key capped grants each (0:
    /// the dense document at the grant caps, [`install_grants`]).
    static THIEF_GRANTS: Cell<(u32, usize)> = const { Cell::new((3, 0)) };
    /// The same for the grant documents a [`worst_lost_key`] account holds
    /// before its key is lost. When set (to any number, 0 included), its
    /// completion is budgeted on a forked host.
    static OWNER_GRANTS: Cell<Option<(u32, usize)>> = const { Cell::new(None) };
    /// Unrelated entries [`worst_compromise`] writes before its completion,
    /// which the completion never touches: the control for the long-lived
    /// host's storage growth (`budgets.md`, "Grant documents").
    static FILLER: Cell<u32> = const { Cell::new(0) };
    /// While set, every [`World::forked`] row also reports the largest
    /// contract-data entry of the contract it calls and the transaction's
    /// size ([`World::report_sizes`]): the two limits a grant document's
    /// size meets that [`report`] does not meter.
    static SIZES: Cell<bool> = const { Cell::new(false) };
}

/// The per-entry and per-transaction size limits ([`World::report_sizes`]):
/// `max_contract_data_entry_size_bytes` (the SDK's mainnet invocation limit)
/// and `tx_max_size_bytes` (`stellar network settings`, protocol 29).
const TX_MAX_ENTRY_BYTES: u64 = 65_536;
const TX_MAX_SIZE_BYTES: u64 = 132_096;

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

/// [`report`] without the budget assertion, for a row measured on a host
/// that is not a network transaction's.
fn report_unbudgeted(label: &str, e: &Env) {
    let was = UNBUDGETED.with(|u| u.replace(true));
    report(label, e);
    UNBUDGETED.with(|u| u.set(was));
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
    versions: HashMap<String, String>,
    pins: HashMap<String, HashMap<String, String>>,
}

fn hex(b: &[u8]) -> String {
    hex::encode(b)
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
    let mut versions = HashMap::new();
    let mut pins = HashMap::new();
    for a in build["artifacts"].as_array().expect("artifacts") {
        let package = a["package"].as_str().unwrap().to_string();
        // A fetched stack's registry code carries no version.
        versions.insert(
            package.clone(),
            a["version"].as_str().unwrap_or_default().to_string(),
        );
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
        versions,
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
    /// The WebAuthn verifier, which `perch/verifiers` deployed, and the
    /// `verifier-name` a document names it by.
    webauthn: Address,
    webauthn_name: String,
    compiler: Address,
    controller: Address,
    adapter: Address,
    pool: Address,
    target: Address,
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
    content("perch-spending-limit");
    // `perch/verifiers`: the stack's registry code at the address the
    // account, the compiler and the factory derive, and the WebAuthn verifier
    // published and `deploy_stateless`'d through it, as a deployment does. A
    // document names the verifier, which the compiler resolves through the
    // registry's own `fetch_hash`.
    let verifiers = perch_smart_account::verifier_registry(&env);
    let manager = Address::generate(&env);
    env.register_at(
        &verifiers,
        stack.wasm["perch-constructorless-registry"].as_slice(),
        (
            Address::generate(&env),
            manager.clone(),
            Address::generate(&env),
        ),
    );
    let webauthn_version = stack.versions["perch-webauthn-verifier"].clone();
    let webauthn = {
        let name = soroban_sdk::String::from_str(&env, "perch-webauthn-verifier");
        let version = soroban_sdk::String::from_str(&env, &webauthn_version);
        let hash = env
            .deployer()
            .upload_contract_wasm(stack.wasm["perch-webauthn-verifier"].as_slice());
        env.mock_all_auths();
        let reg =
            perch_constructorless_registry::ConstructorlessRegistryClient::new(&env, &verifiers);
        reg.publish_hash(&name, &manager, &hash, &version);
        reg.deploy_stateless(&name, &Some(version), &None)
    };
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
        webauthn_name: format!("perch-webauthn-verifier@{webauthn_version}"),
        compiler,
        controller,
        adapter,
        pool,
        target,
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
        support::newest_rule(&self.env, account, name)
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
                r#"{{"id":"{id}","verifier":"{}","verifier-name":"{}","key":"{}"}}"#,
                strkey(&self.webauthn),
                self.webauthn_name,
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
            std::vec![
                self.sc(doc.clone()),
                self.sc(approval_valid_until),
                self.sc(None::<u64>)
            ],
        );
        let entry = self.passkey_entry(&a.address, key, "admin", root.clone());
        let simulated = SIMULATE
            .with(Cell::get)
            .then(|| self.simulated_footprint(&root, &entry));
        self.env.set_auths(&[entry]);
        let ok = matches!(
            self.account(a)
                .try_apply_doc(doc, &approval_valid_until, &None),
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
    /// counts, or why the simulated call failed. Runs the call in recording
    /// mode on a fresh host over a snapshot of this ledger (`e2e_invoke`, what simulation runs), so the
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
            std::vec![self.sc(target.clone()), self.sc(0u32), self.sc(None::<u64>)],
        );
        let entry = self.recovery_rule_entry(&a.address, root.clone());
        let simulated = SIMULATE
            .with(Cell::get)
            .then(|| self.simulated_footprint(&root, &entry));
        self.env.set_auths(&[entry]);
        let ok = matches!(self.account(a).try_apply_doc(target, &0, &None), Ok(Ok(_)));
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
/// the rules: `admin`, `target` (the owner's activity rule, with a program),
/// `both` rules with both a program (from a 1-of-1 threshold and an argument
/// constraint) and a spending cap, `interp` with a program alone, and
/// `plain` with neither. A program and a cap are both parts of the rule's
/// stored rule-eval rule.
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
            canonical_passkey(s)
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
    /// the rules after `target` (each at most the account's `MAX_NAME_SIZE`).
    /// With `with_recovery` false: the same document without its recovery
    /// member (a compromise baseline, to which the target adds the member
    /// back).
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
        let mut scope = format!(
            r#""scope":{{"type":"contract","address":"{}"}}"#,
            strkey(&self.target)
        );
        if ROOT_CONDITIONS.with(Cell::get) {
            scope.push_str(&format!(
                r#","auth-root":{{"contract":"{}","function":"{}"}}"#,
                strkey(&self.target),
                "x".repeat(32)
            ));
        }
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
                    r#"{{"id":"{id}","verifier":"{}","verifier-name":"{}","key":"{}"}}"#,
                    strkey(&self.webauthn),
                    self.webauthn_name,
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
    let a = w.new_account(canonical_passkey([11; 32]));

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
    let new_owner = canonical_passkey([12; 32]);
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
    let next_owner = canonical_passkey([13; 32]);
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
    let a = w.new_account(canonical_passkey([21; 32]));
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

    let thief_key = canonical_passkey([22; 32]);
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
    let a = w.new_account(canonical_passkey([31; 32]));
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

/// The stack's compiler wasm computes `config_hash` as
/// `sha256("perch/recovery/config" || recovery_canonical_json)`, recomputed
/// here from the committed fixtures, and it changes with every configuration
/// field (`support/config_hash.rs`).
#[test]
#[ignore = "needs the built stack"]
fn the_stack_compiler_hashes_the_canonical_recovery_text() {
    let stack = load_stack();
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let compiler = env.register(stack.wasm["perch-doc-compiler"].as_slice(), ());
    support::config_hash::check(&env, &compiler);
}

/// One built account and factory, unchanged, under several networks: each
/// resolves `perch/constructorless` and `perch/verifiers` under that
/// network's own Stellar Registry root, the stack's own infra bytes at their
/// content addresses in the first, and its WebAuthn verifier's in the
/// second. The registries are written out here, not derived
/// (`registry_path.rs` derives them hop by hop), so a rehearsal's stack,
/// built from dev registry paths, fails it by design: run the suite on one
/// with `--skip one_build_resolves_each_networks_own_registry`.
#[test]
#[ignore = "needs the built stack"]
fn one_build_resolves_each_networks_own_registry() {
    use perch_smart_account::InfraPins;
    const NETWORKS: [(&str, &str, &str); 3] = [
        (
            "Test SDF Network ; September 2015",
            "CDZGU4AIND6QRCGAN72I7DCS2EKRZ76JSKYY7KKJR4CG5IR2AMFIBZTM",
            "CCHJ7RWPMO33JB5PS74B64N4LVTWCGLEMH5IAKYCV32X56MXGYLHN5HW",
        ),
        (
            "Public Global Stellar Network ; September 2015",
            "CC236AK2RX7MUO7BV7JYDDW5KHZ3X7YYJOJKCVDC543BQBNNSUCZB7NN",
            "CCDCKRUV4W4DQYBWFWT4FNQ2QXQPGUQ7EXOZHIHSSLB6YJHMLHPMGDPH",
        ),
        (
            "Test SDF Future Network ; October 2022",
            "CBPWEPHLO2QDXWMWMHLOWCLRKQT24EFH7GYW6G3UOFY45RYOHS32A5JP",
            "CCARW6UKQLFDEJZHML2QTHFJNL4RKSSY6JEUCAC4IX5RJ3GTZ75SOGXW",
        ),
    ];
    let stack = load_stack();
    // build-stack.sh builds for one network's registry; the bytes are the
    // same on every network.
    assert!(
        NETWORKS.iter().any(|(_, r, _)| *r == stack.registry),
        "the stack was built for {}, no canonical registry: a rehearsal's stack \
         (--skip one_build_resolves_each_networks_own_registry)",
        stack.registry
    );
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let factory = env.register(stack.wasm["perch-account-factory"].as_slice(), ());
    let factory = PerchAccountFactoryClient::new(&env, &factory);
    env.deployer()
        .upload_contract_wasm(stack.wasm["perch-account"].as_slice());
    let admin = vec![&env, Signer::Delegated(env.register(Key, ()))];
    let account = factory.create(&BytesN::from_array(&env, &[7; 32]), &admin);
    let account = PerchAccountClient::new(&env, &account);

    for (passphrase, registry, verifiers) in NETWORKS {
        let id = env
            .crypto()
            .sha256(&Bytes::from_slice(&env, passphrase.as_bytes()))
            .to_array();
        env.ledger().with_mut(|l| l.network_id = id);
        let registry = Address::from_str(&env, registry);
        let verifiers = Address::from_str(&env, verifiers);
        let content_in = |registry: &Address, pkg: &str| {
            let hash = env
                .crypto()
                .sha256(&Bytes::from_slice(&env, &stack.wasm[pkg]))
                .to_bytes();
            env.deployer()
                .with_address(registry.clone(), hash)
                .deployed_address()
        };
        let content = |pkg: &str| content_in(&registry, pkg);
        assert_eq!(
            account.infra(),
            InfraPins {
                doc_compiler: content("perch-doc-compiler"),
                interpreter: content("perch-interpreter"),
                spending_limit: content("perch-spending-limit"),
            },
            "{passphrase}"
        );
        assert_eq!(
            factory.webauthn_verifier(),
            content_in(&verifiers, "perch-webauthn-verifier"),
            "{passphrase}"
        );
    }
}

/// `GuardianOnly` under `Loss`: no ZK enrollment, proof, or pool access
/// anywhere on the path, and the owner can always veto.
#[test]
#[ignore = "needs the built stack"]
fn guardian_only_recovery_needs_no_zk_and_the_loss_owner_can_veto() {
    let w = world();
    let a = w.new_account(canonical_passkey([41; 32]));
    let rec = Rec {
        profile: "loss",
        mode: Mode::Guardian,
        zk: None,
        delay: DELAY,
        baseline: None,
    };
    assert!(w.try_apply(&a, &a.owner, &w.doc(&a.owner, Some(&rec)), 0));
    report("enroll GuardianOnly through apply_doc", &w.env);

    let new_owner = canonical_passkey([42; 32]);
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
    let a = w.new_account(canonical_passkey([51; 32]));
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

    let new_owner = canonical_passkey([52; 32]);
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
    let a = w.new_account(canonical_passkey([61; 32]));
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
    let thief = canonical_passkey([62; 32]);
    let stolen = w.doc_with(&a.owner, Some(&thief), Some(&rec));
    assert!(w.try_apply(&a, &a.owner, &stolen, 0));
    assert!(w.activity_via(&a, &thief, "thief"));

    let new_owner = canonical_passkey([63; 32]);
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
/// `target` carrying a program and a cap. Each named signer is an OZ
/// registry entry and a registration event, and each rule a stored
/// rule-eval rule: what a completion's footprint, events, and memory grow
/// with.
fn worst_shape() -> Shape {
    Shape {
        signers: MAX_DOC_SIGNERS as usize,
        both: MAX_DOC_RULES - 2,
        interp: 0,
        plain: 0,
        fan: (MAX_DOC_SIGNERS as usize).min(MAX_SIGNERS as usize),
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
    let owner_grants = OWNER_GRANTS.with(Cell::get);
    let grant = owner_grants.map(|(docs, per)| {
        let token = w.funded_token(&a);
        let grant = install_grants(w, &a, &keys[0], &token, docs, per, 3000, "owner");
        (token, grant)
    });

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
    let what = "completion apply_doc (Combined, ZK rotation, every signer revoked)";
    match (owner_grants, grant) {
        (Some((docs, per)), Some((token, grant))) => {
            // Budgeted on a forked host, as the compromise completion with
            // the thief's grant documents is ([`worst_compromise`]).
            let what = format!("{what}; {docs} grant documents of {}", grants_of(per));
            assert!(w.fork_complete(&label(shape, &what), &a, &target));
            assert!(w.try_complete(&a, &target));
            report_unbudgeted(&format!("long-lived host: {what}"), &w.env);
            assert_eq!(w.account(&a).grant_generation(), 1);
            if let Some((i, id)) = grant {
                assert!(!w.spend_id(&a, &gkey(i), &token, 1, id), "a wiped grant");
            }
        }
        _ => {
            assert!(w.try_complete(&a, &target));
            report(&label(shape, what), &w.env);
        }
    }
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
///
/// The thief also grants itself [`THIEF_GRANTS`] grant documents, and the
/// owner had one of its own: the completion wipes them all, and its cost
/// must not depend on them (spec §7.6). The completion is measured twice:
/// on a host forked from the ledger, as one network transaction (the
/// budgeted row), and on the long-lived host.
fn worst_compromise(w: &World, shape: Shape, bytes: usize, seed: u8, variant: Thief) {
    let thief_tag = variant.tag();
    let keys = passkeys(seed, shape.signers);
    let a = w.new_account(passkeys(seed, 1).swap_remove(0));
    let token = w.funded_token(&a);
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
    // The owner's own grant, from before the theft.
    assert!(w.try_apply_grant(&a, &keys[0], 500, &grant_doc(w, &token, &[(900, 100)])));

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
    let (docs, per) = THIEF_GRANTS.with(Cell::get);
    let thief_grant = install_grants(w, &a, &thief[0], &token, docs, per, 2000, "thief");
    if let Some((i, id)) = thief_grant {
        assert!(
            w.spend_id(&a, &gkey(i), &token, 1, id),
            "a thief grant works before recovery"
        );
    }
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
    let filler = FILLER.with(Cell::get);
    if filler > 0 {
        w.env.as_contract(&w.target, || {
            for i in 0..filler {
                w.env
                    .storage()
                    .persistent()
                    .set(&(Symbol::new(&w.env, "fill"), i), &i);
            }
        });
    }
    let what = format!(
        "completion apply_doc (compromise, Combined, ZK rotation, both key sets revoked; {how}; {docs} thief grant documents of {})",
        grants_of(per)
    );
    // Budgeted on a forked host, which holds only what the transaction
    // touches. The long-lived host also holds every entry earlier calls
    // wrote, the thief's grant documents included, which inflates its instructions
    // and memory alone; its row is reported, unbudgeted, without the shape
    // `cap-sweep.py` tabulates (`budgets.md`, "Grant documents").
    assert!(w.fork_complete(&label(shape, &what), &a, &target));
    assert!(w.try_complete(&a, &target));
    report_unbudgeted(&format!("long-lived host: {what}"), &w.env);
    assert!(w.all_revoked(&a, &keys), "every replaced baseline key");
    assert!(w.all_revoked(&a, &thief), "every key the thief added");
    assert!(w.activity(&a, &new_keys[0]));
    assert!(!w.activity(&a, &keys[0]));
    assert!(!w.activity_via(&a, &thief[0], &thief_rule));

    // Every grant document is wiped, the thief's and the owner's.
    assert_eq!(w.account(&a).grant_generation(), 1);
    if let Some((i, id)) = thief_grant {
        assert!(
            !w.spend_id(&a, &gkey(i), &token, 1, id),
            "a wiped thief grant"
        );
    }
    let owner_grant = w.grant_rule_id(&a, 500, "g900");
    assert!(
        !w.spend_id(&a, &gkey(900), &token, 1, owner_grant),
        "the owner's too"
    );
    // Anyone collects a wiped grant document. The new owner re-grants over its own,
    // to a fresh session key: the wiped grant document's key is never named again.
    if docs > 0 {
        w.account(&a).gc_grant(&0);
        report(
            &format!("gc_grant of a wiped grant document ({})", grants_of(per)),
            &w.env,
        );
    }
    assert!(!w.try_apply_grant(&a, &new_keys[0], 500, &grant_doc(w, &token, &[(900, 100)])));
    assert!(w.try_apply_grant(&a, &new_keys[0], 500, &grant_doc(w, &token, &[(901, 100)])));
    report(
        "apply_grant over a wiped grant document (one grant re-granted to a fresh key)",
        &w.env,
    );
    let regrant = w.grant_rule_id(&a, 500, "g901");
    assert!(w.spend_id(&a, &gkey(901), &token, 1, regrant));
    assert!(!w.spend_id(&a, &gkey(900), &token, 1, owner_grant));
}

/// What [`install_grants`] puts in each grant document.
fn grants_of(per: usize) -> String {
    if per == 0 {
        "the dense document at the grant caps".to_string()
    } else {
        format!("{per} own-key grants")
    }
}

/// Grant documents under grants `0..docs`, applied by `key` through `admin`
/// to fresh session keys from [`gkey`] `first` on, each of `per` own-key
/// capped grants or, with `per` 0, the dense document at the grant caps
/// (1-of-15 rules, the most signer references, [`GrantShape::at_caps`]). Each
/// `apply_grant` is reported on the long-lived host as `who`'s. Returns a
/// session key's [`gkey`] index and the rule it may transfer through, from
/// the last one.
#[allow(clippy::too_many_arguments)]
fn install_grants(
    w: &World,
    a: &Acct,
    key: &SoftPasskey,
    token: &Address,
    docs: u32,
    per: usize,
    first: usize,
    who: &str,
) -> Option<(usize, u32)> {
    let mut last = None;
    for s in 0..docs {
        if per == 0 {
            let shape = GrantShape::at_caps(w, 1);
            let start = first + s as usize * shape.signers;
            let (doc, _) = w.grant_shaped(token, &gkeys(start, shape.signers), shape, "a", false);
            assert!(w.try_apply_grant(a, key, s, &doc));
            report(
                &format!(
                    "{who} apply_grant {s} ({}, long-lived host)",
                    grants_of(per)
                ),
                &w.env,
            );
            let k = shape.rules - 1;
            let id = w.shaped_rule_id(a, s, &shape.rule_name("a", k));
            last = Some((start + shape.named(k)[0], id));
        } else {
            let start = first + s as usize * per;
            let grants: std::vec::Vec<(usize, u32)> =
                (start..start + per).map(|i| (i, 1_000)).collect();
            assert!(w.try_apply_grant(a, key, s, &grant_doc(w, token, &grants)));
            report(
                &format!(
                    "{who} apply_grant {s} ({}, long-lived host)",
                    grants_of(per)
                ),
                &w.env,
            );
            last = Some((start, w.grant_rule_id(a, s, &format!("g{start:03}"))));
        }
    }
    last
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
        name: "one swap in a six-key rule",
        owner: (0, 0),
        pay: (&[0, 1, 2, 3, 4, 5], &[0, 1, 2, 3, 4, 6]),
        work: None,
        capped: false,
    },
    Transition {
        name: "five swaps in a six-key rule",
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

/// A soft passkey whose `key_data` is already its verifier-canonical form:
/// the bare 65-byte public key, with no credential-id suffix. The document
/// compiler installs external signers at their canonical key, and the account
/// matches an authorizing signer against that stored key, so a credential the
/// account can both install and later authenticate with carries no suffix.
/// (`a_rejected_signer_transition_changes_nothing` adds a suffix on purpose,
/// to exercise the refusal of a non-canonical key.)
fn canonical_passkey(seed: [u8; 32]) -> SoftPasskey {
    let mut key = SoftPasskey::from_seed(seed);
    key.credential_id = std::vec::Vec::new();
    key
}

fn tkey(i: usize) -> SoftPasskey {
    let mut s = [0x61; 32];
    s[1] = i as u8;
    canonical_passkey(s)
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
                    r#"{{"id":"{id}","verifier":"{}","verifier-name":"{}","key":"{}"}}"#,
                    strkey(&self.webauthn),
                    self.webauthn_name,
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

    /// The account's spending record for rule `id`, if it has one.
    fn window(&self, a: &Acct, id: u32) -> Option<perch_rule_eval::StoredRecord> {
        self.env.as_contract(&a.address, || {
            perch_smart_account::testutils::spend_record(&self.env, id)
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

    // The same passkey under a second credential id: `dup` is tkey(1)'s key
    // with a credential-id suffix, i.e. a non-canonical spelling of a key
    // already declared canonically. The compiler refuses it.
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
            std::vec![w.sc(doc.clone()), w.sc(0u32), w.sc(None::<u64>)],
        );
        w.env
            .set_auths(&[w.passkey_entry(&a.address, &tkey(0), "admin", root)]);
        w.env
            .cost_estimate()
            .budget()
            .reset_limits(cost * percent / 100, 1 << 30);
        let client = w.account(&a);
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.try_apply_doc(&doc, &0, &None)
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

// ---------------------------------------------------------------------------
// Grant documents: grant lifecycle, grant document size, many grant documents, and recovery
// with thief grant documents, single document against split (`budgets.md`, "Grant
// documents")
// ---------------------------------------------------------------------------

/// A grant: one session passkey on an `all` rule of it alone, scoped to
/// `token`, allowed `transfer`, with a spending cap.
fn grant_rule(name: &str, signer: &str, token: &Address, limit: u32) -> String {
    format!(
        r#"{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["{signer}"]}},"functions":["transfer"],"cap":{{"limit":"{limit}","period-ledgers":1000}}}}"#,
        strkey(token)
    )
}

fn passkey_decl(w: &World, id: &str, key: &SoftPasskey) -> String {
    format!(
        r#"{{"id":"{id}","verifier":"{}","verifier-name":"{}","key":"{}"}}"#,
        strkey(&w.webauthn),
        w.webauthn_name,
        hex(&key.key_data())
    )
}

/// The session key of grant `i`.
fn gkey(i: usize) -> SoftPasskey {
    let mut s = [0x47; 32];
    s[1] = (i % 256) as u8;
    s[2] = (i / 256) as u8;
    canonical_passkey(s)
}

/// The single-document shape: `admin` for `owner`, then one grant per
/// entry of `grants` (`(index, limit)`), each with its own session key.
fn single_doc(w: &World, owner: &SoftPasskey, token: &Address, grants: &[(usize, u32)]) -> Bytes {
    let mut signers = std::vec![passkey_decl(w, "owner", owner)];
    let mut rules = std::vec![
        r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#.to_string(),
    ];
    for (i, limit) in grants {
        signers.push(passkey_decl(w, &format!("k{i:03}"), &gkey(*i)));
        rules.push(grant_rule(
            &format!("g{i:03}"),
            &format!("k{i:03}"),
            token,
            *limit,
        ));
    }
    let json = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
        signers.join(","),
        rules.join(",")
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// A grant document: the grants alone, no admin rule, no recovery.
fn grant_doc(w: &World, token: &Address, grants: &[(usize, u32)]) -> Bytes {
    let mut signers = std::vec![];
    let mut rules = std::vec![];
    for (i, limit) in grants {
        signers.push(passkey_decl(w, &format!("k{i:03}"), &gkey(*i)));
        rules.push(grant_rule(
            &format!("g{i:03}"),
            &format!("k{i:03}"),
            token,
            *limit,
        ));
    }
    let json = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
        signers.join(","),
        rules.join(",")
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

impl World {
    fn passkey_entry_id(
        &self,
        account: &Address,
        key: &SoftPasskey,
        rule_id: u32,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        auth_entry(
            &self.env,
            account,
            &self.webauthn,
            key,
            rule_id,
            self.next_nonce(),
            self.ledger() + 1_000_000,
            root,
        )
    }

    /// `apply_grant(grant, doc)` signed by `key` through `admin`.
    fn try_apply_grant(&self, a: &Acct, key: &SoftPasskey, grant: u32, doc: &Bytes) -> bool {
        let root = self.invocation(
            &a.address,
            "apply_grant",
            std::vec![self.sc(grant), self.sc(doc.clone())],
        );
        self.env
            .set_auths(&[self.passkey_entry(&a.address, key, "admin", root)]);
        let ok = matches!(self.account(a).try_apply_grant(&grant, doc), Ok(Ok(_)));
        self.env.set_auths(&[]);
        ok
    }

    fn try_remove_grant(&self, a: &Acct, key: &SoftPasskey, grant: u32) -> bool {
        let root = self.invocation(&a.address, "remove_grant", std::vec![self.sc(grant)]);
        self.env
            .set_auths(&[self.passkey_entry(&a.address, key, "admin", root)]);
        let ok = matches!(self.account(a).try_remove_grant(&grant), Ok(Ok(_)));
        self.env.set_auths(&[]);
        ok
    }

    /// The id of the grant rule `name` in `grant`.
    fn grant_rule_id(&self, a: &Acct, grant: u32, name: &str) -> u32 {
        let wanted = soroban_sdk::String::from_str(&self.env, name);
        self.account(a)
            .grant(&grant)
            .expect("grant exists")
            .rules
            .iter()
            .find(|r| r.name == wanted)
            .expect("rule exists")
            .id
    }

    /// `key` transfers `amount` of `token` through rule `rule_id`.
    fn spend_id(
        &self,
        a: &Acct,
        key: &SoftPasskey,
        token: &Address,
        amount: i128,
        rule_id: u32,
    ) -> bool {
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
            .set_auths(&[self.passkey_entry_id(&a.address, key, rule_id, root)]);
        let ok = TokenClient::new(&self.env, token)
            .try_transfer(&a.address, &to, &amount)
            .is_ok();
        self.env.set_auths(&[]);
        ok
    }

    /// The account's ledger footprint at rest: every contract-data entry
    /// the account owns, plus any policy state the interpreter and the
    /// spending limit keep for it, as (entries, XDR bytes) per key kind.
    fn at_rest(&self, a: &Acct, label: &str) {
        use soroban_sdk::xdr::{LedgerEntryData, LedgerKey, Limits, WriteXdr};
        let snapshot = self.env.to_ledger_snapshot();
        let me: soroban_sdk::xdr::ScAddress = a.address.clone().into();
        let mut by: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
        let mut total = 0usize;
        for (key, (entry, _)) in snapshot.ledger_entries.iter() {
            let LedgerKey::ContractData(k) = &**key else {
                continue;
            };
            let LedgerEntryData::ContractData(_) = &entry.data else {
                continue;
            };
            let size = entry.to_xdr(Limits::none()).unwrap().len();
            let rendered = format!("{:?}", k.key);
            let mine = k.contract == me;
            let policy_state = !mine && rendered.contains(&format!("{:?}", me));
            if !mine && !policy_state {
                continue;
            }
            if let ScVal::LedgerKeyNonce(_) = &k.key {
                continue;
            }
            let kind = match &k.key {
                ScVal::LedgerKeyContractInstance => "instance".to_string(),
                ScVal::Vec(Some(v)) => match v.first() {
                    Some(ScVal::Symbol(s)) => s.to_string(),
                    _ => "vec".to_string(),
                },
                ScVal::Symbol(s) => s.to_string(),
                _ => "other".to_string(),
            };
            let kind = if policy_state {
                format!("policy:{kind}")
            } else {
                kind
            };
            let slot = by.entry(kind).or_default();
            slot.0 += 1;
            slot.1 += size;
            total += size;
        }
        // Mainnet rent at the floor (1 000 stroops per KB, denominator 1 215,
        // 6 307 200 ledgers a year): `rent_fee_for_size_and_ledgers`.
        let rent_xlm_yr = total as f64 * 1000.0 * 6_307_200.0 / (1024.0 * 1215.0) / 1e7;
        let kinds: serde_json::Map<String, serde_json::Value> = by
            .iter()
            .map(|(k, (n, b))| (k.clone(), serde_json::json!([n, b])))
            .collect();
        println!(
            "\n{}",
            serde_json::json!({"at_rest": label, "bytes": total, "rent_xlm_per_year": rent_xlm_yr, "by_kind": kinds})
        );
    }
}

/// Whether this stack's account has the scoped tier.
fn split_stack(w: &World, a: &Acct) -> bool {
    w.account(a).try_grant_generation().is_ok()
}

/// Grant lifecycle and scoped authorization, single document vs split, as
/// the account holds `k` grants. Each row is one transaction.
#[test]
#[ignore = "needs the built stack"]
fn docsplit_grant_lifecycle() {
    let ks: std::vec::Vec<usize> = std::env::var("PERCH_SPLIT_KS")
        .ok()
        .map(|s| s.split(',').map(|x| x.parse().unwrap()).collect())
        .unwrap_or_else(|| std::vec![0, 2, 6]);
    for k in ks {
        // --- single document -------------------------------------------
        if k < MAX_DOC_SIGNERS as usize && k + 2 <= MAX_DOC_RULES as usize {
            let w = world();
            let owner = canonical_passkey([0x51; 32]);
            let a = w.new_account(canonical_passkey([0x51; 32]));
            let token = w.funded_token(&a);
            let base: std::vec::Vec<(usize, u32)> = (0..k).map(|i| (i, 100)).collect();
            if k > 0 {
                assert!(w.try_apply(&a, &owner, &single_doc(&w, &owner, &token, &base), 0));
            }
            let mut added = base.clone();
            added.push((k, 100));
            assert!(w.try_apply(&a, &owner, &single_doc(&w, &owner, &token, &added), 0));
            report(
                &format!("single: add a grant via apply_doc [{k} grants before]"),
                &w.env,
            );
            let id = w.rule_id(&a.address, &format!("g{k:03}"));
            assert!(w.spend_id(&a, &gkey(k), &token, 5, id));
            report(
                &format!("single: capped transfer through a grant [{} grants]", k + 1),
                &w.env,
            );
            let mut updated = base.clone();
            updated.push((k, 200));
            assert!(w.try_apply(&a, &owner, &single_doc(&w, &owner, &token, &updated), 0));
            report(
                &format!(
                    "single: change a grant's cap via apply_doc [{} grants]",
                    k + 1
                ),
                &w.env,
            );
            let new_owner = canonical_passkey([0x52; 32]);
            assert!(w.try_apply(&a, &owner, &single_doc(&w, &new_owner, &token, &updated), 0));
            report(
                &format!(
                    "single: rotate the owner key via apply_doc [{} grants]",
                    k + 1
                ),
                &w.env,
            );
            assert!(w.try_apply(
                &a,
                &new_owner,
                &single_doc(&w, &new_owner, &token, &base),
                0
            ));
            report(
                &format!(
                    "single: revoke a grant via apply_doc [{} grants before]",
                    k + 1
                ),
                &w.env,
            );
            w.at_rest(&a, &format!("single, {k} grants"));
            assert!(!w.spend_id(&a, &gkey(k), &token, 5, id), "revoked");
        }

        // --- split -------------------------------------------------------
        let w = world();
        let owner = canonical_passkey([0x51; 32]);
        let a = w.new_account(canonical_passkey([0x51; 32]));
        if !split_stack(&w, &a) {
            println!("\n{{\"case\":\"skipped\",\"why\":\"no scoped tier in this stack\"}}");
            continue;
        }
        let token = w.funded_token(&a);
        assert!(w.try_apply(&a, &owner, &single_doc(&w, &owner, &token, &[]), 0));
        for i in 0..k {
            assert!(w.try_apply_grant(&a, &owner, i as u32, &grant_doc(&w, &token, &[(i, 100)])));
        }
        let s = k as u32;
        assert!(w.try_apply_grant(&a, &owner, s, &grant_doc(&w, &token, &[(k, 100)])));
        report(
            &format!("split: add a grant via apply_grant [{k} grant documents before]"),
            &w.env,
        );
        let id = w.grant_rule_id(&a, s, &format!("g{k:03}"));
        assert!(w.spend_id(&a, &gkey(k), &token, 5, id));
        report(
            &format!(
                "split: capped transfer through a grant [{} grant documents]",
                k + 1
            ),
            &w.env,
        );
        assert!(w.try_apply_grant(&a, &owner, s, &grant_doc(&w, &token, &[(k, 200)])));
        report(
            &format!(
                "split: change a grant's cap via apply_grant [{} grant documents]",
                k + 1
            ),
            &w.env,
        );
        let new_owner = canonical_passkey([0x52; 32]);
        assert!(w.try_apply(&a, &owner, &single_doc(&w, &new_owner, &token, &[]), 0));
        report(
            &format!(
                "split: rotate the owner key via apply_doc [{} grant documents]",
                k + 1
            ),
            &w.env,
        );
        assert!(
            w.spend_id(&a, &gkey(k), &token, 5, id),
            "grant documents survive an admin change"
        );
        assert!(w.try_remove_grant(&a, &new_owner, s));
        report(
            &format!(
                "split: revoke a grant via remove_grant [{} grant documents before]",
                k + 1
            ),
            &w.env,
        );
        w.at_rest(&a, &format!("split, {k} grant documents"));
        assert!(!w.spend_id(&a, &gkey(k), &token, 5, id), "revoked");
        // An admin auth (`execute`) with grant documents installed.
        assert!(w.execute(&a, &new_owner));
        report(
            &format!("split: execute through admin [{k} grant documents]"),
            &w.env,
        );
    }
}

/// One grant document of `n` grants: added fresh, then every rule
/// replaced (renamed), on a stack whose compiler caps admit `n`.
#[test]
#[ignore = "sizing tool: PERCH_SPLIT_NS=... (more than 8 grants needs a compiler with raised caps)"]
fn docsplit_grant_size_sweep() {
    let ns: std::vec::Vec<usize> = std::env::var("PERCH_SPLIT_NS")
        .ok()
        .map(|s| s.split(',').map(|x| x.parse().unwrap()).collect())
        .unwrap_or_else(|| std::vec![1, 4, 8]);
    UNBUDGETED.with(|u| u.set(true));
    for n in ns {
        let w = world();
        w.env.cost_estimate().disable_resource_limits();
        let owner = canonical_passkey([0x53; 32]);
        let a = w.new_account(canonical_passkey([0x53; 32]));
        assert!(split_stack(&w, &a), "needs a stack with grant documents");
        let token = w.funded_token(&a);
        assert!(w.try_apply(&a, &owner, &single_doc(&w, &owner, &token, &[]), 0));
        let grants: std::vec::Vec<(usize, u32)> = (0..n).map(|i| (i, 100)).collect();
        let doc = grant_doc(&w, &token, &grants);
        assert!(w.try_apply_grant(&a, &owner, 0, &doc), "apply_grant of {n}");
        report(&format!("sweep: apply_grant, {n} grants added"), &w.env);
        let id = w.grant_rule_id(&a, 0, "g000");
        assert!(w.spend_id(&a, &gkey(0), &token, 5, id));
        report(
            &format!("sweep: capped transfer [{n} grants in the grant document]"),
            &w.env,
        );
        // Every grant renamed and rekeyed: every rule replaced.
        let renamed: std::vec::Vec<(usize, u32)> = (0..n).map(|i| (i + 1000, 100)).collect();
        assert!(w.try_apply_grant(&a, &owner, 0, &grant_doc(&w, &token, &renamed)));
        report(&format!("sweep: apply_grant, {n} grants replaced"), &w.env);
        assert!(w.try_remove_grant(&a, &owner, 0));
        report(&format!("sweep: remove_grant, {n} grants"), &w.env);
    }
}

/// Many grant documents installed: authorization stays flat.
#[test]
#[ignore = "needs the built stack"]
fn docsplit_many_grants() {
    let total: usize = std::env::var("PERCH_SPLIT_GRANTS")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(8);
    let w = world();
    let owner = canonical_passkey([0x54; 32]);
    let a = w.new_account(canonical_passkey([0x54; 32]));
    assert!(split_stack(&w, &a), "needs a stack with grant documents");
    let token = w.funded_token(&a);
    assert!(w.try_apply(&a, &owner, &single_doc(&w, &owner, &token, &[]), 0));
    let per = 8usize;
    for s in 0..total {
        let grants: std::vec::Vec<(usize, u32)> =
            (s * per..(s + 1) * per).map(|i| (i, 100)).collect();
        assert!(w.try_apply_grant(&a, &owner, s as u32, &grant_doc(&w, &token, &grants)));
    }
    report_unbudgeted(
        &format!(
            "many (long-lived host): apply_grant of the {total}th grant document of {per} grants"
        ),
        &w.env,
    );
    let last = (total * per - 1) as usize;
    let id = w.grant_rule_id(&a, (total - 1) as u32, &format!("g{last:03}"));
    assert!(w.fork_spend(
        &format!(
            "many: capped transfer, last grant document [{} rules installed]",
            total * per + 1
        ),
        &a,
        &gkey(last),
        &token,
        5,
        id
    ));
    let id0 = w.grant_rule_id(&a, 0, "g000");
    assert!(w.fork_spend(
        &format!(
            "many: capped transfer, first grant document [{} rules installed]",
            total * per + 1
        ),
        &a,
        &gkey(0),
        &token,
        5,
        id0
    ));
    let new_owner = canonical_passkey([0x55; 32]);
    assert!(w.fork_apply_doc(
        &format!(
            "many: rotate the owner key [{} rules installed]",
            total * per + 1
        ),
        &a,
        &owner,
        &single_doc(&w, &new_owner, &token, &[])
    ));
    let grants: std::vec::Vec<(usize, u32)> =
        (total * per..total * per + 1).map(|i| (i, 100)).collect();
    assert!(w.fork_apply_grant(
        &format!(
            "many: add a one-grant document [{} rules installed]",
            total * per + 1
        ),
        &a,
        &owner,
        total as u32,
        &grant_doc(&w, &token, &grants)
    ));
    assert!(w.spend_id(&a, &gkey(last), &token, 5, id));
    assert!(w.execute(&a, &owner));
    report(
        &format!(
            "many: execute through admin [{} rules installed]",
            total * per + 1
        ),
        &w.env,
    );
    w.at_rest(&a, &format!("split, {total} grant documents of {per}"));
}

/// The compromise completion against the grant documents a thief installs
/// and the account document's shape: [`worst_compromise`] over each
/// `signers,both,interp,plain,fan,bytes,thief,docs,per` of
/// `PERCH_SPLIT_RECOVERY` (`;`-separated; thief 0 keeps every name, 1
/// renames every rule, 2 reprograms every rule, and 3 is no thief but the
/// lost-key completion, [`worst_lost_key`], over `docs` grant documents the
/// account held; `per` 0 makes each grant document the dense one at the
/// grant caps), with `PERCH_SPLIT_FILLER`
/// unrelated entries written before the completion as the host-growth
/// control. Unbudgeted: a sizing tool (`budgets.md`, "Grant documents").
#[test]
#[ignore = "sizing tool: PERCH_SPLIT_RECOVERY=..."]
fn docsplit_compromise_completion() {
    let spec = std::env::var("PERCH_SPLIT_RECOVERY")
        .unwrap_or_else(|_| "8,0,1,0,8,4096,2,3,8".to_string());
    let filler: u32 = std::env::var("PERCH_SPLIT_FILLER")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(0);
    UNBUDGETED.with(|u| u.set(true));
    FILLER.with(|f| f.set(filler));
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
        let w = world();
        w.env.cost_estimate().disable_resource_limits();
        if v[6] == 3 {
            OWNER_GRANTS.with(|t| t.set(Some((v[7] as u32, v[8]))));
            worst_lost_key(&w, shape, v[5], 140 + 7 * n as u8);
            OWNER_GRANTS.with(|t| t.set(None));
            continue;
        }
        let thief = match v[6] {
            0 => Thief::KeepNames,
            1 => Thief::Rename,
            _ => Thief::Reprogram,
        };
        THIEF_GRANTS.with(|t| t.set((v[7] as u32, v[8])));
        worst_compromise(&w, shape, v[5], 140 + 7 * n as u8, thief);
    }
}

/// The size of the largest contract-data entry `contract` holds on `e`.
fn largest_entry(e: &Env, contract: &Address) -> usize {
    use soroban_sdk::xdr::{LedgerEntryData, LedgerKey, Limits, ScAddress, WriteXdr};
    let me: ScAddress = Address::from_str(e, &strkey(contract)).into();
    e.to_ledger_snapshot()
        .ledger_entries
        .iter()
        .filter_map(|(key, (entry, _))| match (&**key, &entry.data) {
            (LedgerKey::ContractData(k), LedgerEntryData::ContractData(_)) if k.contract == me => {
                Some(entry.to_xdr(Limits::none()).unwrap().len())
            }
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

impl World {
    /// `fn_name(args)` on `contract`, authorized by the entries `entry`
    /// builds on the fork (none for a permissionless call), run on a fresh
    /// host forked from this ledger: its storage holds only what the
    /// transaction touches, as a network transaction's does, so entries
    /// earlier calls wrote on the long-lived host do not inflate it. Changes
    /// nothing on this host. Reports `label`.
    fn forked(
        &self,
        label: &str,
        contract: &Address,
        fn_name: &str,
        args: std::vec::Vec<ScVal>,
        entry: impl FnOnce(
            &Env,
            SorobanAuthorizedInvocation,
        ) -> std::vec::Vec<SorobanAuthorizationEntry>,
    ) -> bool {
        let mut e2 = Env::from_ledger_snapshot(self.env.to_ledger_snapshot());
        e2.set_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        e2.cost_estimate().budget().reset_unlimited();
        if UNBUDGETED.with(Cell::get) {
            // A sizing tool reports a row past a limit rather than failing it.
            e2.cost_estimate().disable_resource_limits();
        }
        let target = Address::from_str(&e2, &strkey(contract));
        let root = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: target.clone().into(),
                function_name: StringM::try_from(fn_name).unwrap().into(),
                args: args.clone().try_into().unwrap(),
            }),
            sub_invocations: VecM::default(),
        };
        let entries = entry(&e2, root.clone());
        e2.set_auths(&entries);
        let mut vals: Vec<Val> = Vec::new(&e2);
        for a in &args {
            vals.push_back(Val::try_from_val(&e2, a).unwrap());
        }
        let ok = matches!(
            e2.try_invoke_contract::<Val, soroban_sdk::Error>(
                &target,
                &Symbol::new(&e2, fn_name),
                vals
            ),
            Ok(Ok(_))
        );
        if ok {
            report(&format!("fork: {label}"), &e2);
            if SIZES.with(Cell::get) {
                self.report_sizes(&format!("fork: {label}"), contract, &root, &entries, &e2);
            }
        } else {
            println!("\n{{\"fork_failed\":\"{label}\"}}");
        }
        ok
    }

    /// The two sizes [`report`] does not meter, for the row `label` just
    /// reported on the fork `e2`: the largest contract-data entry `contract`
    /// holds after the call, against `max_contract_data_entry_size_bytes`,
    /// and the transaction's size, against `tx_max_size_bytes`: the call and
    /// its authorization entries (`InvokeHostFunctionOp`, which carries a
    /// document argument twice, in the call and in the signed invocation),
    /// the footprint's keys as an RPC-style simulation of it records them,
    /// and 300 bytes for the envelope, the resources and one signature. A
    /// budgeted run asserts each within 75%.
    fn report_sizes(
        &self,
        label: &str,
        contract: &Address,
        root: &SorobanAuthorizedInvocation,
        entries: &[SorobanAuthorizationEntry],
        e2: &Env,
    ) {
        use soroban_env_host::{budget::Budget, e2e_invoke, storage::SnapshotSource};
        use soroban_sdk::xdr::{InvokeHostFunctionOp, Limits, WriteXdr};
        let max_entry = largest_entry(e2, contract);
        let SorobanAuthorizedFunction::ContractFn(call) = &root.function else {
            unreachable!("a contract call")
        };
        let function = HostFunction::InvokeContract(call.clone());
        let budget = Budget::default();
        budget.reset_unlimited().unwrap();
        let snapshot: std::rc::Rc<dyn SnapshotSource> =
            std::rc::Rc::new(self.env.to_ledger_snapshot());
        let out = e2e_invoke::invoke_host_function_in_recording_mode(
            &budget,
            false,
            &function,
            &AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32]))),
            e2e_invoke::RecordingInvocationAuthMode::Enforcing(entries.to_vec()),
            self.env.ledger().get(),
            snapshot,
            [0; 32],
            &mut std::vec::Vec::new(),
        )
        .expect("the simulation runs");
        assert!(out.invoke_result.is_ok(), "{label}: the simulation fails");
        let footprint = out.resources.footprint;
        let keys: usize = footprint
            .read_only
            .iter()
            .chain(footprint.read_write.iter())
            .map(|k| k.to_xdr(Limits::none()).unwrap().len())
            .sum();
        let op = InvokeHostFunctionOp {
            host_function: function,
            auth: entries.to_vec().try_into().unwrap(),
        }
        .to_xdr(Limits::none())
        .unwrap()
        .len();
        let tx = op + keys + 300;
        println!(
            "\n{{\"sizes_of\":\"{label}\",\"max_entry_bytes\":{max_entry},\"tx_bytes\":{tx},\"op_bytes\":{op},\"footprint_key_bytes\":{keys}}}"
        );
        if UNBUDGETED.with(Cell::get) {
            return;
        }
        assert!(
            max_entry as u64 * 100 <= TX_MAX_ENTRY_BYTES * BUDGET_PCT,
            "{label}: largest entry over budget"
        );
        assert!(
            tx as u64 * 100 <= TX_MAX_SIZE_BYTES * BUDGET_PCT,
            "{label}: transaction size over budget"
        );
    }

    /// [`World::forked`], authorized by every one of `keys` through
    /// `rule_id` of `account`.
    #[allow(clippy::too_many_arguments)]
    fn forked_call(
        &self,
        label: &str,
        account: &Address,
        keys: &[&SoftPasskey],
        rule_id: u32,
        contract: &Address,
        fn_name: &str,
        args: std::vec::Vec<ScVal>,
    ) -> bool {
        self.forked(label, contract, fn_name, args, |e2, root| {
            std::vec![auth_entry_for_keys(
                e2,
                &Address::from_str(e2, &strkey(account)),
                &Address::from_str(e2, &strkey(&self.webauthn)),
                keys,
                &[rule_id],
                self.next_nonce(),
                e2.ledger().sequence() + 1_000_000,
                root,
            )]
        })
    }

    /// [`World::try_complete`] on a forked host.
    fn fork_complete(&self, label: &str, a: &Acct, target: &Bytes) -> bool {
        let args = std::vec![self.sc(target.clone()), self.sc(0u32), self.sc(None::<u64>)];
        let address = a.address.clone();
        self.forked(label, &a.address, "apply_doc", args, |e2, root| {
            let mut entry = self.recovery_rule_entry(&address, root);
            if let SorobanCredentials::Address(c) = &mut entry.credentials {
                c.signature_expiration_ledger = e2.ledger().sequence() + 1_000_000;
            }
            std::vec![entry]
        })
    }

    fn fork_apply_doc(&self, label: &str, a: &Acct, key: &SoftPasskey, doc: &Bytes) -> bool {
        let admin = self.rule_id(&a.address, "admin");
        self.forked_call(
            label,
            &a.address,
            &[key],
            admin,
            &a.address,
            "apply_doc",
            std::vec![self.sc(doc.clone()), self.sc(0u32), self.sc(None::<u64>)],
        )
    }

    fn fork_apply_grant(
        &self,
        label: &str,
        a: &Acct,
        key: &SoftPasskey,
        grant: u32,
        doc: &Bytes,
    ) -> bool {
        let admin = self.rule_id(&a.address, "admin");
        self.forked_call(
            label,
            &a.address,
            &[key],
            admin,
            &a.address,
            "apply_grant",
            std::vec![self.sc(grant), self.sc(doc.clone())],
        )
    }

    fn fork_remove_grant(&self, label: &str, a: &Acct, key: &SoftPasskey, grant: u32) -> bool {
        let admin = self.rule_id(&a.address, "admin");
        self.forked_call(
            label,
            &a.address,
            &[key],
            admin,
            &a.address,
            "remove_grant",
            std::vec![self.sc(grant)],
        )
    }

    fn fork_spend(
        &self,
        label: &str,
        a: &Acct,
        key: &SoftPasskey,
        token: &Address,
        amount: i128,
        rule_id: u32,
    ) -> bool {
        self.fork_spend_by(label, a, &[key], token, amount, rule_id)
    }

    /// [`World::fork_spend`] signed by every one of `keys`.
    fn fork_spend_by(
        &self,
        label: &str,
        a: &Acct,
        keys: &[&SoftPasskey],
        token: &Address,
        amount: i128,
        rule_id: u32,
    ) -> bool {
        self.forked_call(
            label,
            &a.address,
            keys,
            rule_id,
            token,
            "transfer",
            std::vec![
                self.sc(a.address.clone()),
                self.sc(self.guardians[1].clone()),
                self.sc(amount)
            ],
        )
    }
}

/// [`docsplit_grant_lifecycle`]'s rows, each measured on a forked host.
#[test]
#[ignore = "needs the built stack"]
fn docsplit_grant_lifecycle_forked() {
    let ks: std::vec::Vec<usize> = std::env::var("PERCH_SPLIT_KS")
        .ok()
        .map(|s| s.split(',').map(|x| x.parse().unwrap()).collect())
        .unwrap_or_else(|| std::vec![0, 2, 6]);
    for k in ks {
        if k < MAX_DOC_SIGNERS as usize && k + 2 <= MAX_DOC_RULES as usize && k <= 9 {
            let w = world();
            let owner = canonical_passkey([0x51; 32]);
            let a = w.new_account(canonical_passkey([0x51; 32]));
            let token = w.funded_token(&a);
            let base: std::vec::Vec<(usize, u32)> = (0..k).map(|i| (i, 100)).collect();
            if k > 0 {
                assert!(w.try_apply(&a, &owner, &single_doc(&w, &owner, &token, &base), 0));
            }
            let mut added = base.clone();
            added.push((k, 100));
            let doc = single_doc(&w, &owner, &token, &added);
            assert!(w.fork_apply_doc(
                &format!("single: add a grant [{k} grants before]"),
                &a,
                &owner,
                &doc
            ));
            assert!(w.try_apply(&a, &owner, &doc, 0));
            let id = w.rule_id(&a.address, &format!("g{k:03}"));
            assert!(w.fork_spend(
                &format!("single: capped transfer [{} grants]", k + 1),
                &a,
                &gkey(k),
                &token,
                5,
                id
            ));
            assert!(w.execute(&a, &owner));
            report(
                &format!("main: single: execute through admin [{} grants]", k + 1),
                &w.env,
            );
            let mut updated = base.clone();
            updated.push((k, 200));
            let doc = single_doc(&w, &owner, &token, &updated);
            assert!(w.fork_apply_doc(
                &format!("single: change a grant's cap [{} grants]", k + 1),
                &a,
                &owner,
                &doc
            ));
            assert!(w.try_apply(&a, &owner, &doc, 0));
            let new_owner = canonical_passkey([0x52; 32]);
            let doc = single_doc(&w, &new_owner, &token, &updated);
            assert!(w.fork_apply_doc(
                &format!("single: rotate the owner key [{} grants]", k + 1),
                &a,
                &owner,
                &doc
            ));
            assert!(w.try_apply(&a, &owner, &doc, 0));
            let doc = single_doc(&w, &new_owner, &token, &base);
            assert!(w.fork_apply_doc(
                &format!("single: revoke a grant [{} grants before]", k + 1),
                &a,
                &new_owner,
                &doc
            ));
        }

        let w = world();
        let owner = canonical_passkey([0x51; 32]);
        let a = w.new_account(canonical_passkey([0x51; 32]));
        if !split_stack(&w, &a) {
            continue;
        }
        let token = w.funded_token(&a);
        assert!(w.try_apply(&a, &owner, &single_doc(&w, &owner, &token, &[]), 0));
        for i in 0..k {
            assert!(w.try_apply_grant(&a, &owner, i as u32, &grant_doc(&w, &token, &[(i, 100)])));
        }
        let s = k as u32;
        let doc = grant_doc(&w, &token, &[(k, 100)]);
        assert!(w.fork_apply_grant(
            &format!("split: add a grant [{k} grant documents before]"),
            &a,
            &owner,
            s,
            &doc
        ));
        assert!(w.try_apply_grant(&a, &owner, s, &doc));
        let id = w.grant_rule_id(&a, s, &format!("g{k:03}"));
        assert!(w.fork_spend(
            &format!("split: capped transfer [{} grant documents]", k + 1),
            &a,
            &gkey(k),
            &token,
            5,
            id
        ));
        assert!(w.execute(&a, &owner));
        report(
            &format!(
                "main: split: execute through admin [{} grant documents]",
                k + 1
            ),
            &w.env,
        );
        let doc = grant_doc(&w, &token, &[(k, 200)]);
        assert!(w.fork_apply_grant(
            &format!("split: change a grant's cap [{} grant documents]", k + 1),
            &a,
            &owner,
            s,
            &doc
        ));
        assert!(w.try_apply_grant(&a, &owner, s, &doc));
        let new_owner = canonical_passkey([0x52; 32]);
        let doc = single_doc(&w, &new_owner, &token, &[]);
        assert!(w.fork_apply_doc(
            &format!("split: rotate the owner key [{} grant documents]", k + 1),
            &a,
            &owner,
            &doc
        ));
        assert!(w.try_apply(&a, &owner, &doc, 0));
        assert!(w.fork_remove_grant(
            &format!("split: revoke a grant [{} grant documents before]", k + 1),
            &a,
            &new_owner,
            s
        ));
    }
}

/// The grant tier's guards, and a key that manages one grant document only.
#[test]
#[ignore = "needs the built stack"]
fn docsplit_guards_and_grant_manager() {
    let w = world();
    let owner = canonical_passkey([0x56; 32]);
    let a = w.new_account(canonical_passkey([0x56; 32]));
    assert!(split_stack(&w, &a), "needs a stack with grant documents");
    let token = w.funded_token(&a);
    let mgr = canonical_passkey([0x57; 32]);
    // admin for the owner, plus `mgr`: a self-scoped rule limited to
    // `apply_grant(7, ..)`.
    let admin_doc = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{},{}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}},{{"name":"mgr","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["mgr"]}},"functions":["apply_grant"],"args":[{{"index":0,"pred":{{"type":"u32-eq","value":7}}}}]}}]}}"#,
        passkey_decl(&w, "owner", &owner),
        passkey_decl(&w, "mgr", &mgr)
    );
    assert!(w.try_apply(
        &a,
        &owner,
        &Bytes::from_slice(&w.env, admin_doc.as_bytes()),
        0
    ));

    // Guards: no self-admin rule, no rule scoped to the account, no recovery.
    let selfadmin = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{{"name":"x","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["k"]}}}}]}}"#,
        passkey_decl(&w, "k", &gkey(1))
    );
    assert!(
        !w.try_apply_grant(
            &a,
            &owner,
            1,
            &Bytes::from_slice(&w.env, selfadmin.as_bytes())
        ),
        "self-admin refused"
    );
    let selfcontract = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{{"name":"x","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["k"]}}}}]}}"#,
        passkey_decl(&w, "k", &gkey(1)),
        strkey(&a.address)
    );
    assert!(
        !w.try_apply_grant(
            &a,
            &owner,
            1,
            &Bytes::from_slice(&w.env, selfcontract.as_bytes())
        ),
        "a rule scoped to the account refused"
    );
    println!("\n{{\"guard\":\"self-admin, self-contract refused\"}}");

    // The manager key: grant 7 yes; grant 8, apply_doc, execute no.
    let mgr_entry = |fn_name: &str, args: std::vec::Vec<ScVal>| {
        let root = w.invocation(&a.address, fn_name, args);
        w.passkey_entry(&a.address, &mgr, "mgr", root)
    };
    let doc7 = grant_doc(&w, &token, &[(7, 100)]);
    w.env.set_auths(&[mgr_entry(
        "apply_grant",
        std::vec![w.sc(7u32), w.sc(doc7.clone())],
    )]);
    assert!(
        matches!(w.account(&a).try_apply_grant(&7, &doc7), Ok(Ok(_))),
        "mgr manages grant 7"
    );
    w.env.set_auths(&[mgr_entry(
        "apply_grant",
        std::vec![w.sc(8u32), w.sc(doc7.clone())],
    )]);
    assert!(
        w.account(&a).try_apply_grant(&8, &doc7).is_err(),
        "mgr cannot touch grant 8"
    );
    let takeover = single_doc(&w, &mgr, &token, &[]);
    w.env.set_auths(&[mgr_entry(
        "apply_doc",
        std::vec![w.sc(takeover.clone()), w.sc(0u32), w.sc(None::<u64>)],
    )]);
    assert!(
        w.account(&a).try_apply_doc(&takeover, &0, &None).is_err(),
        "mgr cannot apply the account document"
    );
    w.env.set_auths(&[]);
    println!("\n{{\"guard\":\"scope manager confined to its grant id\"}}");

    // But within its grant id the manager is unconfined: it can grant itself
    // an uncapped transfer and move the account's tokens.
    let drain = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{{"name":"drain","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["m"]}}}}]}}"#,
        passkey_decl(&w, "m", &mgr),
        strkey(&token)
    );
    let drain = Bytes::from_slice(&w.env, drain.as_bytes());
    w.env.set_auths(&[mgr_entry(
        "apply_grant",
        std::vec![w.sc(7u32), w.sc(drain.clone())],
    )]);
    assert!(matches!(
        w.account(&a).try_apply_grant(&7, &drain),
        Ok(Ok(_))
    ));
    w.env.set_auths(&[]);
    let id = w.grant_rule_id(&a, 7, "drain");
    assert!(
        w.spend_id(&a, &mgr, &token, 900, id),
        "the manager moves 900 of 1 000"
    );
    println!("\n{{\"guard\":\"a grant manager without an envelope can grant itself any non-account authority\"}}");
}

/// A capped transfer's cost against its spending record's history length.
/// The record keeps every spend in the window, 72 bytes each in a ledger
/// entry of 172 bytes more, so the network's 65 536-byte entry limit holds
/// 907 of them (below rule-eval's own bound of 1 000): the transfer after
/// 906 spends is the costliest the window admits, and the next one fails
/// until spends leave the window.
#[test]
#[ignore = "needs the built stack"]
fn docsplit_spending_history() {
    let w = world();
    let owner = canonical_passkey([0x58; 32]);
    let a = w.new_account(canonical_passkey([0x58; 32]));
    let token = w.funded_token(&a);
    assert!(w.try_apply(
        &a,
        &owner,
        &single_doc(&w, &owner, &token, &[(0, 100_000)]),
        0
    ));
    let id = w.rule_id(&a.address, "g000");
    let mut done = 0;
    for n in [0usize, 10, 100, 400, 906] {
        while done < n {
            assert!(w.spend_id(&a, &gkey(0), &token, 1, id));
            done += 1;
        }
        assert!(w.fork_spend(
            &format!("capped transfer after {n} spends in the window"),
            &a,
            &gkey(0),
            &token,
            1,
            id
        ));
    }
}

// ---------------------------------------------------------------------------
// Grant-document caps: every grant flow at the grant caps (`budgets.md`,
// "Grant-document caps")
// ---------------------------------------------------------------------------

/// A grant document's shape: `signers` session passkeys and `rules` rules,
/// each naming `fan` of the signers (1-of-`fan`, wrapping, so every signer
/// is some rule's), padded to `bytes` canonical bytes (0: unpadded).
#[derive(Clone, Copy, Debug)]
struct GrantShape {
    signers: usize,
    rules: usize,
    fan: usize,
    bytes: usize,
    /// 0: every rule a capped `transfer` from the account. 1: every rule a
    /// bare grant, with the shortest signer ids and rule names: the most
    /// signer references, each a passkey the account's record of the grant
    /// document holds, per document byte. 2: as 1, every rule asking all of
    /// its signers (`all`, shorter than a `threshold`). 3: as 2, the last
    /// two rules capped `transfer`s from the account, the second-last
    /// asking [`QUORUM`] of its signers and the last all of them.
    dense: u8,
}

/// The signers the second-last rule of a `dense` 3 grant document asks.
const QUORUM: usize = 8;

/// The characters of a padding `string-in` value: canonical JSON escapes
/// none of them.
const VALUE_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The characters of a dense rule's name: [`VALUE_CHARS`] without the `x`
/// that pads a name.
const NAME_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwyz";

/// The `n`th string over `chars`, shortest first: distinct for distinct `n`.
fn shortest(chars: &[u8], mut n: usize) -> String {
    let (mut len, mut span) = (1, chars.len());
    while n >= span {
        n -= span;
        len += 1;
        span *= chars.len();
    }
    let mut out = std::vec![0u8; len];
    for slot in out.iter_mut().rev() {
        *slot = chars[n % chars.len()];
        n /= chars.len();
    }
    String::from_utf8(out).unwrap()
}

impl GrantShape {
    /// The grant documents with the most signer references the grant caps
    /// admit, `dense` or capped: every signer a passkey, every rule naming
    /// as many signers as a rule may (OZ's 15), as many rules as fit the
    /// byte cap, padded to it.
    fn at_caps(w: &World, dense: u8) -> GrantShape {
        let signers = MAX_GRANT_SIGNERS as usize;
        let mut shape = GrantShape {
            signers,
            rules: MAX_GRANT_RULES as usize,
            fan: signers.min(MAX_SIGNERS as usize),
            bytes: 0,
            dense,
        };
        let keys = gkeys(0, signers);
        while canonical_len(&w.grant_json(&w.target, &keys, shape, "a", false, 0, 0))
            > MAX_GRANT_CANONICAL_BYTES as usize
        {
            shape.rules -= 1;
        }
        GrantShape {
            bytes: MAX_GRANT_CANONICAL_BYTES as usize,
            ..shape
        }
    }

    fn label(&self, what: &str, bytes: usize) -> String {
        format!(
            "grant: {what} [{} signers, {} rules, {} per rule, {bytes} bytes{}]",
            self.signers,
            self.rules,
            self.fan,
            ["", ", dense", ", dense all", ", dense all, quorum rules"][self.dense as usize]
        )
    }

    /// Signer `i`'s id: `a`, ..., `z`, `ba`, ... when dense.
    fn id(&self, i: usize) -> String {
        if self.dense == 0 {
            return format!("k{i:02}");
        }
        let letter = |n: usize| char::from(b'a' + n as u8);
        if i < 26 {
            letter(i).to_string()
        } else {
            format!("{}{}", letter(i / 26), letter(i % 26))
        }
    }

    /// Rule `k`'s name before padding: when dense, the shortest that is
    /// distinct in the documents of every `tag` (`a`, `b`, `c`).
    fn rule_name(&self, tag: &str, k: usize) -> String {
        if self.dense > 0 {
            let t = ["a", "b", "c"]
                .iter()
                .position(|x| *x == tag)
                .expect("a known tag");
            shortest(NAME_CHARS, k * 3 + t)
        } else {
            format!("{tag}g{k:02}")
        }
    }

    /// The signers rule `k` names, in the order it names them: the `fan`
    /// from `k * fan` on, wrapping, by id.
    fn named(&self, k: usize) -> std::vec::Vec<usize> {
        let mut named: std::vec::Vec<usize> = (0..self.fan)
            .map(|i| (k * self.fan + i) % self.signers)
            .collect();
        named.sort_by_key(|&i| self.id(i));
        named.dedup();
        named
    }

    /// Whether rule `k` is a capped `transfer` from the account.
    fn capped(&self, k: usize) -> bool {
        self.dense == 0 || (self.dense == 3 && k + 2 >= self.rules)
    }

    /// The signers rule `k` asks of those it names.
    fn quorum(&self, k: usize) -> usize {
        let named = self.named(k).len();
        if self.dense < 2 {
            1
        } else if self.dense == 3 && k + 2 == self.rules {
            QUORUM.min(named)
        } else {
            named
        }
    }

    /// The signers in the order the rules first name them, which normal
    /// form declares them in.
    fn declared(&self) -> std::vec::Vec<usize> {
        let mut order = std::vec![];
        for k in 0..self.rules {
            for i in self.named(k) {
                if !order.contains(&i) {
                    order.push(i);
                }
            }
        }
        assert_eq!(
            order.len(),
            self.signers,
            "{self:?} leaves a signer unnamed"
        );
        order
    }
}

/// `n` session passkeys, from [`gkey`] `first` on.
fn gkeys(first: usize, n: usize) -> std::vec::Vec<SoftPasskey> {
    (first..first + n).map(gkey).collect()
}

impl World {
    /// The grant document of `shape` over `keys`, one per signer: rule `k`
    /// lets [`GrantShape::quorum`] of its named signers
    /// ([`GrantShape::named`]; `all` when it asks every one) call `token`.
    /// A capped rule ([`GrantShape::capped`]) may transfer from the account
    /// (`is-self` on argument 0) within a cap, and `edit` changes every cap's
    /// limit and period; a dense rule may call anything, and `edit` asks two
    /// of its signers where it names three or more. Either edit keeps the
    /// length. `values` strings, the shortest distinct ones, in a
    /// `string-in` on argument 1 of rule 0 and `pad` bytes over the rule
    /// names grow it. Normal form, as `apply_grant`
    /// requires.
    #[allow(clippy::too_many_arguments)]
    fn grant_json(
        &self,
        token: &Address,
        keys: &[SoftPasskey],
        shape: GrantShape,
        tag: &str,
        edit: bool,
        values: usize,
        pad: usize,
    ) -> String {
        let signers: std::vec::Vec<String> = shape
            .declared()
            .into_iter()
            .map(|i| passkey_decl(self, &shape.id(i), &keys[i]))
            .collect();
        let mut pad = pad;
        let mut rules = std::vec![];
        for k in 0..shape.rules {
            let named = shape.named(k);
            let quoted: std::vec::Vec<String> = named
                .iter()
                .map(|&i| format!(r#""{}""#, shape.id(i)))
                .collect();
            let quorum = shape.quorum(k);
            let m = if edit && named.len() >= 3 { 2 } else { quorum };
            let principals = if quorum == named.len() {
                format!(r#"{{"type":"all","signers":[{}]}}"#, quoted.join(","))
            } else {
                format!(
                    r#"{{"type":"threshold","m":{m},"signers":[{}]}}"#,
                    quoted.join(",")
                )
            };
            let base = shape.rule_name(tag, k);
            let grow = pad.min(MAX_NAME_SIZE as usize - base.len());
            pad -= grow;
            let name = format!("{base}{}", "x".repeat(grow));
            let mut args = std::vec![];
            if shape.capped(k) {
                args.push(r#"{"index":0,"pred":{"type":"is-self"}}"#.to_string());
            }
            if k == 0 && values > 0 {
                let values: std::vec::Vec<String> = (0..values)
                    .map(|v| format!(r#""{}""#, shortest(VALUE_CHARS, v)))
                    .collect();
                args.push(format!(
                    r#"{{"index":1,"pred":{{"type":"string-in","values":[{}]}}}}"#,
                    values.join(",")
                ));
            }
            let mut rule = format!(
                r#"{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{principals}"#,
                strkey(token)
            );
            if !args.is_empty() {
                rule.push_str(&format!(
                    r#","functions":["transfer"],"args":[{}]"#,
                    args.join(",")
                ));
            }
            if shape.capped(k) {
                let (limit, period) = if edit {
                    ("1001", "1001")
                } else {
                    ("1000", "1000")
                };
                rule.push_str(&format!(
                    r#","cap":{{"limit":"{limit}","period-ledgers":{period}}}"#
                ));
            }
            rule.push('}');
            rules.push(rule);
        }
        assert_eq!(pad, 0, "the rule names cannot absorb the padding");
        format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
            signers.join(","),
            rules.join(",")
        )
    }

    /// [`World::grant_json`] padded to exactly `shape.bytes` canonical bytes
    /// (unpadded at 0): first a `string-in` with as many strings as fit,
    /// which the account's record stores at several times their document
    /// bytes, then the rule names. Returns the document and its canonical
    /// length.
    fn grant_shaped(
        &self,
        token: &Address,
        keys: &[SoftPasskey],
        shape: GrantShape,
        tag: &str,
        edit: bool,
    ) -> (Bytes, usize) {
        let json =
            |values: usize, pad: usize| self.grant_json(token, keys, shape, tag, edit, values, pad);
        let len = |values: usize, pad: usize| canonical_len(&json(values, pad));
        // Within the byte target and the entry the compiler admits.
        let fits = |values: usize, pad: usize| {
            len(values, pad) <= shape.bytes
                && stored_bytes(&json(values, pad)) <= MAX_GRANT_STORED_BYTES
        };
        // The most of `0..=hi` that `ok` holds for, `ok` holding up to it.
        let most = |hi: usize, ok: &dyn Fn(usize) -> bool| {
            let (mut lo, mut hi) = (0usize, hi);
            while lo < hi {
                let mid = (lo + hi).div_ceil(2);
                if ok(mid) {
                    lo = mid;
                } else {
                    hi = mid - 1;
                }
            }
            lo
        };
        let (values, pad) = if shape.bytes == 0 {
            (0, 0)
        } else {
            assert!(fits(0, 0), "{shape:?} does not fit its bytes");
            // Each value adds at least four bytes.
            let values = most(shape.bytes / 4 + 1, &|v| fits(v, 0));
            // What the rule names can grow by.
            let room: usize = (0..shape.rules)
                .map(|k| MAX_NAME_SIZE as usize - shape.rule_name(tag, k).len())
                .sum();
            let pad = (shape.bytes - len(values, 0)).min(room);
            (values, most(pad, &|p| fits(values, p)))
        };
        let size = len(values, pad);
        let json = self.grant_json(token, keys, shape, tag, edit, values, pad);
        (Bytes::from_slice(&self.env, json.as_bytes()), size)
    }

    /// A grant document of one signer and one rule that spends its bytes on
    /// `string-in` values: `values` of them, each one character, a
    /// [`VALUE_CHARS`] of them on each argument index from 0 (a value must
    /// be distinct only within its predicate), the first `pad` bytes
    /// longer. Normal form, as `apply_grant` requires.
    fn values_json(&self, token: &Address, signer: &str, values: usize, pad: usize) -> String {
        let per = VALUE_CHARS.len();
        let preds: std::vec::Vec<String> = (0..values.div_ceil(per))
            .map(|i| {
                let quoted: std::vec::Vec<String> = (0..per.min(values - i * per))
                    .map(|v| {
                        let longer = if i == 0 && v == 0 { pad } else { 0 };
                        format!(r#""{}{}""#, char::from(VALUE_CHARS[v]), "0".repeat(longer))
                    })
                    .collect();
                format!(
                    r#"{{"index":{i},"pred":{{"type":"string-in","values":[{}]}}}}"#,
                    quoted.join(",")
                )
            })
            .collect();
        assert!(preds.len() <= MAX_RULE_CONSTRAINTS as usize);
        format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{{"name":"a","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["a"]}},"args":[{}]}}]}}"#,
            signer,
            strkey(token),
            preds.join(",")
        )
    }

    /// [`World::values_json`] with as many values as `bytes` canonical bytes
    /// hold, filled to exactly `bytes`.
    fn values_grant(&self, token: &Address, signer: &str, bytes: usize) -> Bytes {
        let json = |values: usize, pad: usize| self.values_json(token, signer, values, pad);
        let fits = |values: usize, pad: usize| canonical_len(&json(values, pad)) <= bytes;
        // Each value adds at least four bytes.
        let (mut values, mut hi) = (1usize, bytes / 4);
        while values < hi {
            let mid = (values + hi).div_ceil(2);
            if fits(mid, 0) {
                values = mid;
            } else {
                hi = mid - 1;
            }
        }
        let pad = bytes - canonical_len(&json(values, 0));
        assert_eq!(canonical_len(&json(values, pad)), bytes);
        Bytes::from_slice(&self.env, json(values, pad).as_bytes())
    }

    /// The id of the rule named `base`, padded or not, in the grant
    /// document under `grant`.
    fn shaped_rule_id(&self, a: &Acct, grant: u32, base: &str) -> u32 {
        self.account(a)
            .grant(&grant)
            .expect("grant exists")
            .rules
            .iter()
            .find(|r| {
                let mut buf = [0u8; 32];
                let n = r.name.len() as usize;
                r.name.copy_into_slice(&mut buf[..n]);
                let name = std::str::from_utf8(&buf[..n]).unwrap();
                name.strip_prefix(base)
                    .is_some_and(|rest| rest.bytes().all(|b| b == b'x'))
            })
            .expect("rule exists")
            .id
    }

    fn fork_gc_grant(&self, label: &str, a: &Acct, grant: u32) -> bool {
        self.forked(
            label,
            &a.address,
            "gc_grant",
            std::vec![self.sc(grant)],
            |_, _| std::vec![],
        )
    }
}

/// Every grant flow over a grant document of `shape`, each one transaction
/// on a host forked from the ledger (`World::forked`): `apply_grant`
/// adding every rule, a transfer through the last rule signed by as many
/// keys as it asks (and through a `dense` 3 document's second-last), every
/// rule edited in place, every rule replaced (renamed and rekeyed), `remove_grant`,
/// then, after a lost-key recovery wipes the grant document, `gc_grant` of
/// it and a re-grant over it. A capped document's rules have each spent
/// through their cap before the edits, so each holds a spending record to
/// drop (all but rule 0, whose `string-in` padding no transfer meets).
fn grant_flows(w: &World, shape: GrantShape, seed: u8) {
    let owner = canonical_passkey([seed; 32]);
    let a = w.new_account(canonical_passkey([seed; 32]));
    assert!(split_stack(w, &a), "needs a stack with grant documents");
    let token = w.funded_token(&a);
    let rec = Rec {
        profile: "loss",
        mode: Mode::Guardian,
        zk: None,
        delay: DELAY,
        baseline: None,
    };
    assert!(w.try_apply(&a, &owner, &w.doc(&owner, Some(&rec)), 0));

    let first = 1000 * (seed as usize % 16);
    let keys = gkeys(first, shape.signers);
    let (doc, bytes) = w.grant_shaped(&token, &keys, shape, "a", false);
    let label = |what: &str| shape.label(what, bytes);
    assert!(w.fork_apply_grant(&label("apply_grant, every rule added"), &a, &owner, 0, &doc));
    assert!(
        w.try_apply_grant(&a, &owner, 0, &doc),
        "apply_grant of {shape:?}"
    );
    let spender = |k: usize| &keys[shape.named(k)[0]];
    if shape.dense == 0 {
        for k in 1..shape.rules {
            let id = w.shaped_rule_id(&a, 0, &shape.rule_name("a", k));
            assert!(
                w.spend_id(&a, spender(k), &token, 5, id),
                "a transfer through rule {k}"
            );
        }
    }
    let last = shape.rules - 1;
    let id = w.shaped_rule_id(&a, 0, &shape.rule_name("a", last));
    let one_signs = shape.quorum(last) == 1;
    for k in last.saturating_sub((shape.dense == 3) as usize)..=last {
        let named = shape.named(k);
        let signing: std::vec::Vec<&SoftPasskey> =
            named[..shape.quorum(k)].iter().map(|&i| &keys[i]).collect();
        let what = if k == last && one_signs {
            "transfer through the last rule".to_string()
        } else {
            format!(
                "transfer through a {} rule, {} of {} signing",
                if shape.capped(k) { "capped" } else { "bare" },
                signing.len(),
                named.len()
            )
        };
        assert!(w.fork_spend_by(
            &label(&what),
            &a,
            &signing,
            &token,
            5,
            w.shaped_rule_id(&a, 0, &shape.rule_name("a", k))
        ));
    }
    // An `all` rule has no same-length edit.
    if shape.dense < 2 {
        let (edited, _) = w.grant_shaped(&token, &keys, shape, "a", true);
        assert!(w.fork_apply_grant(
            &label("apply_grant, every rule edited (names kept)"),
            &a,
            &owner,
            0,
            &edited
        ));
    }
    let (replaced, _) = w.grant_shaped(
        &token,
        &gkeys(first + 200, shape.signers),
        shape,
        "b",
        false,
    );
    assert!(w.fork_apply_grant(
        &label("apply_grant, every rule replaced (renamed, rekeyed)"),
        &a,
        &owner,
        0,
        &replaced
    ));
    assert!(w.fork_remove_grant(&label("remove_grant"), &a, &owner, 0));

    // A lost-key recovery wipes the grant document.
    let new_owner = canonical_passkey([seed.wrapping_add(1); 32]);
    let replacements = w.replacements(&new_owner, None);
    let attempt = w.ctl().begin_lost_key(&a.address, &replacements);
    w.guardian(1, &a, attempt, EvidenceDomain::Initiate);
    w.guardian(2, &a, attempt, EvidenceDomain::Initiate);
    w.advance(DELAY);
    assert!(w.try_complete(&a, &w.target_bytes(&a, &replacements)));
    assert_eq!(w.account(&a).grant_generation(), 1);
    if one_signs {
        assert!(
            !w.spend_id(&a, spender(last), &token, 1, id),
            "a wiped grant"
        );
    }
    assert!(w.fork_gc_grant(&label("gc_grant of the wiped grant document"), &a, 0));
    let (regrant, _) = w.grant_shaped(
        &token,
        &gkeys(first + 400, shape.signers),
        shape,
        "c",
        false,
    );
    assert!(w.fork_apply_grant(
        &label("apply_grant over the wiped grant document (every rule replaced, fresh keys)"),
        &a,
        &new_owner,
        0,
        &regrant
    ));
}

/// The grant flows at the compiled-in grant caps, over the capped and dense
/// grant documents with the most signer references they admit, a transfer
/// every signer of a rule signs among them, the most rules (one signer, as
/// many rules as the rule cap allows), and the values-only document (one
/// signer, two rules, the rest of the byte cap a `string-in`'s values):
/// each row within 75% of every metered limit, the largest entry and the
/// transaction's size included. Then [`values_grants_at_the_byte_cap`].
#[test]
#[ignore = "needs the built stack"]
fn worst_case_grant_flows_at_the_grant_caps() {
    SIZES.with(|s| s.set(true));
    for (dense, seed) in [(0, 60), (1, 70), (2, 80), (3, 90)] {
        let w = world();
        w.env.cost_estimate().disable_resource_limits();
        grant_flows(&w, GrantShape::at_caps(&w, dense), seed);
    }
    let most_rules = GrantShape {
        signers: 1,
        rules: MAX_GRANT_RULES as usize,
        fan: 1,
        bytes: MAX_GRANT_CANONICAL_BYTES as usize,
        dense: 1,
    };
    let values_only = GrantShape {
        signers: 1,
        rules: 2,
        fan: 1,
        bytes: MAX_GRANT_CANONICAL_BYTES as usize,
        dense: 0,
    };
    for (shape, seed) in [(most_rules, 95), (values_only, 100)] {
        let w = world();
        w.env.cost_estimate().disable_resource_limits();
        grant_flows(&w, shape, seed);
    }
    values_grants_at_the_byte_cap();
    SIZES.with(|s| s.set(false));
}

/// The size, in bytes, of the entry an account stores for grant document
/// `json` (`perch_doc_compiler::grant_stored_bytes`).
fn stored_bytes(json: &str) -> u32 {
    perch_doc_compiler::grant_stored_bytes(&perch_ir::from_json(json).expect("a valid document"))
}

/// The grant documents of one-character `string-in` values on every argument
/// index ([`World::values_json`]), which the record stores densest, filling
/// the byte cap beside a passkey signer and beside a delegated one (whose
/// shorter declaration leaves room for more values): each applies within
/// 75% of every limit, its record within [`MAX_GRANT_STORED_BYTES`], the
/// largest entry any grant document the caps admit stores.
fn values_grants_at_the_byte_cap() {
    let bytes = MAX_GRANT_CANONICAL_BYTES as usize;
    let w = world();
    w.env.cost_estimate().disable_resource_limits();
    let owner = canonical_passkey([110; 32]);
    let a = w.new_account(canonical_passkey([110; 32]));
    assert!(split_stack(&w, &a), "needs a stack with grant documents");
    let token = w.funded_token(&a);
    let passkey = passkey_decl(&w, "a", &gkey(0));
    let delegate = format!(r#"{{"id":"a","address":"{}"}}"#, strkey(&w.guardians[0]));
    for (kind, signer) in [("passkey", passkey), ("delegated", delegate)] {
        let doc = w.values_grant(&token, &signer, bytes);
        let json = std::str::from_utf8(&doc.to_alloc_vec())
            .unwrap()
            .to_string();
        assert!(stored_bytes(&json) <= MAX_GRANT_STORED_BYTES);
        assert!(w.fork_apply_grant(
            &format!("grant: apply_grant, one rule of one-character values [1 {kind} signer, 1 rule, {bytes} bytes, {} stored]", stored_bytes(&json)),
            &a,
            &owner,
            0,
            &doc
        ));
    }
}

/// Size the grant caps: [`grant_flows`] over each
/// `signers,rules,fan,bytes[,dense]` of `PERCH_GRANT_SWEEP` (`;`-separated;
/// bytes 0 leaves the document unpadded, dense as [`GrantShape`]'s),
/// unbudgeted. `scripts/cap-sweep.py --grants` runs and tabulates it. The
/// stack's compiler must admit the shapes: to measure past the grant caps,
/// build a stack with them raised.
#[test]
#[ignore = "sizing tool: PERCH_GRANT_SWEEP=..."]
fn grant_cap_sweep() {
    let spec = std::env::var("PERCH_GRANT_SWEEP").unwrap_or_default();
    UNBUDGETED.with(|u| u.set(true));
    SIZES.with(|s| s.set(true));
    for (n, item) in spec.split(';').filter(|s| !s.is_empty()).enumerate() {
        let v: std::vec::Vec<usize> = item.split(',').map(|x| x.trim().parse().unwrap()).collect();
        let shape = GrantShape {
            signers: v[0],
            rules: v[1],
            fan: v[2].min(v[0]),
            bytes: v[3],
            dense: v.get(4).copied().unwrap_or(0) as u8,
        };
        let w = world();
        w.env.cost_estimate().disable_resource_limits();
        let own = canonical_len(&w.grant_json(
            &w.target,
            &gkeys(0, shape.signers),
            shape,
            "a",
            false,
            0,
            0,
        ));
        let skip = |why: &str| {
            println!(
                "\n{{\"case\":\"skipped\",\"signers\":{},\"rules\":{},\"bytes\":{},\"why\":\"{why} ({own} bytes unpadded)\"}}",
                shape.signers, shape.rules, shape.bytes
            )
        };
        if shape.signers > MAX_GRANT_SIGNERS as usize
            || shape.rules > MAX_GRANT_RULES as usize
            || shape.bytes.max(own) > MAX_GRANT_CANONICAL_BYTES as usize
        {
            skip("past this build's grant caps");
            continue;
        }
        if shape.bytes > 0 && own > shape.bytes {
            skip("does not fit the byte target");
            continue;
        }
        grant_flows(&w, shape, 60 + (n % 16) as u8);
    }
}

// ---------------------------------------------------------------------------
// Storage census: the testnet preview account's grant, entry by entry
// (`budgets.md`, "Account storage")
// ---------------------------------------------------------------------------

/// The preview documents' `not-after-ledger`s and signer ids. Every key is a
/// 65-byte passkey, so sizes match testnet's.
const CENSUS_NALS: [u32; 2] = [5_581_508, 5_581_591];
const CENSUS_IDS: [&str; 2] = [
    "http://localhost:5542#59ee8848",
    "http://localhost:5543#abbe5266",
];
/// The preview's grant ids: candidate 0 of each app's origin.
const CENSUS_GRANTS: [u32; 2] = [3_395_152_355, 3_943_074_923];

fn census_key(i: u8) -> SoftPasskey {
    canonical_passkey([0x60 + i; 32])
}

/// One app's two rules, as the preview's grant documents spell them.
fn census_rules(game: &Address, token: &Address, sid: &str, nal: u32, sfx: &str) -> [String; 2] {
    let (g, t) = (strkey(game), strkey(token));
    [
        format!(
            r#"{{"functions":["guess"],"name":"guess{sfx}","not-after-ledger":{nal},"principals":{{"signers":["{sid}"],"type":"all"}},"scope":{{"address":"{g}","type":"contract"}}}}"#
        ),
        format!(
            r#"{{"args":[{{"index":1,"pred":{{"address":"{g}","type":"address-eq"}}}}],"cap":{{"limit":"20000000","period-ledgers":17280}},"functions":["transfer"],"name":"guess-xlm{sfx}","not-after-ledger":{nal},"principals":{{"signers":["{sid}"],"type":"all"}},"scope":{{"address":"{t}","type":"contract"}}}}"#
        ),
    ]
}

fn census_doc(w: &World, signers: &[String], rules: &[String]) -> Bytes {
    let json = format!(
        r#"{{"network":"{FIXTURE_NETWORK}","rules":[{}],"signers":[{}],"version":1}}"#,
        rules.join(","),
        signers.join(",")
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// An account for `census_key(0)`, the game contract, and a funded token.
fn census_world() -> (World, Acct, Address, Address) {
    let w = world();
    let a = w.new_account(census_key(0));
    let game = w.env.register(support::Target, ());
    let token = w
        .env
        .register_stellar_asset_contract_v2(w.guardians[0].clone())
        .address();
    w.env.mock_all_auths();
    StellarAssetClient::new(&w.env, &token).mint(&a.address, &100_000_000);
    w.env.set_auths(&[]);
    (w, a, game, token)
}

/// `key` transfers 1 XLM to the game through rule `id`.
fn census_spend(
    w: &World,
    a: &Acct,
    key: &SoftPasskey,
    token: &Address,
    game: &Address,
    id: u32,
) -> bool {
    let amount: i128 = 10_000_000;
    let root = w.invocation(
        token,
        "transfer",
        std::vec![w.sc(a.address.clone()), w.sc(game.clone()), w.sc(amount)],
    );
    let entry = auth_entry(
        &w.env,
        &a.address,
        &w.webauthn,
        key,
        id,
        w.next_nonce(),
        w.ledger() + 720,
        root,
    );
    w.env.set_auths(&[entry]);
    let ok = TokenClient::new(&w.env, token)
        .try_transfer(&a.address, game, &amount)
        .is_ok();
    w.env.set_auths(&[]);
    ok
}

/// Print every contract-data entry the account owns, and any entry another
/// contract keeps that names it, one `{"census": ...}` line each, then the
/// account's own entries' total; returns that total (bytes, entries),
/// host nonces left out.
fn census_dump(w: &World, a: &Acct, label: &str) -> (usize, usize) {
    use soroban_sdk::xdr::{ContractDataDurability, LedgerEntryData, LedgerKey, Limits, WriteXdr};
    let snapshot = w.env.to_ledger_snapshot();
    let me: soroban_sdk::xdr::ScAddress = a.address.clone().into();
    let (mut bytes, mut entries) = (0, 0);
    for (key, (entry, live_until)) in snapshot.ledger_entries.iter() {
        let LedgerKey::ContractData(k) = &**key else {
            continue;
        };
        let LedgerEntryData::ContractData(d) = &entry.data else {
            continue;
        };
        let mine = k.contract == me;
        if !mine && !format!("{:?}", k.key).contains(&format!("{me:?}")) {
            continue;
        }
        let size = entry.to_xdr(Limits::none()).unwrap().len();
        if mine && !matches!(k.key, ScVal::LedgerKeyNonce(_)) {
            bytes += size;
            entries += 1;
        }
        let owner = if mine {
            "account".to_string()
        } else {
            strkey(&Address::try_from_val(&w.env, &k.contract).unwrap())
        };
        println!(
            "\n{}",
            serde_json::json!({
                "census": label,
                "owner": owner,
                "durability": match k.durability {
                    ContractDataDurability::Persistent => "persistent",
                    ContractDataDurability::Temporary => "temporary",
                },
                "entry_bytes": size,
                "key_xdr": hex(&k.key.to_xdr(Limits::none()).unwrap()),
                "val_xdr": hex(&d.val.to_xdr(Limits::none()).unwrap()),
                "live_until": live_until,
            })
        );
    }
    println!(
        "\n{}",
        serde_json::json!({"census_total": label, "bytes": bytes, "entries": entries})
    );
    (bytes, entries)
}

/// The preview account's grant: the constructor's admin rule, then one
/// grant document per app (`guess` on the game contract, and `guess-xlm`, a
/// capped XLM `transfer` to it), then a 1 XLM transfer through the second
/// app's capped rule.
#[test]
#[ignore = "needs the built stack"]
fn census_of_the_preview_grant() {
    let (w, a, game, token) = census_world();
    census_dump(&w, &a, "constructor");
    for (i, sid) in CENSUS_IDS.iter().enumerate() {
        let key = census_key(1 + i as u8);
        let doc = census_doc(
            &w,
            &[format!(
                r#"{{"id":"{sid}","key":"{}","verifier":"{}"}}"#,
                hex(&key.key_data()),
                strkey(&w.webauthn)
            )],
            &census_rules(&game, &token, sid, CENSUS_NALS[i], ""),
        );
        assert!(w.try_apply_grant(&a, &census_key(0), CENSUS_GRANTS[i], &doc));
        report_unbudgeted(&format!("census: apply_grant app {}", i + 1), &w.env);
        w.advance(80);
    }
    let id = w.grant_rule_id(&a, CENSUS_GRANTS[1], "guess-xlm");
    assert!(census_spend(&w, &a, &census_key(2), &token, &game, id));
    report_unbudgeted("census: 1 XLM transfer through app 2's guess-xlm", &w.env);
    census_dump(&w, &a, "grant");
}

/// A deterministic native game; compiler/account/verifier run their built
/// Wasm. Setup may mock registry/token admin, but every tested game entry is
/// enforced and carries a real WebAuthn signature.
#[soroban_sdk::contract]
struct RootGame;
#[soroban_sdk::contractimpl]
impl RootGame {
    pub fn guess(e: Env, account: Address, token: Address, win: bool) {
        account.require_auth();
        let me = e.current_contract_address();
        if win {
            TokenClient::new(&e, &token).transfer(&me, &account, &1);
        } else {
            TokenClient::new(&e, &token).transfer(&account, &me, &1);
        }
    }
}

#[test]
#[ignore = "needs the built stack"]
fn exact_root_wasm_game_and_cap_costs() {
    use perch_testkit::passkey::auth_entry_for_rules;
    let w = world();
    let e = &w.env;
    let a = w.new_account(canonical_passkey([61; 32]));
    let token = w.funded_token(&a);
    let game = e.register(RootGame, ());
    let original = w.doc(&a.owner, None);
    let mut text = std::vec![0; original.len() as usize];
    original.copy_into_slice(&mut text);
    let mut doc = perch_ir::from_json(&String::from_utf8(text).unwrap()).unwrap();
    let mut game_rule = doc.rules[1].clone();
    game_rule.name = "game".into();
    game_rule.scope = perch_ir::Scope::contract(strkey(&game));
    game_rule.functions = Some(std::vec!["guess".into()]);
    let mut pay = game_rule.clone();
    pay.name = "pay".into();
    pay.scope = perch_ir::Scope::contract(strkey(&token));
    pay.functions = Some(std::vec!["transfer".into()]);
    pay.auth_root = Some(perch_ir::AuthRoot {
        contract: strkey(&game),
        function: "guess".into(),
    });
    pay.cap = Some(perch_ir::CapConstraint {
        token: None,
        limit: "2".into(),
        period_ledgers: 100,
    });
    doc.rules = std::vec![doc.rules[0].clone(), game_rule, pay];
    let bytes = Bytes::from_slice(e, perch_ir::canonical_json(&doc).as_bytes());
    assert!(w.try_apply(&a, &a.owner, &bytes, 0));
    report("exact root: apply game grant", e);
    assert_eq!(w.account(&a).capabilities().interface_version, 4);
    let ids = [w.rule_id(&a.address, "game"), w.rule_id(&a.address, "pay")];
    for win in [false, true] {
        let mut root = w.invocation(
            &game,
            "guess",
            std::vec![w.sc(a.address.clone()), w.sc(token.clone()), w.sc(win)],
        );
        if !win {
            root.sub_invocations = std::vec![w.invocation(
                &token,
                "transfer",
                std::vec![w.sc(a.address.clone()), w.sc(game.clone()), w.sc(1i128)]
            )]
            .try_into()
            .unwrap();
        }
        let selected = if win { &ids[..1] } else { &ids[..] };
        e.set_auths(&[auth_entry_for_rules(
            e,
            &a.address,
            &w.webauthn,
            &a.owner,
            selected,
            w.next_nonce(),
            w.ledger() + 1000,
            root,
        )]);
        assert!(RootGameClient::new(e, &game)
            .try_guess(&a.address, &token, &win)
            .is_ok());
        report(
            if win {
                "exact root: winning guess"
            } else {
                "exact root: losing guess"
            },
            e,
        );
        e.set_auths(&[]);
        assert_eq!(w.window(&a, ids[1]).unwrap().total, 1);
    }
    assert!(!w.spend(&a, &a.owner, &token, 1));
    report("exact root: direct transfer refused below cap", e);
    assert_eq!(w.window(&a, ids[1]).unwrap().total, 1);
}

#[test]
#[ignore = "needs the built stack"]
fn exact_root_wasm_at_document_caps() {
    let w = world();
    let shape = worst_shape();
    let keys = passkeys(65, shape.signers);
    let a = w.new_account(canonical_passkey([65; 32]));
    let rec = Rec {
        profile: "loss",
        mode: Mode::Guardian,
        zk: None,
        delay: DELAY,
        baseline: None,
    };
    ROOT_CONDITIONS.with(|x| x.set(true));
    let doc = w.shaped_doc(&keys, &rec, shape, MAX_DOC_CANONICAL_BYTES as usize, true);
    ROOT_CONDITIONS.with(|x| x.set(false));
    assert_eq!(doc.len(), MAX_DOC_CANONICAL_BYTES);
    assert!(w.try_apply(&a, &a.owner, &doc, 0));
    report("exact root: maximum-sized document apply", &w.env);
    let stored = w.account(&a).rule_set();
    assert_eq!(
        stored.iter().filter(|r| r.auth_root().is_some()).count(),
        MAX_DOC_RULES as usize - 1
    );
    let replacement_keys = passkeys(90, shape.signers);
    let replacements = w.replacing_all(&replacement_keys, None);
    let attempt = w.ctl().begin_lost_key(&a.address, &replacements);
    let target = w.target_bytes(&a, &replacements);
    report(
        "exact root: maximum-sized recovery target derivation",
        &w.env,
    );
    for guardian in [0, 1] {
        w.guardian(guardian, &a, attempt, EvidenceDomain::Initiate);
    }
    w.advance(DELAY);
    assert!(w.try_complete(&a, &target));
    report(
        "exact root: maximum-sized guardian recovery completion",
        &w.env,
    );
    assert_eq!(
        w.account(&a)
            .rule_set()
            .iter()
            .filter(|r| r.auth_root().is_some())
            .count(),
        MAX_DOC_RULES as usize - 1
    );
}
