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
//! (`docs/recovery/budgets.md` §2).

mod support;

use perch_account::PerchAccountClient;
use perch_account_factory::PerchAccountFactoryClient;
use perch_doc_compiler::PerchDocCompilerClient;
use perch_recovery::{EvidenceDomain, PerchRecoveryClient, RecoveryError};
use perch_recovery_interface::credential::{Credential, Replacement, ReplacementSet, ZkEnrollment};
use perch_recovery_interface::zk::{ZkAdapterClient, ZkEvidence};
use perch_recovery_interface::{
    ConfigChange, RecoveryAction, RecoveryStatement, StatementSubject, UpgradeSubject,
};
use perch_testkit::passkey::{auth_entry, SoftPasskey};
use perch_testkit::FIXTURE_NETWORK;
use perch_zk_pool::{PerchZkPoolClient, PoolKey, TreeState};
use perch_zk_primitives::{contract_id, ZERO_HASHES};
use perch_zk_prover::{Inputs, Toolchain, Tree};
use soroban_sdk::testutils::{EnvTestConfig, Ledger as _};
use soroban_sdk::xdr::{
    InvokeContractArgs, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, StringM, VecM,
};
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol, TryFromVal, Val, Vec};
use std::cell::Cell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use stellar_accounts::smart_account::{AuthPayload, SmartAccountStorageKey};
use support::{strkey, Key, TargetClient};

// ---------------------------------------------------------------------------
// Limits and the budget rule
// ---------------------------------------------------------------------------

/// Protocol-29 per-transaction limits (`stellar network settings` on
/// testnet, 2026-10-03; identical on mainnet).
const TX_MAX_INSTRUCTIONS: u64 = 400_000_000;
const TX_MEMORY_LIMIT: u64 = 41_943_040;
const TX_MAX_WRITE_BYTES: u64 = 132_096;
const TX_MAX_WRITE_ENTRIES: u64 = 50;
/// `docs/recovery/budgets.md` §2: every row within 75% of each limit.
const BUDGET_PCT: u64 = 75;

fn report(label: &str, e: &Env) {
    let r = e.cost_estimate().resources();
    let fee = e.cost_estimate().fee();
    println!(
        "\n{{\"case\":\"{label}\",\"instructions\":{},\"instructions_pct_of_tx_limit\":{:.1},\"mem_bytes\":{},\"read_entries\":{},\"write_entries\":{},\"write_bytes\":{},\"events_bytes\":{},\"fee_resource_stroops\":{},\"fee_rent_stroops\":{}}}",
        r.instructions,
        r.instructions as f64 * 100.0 / TX_MAX_INSTRUCTIONS as f64,
        r.mem_bytes,
        r.memory_read_entries + r.disk_read_entries,
        r.write_entries,
        r.write_bytes,
        r.contract_events_size_bytes,
        fee.total - fee.persistent_entry_rent - fee.temporary_entry_rent,
        fee.persistent_entry_rent + fee.temporary_entry_rent,
    );
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
}

fn world() -> World {
    let stack = load_stack();
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.cost_estimate()
        .budget()
        .reset_limits(TX_MAX_INSTRUCTIONS, TX_MEMORY_LIMIT);
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
            .expect("rule exists")
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
        format!(
            r#"{{"profile":"{}","mode":{mode},"controller":"{}","replaceable":["owner"],"delay-ledgers":{},"expiry-ledgers":{EXPIRY},"max-cancels":3}}"#,
            r.profile,
            strkey(&self.controller),
            r.delay,
        )
    }

    /// The owner passkey as admin, a rule letting it call the target, and
    /// `recovery`.
    fn doc(&self, owner: &SoftPasskey, recovery: Option<&Rec>) -> Bytes {
        let recovery = recovery
            .map(|r| format!(r#","recovery":{}"#, self.recovery_json(r)))
            .unwrap_or_default();
        let json = format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{{"id":"owner","verifier":"{}","key":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}},{{"name":"target","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}}}}]{recovery}}}"#,
            strkey(&self.webauthn),
            hex(&owner.key_data()),
            strkey(&self.target),
        );
        Bytes::from_slice(&self.env, json.as_bytes())
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
        self.env
            .set_auths(&[self.passkey_entry(&a.address, key, "admin", root)]);
        let ok = matches!(
            self.account(a).try_apply_doc(doc, &approval_valid_until),
            Ok(Ok(_))
        );
        self.env.set_auths(&[]);
        ok
    }

    /// Ordinary activity: `key` authorizes the target's `protected`.
    fn activity(&self, a: &Acct, key: &SoftPasskey) -> bool {
        let root = self.invocation(
            &self.target,
            "protected",
            std::vec![self.sc(a.address.clone())],
        );
        self.env
            .set_auths(&[self.passkey_entry(&a.address, key, "target", root)]);
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

    /// Complete through the recovery rule: anyone may submit.
    fn try_complete(&self, a: &Acct, target: &Bytes) -> bool {
        let root = self.invocation(
            &a.address,
            "apply_doc",
            std::vec![self.sc(target.clone()), self.sc(0u32)],
        );
        self.env
            .set_auths(&[self.recovery_rule_entry(&a.address, root)]);
        let ok = matches!(self.account(a).try_apply_doc(target, &0), Ok(Ok(_)));
        self.env.set_auths(&[]);
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

/// `nargo execute` + `bb prove` writes into the shared circuit target dir,
/// keyed by process id: serialize the tests' proving.
static PROVING: Mutex<()> = Mutex::new(());

fn prove_inputs(inputs: &Inputs) -> std::vec::Vec<u8> {
    let _guard = PROVING.lock().unwrap_or_else(|p| p.into_inner());
    let tc = Toolchain::from_env().expect("pinned nargo/bb (eval \"$(scripts/zk-toolchain.sh)\")");
    let work = repo().join("target/release-stack-proofs");
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

    let execute = |w: &World| -> Option<bool> {
        let root = w.invocation(&a.address, "execute_upgrade", std::vec![w.sc(request_id)]);
        w.env
            .set_auths(&[w.passkey_entry(&a.address, &a.owner, "admin", root)]);
        let out = w.account(&a).try_execute_upgrade(&request_id);
        w.env.set_auths(&[]);
        match out {
            Ok(Ok(done)) => Some(done),
            _ => None,
        }
    };
    assert_eq!(execute(&w), None, "the seven-day delay has not elapsed");
    w.advance(perch_recovery_interface::account::ACCOUNT_UPGRADE_DELAY_LEDGERS);
    assert_eq!(execute(&w), Some(true));
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
