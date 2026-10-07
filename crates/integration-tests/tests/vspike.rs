//! SPIKE ONLY (never pushed): benchmark the versioned rule backend
//! (`perch-vspike`) against the OZ context-rule backend (`perch-account`,
//! this branch) in release wasm, with real passkey signatures and enforcing
//! authorization, metered the way `release_stack.rs` meters (in-process
//! `cost_estimate`, protocol-29 limits).
//!
//! ```text
//! scripts/build-stack.sh --builder contract --registry <C...>   # target/stack
//! stellar contract build --package perch-vspike-eval --out-dir target/vspike
//! stellar contract build --package perch-vspike --out-dir target/vspike
//! cargo test -p perch-integration-tests --test vspike -- --ignored --nocapture --test-threads 1
//! ```

mod support;

use perch_account::PerchAccountClient;
use perch_account_factory::PerchAccountFactoryClient;
use perch_doc_compiler::{CompiledDoc, PerchDocCompilerClient, RuleScope};
use perch_testkit::passkey::{sig_data, signature_payload, SoftPasskey};
use perch_testkit::FIXTURE_NETWORK;
use perch_vspike::{Cap, Scope, StoredRule, VAccountClient, VAuth};
use sha2::{Digest, Sha256};
use soroban_sdk::testutils::EnvTestConfig;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::xdr::{
    InvokeContractArgs, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, StringM, ToXdr,
    VecM,
};
use soroban_sdk::{
    contract, contractimpl, map, Address, Bytes, BytesN, Env, IntoVal, Map, TryFromVal, Val, Vec,
};
use std::cell::Cell;
use std::collections::HashMap;
use std::path::PathBuf;
use stellar_accounts::smart_account::{AuthPayload, Signer, SmartAccountStorageKey};
use support::strkey;

const TX_MAX_INSTRUCTIONS: u64 = 400_000_000;
const TX_MEMORY_LIMIT: u64 = 41_943_040;
const TX_MAX_WRITE_BYTES: u64 = 132_096;
const TX_MAX_WRITE_ENTRIES: u64 = 200;
const TX_MAX_FOOTPRINT_ENTRIES: u64 = 400;
const TX_MAX_EVENTS_BYTES: u64 = 16_384;
const TX_MAX_READ_BYTES: u64 = 200_000;

/// One metered row, printed as a JSON line and returned for aggregation.
#[derive(Clone, Copy, Default, Debug)]
struct Row {
    instructions: u64,
    mem: u64,
    read_entries: u64,
    write_entries: u64,
    footprint: u64,
    read_bytes: u64,
    write_bytes: u64,
    events: u64,
    fee_resource: i64,
    fee_rent: i64,
}

impl Row {
    fn add(&mut self, o: &Row) {
        self.instructions += o.instructions;
        self.mem += o.mem;
        self.read_entries += o.read_entries;
        self.write_entries += o.write_entries;
        self.footprint += o.footprint;
        self.read_bytes += o.read_bytes;
        self.write_bytes += o.write_bytes;
        self.events += o.events;
        self.fee_resource += o.fee_resource;
        self.fee_rent += o.fee_rent;
    }
    fn max(&mut self, o: &Row) {
        self.instructions = self.instructions.max(o.instructions);
        self.mem = self.mem.max(o.mem);
        self.read_entries = self.read_entries.max(o.read_entries);
        self.write_entries = self.write_entries.max(o.write_entries);
        self.footprint = self.footprint.max(o.footprint);
        self.read_bytes = self.read_bytes.max(o.read_bytes);
        self.write_bytes = self.write_bytes.max(o.write_bytes);
        self.events = self.events.max(o.events);
        self.fee_resource = self.fee_resource.max(o.fee_resource);
        self.fee_rent = self.fee_rent.max(o.fee_rent);
    }
}

fn print_row(label: &str, r: &Row) {
    let pct = |u: u64, l: u64| u as f64 * 100.0 / l as f64;
    let worst = [
        ("instructions", pct(r.instructions, TX_MAX_INSTRUCTIONS)),
        ("memory", pct(r.mem, TX_MEMORY_LIMIT)),
        ("footprint", pct(r.footprint, TX_MAX_FOOTPRINT_ENTRIES)),
        ("written", pct(r.write_entries, TX_MAX_WRITE_ENTRIES)),
        ("write_bytes", pct(r.write_bytes, TX_MAX_WRITE_BYTES)),
        ("read_bytes", pct(r.read_bytes, TX_MAX_READ_BYTES)),
        ("events", pct(r.events, TX_MAX_EVENTS_BYTES)),
    ]
    .into_iter()
    .fold(("", 0.0), |a, b| if b.1 > a.1 { b } else { a });
    println!(
        "{{\"case\":\"{label}\",\"instructions\":{},\"instructions_pct\":{:.1},\"mem_bytes\":{},\"mem_pct\":{:.1},\"read_entries\":{},\"write_entries\":{},\"footprint_entries\":{},\"footprint_pct\":{:.1},\"read_bytes\":{},\"write_bytes\":{},\"events_bytes\":{},\"fee_resource_stroops\":{},\"fee_rent_stroops\":{},\"binding\":\"{}\",\"binding_pct\":{:.1}}}",
        r.instructions,
        pct(r.instructions, TX_MAX_INSTRUCTIONS),
        r.mem,
        pct(r.mem, TX_MEMORY_LIMIT),
        r.read_entries,
        r.write_entries,
        r.footprint,
        pct(r.footprint, TX_MAX_FOOTPRINT_ENTRIES),
        r.read_bytes,
        r.write_bytes,
        r.events,
        r.fee_resource,
        r.fee_rent,
        worst.0,
        worst.1,
    );
}

fn measure(label: &str, e: &Env) -> Row {
    let r = e.cost_estimate().resources();
    let fee = e.cost_estimate().fee();
    let read_entries = (r.memory_read_entries + r.disk_read_entries) as u64;
    let row = Row {
        instructions: r.instructions as u64,
        mem: r.mem_bytes as u64,
        read_entries,
        write_entries: r.write_entries as u64,
        footprint: read_entries + r.write_entries as u64,
        read_bytes: r.disk_read_bytes as u64,
        write_bytes: r.write_bytes as u64,
        events: r.contract_events_size_bytes as u64,
        fee_resource: fee.total - fee.persistent_entry_rent - fee.temporary_entry_rent,
        fee_rent: fee.persistent_entry_rent + fee.temporary_entry_rent,
    };
    print_row(label, &row);
    row
}

// ---------------------------------------------------------------------------
// Stack
// ---------------------------------------------------------------------------

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_wasm() -> (String, HashMap<String, std::vec::Vec<u8>>) {
    let dir =
        repo().join(std::env::var("PERCH_STACK_DIR").unwrap_or_else(|_| "target/stack".into()));
    let build: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("build.json")).expect("build.json"))
            .unwrap();
    let mut wasm = HashMap::new();
    for a in build["artifacts"].as_array().unwrap() {
        wasm.insert(
            a["package"].as_str().unwrap().to_string(),
            std::fs::read(dir.join(a["wasm"].as_str().unwrap())).unwrap(),
        );
    }
    for (pkg, file) in [
        ("perch-vspike", "perch_vspike.wasm"),
        ("perch-vspike-eval", "perch_vspike_eval.wasm"),
    ] {
        wasm.insert(
            pkg.to_string(),
            std::fs::read(repo().join("target/vspike").join(file)).expect("spike wasm"),
        );
    }
    (build["registry"].as_str().unwrap().to_string(), wasm)
}

#[contract]
pub struct TokenStub;

#[contractimpl]
impl TokenStub {
    pub fn transfer(_e: Env, from: Address, _to: Address, _amount: i128) {
        from.require_auth();
    }
}

#[contract]
pub struct Multi;

#[contractimpl]
impl Multi {
    /// `from`'s authorization of this call and of `k` transfers under it:
    /// `k + 1` contexts in one `__check_auth`.
    pub fn run(e: Env, from: Address, token: Address, to: Address, k: u32) {
        from.require_auth();
        for _ in 0..k {
            TokenStubClient::new(&e, &token).transfer(&from, &to, &1);
        }
    }
}

struct W {
    env: Env,
    wasm: HashMap<String, std::vec::Vec<u8>>,
    webauthn: Address,
    compiler: Address,
    factory: Address,
    eval: Address,
    token: Address,
    multi: Address,
    sink: Address,
    controller: Address,
    nonce: Cell<i64>,
    salt: Cell<u8>,
}

fn world() -> W {
    let (registry, wasm) = load_wasm();
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.cost_estimate().budget().reset_unlimited();
    let network_id: [u8; 32] = Sha256::digest(FIXTURE_NETWORK.as_bytes()).into();
    env.ledger().with_mut(|l| {
        l.sequence_number = 1_000;
        l.network_id = network_id;
        l.min_persistent_entry_ttl = 1_000_000;
        l.min_temp_entry_ttl = 1_000_000;
        l.max_entry_ttl = 10_000_000;
    });
    let registry = Address::from_str(&env, &registry);
    let content = |pkg: &str| -> Address {
        let hash = env
            .crypto()
            .sha256(&Bytes::from_slice(&env, &wasm[pkg]))
            .to_bytes();
        let addr = env
            .deployer()
            .with_address(registry.clone(), hash)
            .deployed_address();
        env.register_at(&addr, wasm[pkg].as_slice(), ());
        addr
    };
    let compiler = content("perch-doc-compiler");
    content("perch-interpreter");
    content("perch-spending-limit");
    let webauthn = content("perch-webauthn-verifier");
    let factory = content("perch-account-factory");
    env.deployer()
        .upload_contract_wasm(wasm["perch-account"].as_slice());
    let eval = env.register(wasm["perch-vspike-eval"].as_slice(), ());
    let token = env.register(TokenStub, ());
    let multi = env.register(Multi, ());
    let sink = env.register(TokenStub, ());
    let controller = env.register(support::Key, ());
    env.set_auths(&[]);
    W {
        env,
        wasm,
        webauthn,
        compiler,
        factory,
        eval,
        token,
        multi,
        sink,
        controller,
        nonce: Cell::new(0),
        salt: Cell::new(0),
    }
}

const P: usize = 6;
const BATCH: usize = 13;

fn keys(seed: u8) -> std::vec::Vec<SoftPasskey> {
    keys_n(seed, P)
}

fn keys_n(seed: u8, count: usize) -> std::vec::Vec<SoftPasskey> {
    (0..count as u8)
        .map(|i| {
            let mut s = [seed; 32];
            s[1] = i;
            SoftPasskey::from_seed(s)
        })
        .collect()
}

fn ids() -> std::vec::Vec<String> {
    let mut v = std::vec!["owner".to_string()];
    v.extend((1..P).map(|i| format!("s{i:02}")));
    v
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl W {
    fn next_nonce(&self) -> i64 {
        self.nonce.set(self.nonce.get() + 1);
        self.nonce.get()
    }

    fn sc<T: IntoVal<Env, Val>>(&self, v: T) -> ScVal {
        let val: Val = v.into_val(&self.env);
        ScVal::try_from_val(&self.env, &val).unwrap()
    }

    fn inv(
        &self,
        contract: &Address,
        f: &str,
        args: std::vec::Vec<ScVal>,
        subs: std::vec::Vec<SorobanAuthorizedInvocation>,
    ) -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: contract.clone().into(),
                function_name: StringM::try_from(f).unwrap().into(),
                args: args.try_into().unwrap(),
            }),
            sub_invocations: VecM::try_from(subs).unwrap(),
        }
    }

    fn passkey_signer(&self, k: &SoftPasskey) -> Signer {
        Signer::External(
            self.webauthn.clone(),
            Bytes::from_slice(&self.env, &k.key_data()),
        )
    }

    // --- the document shape both backends get ------------------------------

    /// Rule `i`'s JSON. 0: `admin` (owner, plain). 1: `multi` (any one of
    /// the P signers may call `Multi.run` as the account). 2..: a 20-byte
    /// name, any one of the P signers may `transfer` from the account on
    /// the token, under a cap: both policies, every signer named.
    fn rule_json(&self, i: usize, tag: &str) -> String {
        let all: std::vec::Vec<String> = ids().iter().map(|id| format!(r#""{id}""#)).collect();
        let all = all.join(",");
        match i {
            0 => r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#.to_string(),
            1 => format!(
                r#"{{"name":"{tag}multi","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"threshold","m":1,"signers":[{all}]}},"functions":["run"],"args":[{{"index":0,"pred":{{"type":"is-self"}}}}]}}"#,
                strkey(&self.multi)
            ),
            _ => {
                let base = format!("{tag}r{i:04}");
                let name = format!("{base}{}", "x".repeat(20 - base.len()));
                format!(
                    r#"{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"threshold","m":1,"signers":[{all}]}},"functions":["transfer"],"args":[{{"index":0,"pred":{{"type":"is-self"}}}}],"cap":{{"limit":"1000000","period-ledgers":1000}}}}"#,
                    strkey(&self.token)
                )
            }
        }
    }

    fn rule_name(&self, i: usize, tag: &str) -> String {
        match i {
            0 => "admin".into(),
            1 => format!("{tag}multi"),
            _ => {
                let base = format!("{tag}r{i:04}");
                format!("{base}{}", "x".repeat(20 - base.len()))
            }
        }
    }

    fn doc_json(&self, ks: &[SoftPasskey], rules: std::ops::Range<usize>, tag: &str) -> String {
        let signers: std::vec::Vec<String> = ids()
            .iter()
            .zip(ks)
            .map(|(id, k)| {
                format!(
                    r#"{{"id":"{id}","verifier":"{}","key":"{}"}}"#,
                    strkey(&self.webauthn),
                    hex(&k.key_data())
                )
            })
            .collect();
        let rules: std::vec::Vec<String> = rules.map(|i| self.rule_json(i, tag)).collect();
        format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
            signers.join(","),
            rules.join(",")
        )
    }

    fn bytes(&self, s: &str) -> Bytes {
        Bytes::from_slice(&self.env, s.as_bytes())
    }

    // --- versioned backend --------------------------------------------------

    fn new_vaccount(&self, ks: &[SoftPasskey]) -> Address {
        let signers = Vec::from_iter(&self.env, ks.iter().map(|k| self.passkey_signer(k)));
        self.env.register(
            self.wasm["perch-vspike"].as_slice(),
            (
                self.eval.clone(),
                self.compiler.clone(),
                self.controller.clone(),
                signers,
            ),
        )
    }

    /// A VAuth entry: `signers` (principal id, key) sign the digest that
    /// binds `(version, rule_ids)`.
    fn ventry(
        &self,
        account: &Address,
        signers: &[(u32, &SoftPasskey)],
        version: u32,
        rule_ids: &[u32],
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        let nonce = self.next_nonce();
        let exp = self.env.ledger().sequence() + 1_000_000;
        let payload = signature_payload(&self.env, nonce, exp, &root);
        let ids = Vec::from_slice(&self.env, rule_ids);
        let mut pre = Bytes::from_array(&self.env, &payload);
        pre.append(&(version, ids.clone()).to_xdr(&self.env));
        let digest = self.env.crypto().sha256(&pre).to_array();
        let mut sigs: Map<u32, Bytes> = Map::new(&self.env);
        for (pid, k) in signers {
            sigs.set(*pid, sig_data(&self.env, &k.assert(&digest)));
        }
        let auth = VAuth {
            version,
            rule_ids: ids,
            signers: sigs,
        };
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: account.clone().into(),
                nonce,
                signature_expiration_ledger: exp,
                signature: self.sc(auth),
            }),
            root_invocation: root,
        }
    }

    /// Call `f` on the versioned account, authorized by the owner (pid 0)
    /// through the active version's admin rule (id 0).
    fn vadmin(
        &self,
        acct: &Address,
        owner: &SoftPasskey,
        f: &str,
        args: std::vec::Vec<ScVal>,
        call: impl FnOnce(&VAccountClient),
    ) {
        let version = VAccountClient::new(&self.env, acct).active().version;
        let root = self.inv(acct, f, args, std::vec![]);
        self.env
            .set_auths(&[self.ventry(acct, &[(0, owner)], version, &[0], root)]);
        call(&VAccountClient::new(&self.env, acct));
        self.env.set_auths(&[]);
    }

    /// What a client computes off-chain from a batch document: its stored
    /// rules (principals mapped onto the binding table) and provenance.
    fn stored_rules(&self, batch_doc: &str, ks: &[SoftPasskey]) -> std::vec::Vec<StoredRule> {
        let compiled: CompiledDoc = PerchDocCompilerClient::new(&self.env, &self.compiler)
            .compile_doc(&self.bytes(batch_doc));
        let parsed = perch_ir::from_json(batch_doc).unwrap();
        let table: std::vec::Vec<Signer> = ks.iter().map(|k| self.passkey_signer(k)).collect();
        compiled
            .rules
            .iter()
            .zip(parsed.rules.iter())
            .map(|(c, src)| {
                let mut principals: std::vec::Vec<u32> = c
                    .signers
                    .iter()
                    .map(|s| table.iter().position(|t| *t == s).unwrap() as u32)
                    .collect();
                principals.sort();
                StoredRule {
                    key: BytesN::from_array(&self.env, &Sha256::digest(src.name.as_bytes()).into()),
                    scope: match c.scope {
                        RuleScope::SelfAdmin => Scope::SelfAdmin,
                        RuleScope::Contract(a) => Scope::Contract(a),
                    },
                    principals: Vec::from_slice(&self.env, &principals),
                    program: Vec::from_iter(&self.env, c.install.iter().map(|i| i.program)),
                    cap: Vec::from_iter(
                        &self.env,
                        c.cap.iter().map(|k| Cap {
                            limit: k.spending_limit,
                            period: k.period_ledgers,
                        }),
                    ),
                    valid_until: c.valid_until,
                    rule_hash: BytesN::from_array(&self.env, &perch_ir::rule_hash(src)),
                }
            })
            .collect()
    }

    fn principals_hash(&self) -> [u8; 32] {
        Sha256::digest(ids().join(",").as_bytes()).into()
    }

    /// `token.transfer(account, sink, amount)` through rule `rule_id`,
    /// signed by principal `pid`.
    fn vtransfer(&self, acct: &Address, pid: u32, k: &SoftPasskey, rule_id: u32) -> bool {
        let version = VAccountClient::new(&self.env, acct).active().version;
        let root = self.inv(
            &self.token,
            "transfer",
            std::vec![
                self.sc(acct.clone()),
                self.sc(self.sink.clone()),
                self.sc(10i128)
            ],
            std::vec![],
        );
        self.env
            .set_auths(&[self.ventry(acct, &[(pid, k)], version, &[rule_id], root)]);
        let ok = TokenStubClient::new(&self.env, &self.token)
            .try_transfer(acct, &self.sink, &10)
            .is_ok();
        self.env.set_auths(&[]);
        ok
    }

    fn multi_root(&self, acct: &Address, k: u32) -> SorobanAuthorizedInvocation {
        let subs = (0..k)
            .map(|_| {
                self.inv(
                    &self.token,
                    "transfer",
                    std::vec![
                        self.sc(acct.clone()),
                        self.sc(self.sink.clone()),
                        self.sc(1i128)
                    ],
                    std::vec![],
                )
            })
            .collect();
        self.inv(
            &self.multi,
            "run",
            std::vec![
                self.sc(acct.clone()),
                self.sc(self.token.clone()),
                self.sc(self.sink.clone()),
                self.sc(k)
            ],
            subs,
        )
    }

    /// `Multi.run` + `k` transfers: `k + 1` contexts, rules 1..=k+1.
    fn vmulti(&self, acct: &Address, k: &SoftPasskey, n: u32) -> bool {
        let version = VAccountClient::new(&self.env, acct).active().version;
        let ids: std::vec::Vec<u32> = (1..=n + 1).collect();
        self.env.set_auths(&[self.ventry(
            acct,
            &[(0, k)],
            version,
            &ids,
            self.multi_root(acct, n),
        )]);
        let ok = MultiClient::new(&self.env, &self.multi)
            .try_run(acct, &self.token, &self.sink, &n)
            .is_ok();
        self.env.set_auths(&[]);
        ok
    }

    // --- OZ backend (perch-account, this branch) -----------------------------

    fn new_oz(&self, owner: &SoftPasskey) -> Address {
        self.salt.set(self.salt.get() + 1);
        let salt = BytesN::from_array(&self.env, &[self.salt.get(); 32]);
        PerchAccountFactoryClient::new(&self.env, &self.factory)
            .create_passkey(&salt, &Bytes::from_slice(&self.env, &owner.key_data()))
    }

    fn oz_rule_id(&self, acct: &Address, name: &str) -> u32 {
        let next: u32 = self.env.as_contract(acct, || {
            self.env
                .storage()
                .instance()
                .get(&SmartAccountStorageKey::NextId)
                .unwrap_or(0)
        });
        let client = PerchAccountClient::new(&self.env, acct);
        let wanted = soroban_sdk::String::from_str(&self.env, name);
        (0..next)
            .rev()
            .find(|id| matches!(client.try_get_context_rule(id), Ok(Ok(r)) if r.name == wanted))
            .expect("rule exists")
    }

    fn oz_entry(
        &self,
        acct: &Address,
        k: &SoftPasskey,
        rule_ids: &[u32],
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        let nonce = self.next_nonce();
        let exp = self.env.ledger().sequence() + 1_000_000;
        let payload = signature_payload(&self.env, nonce, exp, &root);
        let ids = Vec::from_slice(&self.env, rule_ids);
        let digest =
            perch_testkit::auth_digest(&self.env, &BytesN::from_array(&self.env, &payload), &ids);
        let auth = AuthPayload {
            signers: map![
                &self.env,
                (
                    self.passkey_signer(k),
                    sig_data(&self.env, &k.assert(&digest))
                )
            ],
            context_rule_ids: ids,
        };
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: acct.clone().into(),
                nonce,
                signature_expiration_ledger: exp,
                signature: self.sc(auth),
            }),
            root_invocation: root,
        }
    }

    fn oz_apply(&self, acct: &Address, signer: &SoftPasskey, admin: u32, doc: &Bytes) -> bool {
        let root = self.inv(
            acct,
            "apply_doc",
            std::vec![self.sc(doc.clone()), self.sc(0u32)],
            std::vec![],
        );
        self.env
            .set_auths(&[self.oz_entry(acct, signer, &[admin], root)]);
        let ok = matches!(
            PerchAccountClient::new(&self.env, acct).try_apply_doc(doc, &0),
            Ok(Ok(_))
        );
        self.env.set_auths(&[]);
        ok
    }

    fn oz_transfer(&self, acct: &Address, k: &SoftPasskey, id: u32) -> bool {
        let root = self.inv(
            &self.token,
            "transfer",
            std::vec![
                self.sc(acct.clone()),
                self.sc(self.sink.clone()),
                self.sc(10i128)
            ],
            std::vec![],
        );
        self.env.set_auths(&[self.oz_entry(acct, k, &[id], root)]);
        let ok = TokenStubClient::new(&self.env, &self.token)
            .try_transfer(acct, &self.sink, &10)
            .is_ok();
        self.env.set_auths(&[]);
        ok
    }

    fn oz_multi(&self, acct: &Address, k: &SoftPasskey, ids: &[u32]) -> bool {
        let n = ids.len() as u32 - 1;
        self.env
            .set_auths(&[self.oz_entry(acct, k, ids, self.multi_root(acct, n))]);
        let ok = MultiClient::new(&self.env, &self.multi)
            .try_run(acct, &self.token, &self.sink, &n)
            .is_ok();
        self.env.set_auths(&[]);
        ok
    }
}

fn entry_size<K: IntoVal<Env, Val>, V: IntoVal<Env, Val> + TryFromVal<Env, Val>>(
    e: &Env,
    acct: &Address,
    k: &K,
) -> (usize, usize) {
    e.as_contract(acct, || {
        let key: Val = k.into_val(e);
        let v: V = e.storage().persistent().get(k).expect("entry");
        let val: Val = v.into_val(e);
        (key.to_xdr(e).len() as usize, val.to_xdr(e).len() as usize)
    })
}

/// A sequence of transactions, each run on a fresh fork of the state the
/// previous one left (see [`fork`]) and metered alone.
struct Chain {
    cur: W,
}

impl Chain {
    fn step<R>(&mut self, label: &str, op: impl FnOnce(&W) -> R) -> (R, Row) {
        let f = fork(&self.cur);
        let r = op(&f);
        let row = measure(label, &f.env);
        self.cur = f;
        (r, row)
    }

    fn addr(&self, s: &str) -> Address {
        Address::from_str(&self.cur.env, s)
    }
}

/// Carry a value built in one env into another.
fn carry<T: IntoVal<Env, Val> + TryFromVal<Env, Val>>(from: &W, to: &W, v: T) -> T {
    let sc = from.sc(v);
    let val = Val::try_from_val(&to.env, &sc).unwrap();
    T::try_from_val(&to.env, &val).unwrap_or_else(|_| panic!("carry"))
}

/// Prepare `version` (n rules, names tagged `tag`) in batches; returns
/// (worst batch, total, batches, commitment).
#[allow(clippy::too_many_arguments)]
fn prepare_version(
    ch: &mut Chain,
    acct: &str,
    owner: &SoftPasskey,
    ks: &[SoftPasskey],
    version: u32,
    n: usize,
    tag: &str,
    compile_on_chain: bool,
    label: &str,
) -> (Row, Row, usize, [u8; 32]) {
    let ph = ch.cur.principals_hash();
    ch.step(&format!("{label} begin"), |f| {
        let ph = BytesN::from_array(&f.env, &ph);
        f.vadmin(
            &Address::from_str(&f.env, acct),
            owner,
            "begin",
            std::vec![
                f.sc(version),
                f.sc(n as u32),
                f.sc(P as u32),
                f.sc(ph.clone())
            ],
            |c| c.begin(&version, &(n as u32), &(P as u32), &ph),
        );
    });
    let mut hashes: std::vec::Vec<[u8; 32]> = std::vec::Vec::new();
    let (mut max, mut sum, mut batches) = (Row::default(), Row::default(), 0);
    let mut start = 0;
    while start < n {
        let end = (start + BATCH).min(n);
        let doc = ch.cur.doc_json(ks, start..end, tag);
        let rules = ch.cur.stored_rules(&doc, ks);
        hashes.extend(rules.iter().map(|r| r.rule_hash.to_array()));
        let rv = Vec::from_slice(&ch.cur.env, &rules);
        let label = format!("{label} prepare batch {batches} ({} rules)", end - start);
        let prev = &ch.cur as *const W;
        let (_, row) = ch.step(&label, |f| {
            // SAFETY: `prev` is `ch.cur`, alive until `step` replaces it after `op`.
            let rv = carry(unsafe { &*prev }, f, rv);
            let batch_doc = if compile_on_chain {
                f.bytes(&doc)
            } else {
                Bytes::new(&f.env)
            };
            f.vadmin(
                &Address::from_str(&f.env, acct),
                owner,
                "prepare",
                std::vec![f.sc(version), f.sc(rv.clone()), f.sc(batch_doc.clone())],
                |c| c.prepare(&version, &rv, &batch_doc),
            );
        });
        max.max(&row);
        sum.add(&row);
        batches += 1;
        start = end;
    }
    let mut h = Sha256::new();
    h.update(b"perch/vspike/version");
    h.update((n as u32).to_be_bytes());
    h.update((P as u32).to_be_bytes());
    h.update(ph);
    let mut acc: [u8; 32] = h.finalize().into();
    for rh in hashes {
        let mut h = Sha256::new();
        h.update(acc);
        h.update(rh);
        acc = h.finalize().into();
    }
    (max, sum, batches, acc)
}

/// Every versioned operation at `n` rules.
fn versioned(n: usize) {
    let w = world();
    let ks = keys(1);
    let acct_addr = w.new_vaccount(&ks);
    let acct = strkey(&acct_addr);
    let mut ch = Chain { cur: w };
    let l = |what: &str| format!("V n={n} {what}");

    // Storage-only prepare (client-compiled rules), version 9, for the cost split.
    let (raw_max, raw_sum, _, _) =
        prepare_version(&mut ch, &acct, &ks[0], &ks, 9, n, "q", false, &l("raw"));
    print_row(&l("prepare raw: worst batch"), &raw_max);
    print_row(&l("prepare raw: total"), &raw_sum);

    let (max, sum, batches, commitment) =
        prepare_version(&mut ch, &acct, &ks[0], &ks, 1, n, "", true, &l("compiled"));
    print_row(
        &l(&format!("prepare compiled: worst batch (of {batches})")),
        &max,
    );
    print_row(&l("prepare compiled: total"), &sum);

    ch.step(&l("activate"), |f| {
        let c = BytesN::from_array(&f.env, &commitment);
        let a = Address::from_str(&f.env, &acct);
        f.vadmin(
            &a,
            &ks[0],
            "activate",
            std::vec![f.sc(1u32), f.sc(c.clone())],
            |cl| {
                cl.activate(&1, &c);
            },
        );
    });
    let a = ch.addr(&acct);
    assert_eq!(VAccountClient::new(&ch.cur.env, &a).active().version, 1);

    // A sealed version's entries.
    let e = &ch.cur.env;
    let (rk, rv) = entry_size::<_, StoredRule>(e, &a, &perch_vspike::Key::Rule(1, 2));
    let (bk, bv) = entry_size::<_, Vec<perch_vspike::Binding>>(e, &a, &perch_vspike::Key::Bindings);
    let (mk, mv) =
        entry_size::<_, perch_vspike::VersionMeta>(e, &a, &perch_vspike::Key::Version(1));
    let (dk, dv) = entry_size::<_, Bytes>(e, &a, &perch_vspike::Key::Doc(1, 0));
    println!(
        "{{\"case\":\"V n={n} entry sizes\",\"rule_key\":{rk},\"rule_val\":{rv},\"bindings_key\":{bk},\"bindings_val\":{bv},\"version_key\":{mk},\"version_val\":{mv},\"batch_doc_key\":{dk},\"batch_doc_val\":{dv}}}"
    );

    let on = |f: &W| Address::from_str(&f.env, &acct);
    ch.step(&l("authorize 1 rule (rule 2, capped transfer)"), |f| {
        assert!(f.vtransfer(&on(f), 0, &ks[0], 2))
    });
    ch.step(&l("authorize 1 rule (last rule, signer s03)"), |f| {
        assert!(f.vtransfer(&on(f), 3, &ks[3], (n - 1) as u32))
    });
    let k = 3.min(n as u32 - 2);
    ch.step(
        &l(&format!("authorize {} rules ({} contexts)", k + 1, k + 1)),
        |f| assert!(f.vmulti(&on(f), &ks[0], k)),
    );
    ch.step(&l("refused: admin rule cannot transfer"), |f| {
        assert!(!f.vtransfer(&on(f), 0, &ks[0], 0))
    });

    // Rotate the owner (named by every rule, admin included).
    let rotated = keys(2);
    ch.step(&l("rotate owner (every rule names it)"), |f| {
        let s = f.passkey_signer(&rotated[0]);
        f.vadmin(
            &on(f),
            &ks[0],
            "rotate",
            std::vec![f.sc(0u32), f.sc(s.clone())],
            |c| {
                c.rotate(&0, &s);
            },
        );
    });
    ch.step(&l("refused: old owner key after rotation"), |f| {
        assert!(!f.vtransfer(&on(f), 0, &ks[0], 2))
    });
    ch.step(&l("authorize 1 rule (rotated owner)"), |f| {
        assert!(f.vtransfer(&on(f), 0, &rotated[0], 2))
    });
    let owner = &rotated[0];

    ch.step(&l("publish_baseline"), |f| {
        f.vadmin(&on(f), owner, "publish_baseline", std::vec![], |c| {
            c.publish_baseline()
        });
    });
    let a = ch.addr(&acct);
    let key2 = VAccountClient::new(&ch.cur.env, &a)
        .rule(&1, &2)
        .unwrap()
        .key
        .to_array();
    let spent_before = VAccountClient::new(&ch.cur.env, &a)
        .window(&BytesN::from_array(&ch.cur.env, &key2))
        .unwrap()
        .spent;

    // The thief (holding the owner key): swap every credential, then
    // prepare and activate a version of n renamed rules.
    let thief = keys(3);
    ch.step(&l("thief set_bindings (every credential swapped)"), |f| {
        let t = Vec::from_iter(&f.env, thief.iter().map(|k| f.passkey_signer(k)));
        f.vadmin(
            &on(f),
            owner,
            "set_bindings",
            std::vec![f.sc(t.clone())],
            |c| {
                c.set_bindings(&t);
            },
        );
    });
    let (tmax, _, _, tcommit) = prepare_version(
        &mut ch,
        &acct,
        &thief[0],
        &thief,
        2,
        n,
        "t",
        true,
        &l("thief"),
    );
    print_row(&l("thief prepare: worst batch"), &tmax);
    ch.step(&l("thief activate"), |f| {
        let c = BytesN::from_array(&f.env, &tcommit);
        f.vadmin(
            &on(f),
            &thief[0],
            "activate",
            std::vec![f.sc(2u32), f.sc(c.clone())],
            |cl| {
                cl.activate(&2, &c);
            },
        );
    });
    ch.step(
        &l("refused: a signature over version 1 after version 2 activated"),
        |f| {
            let a = on(f);
            let root = f.inv(
                &f.token,
                "transfer",
                std::vec![f.sc(a.clone()), f.sc(f.sink.clone()), f.sc(10i128)],
                std::vec![],
            );
            f.env
                .set_auths(&[f.ventry(&a, &[(0, &thief[0])], 1, &[2], root)]);
            assert!(TokenStubClient::new(&f.env, &f.token)
                .try_transfer(&a, &f.sink, &10)
                .is_err());
            f.env.set_auths(&[]);
        },
    );
    ch.step(&l("thief spends (authorize 1 rule, thief version)"), |f| {
        assert!(f.vtransfer(&on(f), 0, &thief[0], 2))
    });

    // Completion: restore the baseline with new keys, revoking the
    // baseline's credentials and the thief's.
    let fresh = keys(4);
    ch.step(
        &l("restore baseline (thief swapped every key, renamed every rule; 12 revoked)"),
        |f| {
            let a = on(f);
            let fs = Vec::from_iter(&f.env, fresh.iter().map(|k| f.passkey_signer(k)));
            let root = f.inv(&a, "restore", std::vec![f.sc(fs.clone())], std::vec![]);
            f.env.set_auths(&[SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                    address: f.controller.clone().into(),
                    nonce: f.next_nonce(),
                    signature_expiration_ledger: f.env.ledger().sequence() + 1_000_000,
                    signature: ScVal::Void,
                }),
                root_invocation: root,
            }]);
            VAccountClient::new(&f.env, &a).restore(&fs);
            f.env.set_auths(&[]);
        },
    );
    let a = ch.addr(&acct);
    assert_eq!(VAccountClient::new(&ch.cur.env, &a).active().version, 1);
    ch.step(&l("authorize 1 rule (after restore, new owner)"), |f| {
        assert!(
            f.vtransfer(&on(f), 0, &fresh[0], 2),
            "new owner acts under the baseline"
        )
    });
    ch.step(&l("refused: thief key after restore"), |f| {
        assert!(!f.vtransfer(&on(f), 0, &thief[0], 2))
    });
    let a = ch.addr(&acct);
    let spent_after = VAccountClient::new(&ch.cur.env, &a)
        .window(&BytesN::from_array(&ch.cur.env, &key2))
        .unwrap()
        .spent;
    assert!(
        spent_after > spent_before,
        "the counter kept the pre-restore spend"
    );
    ch.step(&l("refused: rebinding a revoked thief key"), |f| {
        let a = on(f);
        let back = f.passkey_signer(&thief[1]);
        f.env.set_auths(&[f.ventry(
            &a,
            &[(0, &fresh[0])],
            1,
            &[0],
            f.inv(
                &a,
                "rotate",
                std::vec![f.sc(1u32), f.sc(back.clone())],
                std::vec![],
            ),
        )]);
        assert!(VAccountClient::new(&f.env, &a)
            .try_rotate(&1, &back)
            .is_err());
        f.env.set_auths(&[]);
    });
}

#[test]
#[ignore]
fn versioned_8() {
    versioned(8);
}

#[test]
#[ignore]
fn versioned_13() {
    versioned(13);
}

#[test]
#[ignore]
fn versioned_32() {
    versioned(32);
}

#[test]
#[ignore]
fn versioned_128() {
    versioned(128);
}

#[test]
#[ignore]
fn versioned_512() {
    versioned(512);
}

/// The same document shape and transactions on the OZ backend, at `n`
/// rules (the compiler caps this branch at 13).
fn oz(n: usize) {
    let w = world();
    let ks = keys(1);
    let acct_addr = w.new_oz(&ks[0]);
    let acct = strkey(&acct_addr);
    let mut ch = Chain { cur: w };
    let l = |what: &str| format!("OZ n={n} {what}");
    let on = |f: &W| Address::from_str(&f.env, &acct);
    let id = |ch: &Chain, name: &str| ch.cur.oz_rule_id(&ch.addr(&acct), name);
    let apply =
        |ch: &mut Chain, label: &str, signer: &SoftPasskey, ks: &[SoftPasskey], tag: &str| {
            let admin = id(ch, "admin");
            ch.step(&l(label), |f| {
                let doc = f.bytes(&f.doc_json(ks, 0..n, tag));
                assert!(f.oz_apply(&on(f), signer, admin, &doc));
            });
        };
    apply(
        &mut ch,
        "apply_doc (install from the factory's admin)",
        &ks[0],
        &ks,
        "",
    );
    {
        let a = ch.addr(&acct);
        let c = PerchAccountClient::new(&ch.cur.env, &a);
        let inv: Val = c.installed_rules().into_val(&ch.cur.env);
        let doc = c.applied_doc().unwrap();
        println!(
            "{{\"case\":\"OZ n={n} single-key entries\",\"installed_rules_xdr\":{},\"applied_doc_bytes\":{}}}",
            inv.to_xdr(&ch.cur.env).len(),
            doc.len()
        );
    }

    let r2 = id(&ch, &ch.cur.rule_name(2, ""));
    let last = id(&ch, &ch.cur.rule_name(n - 1, ""));
    let k = 3.min(n - 2);
    let multi: std::vec::Vec<u32> = (1..=k + 1)
        .map(|i| id(&ch, &ch.cur.rule_name(i, "")))
        .collect();
    ch.step(&l("authorize 1 rule (rule 2, capped transfer)"), |f| {
        assert!(f.oz_transfer(&on(f), &ks[0], r2))
    });
    ch.step(&l("authorize 1 rule (last rule, signer s03)"), |f| {
        assert!(f.oz_transfer(&on(f), &ks[3], last))
    });
    ch.step(
        &l(&format!("authorize {} rules ({} contexts)", k + 1, k + 1)),
        |f| assert!(f.oz_multi(&on(f), &ks[0], &multi)),
    );

    // Rotate the owner: every rule names it.
    let mut rotated = keys(1);
    rotated[0] = keys(2).swap_remove(0);
    apply(
        &mut ch,
        "rotate owner via apply_doc (every rule names it)",
        &ks[0],
        &rotated,
        "",
    );
    let r2 = id(&ch, &ch.cur.rule_name(2, ""));
    ch.step(&l("authorize 1 rule (rotated owner)"), |f| {
        assert!(f.oz_transfer(&on(f), &rotated[0], r2))
    });

    // Rotate one non-admin signer (s01): every rule but admin names it.
    let mut rotated2 = keys(1);
    rotated2[0] = keys(2).swap_remove(0);
    rotated2[1] = keys(5).swap_remove(1);
    apply(
        &mut ch,
        "rotate s01 via apply_doc (every rule but admin names it)",
        &rotated[0],
        &rotated2,
        "",
    );

    // The thief's every-key swap with every rule renamed, then back: the
    // account-side rule work of the binding completion row, without the
    // controller, the pool, or the revocations.
    let thief = keys(3);
    apply(
        &mut ch,
        "thief apply_doc (every key swapped, every rule renamed)",
        &rotated[0],
        &thief,
        "t",
    );
    let fresh = keys(4);
    apply(
        &mut ch,
        "restore-shaped apply_doc (every key swapped back, every rule renamed back)",
        &thief[0],
        &fresh,
        "",
    );
}

#[test]
#[ignore]
fn oz_8() {
    oz(8);
}

#[test]
#[ignore]
fn oz_13() {
    oz(13);
}

/// A fresh host over `w`'s ledger: the storage map starts empty and loads
/// entries as they are touched, as a transaction's footprint does, instead of
/// holding every entry the test ever wrote.
fn fork(w: &W) -> W {
    let mut env = Env::from_ledger_snapshot(w.env.to_ledger_snapshot());
    env.set_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.cost_estimate().budget().reset_unlimited();
    let a = |x: &Address| Address::from_str(&env, &strkey(x));
    let (token, sink, multi, controller) = (a(&w.token), a(&w.sink), a(&w.multi), a(&w.controller));
    env.register_at(&token, TokenStub, ());
    env.register_at(&sink, TokenStub, ());
    env.register_at(&multi, Multi, ());
    env.register_at(&controller, support::Key, ());
    env.set_auths(&[]);
    W {
        wasm: w.wasm.clone(),
        webauthn: a(&w.webauthn),
        compiler: a(&w.compiler),
        factory: a(&w.factory),
        eval: a(&w.eval),
        token,
        multi,
        sink,
        controller,
        nonce: Cell::new(w.nonce.get() + 1_000),
        salt: Cell::new(w.salt.get()),
        env,
    }
}

fn moved(f: &W, x: &Address) -> Address {
    Address::from_str(&f.env, &strkey(x))
}

/// Control: the same n=8 authorization with and without 3 000 unrelated
/// entries in the test host's storage, then on a fork.
#[test]
#[ignore]
fn control_storage_map_size() {
    let w = world();
    let ks = keys(1);
    let acct = strkey(&w.new_vaccount(&ks));
    let mut ch = Chain { cur: w };
    let (_, _, _, commitment) =
        prepare_version(&mut ch, &acct, &ks[0], &ks, 1, 8, "", false, "control");
    ch.step("control activate", |f| {
        let c = BytesN::from_array(&f.env, &commitment);
        let a = Address::from_str(&f.env, &acct);
        f.vadmin(
            &a,
            &ks[0],
            "activate",
            std::vec![f.sc(1u32), f.sc(c.clone())],
            |cl| {
                cl.activate(&1, &c);
            },
        );
    });
    let w = ch.cur;
    let acct = Address::from_str(&w.env, &acct);
    assert!(w.vtransfer(&acct, 0, &ks[0], 2));
    measure("control: authorize, small ledger", &w.env);
    for chunk in 0..30u32 {
        w.env.as_contract(&w.sink, || {
            for i in 0..100u32 {
                w.env.storage().persistent().set(&(chunk * 100 + i), &i);
            }
        });
    }
    assert!(w.vtransfer(&acct, 0, &ks[0], 2));
    measure(
        "control: authorize, +3000 unrelated entries in the host map",
        &w.env,
    );
    let f = fork(&w);
    let acct = moved(&f, &acct);
    assert!(f.vtransfer(&acct, 0, &ks[0], 2));
    measure("control: authorize, fork (cold)", &f.env);
    assert!(f.vtransfer(&acct, 0, &ks[0], 2));
    measure("control: authorize, fork (second call)", &f.env);
}

/// Where an authorization's and a batch's cost comes from: each piece
/// alone, on its own fork.
#[test]
#[ignore]
fn breakdown() {
    let w = world();
    let ks = keys(1);
    let acct = strkey(&w.new_vaccount(&ks));
    let mut ch = Chain { cur: w };
    ch.step(
        "piece: compile_doc alone (13-rule batch doc, 6 passkeys)",
        |f| {
            let doc = f.bytes(&f.doc_json(&ks, 0..13, ""));
            PerchDocCompilerClient::new(&f.env, &f.compiler).compile_doc(&doc);
        },
    );
    ch.step("piece: compile_doc alone (8-rule doc, 6 passkeys)", |f| {
        let doc = f.bytes(&f.doc_json(&ks, 0..8, ""));
        PerchDocCompilerClient::new(&f.env, &f.compiler).compile_doc(&doc);
    });
    ch.step("piece: one passkey verify (webauthn verifier)", |f| {
        let digest = [7u8; 32];
        let sig = sig_data(&f.env, &ks[0].assert(&digest));
        let key = Bytes::from_slice(&f.env, &ks[0].key_data());
        assert!(
            stellar_accounts::verifiers::VerifierClient::new(&f.env, &f.webauthn).verify(
                &Bytes::from_array(&f.env, &digest),
                &key.into_val(&f.env),
                &sig.into_val(&f.env),
            )
        );
    });
    let doc = ch.cur.doc_json(&ks, 0..13, "");
    let rules = ch.cur.stored_rules(&doc, &ks);
    let program = rules[2].program.get(0).unwrap();
    let sc_prog = ch.cur.sc(program);
    ch.step(
        "piece: evaluate one rule's program (perch-vspike-eval)",
        |f| {
            let program: perch_program::RpnProgram = perch_program::RpnProgram::try_from_val(
                &f.env,
                &Val::try_from_val(&f.env, &sc_prog).unwrap(),
            )
            .unwrap();
            let a = Address::from_str(&f.env, &acct);
            let ctx = soroban_sdk::auth::Context::Contract(soroban_sdk::auth::ContractContext {
                contract: f.token.clone(),
                fn_name: soroban_sdk::Symbol::new(&f.env, "transfer"),
                args: soroban_sdk::vec![
                    &f.env,
                    a.into_val(&f.env),
                    f.sink.into_val(&f.env),
                    10i128.into_val(&f.env)
                ],
            });
            let ok: bool = f.env.invoke_contract(
                &f.eval,
                &soroban_sdk::Symbol::new(&f.env, "evaluate"),
                soroban_sdk::vec![
                    &f.env,
                    program.into_val(&f.env),
                    ctx.into_val(&f.env),
                    1u32.into_val(&f.env),
                    a.into_val(&f.env)
                ],
            );
            assert!(ok);
        },
    );
    ch.step("piece: canonicalize 6 passkeys (one batch call)", |f| {
        let keys = Vec::from_iter(
            &f.env,
            ks.iter()
                .map(|k| Bytes::from_slice(&f.env, &k.key_data()).into_val(&f.env)),
        );
        stellar_accounts::verifiers::VerifierClient::new(&f.env, &f.webauthn)
            .batch_canonicalize_key(&keys);
    });
}

/// Restore's cost against how many credentials the thief bound: what
/// actually grows, and where a limit binds.
fn restore_vs_thief(thief_count: usize) {
    let w = world();
    let ks = keys(1);
    let acct = strkey(&w.new_vaccount(&ks));
    let mut ch = Chain { cur: w };
    let (_, _, _, c) = prepare_version(&mut ch, &acct, &ks[0], &ks, 1, 13, "", false, "setup");
    let on = |f: &W| Address::from_str(&f.env, &acct);
    ch.step("setup activate", |f| {
        let c = BytesN::from_array(&f.env, &c);
        f.vadmin(
            &on(f),
            &ks[0],
            "activate",
            std::vec![f.sc(1u32), f.sc(c.clone())],
            |cl| {
                cl.activate(&1, &c);
            },
        );
    });
    ch.step("setup publish_baseline", |f| {
        f.vadmin(&on(f), &ks[0], "publish_baseline", std::vec![], |cl| {
            cl.publish_baseline()
        });
    });
    let thief = keys_n(3, thief_count);
    ch.step(
        &format!("T={thief_count} thief set_bindings ({thief_count} credentials)"),
        |f| {
            let t = Vec::from_iter(&f.env, thief.iter().map(|k| f.passkey_signer(k)));
            f.vadmin(
                &on(f),
                &ks[0],
                "set_bindings",
                std::vec![f.sc(t.clone())],
                |cl| {
                    cl.set_bindings(&t);
                },
            );
        },
    );
    let fresh = keys(4);
    ch.step(
        &format!(
            "T={thief_count} restore baseline ({} revoked)",
            P + thief_count
        ),
        |f| {
            let a = on(f);
            let fs = Vec::from_iter(&f.env, fresh.iter().map(|k| f.passkey_signer(k)));
            let root = f.inv(&a, "restore", std::vec![f.sc(fs.clone())], std::vec![]);
            f.env.set_auths(&[SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                    address: f.controller.clone().into(),
                    nonce: f.next_nonce(),
                    signature_expiration_ledger: f.env.ledger().sequence() + 1_000_000,
                    signature: ScVal::Void,
                }),
                root_invocation: root,
            }]);
            VAccountClient::new(&f.env, &a).restore(&fs);
            f.env.set_auths(&[]);
        },
    );
}

#[test]
#[ignore]
fn restore_thief_bindings_sweep() {
    for t in [6usize, 15, 30, 45, 60, 75, 90] {
        restore_vs_thief(t);
    }
}

/// A partial upload never grants authority, and a batch must match its
/// compiled twin.
#[test]
#[ignore]
fn partial_or_unapproved_never_activates() {
    let w = world();
    let ks = keys(1);
    let acct = strkey(&w.new_vaccount(&ks));
    let mut ch = Chain { cur: w };
    let on = |f: &W| Address::from_str(&f.env, &acct);
    let ph = ch.cur.principals_hash();
    ch.step("partial begin (32 rules)", |f| {
        let ph = BytesN::from_array(&f.env, &ph);
        f.vadmin(
            &on(f),
            &ks[0],
            "begin",
            std::vec![f.sc(1u32), f.sc(32u32), f.sc(P as u32), f.sc(ph.clone())],
            |c| c.begin(&1, &32, &(P as u32), &ph),
        );
    });
    let doc = ch.cur.doc_json(&ks, 0..13, "");
    let rules = ch.cur.stored_rules(&doc, &ks);
    let sc = ch.cur.sc(Vec::from_slice(&ch.cur.env, &rules));
    ch.step("partial prepare (13 of 32)", |f| {
        let rv: Vec<StoredRule> =
            Vec::try_from_val(&f.env, &Val::try_from_val(&f.env, &sc).unwrap()).unwrap();
        let d = f.bytes(&doc);
        f.vadmin(
            &on(f),
            &ks[0],
            "prepare",
            std::vec![f.sc(1u32), f.sc(rv.clone()), f.sc(d.clone())],
            |c| c.prepare(&1, &rv, &d),
        );
    });
    ch.step("refused: activate a partial version", |f| {
        let a = on(f);
        let meta = VAccountClient::new(&f.env, &a).version(&1).unwrap();
        let root = f.inv(
            &a,
            "activate",
            std::vec![f.sc(1u32), f.sc(meta.acc.clone())],
            std::vec![],
        );
        f.env
            .set_auths(&[f.ventry(&a, &[(0, &ks[0])], 0, &[0], root)]);
        assert!(VAccountClient::new(&f.env, &a)
            .try_activate(&1, &meta.acc)
            .is_err());
        f.env.set_auths(&[]);
        assert_eq!(VAccountClient::new(&f.env, &a).active().version, 0);
    });
    ch.step(
        "refused: a batch whose stored rules differ from its compiled twin",
        |f| {
            let a = on(f);
            let mut rv: Vec<StoredRule> =
                Vec::try_from_val(&f.env, &Val::try_from_val(&f.env, &sc).unwrap()).unwrap();
            let mut r = rv.get(2).unwrap();
            r.cap = Vec::from_array(
                &f.env,
                [Cap {
                    limit: i128::MAX,
                    period: 1,
                }],
            );
            rv.set(2, r);
            let d = f.bytes(&doc);
            let root = f.inv(
                &a,
                "prepare",
                std::vec![f.sc(1u32), f.sc(rv.clone()), f.sc(d.clone())],
                std::vec![],
            );
            f.env
                .set_auths(&[f.ventry(&a, &[(0, &ks[0])], 0, &[0], root)]);
            assert!(VAccountClient::new(&f.env, &a)
                .try_prepare(&1, &rv, &d)
                .is_err());
            f.env.set_auths(&[]);
        },
    );
}

// ---------------------------------------------------------------------------
// Archived entries: the host auto-restores an archived persistent entry a
// transaction touches (recording mode marks it read-write and meters it as a
// disk read), which is what a transaction after a long dormancy pays.
// ---------------------------------------------------------------------------

/// [`fork`], with every persistent contract-data entry `archive` selects
/// archived by the time the caller's next transaction runs: the entries get
/// a short TTL, are read once while live (so the host's storage map holds
/// them when the measured invocation starts, as a real footprint would),
/// and the ledger then moves past that TTL. Instances and code stay live.
fn fork_archived(w: &W, archive: impl Fn(&soroban_sdk::xdr::LedgerKeyContractData) -> bool) -> W {
    let mut snap = w.env.to_ledger_snapshot();
    let soon = snap.sequence_number + 5;
    let mut picked = std::vec::Vec::new();
    for (k, (_, live_until)) in snap.ledger_entries.iter_mut() {
        if let soroban_sdk::xdr::LedgerKey::ContractData(d) = k.as_ref() {
            if d.durability == soroban_sdk::xdr::ContractDataDurability::Persistent
                && d.key != ScVal::LedgerKeyContractInstance
                && archive(d)
            {
                *live_until = Some(soon);
                picked.push((d.contract.clone(), d.key.clone()));
            }
        }
    }
    assert!(!picked.is_empty(), "nothing archived");
    let mut env = Env::from_ledger_snapshot(snap);
    env.set_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.cost_estimate().budget().reset_unlimited();
    let a = |x: &Address| Address::from_str(&env, &strkey(x));
    let (token, sink, multi, controller) = (a(&w.token), a(&w.sink), a(&w.multi), a(&w.controller));
    env.register_at(&token, TokenStub, ());
    env.register_at(&sink, TokenStub, ());
    env.register_at(&multi, Multi, ());
    env.register_at(&controller, support::Key, ());
    for (contract, key) in &picked {
        let c = Address::try_from_val(
            &env,
            &Val::try_from_val(&env, &ScVal::Address(contract.clone())).unwrap(),
        )
        .unwrap();
        let k = Val::try_from_val(&env, key).unwrap();
        env.as_contract(&c, || assert!(env.storage().persistent().has(&k)));
    }
    env.ledger().with_mut(|l| l.sequence_number = soon + 5);
    env.set_auths(&[]);
    println!(
        "{{\"case\":\"archived entries\",\"count\":{}}}",
        picked.len()
    );
    W {
        wasm: w.wasm.clone(),
        webauthn: a(&w.webauthn),
        compiler: a(&w.compiler),
        factory: a(&w.factory),
        eval: a(&w.eval),
        token,
        multi,
        sink,
        controller,
        nonce: Cell::new(w.nonce.get() + 2_000),
        salt: Cell::new(w.salt.get()),
        env,
    }
}

fn data_key(contract: &Address, key: ScVal) -> (soroban_sdk::xdr::ScAddress, ScVal) {
    (contract.clone().into(), key)
}

fn archived_row(label: &str, e: &Env) -> Row {
    let r = e.cost_estimate().resources();
    println!(
        "{{\"case\":\"{label} (restored)\",\"disk_read_entries\":{},\"disk_read_bytes\":{}}}",
        r.disk_read_entries, r.disk_read_bytes
    );
    measure(label, e)
}

/// Authorization, activation, and restore with their persistent entries
/// archived, on both backends.
fn archived(n: usize) {
    let w = world();
    let ks = keys(1);
    let acct_addr = w.new_vaccount(&ks);
    let acct = strkey(&acct_addr);
    let mut ch = Chain { cur: w };
    let l = |what: &str| format!("ARCH V n={n} {what}");
    let on = |f: &W| Address::from_str(&f.env, &acct);
    let (_, _, _, c1) =
        prepare_version(&mut ch, &acct, &ks[0], &ks, 1, n, "", false, &l("setup v1"));
    ch.step(&l("setup activate v1"), |f| {
        let c = BytesN::from_array(&f.env, &c1);
        f.vadmin(
            &on(f),
            &ks[0],
            "activate",
            std::vec![f.sc(1u32), f.sc(c.clone())],
            |cl| {
                cl.activate(&1, &c);
            },
        );
    });
    ch.step(&l("setup first spend"), |f| {
        assert!(f.vtransfer(&on(f), 0, &ks[0], 2))
    });
    ch.step(&l("setup publish_baseline"), |f| {
        f.vadmin(&on(f), &ks[0], "publish_baseline", std::vec![], |cl| {
            cl.publish_baseline()
        });
    });
    let (_, _, _, c2) = prepare_version(
        &mut ch,
        &acct,
        &ks[0],
        &ks,
        2,
        n,
        "t",
        false,
        &l("setup v2"),
    );

    let a = ch.addr(&acct);
    let rule2 = data_key(&a, ch.cur.sc(perch_vspike::Key::Rule(1, 2)));
    let meta2 = data_key(&a, ch.cur.sc(perch_vspike::Key::Version(2)));
    let acct_sc: soroban_sdk::xdr::ScAddress = a.clone().into();

    // Authorize with only the selected rule archived.
    let f = fork_archived(&ch.cur, |d| d.contract == rule2.0 && d.key == rule2.1);
    assert!(f.vtransfer(&on(&f), 0, &ks[0], 2));
    archived_row(&l("authorize 1 rule, the selected rule archived"), &f.env);
    // Authorize with every persistent entry of the account archived.
    let f = fork_archived(&ch.cur, |d| d.contract == acct_sc);
    assert!(f.vtransfer(&on(&f), 0, &ks[0], 2));
    archived_row(
        &l("authorize 1 rule, every persistent account entry archived"),
        &f.env,
    );
    // Activate v2 with its metadata archived.
    let f = fork_archived(&ch.cur, |d| d.contract == meta2.0 && d.key == meta2.1);
    let c = BytesN::from_array(&f.env, &c2);
    f.vadmin(
        &on(&f),
        &ks[0],
        "activate",
        std::vec![f.sc(2u32), f.sc(c.clone())],
        |cl| {
            cl.activate(&2, &c);
        },
    );
    archived_row(&l("activate, version metadata archived"), &f.env);

    // Thief swaps every credential; then restore with every persistent
    // entry of the account archived (baseline record, version metadata,
    // bindings).
    let thief = keys(3);
    ch.step(&l("setup thief set_bindings"), |f| {
        let t = Vec::from_iter(&f.env, thief.iter().map(|k| f.passkey_signer(k)));
        f.vadmin(
            &on(f),
            &ks[0],
            "set_bindings",
            std::vec![f.sc(t.clone())],
            |cl| {
                cl.set_bindings(&t);
            },
        );
    });
    let fresh = keys(4);
    let restore = |f: &W| {
        let a = on(f);
        let fs = Vec::from_iter(&f.env, fresh.iter().map(|k| f.passkey_signer(k)));
        let root = f.inv(&a, "restore", std::vec![f.sc(fs.clone())], std::vec![]);
        f.env.set_auths(&[SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: f.controller.clone().into(),
                nonce: f.next_nonce(),
                signature_expiration_ledger: f.env.ledger().sequence() + 1_000_000,
                signature: ScVal::Void,
            }),
            root_invocation: root,
        }]);
        VAccountClient::new(&f.env, &a).restore(&fs);
        f.env.set_auths(&[]);
    };
    let acct_sc: soroban_sdk::xdr::ScAddress = ch.addr(&acct).into();
    let f = fork(&ch.cur);
    restore(&f);
    measure(&l("restore baseline, everything live (reference)"), &f.env);
    let f = fork_archived(&ch.cur, |d| d.contract == acct_sc);
    restore(&f);
    archived_row(
        &l("restore baseline, every persistent account entry archived"),
        &f.env,
    );
}

#[test]
#[ignore]
fn archived_13() {
    archived(13);
}

#[test]
#[ignore]
fn archived_512() {
    archived(512);
}

/// The OZ backend's authorization with archived entries.
#[test]
#[ignore]
fn archived_oz_13() {
    let n = 13;
    let w = world();
    let ks = keys(1);
    let acct_addr = w.new_oz(&ks[0]);
    let acct = strkey(&acct_addr);
    let mut ch = Chain { cur: w };
    let on = |f: &W| Address::from_str(&f.env, &acct);
    let admin = ch.cur.oz_rule_id(&ch.addr(&acct), "admin");
    ch.step("ARCH OZ n=13 setup apply_doc", |f| {
        let doc = f.bytes(&f.doc_json(&ks, 0..n, ""));
        assert!(f.oz_apply(&on(f), &ks[0], admin, &doc));
    });
    let r2 = ch.cur.oz_rule_id(&ch.addr(&acct), &ch.cur.rule_name(2, ""));
    ch.step("ARCH OZ n=13 setup first spend", |f| {
        assert!(f.oz_transfer(&on(f), &ks[0], r2))
    });
    let a = ch.addr(&acct);
    let rule = data_key(&a, ch.cur.sc(SmartAccountStorageKey::ContextRuleData(r2)));
    let f = fork_archived(&ch.cur, |d| d.contract == rule.0 && d.key == rule.1);
    assert!(f.oz_transfer(&on(&f), &ks[0], r2));
    archived_row(
        "ARCH OZ n=13 authorize 1 rule, the selected rule archived",
        &f.env,
    );
    // Every persistent data entry in the ledger archived: the account's
    // rules and signer registry, the interpreter's program, the spending
    // limit's window.
    let f = fork_archived(&ch.cur, |_| true);
    assert!(f.oz_transfer(&on(&f), &ks[0], r2));
    archived_row(
        "ARCH OZ n=13 authorize 1 rule, every persistent data entry archived",
        &f.env,
    );
    // The same for the versioned backend, for a like-for-like row.
    let _ = ks;
}

#[test]
#[ignore]
fn archived_v_all_13() {
    let n = 13;
    let w = world();
    let ks = keys(1);
    let acct = strkey(&w.new_vaccount(&ks));
    let mut ch = Chain { cur: w };
    let on = |f: &W| Address::from_str(&f.env, &acct);
    let (_, _, _, c1) = prepare_version(
        &mut ch,
        &acct,
        &ks[0],
        &ks,
        1,
        n,
        "",
        false,
        "ARCH Vall setup",
    );
    ch.step("ARCH Vall setup activate", |f| {
        let c = BytesN::from_array(&f.env, &c1);
        f.vadmin(
            &on(f),
            &ks[0],
            "activate",
            std::vec![f.sc(1u32), f.sc(c.clone())],
            |cl| {
                cl.activate(&1, &c);
            },
        );
    });
    ch.step("ARCH Vall setup first spend", |f| {
        assert!(f.vtransfer(&on(f), 0, &ks[0], 2))
    });
    let f = fork_archived(&ch.cur, |_| true);
    assert!(f.vtransfer(&on(&f), 0, &ks[0], 2));
    archived_row(
        "ARCH V n=13 authorize 1 rule, every persistent data entry archived",
        &f.env,
    );
}

/// Control for `fork_archived`: archive an entry the measured transaction
/// never touches.
#[test]
#[ignore]
fn archived_control() {
    let w = world();
    let ks = keys(1);
    let acct = strkey(&w.new_vaccount(&ks));
    let mut ch = Chain { cur: w };
    let on = |f: &W| Address::from_str(&f.env, &acct);
    let (_, _, _, c1) =
        prepare_version(&mut ch, &acct, &ks[0], &ks, 1, 13, "", false, "ARCHC setup");
    ch.step("ARCHC setup activate", |f| {
        let c = BytesN::from_array(&f.env, &c1);
        f.vadmin(
            &on(f),
            &ks[0],
            "activate",
            std::vec![f.sc(1u32), f.sc(c.clone())],
            |cl| {
                cl.activate(&1, &c);
            },
        );
    });
    ch.step("ARCHC setup first spend", |f| {
        assert!(f.vtransfer(&on(f), 0, &ks[0], 2))
    });
    ch.step("ARCHC live authorize", |f| {
        assert!(f.vtransfer(&on(f), 0, &ks[0], 2))
    });
    let a = ch.addr(&acct);
    let untouched = ch.cur.sc(perch_vspike::Key::Rule(1, 5));
    let acct_sc: soroban_sdk::xdr::ScAddress = a.into();
    let f = fork_archived(&ch.cur, |d| d.contract == acct_sc && d.key == untouched);
    assert!(f.vtransfer(&on(&f), 0, &ks[0], 2));
    archived_row("ARCHC authorize, an untouched entry archived", &f.env);
}
