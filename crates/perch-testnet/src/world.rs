//! The deployed stack as the exercise sees it: manifest addresses, fresh
//! keys, passkey accounts from the factory, documents, and the account,
//! controller, and proof operations every scenario composes.

use anyhow::{bail, Context, Result};
use perch_account::AccountConfiguration;
use perch_deploy::keys::SeedKey;
use perch_recovery::{Attempt, EvidenceDomain};
use perch_recovery_interface::credential::{Credential, Replacement, ReplacementSet, ZkEnrollment};
use perch_recovery_interface::zk::ZkEvidence;
use perch_recovery_interface::{RecoveryAction, RecoveryStatement, StatementSubject};
use perch_testkit::passkey::SoftPasskey;
use perch_zk_pool::{LeafPosition, TreeInfo};
use perch_zk_prover::{Inputs, Toolchain, Tree};
use sha2::{Digest, Sha256};
use soroban_sdk::{vec, Address, Bytes, BytesN, IntoVal, Symbol, Val, Vec};
use stellar_xdr::ScVal;

use crate::chain::{Auth, Chain, Entries};

pub const NETWORK: &str = "Test SDF Network ; September 2015";
/// Small enough to wait out on testnet (about 5 s per ledger).
pub const DELAY: u32 = 6;
pub const EXPIRY: u32 = 720;

pub struct Stack {
    pub factory: String,
    pub webauthn: String,
    pub compiler: String,
    pub controller: String,
    pub adapter: String,
    pub pool: String,
    pub circuit_id: [u8; 32],
    pub tree_depth: u32,
    pub account_wasm: [u8; 32],
    /// The native asset's contract: ordinary activity is an XLM transfer.
    pub xlm: String,
}

impl Stack {
    pub fn from_manifest(m: &serde_json::Value, xlm: String) -> Result<Self> {
        let addr = |n: &str| -> Result<String> {
            m["contracts"][n]["address"]
                .as_str()
                .map(String::from)
                .with_context(|| format!("{n} address"))
        };
        let h32 = |s: &str| -> Result<[u8; 32]> {
            hex::decode(s)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("not 32 bytes"))
        };
        Ok(Self {
            factory: addr("perch-account-factory")?,
            webauthn: addr("perch-webauthn-verifier")?,
            compiler: addr("perch-doc-compiler")?,
            controller: addr("perch-recovery")?,
            adapter: addr("perch-zk-adapter")?,
            pool: addr("perch-zk-pool")?,
            circuit_id: h32(m["zk"]["circuit_id"].as_str().context("circuit id")?)?,
            tree_depth: m["zk"]["tree_depth"].as_u64().context("depth")? as u32,
            account_wasm: h32(m["contracts"]["perch-account"]["sha256"]
                .as_str()
                .context("account hash")?)?,
            xlm,
        })
    }
}

pub struct Acct {
    pub label: String,
    pub address: String,
    pub owner: SoftPasskey,
}

#[derive(Clone)]
pub struct Zk {
    pub secret: [u8; 32],
    pub id: [u8; 32],
}

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Guardian,
    Zk,
    Combined,
}

#[derive(Clone)]
pub struct Rec {
    pub profile: &'static str,
    pub mode: Mode,
    pub zk: Option<Zk>,
    pub guardians: std::vec::Vec<String>,
    pub delay: u32,
    pub baseline: Option<[u8; 32]>,
}

pub struct World<'a> {
    pub c: &'a Chain,
    pub s: Stack,
    pub run: String,
    /// Random, never recorded: every key of the run derives from it, so
    /// nobody can rederive the exercised accounts' keys from the report.
    secret: [u8; 32],
    salt: std::cell::Cell<u32>,
    pub accounts: std::cell::RefCell<std::vec::Vec<(String, String)>>,
    pub proving: std::cell::RefCell<std::vec::Vec<(u128, u128, Option<u64>)>>,
}

fn tagged(secret: &[u8; 32], tag: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"perch-testnet/");
    h.update(secret);
    h.update(tag.as_bytes());
    h.finalize().into()
}

/// 32 bytes from the operating system's random source.
pub fn os_random() -> Result<[u8; 32]> {
    use std::io::Read as _;
    let mut out = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut out))
        .context("read /dev/urandom")?;
    Ok(out)
}

fn hexs(b: &[u8]) -> String {
    hex::encode(b)
}

impl<'a> World<'a> {
    pub fn new(c: &'a Chain, s: Stack, run: String, secret: [u8; 32]) -> Self {
        Self {
            c,
            s,
            run,
            secret,
            salt: std::cell::Cell::new(0),
            accounts: Default::default(),
            proving: Default::default(),
        }
    }

    // --- fresh keys --------------------------------------------------------

    pub fn passkey(&self, tag: &str) -> SoftPasskey {
        let mut seed = tagged(&self.secret, tag);
        seed[0] &= 0x7f; // below the P-256 group order
        SoftPasskey::from_seed(seed)
    }

    pub fn field(&self, tag: &str) -> [u8; 32] {
        let mut f = tagged(&self.secret, tag);
        f[0] = 0; // a canonical BN254 element
        f
    }

    pub fn zk(&self, tag: &str) -> Zk {
        Zk {
            secret: self.field(&format!("{tag}/secret")),
            id: tagged(&self.secret, &format!("{tag}/enrollment")),
        }
    }

    /// A funded G-account.
    pub fn g_account(&self, tag: &str) -> Result<SeedKey> {
        let key = SeedKey::from_seed(tagged(&self.secret, tag));
        self.c.friendbot(&key.account())?;
        Ok(key)
    }

    // --- accounts ----------------------------------------------------------

    /// A passkey account from the factory, funded with 10 XLM for activity.
    pub fn new_account(&self, label: &str, owner: SoftPasskey) -> Result<Acct> {
        self.salt.set(self.salt.get() + 1);
        let salt = BytesN::from_array(
            &self.c.env,
            &tagged(&self.secret, &format!("salt/{}", self.salt.get())),
        );
        let key_data = Bytes::from_slice(&self.c.env, &owner.key_data());
        let r = self.c.call(
            "factory create_passkey",
            &self.s.factory,
            "create_passkey",
            std::vec![self.c.sc(salt), self.c.sc(key_data)],
            &[],
        )?;
        let address: Address = self.c.decode(&r.value)?;
        let address = strkey(&address);
        self.c.call(
            "fund the account (XLM transfer)",
            &self.s.xlm,
            "transfer",
            std::vec![
                self.c.sc(self.c.address(&self.c.payer.account())),
                self.c.sc(self.c.address(&address)),
                self.c.sc(100_000_000i128),
            ],
            &[],
        )?;
        self.accounts
            .borrow_mut()
            .push((label.to_string(), address.clone()));
        eprintln!("  account {label}: {address}");
        Ok(Acct {
            label: label.to_string(),
            address,
            owner,
        })
    }

    /// The id of the account's live rule named `name`, by name in its
    /// `configuration()` snapshot: ids are assigned when a rule is added and
    /// kept while it is edited in place, so they move on replacement.
    pub fn rule_id(&self, a: &Acct, name: &str) -> Result<u32> {
        let config: AccountConfiguration =
            self.c.read_as(&a.address, "configuration", std::vec![])?;
        let wanted = soroban_sdk::String::from_str(&self.c.env, name);
        config
            .rules
            .iter()
            .find(|r| r.name == wanted && (r.recovery == (name == "recovery")))
            .map(|r| r.id)
            .with_context(|| format!("{}: no rule named {name}", a.label))
    }

    pub fn owner_auth<'k>(
        &'k self,
        a: &'k Acct,
        key: &'k SoftPasskey,
        rule: &str,
    ) -> Result<Auth<'k>> {
        Ok(Auth::Passkey {
            account: &a.address,
            webauthn: &self.s.webauthn,
            key,
            rule: self.rule_id(a, rule)?,
        })
    }

    // --- documents ---------------------------------------------------------

    pub fn commitment(zk: &Zk) -> [u8; 32] {
        perch_zk_prover::commitment(&perch_zk_prover::host(), &zk.secret)
    }

    fn recovery_json(&self, r: &Rec) -> String {
        let guardians: std::vec::Vec<String> =
            r.guardians.iter().map(|g| format!(r#""{g}""#)).collect();
        let guardian_fields = format!(r#""guardians":[{}],"quorum":2"#, guardians.join(","));
        let zk_fields = || {
            let z = r.zk.as_ref().expect("zk mode needs an enrollment");
            format!(
                r#""adapter":"{}","circuit-id":"{}","pool":"{}","enrollment-id":"{}","commitment":"{}""#,
                self.s.adapter,
                hexs(&self.s.circuit_id),
                self.s.pool,
                hexs(&z.id),
                hexs(&Self::commitment(z)),
            )
        };
        let mode = match r.mode {
            Mode::Guardian => format!(r#"{{"type":"guardian-only",{guardian_fields}}}"#),
            Mode::Zk => format!(r#"{{"type":"zk-only",{}}}"#, zk_fields()),
            Mode::Combined => format!(r#"{{"type":"combined",{guardian_fields},{}}}"#, zk_fields()),
        };
        let baseline = r
            .baseline
            .map(|b| format!(r#","baseline":{{"doc-hash":"{}"}}"#, hexs(&b)))
            .unwrap_or_default();
        format!(
            r#"{{"profile":"{}","mode":{mode},"controller":"{}"{baseline},"replaceable":["owner"],"delay-ledgers":{},"expiry-ledgers":{EXPIRY},"max-cancels":3}}"#,
            r.profile, self.s.controller, r.delay,
        )
    }

    /// The owner passkey as admin, a rule letting it move the account's XLM
    /// (ordinary activity), and `recovery`.
    pub fn doc(&self, owner: &SoftPasskey, recovery: Option<&Rec>) -> Bytes {
        self.doc_with(owner, None, recovery)
    }

    /// [`World::doc`] plus, with `extra`, a second passkey signer "thief"
    /// and a rule letting it move the account's XLM.
    pub fn doc_with(
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
                self.s.webauthn,
                hexs(&key.key_data())
            )
        };
        let xlm_rule = |name: &str, signer: &str| {
            format!(
                r#"{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["{signer}"]}}}}"#,
                self.s.xlm
            )
        };
        let mut signers = std::vec![signer("owner", owner)];
        let mut rules = std::vec![
            r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#.to_string(),
            xlm_rule("xlm", "owner"),
        ];
        if let Some(thief) = extra {
            signers.push(signer("thief", thief));
            rules.push(xlm_rule("thief", "thief"));
        }
        let json = format!(
            r#"{{"version":1,"network":"{NETWORK}","signers":[{}],"rules":[{}]{recovery}}}"#,
            signers.join(","),
            rules.join(","),
        );
        Bytes::from_slice(&self.c.env, json.as_bytes())
    }

    /// A guardian account's document: the owner passkey as admin, and an
    /// `approve` rule through which `approver`, a delegated G-account, can
    /// authorize calls to the controller (guardian approvals) and nothing
    /// else.
    pub fn guardian_doc(&self, owner: &SoftPasskey, approver: &str) -> Bytes {
        let json = format!(
            r#"{{"version":1,"network":"{NETWORK}","signers":[{{"id":"owner","verifier":"{}","key":"{}"}},{{"id":"approver","address":"{approver}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}},{{"name":"approve","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["approver"]}}}}]}}"#,
            self.s.webauthn,
            hexs(&owner.key_data()),
            self.s.controller,
        );
        Bytes::from_slice(&self.c.env, json.as_bytes())
    }

    pub fn doc_hash(&self, doc: &Bytes) -> Result<BytesN<32>> {
        let compiled: perch_doc_compiler::CompiledDoc = self.c.read_as(
            &self.s.compiler,
            "compile_doc",
            std::vec![self.c.sc(doc.clone())],
        )?;
        Ok(compiled.doc_hash)
    }

    pub fn config_hash(&self, doc: &Bytes) -> Result<BytesN<32>> {
        let compiled: perch_doc_compiler::CompiledDoc = self.c.read_as(
            &self.s.compiler,
            "compile_doc",
            std::vec![self.c.sc(doc.clone())],
        )?;
        Ok(compiled.recovery.get(0).context("no recovery")?.config_hash)
    }

    // --- account calls -----------------------------------------------------

    fn apply_args(&self, doc: &Bytes, valid_until: u32) -> std::vec::Vec<ScVal> {
        std::vec![self.c.sc(doc.clone()), self.c.sc(valid_until), ScVal::Void]
    }

    pub fn apply(
        &self,
        label: &str,
        a: &Acct,
        key: &SoftPasskey,
        doc: &Bytes,
        valid_until: u32,
    ) -> Result<()> {
        let auth = self.owner_auth(a, key, "admin")?;
        self.c.call(
            label,
            &a.address,
            "apply_doc",
            self.apply_args(doc, valid_until),
            &[auth],
        )?;
        Ok(())
    }

    /// `apply_doc` signed by `key`, simulated under enforcing authorization
    /// only, must be refused at `__check_auth` (the `Protected` freeze).
    pub fn apply_refused_at_auth(
        &self,
        label: &str,
        a: &Acct,
        key: &SoftPasskey,
        doc: &Bytes,
    ) -> Result<()> {
        let auth = self.owner_auth(a, key, "admin")?;
        self.c.refused_with(
            label,
            &a.address,
            "apply_doc",
            self.apply_args(doc, 0),
            &[auth],
            None,
            Entries::Root(a.address.clone()),
        )?;
        let step = self.c.steps.borrow().last().cloned().unwrap_or_default();
        anyhow::ensure!(
            step.error
                .as_deref()
                .is_some_and(|e| e.contains("Error(Auth")),
            "{label}: refused, but not by authorization: {:?}",
            step.error
        );
        Ok(())
    }

    /// `apply_doc` signed by `key` must be refused; with `code`, by exactly
    /// that account error.
    pub fn apply_refused(
        &self,
        label: &str,
        a: &Acct,
        key: &SoftPasskey,
        doc: &Bytes,
        valid_until: u32,
        code: Option<perch_account::PerchAccountError>,
    ) -> Result<()> {
        use soroban_sdk_tools::ContractError as _;
        let auth = self.owner_auth(a, key, "admin")?;
        self.c.refused(
            label,
            &a.address,
            "apply_doc",
            self.apply_args(doc, valid_until),
            &[auth],
            code.map(|c| c.into_code()),
        )
    }

    fn transfer_args(&self, a: &Acct) -> std::vec::Vec<ScVal> {
        std::vec![
            self.c.sc(self.c.address(&a.address)),
            self.c.sc(self.c.address(&self.c.payer.account())),
            self.c.sc(1i128),
        ]
    }

    /// Ordinary activity: the account sends 1 stroop of XLM, authorized
    /// directly by `key` through the `xlm` rule.
    pub fn activity(&self, label: &str, a: &Acct, key: &SoftPasskey) -> Result<()> {
        self.activity_via(label, a, key, "xlm")
    }

    pub fn activity_via(&self, label: &str, a: &Acct, key: &SoftPasskey, rule: &str) -> Result<()> {
        let auth = self.owner_auth(a, key, rule)?;
        self.c.call(
            label,
            &self.s.xlm,
            "transfer",
            self.transfer_args(a),
            &[auth],
        )?;
        Ok(())
    }

    pub fn activity_refused(&self, label: &str, a: &Acct, key: &SoftPasskey) -> Result<()> {
        self.activity_refused_via(label, a, key, "xlm")
    }

    pub fn activity_refused_via(
        &self,
        label: &str,
        a: &Acct,
        key: &SoftPasskey,
        rule: &str,
    ) -> Result<()> {
        let auth = self.owner_auth(a, key, rule)?;
        self.c.refused(
            label,
            &self.s.xlm,
            "transfer",
            self.transfer_args(a),
            &[auth],
            None,
        )
    }

    fn execute_args(&self, a: &Acct) -> std::vec::Vec<ScVal> {
        let args: Vec<Val> = vec![
            &self.c.env,
            self.c.address(&a.address).into_val(&self.c.env),
            self.c
                .address(&self.c.payer.account())
                .into_val(&self.c.env),
            1i128.into_val(&self.c.env),
        ];
        std::vec![
            self.c.sc(self.c.address(&self.s.xlm)),
            self.c.sc(Symbol::new(&self.c.env, "transfer")),
            self.c.sc(args),
        ]
    }

    /// The same transfer through `execute`, authorized by the admin rule.
    pub fn execute(&self, label: &str, a: &Acct, key: &SoftPasskey) -> Result<()> {
        let auth = self.owner_auth(a, key, "admin")?;
        self.c
            .call(label, &a.address, "execute", self.execute_args(a), &[auth])?;
        Ok(())
    }

    pub fn execute_refused(&self, label: &str, a: &Acct, key: &SoftPasskey) -> Result<()> {
        let auth = self.owner_auth(a, key, "admin")?;
        self.c.refused(
            label,
            &a.address,
            "execute",
            self.execute_args(a),
            &[auth],
            None,
        )
    }

    /// The last refusal came from the account's `__check_auth` refusing
    /// everything but the completion: the `Protected` freeze.
    pub fn was_frozen(&self) -> Result<()> {
        use soroban_sdk_tools::ContractError as _;
        let want = perch_account::PerchAuthError::AccountFrozen.into_code();
        let step = self.c.steps.borrow().last().cloned().unwrap_or_default();
        anyhow::ensure!(
            step.auth_error_code == Some(want),
            "{}: refused by {:?}, not the freeze (#{want})",
            step.label,
            step.auth_error_code
        );
        Ok(())
    }

    // --- recovery ----------------------------------------------------------

    pub fn replacements(&self, new_owner: &SoftPasskey, zk: Option<&Zk>) -> ReplacementSet {
        let e = &self.c.env;
        ReplacementSet {
            signers: vec![
                e,
                Replacement {
                    signer_id: soroban_sdk::String::from_str(e, "owner"),
                    credential: Credential::External(
                        self.c.address(&self.s.webauthn),
                        Bytes::from_slice(e, &new_owner.key_data()),
                    ),
                },
            ],
            zk_enrollment: match zk {
                Some(z) => vec![
                    e,
                    ZkEnrollment {
                        id: BytesN::from_array(e, &z.id),
                        commitment: BytesN::from_array(e, &Self::commitment(z)),
                    },
                ],
                None => Vec::new(e),
            },
        }
    }

    pub fn begin_lost_key(&self, label: &str, a: &Acct, r: &ReplacementSet) -> Result<u64> {
        let out = self.c.call(
            label,
            &self.s.controller,
            "begin_lost_key",
            std::vec![self.c.sc(self.c.address(&a.address)), self.c.sc(r.clone())],
            &[],
        )?;
        self.c.decode(&out.value)
    }

    pub fn statement(
        &self,
        a: &Acct,
        attempt: u64,
        domain: EvidenceDomain,
    ) -> Result<RecoveryStatement> {
        self.c.read_as(
            &self.s.controller,
            "statement",
            std::vec![
                self.c.sc(self.c.address(&a.address)),
                self.c.sc(attempt),
                self.c.sc(domain),
            ],
        )
    }

    pub fn change_statement(
        &self,
        a: &Acct,
        subject: &StatementSubject,
        valid_until: u32,
    ) -> Result<RecoveryStatement> {
        self.c.read_as(
            &self.s.controller,
            "change_statement",
            std::vec![
                self.c.sc(self.c.address(&a.address)),
                self.c.sc(subject.clone()),
                self.c.sc(valid_until),
            ],
        )
    }

    pub fn attempt(&self, a: &Acct, attempt: u64) -> Result<Attempt> {
        let at: Option<Attempt> = self.c.read_as(
            &self.s.controller,
            "attempt",
            std::vec![self.c.sc(self.c.address(&a.address)), self.c.sc(attempt)],
        )?;
        at.context("no such attempt")
    }

    pub fn zk_args(
        &self,
        a: &Acct,
        attempt: u64,
        domain: EvidenceDomain,
        ev: &ZkEvidence,
    ) -> std::vec::Vec<ScVal> {
        std::vec![
            self.c.sc(self.c.address(&a.address)),
            self.c.sc(attempt),
            self.c.sc(domain),
            self.c.sc(ev.clone()),
        ]
    }

    pub fn guardian(
        &self,
        label: &str,
        g: &SeedKey,
        a: &Acct,
        attempt: u64,
        domain: EvidenceDomain,
    ) -> Result<()> {
        self.c.call(
            label,
            &self.s.controller,
            "submit_guardian",
            std::vec![
                self.c.sc(self.c.address(&a.address)),
                self.c.sc(attempt),
                self.c.sc(domain),
                self.c.sc(self.c.address(&g.account())),
            ],
            &[Auth::Account(g)],
        )?;
        Ok(())
    }

    pub fn approve_change(
        &self,
        label: &str,
        g: &SeedKey,
        a: &Acct,
        subject: &StatementSubject,
        valid_until: u32,
    ) -> Result<()> {
        self.c.call(
            label,
            &self.s.controller,
            "approve_change",
            std::vec![
                self.c.sc(self.c.address(&a.address)),
                self.c.sc(subject.clone()),
                self.c.sc(valid_until),
                self.c.sc(self.c.address(&g.account())),
            ],
            &[Auth::Account(g)],
        )?;
        Ok(())
    }

    /// The attempt's canonical target, as a completer simulates it.
    pub fn target_bytes(&self, a: &Acct, r: &ReplacementSet) -> Result<Bytes> {
        let current: Option<Bytes> = self.c.read_as(&a.address, "applied_doc", std::vec![])?;
        let current = current.context("no applied document")?;
        self.derive(current.clone(), current, RecoveryAction::LostKey, r)
    }

    /// A compromise attempt's target: the published baseline with the
    /// current recovery member and `r`.
    pub fn compromise_target(&self, a: &Acct, r: &ReplacementSet) -> Result<Bytes> {
        let current: Option<Bytes> = self.c.read_as(&a.address, "applied_doc", std::vec![])?;
        let baseline: Option<Bytes> = self.c.read_as(
            &self.s.controller,
            "baseline",
            std::vec![self.c.sc(self.c.address(&a.address))],
        )?;
        self.derive(
            baseline.context("no published baseline")?,
            current.context("no applied document")?,
            RecoveryAction::Compromise,
            r,
        )
    }

    fn derive(
        &self,
        source: Bytes,
        current: Bytes,
        action: RecoveryAction,
        r: &ReplacementSet,
    ) -> Result<Bytes> {
        let derived: perch_doc_compiler::DerivedTarget = self.c.read_as(
            &self.s.compiler,
            "derive_target",
            std::vec![
                self.c.sc(source),
                self.c.sc(current),
                self.c.sc(action),
                self.c.sc(r.clone()),
            ],
        )?;
        Ok(derived.canonical)
    }

    fn complete_args(&self, target: &Bytes) -> std::vec::Vec<ScVal> {
        std::vec![self.c.sc(target.clone()), self.c.sc(0u32), ScVal::Void]
    }

    /// Complete through the recovery rule. The entry is built, not
    /// recorded: a completion simulates only under enforcing authorization.
    pub fn complete(&self, label: &str, a: &Acct, target: &Bytes) -> Result<()> {
        let rule = self.rule_id(a, "recovery")?;
        self.c.call_with(
            label,
            &a.address,
            "apply_doc",
            self.complete_args(target),
            &[Auth::RecoveryRule {
                account: &a.address,
                rule,
            }],
            Entries::Root(a.address.clone()),
        )?;
        Ok(())
    }

    pub fn complete_refused(&self, label: &str, a: &Acct, target: &Bytes) -> Result<()> {
        let rule = self.rule_id(a, "recovery")?;
        self.c.refused_with(
            label,
            &a.address,
            "apply_doc",
            self.complete_args(target),
            &[Auth::RecoveryRule {
                account: &a.address,
                rule,
            }],
            None,
            Entries::Root(a.address.clone()),
        )
    }

    // --- proofs ------------------------------------------------------------

    fn leaves(&self, tree_id: u32, size: u64) -> Result<std::vec::Vec<[u8; 32]>> {
        let mut out = std::vec::Vec::new();
        let mut start = 0u64;
        while start < size {
            let count = (size - start).min(perch_zk_pool::MAX_PAGE as u64) as u32;
            let page: Vec<BytesN<32>> = self.c.read_as(
                &self.s.pool,
                "leaves",
                std::vec![self.c.sc(tree_id), self.c.sc(start), self.c.sc(count)],
            )?;
            out.extend(page.iter().map(|l| l.to_array()));
            start += u64::from(count);
        }
        Ok(out)
    }

    /// A real proof of `statement` by `zk`, from the pool's on-chain leaves.
    pub fn prove(&self, a: &Acct, zk: &Zk, statement: &RecoveryStatement) -> Result<ZkEvidence> {
        let e = &self.c.env;
        let at: Option<LeafPosition> = self.c.read_as(
            &self.s.pool,
            "enrollment",
            std::vec![
                self.c.sc(self.c.address(&a.address)),
                self.c.sc(BytesN::from_array(e, &zk.id)),
            ],
        )?;
        let at = at.context("the leaf was not inserted")?;
        let info: TreeInfo =
            self.c
                .read_as(&self.s.pool, "tree", std::vec![self.c.sc(at.tree_id)])?;
        let host = perch_zk_prover::host();
        let leaves = self.leaves(at.tree_id, info.size)?;
        let path = Tree::new(&host, self.s.tree_depth, &leaves).path(at.index);
        let account_id = perch_zk_primitives::contract_id(e, &self.c.address(&a.address))
            .context("account is not a contract")?;
        let inputs = Inputs::new(
            &host,
            zk.secret,
            account_id.to_array(),
            zk.id,
            statement
                .digest(e)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?
                .to_array(),
            at.index,
            path,
        );
        let known: bool = self.c.read_as(
            &self.s.pool,
            "is_known_root",
            std::vec![
                self.c.sc(at.tree_id),
                self.c.sc(BytesN::from_array(e, &inputs.root))
            ],
        )?;
        if !known {
            bail!("rebuilt root is not one the pool recorded");
        }
        let tc = Toolchain::from_env()
            .map_err(|e| anyhow::anyhow!("{e} (eval \"$(scripts/zk-toolchain.sh)\")"))?;
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let proof = perch_zk_prover::prove(
            &tc,
            &repo.join("circuits"),
            "perch_zk_recovery",
            &inputs,
            &repo.join("target/perch-testnet-proofs").join(&self.run),
        )?;
        self.proving.borrow_mut().push((
            proof.execute_ms,
            proof.prove_ms,
            proof.prove_peak_rss_bytes,
        ));
        Ok(ZkEvidence {
            tree_id: at.tree_id,
            root: BytesN::from_array(e, &inputs.root),
            nullifier: BytesN::from_array(e, &inputs.nullifier),
            proof: Bytes::from_slice(e, &proof.proof),
        })
    }
}

pub fn strkey(a: &Address) -> String {
    let s = a.to_string();
    let mut buf = std::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    String::from_utf8(buf).expect("strkey")
}

pub fn tamper(e: &soroban_sdk::Env, ev: &ZkEvidence) -> ZkEvidence {
    let mut proof = std::vec![0u8; ev.proof.len() as usize];
    ev.proof.copy_into_slice(&mut proof);
    proof[1000] ^= 1;
    ZkEvidence {
        proof: Bytes::from_slice(e, &proof),
        ..ev.clone()
    }
}
