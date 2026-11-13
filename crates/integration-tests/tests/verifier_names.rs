//! Verifier names end to end: a document's `verifier-name` resolved through
//! the `perch/verifiers` registry and bound by `doc_hash`; a verifier named
//! by contract id alone refused in an account document and a recovery target,
//! and in a grant document allowed once per rule and flagged; a repointed
//! name leaving an applied account as it was; account creation refusing an
//! unverified admin verifier; and a grant document with named verifiers
//! rebuilt byte for byte from the account's views.
//!
//! The registry is `perch_testkit::verifiers`' stand-in unless a test says
//! otherwise (`the_real_registry_resolves_a_published_name` runs the real
//! `perch-constructorless-registry`).

use ed25519_dalek::{Signer as _, SigningKey};
use perch_account::{PerchAccount, PerchAccountClient, PerchAccountError};
use perch_account_factory::{pins, PerchAccountFactory, PerchAccountFactoryClient};
use perch_account_types::{AuthPayload, Signer, SmartAccountError};
use perch_constructorless_registry::{ConstructorlessRegistry, ConstructorlessRegistryClient};
use perch_doc_compiler::{CompiledDoc, DocCompilerError, PerchDocCompiler, PerchDocCompilerClient};
use perch_ed25519_verifier::PerchEd25519Verifier;
use perch_interpreter::PerchInterpreter;
use perch_recovery_interface::credential::{Credential, Replacement, ReplacementSet};
use perch_recovery_interface::RecoveryAction;
use perch_smart_account::{infra, is_verified_verifier, verifier_registry};
use perch_spending_limit::PerchSpendingLimit;
use perch_testkit::delta::strkey;
use perch_testkit::passkey::SoftPasskey;
use perch_testkit::{auth_digest, rebuild, verifiers, AnyKeyVerifier, FIXTURE_NETWORK};
use perch_webauthn_verifier::PerchWebAuthnVerifier;
use sha2::{Digest, Sha256};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, EnvTestConfig, Ledger as _};
use soroban_sdk::{map, vec, Address, Bytes, BytesN, Env, IntoVal, Map, String as SString, Symbol};

const ED: &str = "perch-ed25519-verifier@1.0.0";
const OTHER: &str = "other-verifier@1.0.0";

struct World {
    env: Env,
    account: Address,
    compiler: Address,
    /// The ed25519 verifier, deployed where `perch/verifiers` deploys it and
    /// published as [`ED`].
    verifier: Address,
    /// A pass-through verifier at an address of its own: unverified.
    raw: Address,
    admin_key: SigningKey,
    target: Address,
}

fn bind_network(env: &Env) {
    let id = env
        .crypto()
        .sha256(&Bytes::from_slice(env, FIXTURE_NETWORK.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| {
        l.sequence_number = 1_000;
        l.network_id = id;
        l.min_persistent_entry_ttl = 1_000_000;
        l.max_entry_ttl = 10_000_000;
    });
}

fn register_infra(env: &Env) -> Address {
    let compiler = infra::perch_doc_compiler::address(env);
    env.register_at(&compiler, PerchDocCompiler, ());
    env.register_at(
        &infra::perch_interpreter::address(env),
        PerchInterpreter,
        (),
    );
    env.register_at(
        &infra::perch_spending_limit::address(env),
        PerchSpendingLimit,
        (),
    );
    compiler
}

fn fresh_env() -> Env {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    bind_network(&env);
    env.mock_all_auths();
    env
}

fn world() -> World {
    let env = fresh_env();
    let compiler = register_infra(&env);
    let verifier = verifiers::deploy(&env, PerchEd25519Verifier);
    verifiers::name(&env, ED, &verifier);
    let raw = env.register(AnyKeyVerifier, ());
    let admin_key = SigningKey::from_bytes(&[9u8; 32]);
    let account = env.register(
        PerchAccount,
        (vec![
            &env,
            Signer::External(verifier.clone(), pubkey(&env, &admin_key).into()),
        ],),
    );
    let target = Address::generate(&env);
    World {
        env,
        account,
        compiler,
        verifier,
        raw,
        admin_key,
        target,
    }
}

fn pubkey(env: &Env, key: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &key.verifying_key().to_bytes())
}

fn key_hex(key: &SigningKey) -> std::string::String {
    hex::encode(key.verifying_key().to_bytes())
}

impl World {
    fn client(&self) -> PerchAccountClient<'_> {
        PerchAccountClient::new(&self.env, &self.account)
    }

    fn compile(&self, json: &str) -> Result<CompiledDoc, DocCompilerError> {
        match PerchDocCompilerClient::new(&self.env, &self.compiler)
            .try_compile_doc(&Bytes::from_slice(&self.env, json.as_bytes()))
        {
            Ok(Ok(c)) => Ok(c),
            Err(Ok(e)) => Err(e),
            other => panic!("compile_doc: {other:?}"),
        }
    }

    fn apply(&self, json: &str) -> Result<BytesN<32>, PerchAccountError> {
        match self
            .client()
            .try_apply_doc(&Bytes::from_slice(&self.env, json.as_bytes()), &0, &None)
        {
            Ok(Ok(h)) => Ok(h),
            Err(Ok(e)) => Err(e),
            other => panic!("apply_doc: {other:?}"),
        }
    }

    fn apply_grant(&self, grant: u32, json: &str) -> Result<BytesN<32>, PerchAccountError> {
        match self
            .client()
            .try_apply_grant(&grant, &Bytes::from_slice(&self.env, json.as_bytes()))
        {
            Ok(Ok(h)) => Ok(h),
            Err(Ok(e)) => Err(e),
            other => panic!("apply_grant: {other:?}"),
        }
    }

    /// A named signer under the ed25519 verifier.
    fn named(&self, id: &str, key: &SigningKey) -> std::string::String {
        format!(
            r#"{{"id":"{id}","verifier":"{}","verifier-name":"{ED}","key":"{}"}}"#,
            strkey(&self.verifier),
            key_hex(key)
        )
    }

    /// A signer under the pass-through verifier, named by contract id.
    fn raw(&self, id: &str, key: &SigningKey) -> std::string::String {
        format!(
            r#"{{"id":"{id}","verifier":"{}","key":"{}"}}"#,
            strkey(&self.raw),
            key_hex(key)
        )
    }

    /// An account document: `admin` (named) holds the self-admin rule, and
    /// `extra` signers and rules follow.
    fn admin_doc(
        &self,
        extra_signers: &[std::string::String],
        extra_rules: &[&str],
    ) -> std::string::String {
        let mut signers = std::vec![self.named("admin", &self.admin_key)];
        signers.extend(extra_signers.iter().cloned());
        let mut rules = std::vec![
            r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["admin"]}}"#.to_string()
        ];
        rules.extend(extra_rules.iter().map(|r| r.to_string()));
        format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
            signers.join(","),
            rules.join(",")
        )
    }

    /// A grant document over `target`: `signers` and one rule per entry of
    /// `rules` (each a principals object).
    fn grant_doc(&self, signers: &[std::string::String], rules: &[&str]) -> std::string::String {
        let rules: std::vec::Vec<std::string::String> = rules
            .iter()
            .enumerate()
            .map(|(i, p)| {
                format!(
                    r#"{{"name":"app{i}","scope":{{"type":"contract","address":"{}"}},"principals":{p}}}"#,
                    strkey(&self.target)
                )
            })
            .collect();
        format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
            signers.join(","),
            rules.join(",")
        )
    }

    fn target_rule(&self, signers: &[&str]) -> std::string::String {
        format!(
            r#"{{"name":"app","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":{signers:?}}}}}"#,
            strkey(&self.target)
        )
    }

    /// Drive the account's exported `__check_auth` for a call on itself,
    /// signed by `key` as `verifier`'s signer.
    fn check_admin(&self, verifier: &Address, key: &SigningKey, sig: Option<[u8; 64]>) -> bool {
        let payload = self
            .env
            .crypto()
            .sha256(&Bytes::from_array(&self.env, &[0x11; 32]))
            .to_bytes();
        let ids = vec![&self.env, 0u32];
        let digest = auth_digest(&self.env, &self.account, &payload, &ids);
        let sig = sig.unwrap_or_else(|| key.sign(&digest).to_bytes());
        let signers: Map<Signer, Bytes> = map![
            &self.env,
            (
                Signer::External(verifier.clone(), pubkey(&self.env, key).into()),
                Bytes::from_array(&self.env, &sig)
            )
        ];
        let auth = AuthPayload {
            signers,
            context_rule_ids: ids,
        };
        let ctx = Context::Contract(ContractContext {
            contract: self.account.clone(),
            fn_name: Symbol::new(&self.env, "apply_doc"),
            args: vec![&self.env, 0u32.into_val(&self.env)],
        });
        self.env
            .try_invoke_contract_check_auth::<SmartAccountError>(
                &self.account,
                &payload,
                auth.into_val(&self.env),
                &vec![&self.env, ctx],
            )
            .is_ok()
    }
}

fn sha256_hex(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

#[test]
fn a_named_verifier_resolves_and_its_name_is_bound() {
    let w = world();
    let doc = w.admin_doc(&[], &[]);
    let c = w.compile(&doc).unwrap();
    let canonical = perch_ir::canonical_json(&perch_ir::from_json(&doc).unwrap());
    assert!(canonical.contains(&format!(r#""verifier-name":"{ED}""#)));
    assert_eq!(c.doc_hash.to_array(), sha256_hex(&canonical));
    assert_eq!(
        c.verifier_names,
        vec![&w.env, SString::from_str(&w.env, ED)]
    );
    assert!(c.unverified.is_empty());

    // The account stores the address the name resolved to.
    assert_eq!(w.apply(&doc), Ok(c.doc_hash.clone()));
    assert_eq!(
        w.client().rule_set().get_unchecked(0).signers,
        vec![
            &w.env,
            Signer::External(w.verifier.clone(), pubkey(&w.env, &w.admin_key).into())
        ]
    );

    // A version nobody published, and a name that is another verifier's.
    let other = verifiers::deploy(&w.env, AnyKeyVerifier);
    verifiers::name(&w.env, OTHER, &other);
    for spelled in [
        "perch-ed25519-verifier@1.0.1",
        "nobody-verifier@1.0.0",
        OTHER,
    ] {
        let wrong = doc.replace(ED, spelled);
        assert_eq!(
            w.compile(&wrong).err(),
            Some(DocCompilerError::DocInvalid),
            "{spelled}"
        );
    }
}

#[test]
fn a_name_resolves_nowhere_without_the_registry() {
    // A network where nobody created `perch/verifiers`.
    let env = fresh_env();
    let compiler = register_infra(&env);
    let verifier = env.register(PerchEd25519Verifier, ());
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let doc = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{{"id":"admin","verifier":"{}","verifier-name":"{ED}","key":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["admin"]}}}}]}}"#,
        strkey(&verifier),
        key_hex(&key)
    );
    assert!(verifier_registry(&env).executable().is_none());
    assert_eq!(
        PerchDocCompilerClient::new(&env, &compiler)
            .try_compile_doc(&Bytes::from_slice(&env, doc.as_bytes()))
            .err(),
        Some(Ok(DocCompilerError::DocInvalid))
    );
}

#[test]
fn the_real_registry_resolves_a_published_name() {
    let env = fresh_env();
    let compiler = register_infra(&env);
    let manager = Address::generate(&env);
    let registry = verifier_registry(&env);
    env.register_at(
        &registry,
        ConstructorlessRegistry,
        (
            Address::generate(&env),
            manager.clone(),
            Address::generate(&env),
        ),
    );
    let reg = ConstructorlessRegistryClient::new(&env, &registry);
    // The registry's own publish and content-addressed deploy.
    let hash = env.upload(PerchEd25519Verifier);
    let (name, version) = perch_ir::parse_verifier_name(ED).unwrap();
    let (name, version) = (
        SString::from_str(&env, name),
        SString::from_str(&env, version),
    );
    reg.publish_hash(&name, &manager, &hash, &version);
    let verifier = reg.deploy_stateless(&name, &Some(version.clone()), &None);
    assert!(is_verified_verifier(&env, &verifier));

    let key = SigningKey::from_bytes(&[4u8; 32]);
    let doc = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{{"id":"admin","verifier":"{}","verifier-name":"{ED}","key":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["admin"]}}}}]}}"#,
        strkey(&verifier),
        key_hex(&key)
    );
    let compile = |json: &str| {
        PerchDocCompilerClient::new(&env, &compiler)
            .try_compile_doc(&Bytes::from_slice(&env, json.as_bytes()))
    };
    let c = compile(&doc).unwrap().unwrap();
    assert_eq!(c.verifier_names, vec![&env, SString::from_str(&env, ED)]);
    // The registry's own refusal for a version it never published.
    assert_eq!(
        compile(&doc.replace(ED, "perch-ed25519-verifier@2.0.0")).err(),
        Some(Ok(DocCompilerError::DocInvalid))
    );
}

#[test]
fn an_admin_document_may_not_name_a_verifier_by_contract_id() {
    let w = world();
    let ci = SigningKey::from_bytes(&[7u8; 32]);
    // A raw signer in a contract-scoped rule of the account document, and one
    // declared and named by no rule.
    for doc in [
        w.admin_doc(&[w.raw("ci", &ci)], &[&w.target_rule(&["ci"])]),
        w.admin_doc(&[w.raw("ci", &ci)], &[]),
    ] {
        assert_eq!(w.compile(&doc).err(), Some(DocCompilerError::DocInvalid));
        assert_eq!(
            w.apply(&doc),
            Err(PerchAccountError::Compiler(DocCompilerError::DocInvalid))
        );
    }
    // The named verifier's own address, written without its name, is
    // unverified too: the name is what the document is reviewed by.
    let unnamed = w
        .admin_doc(&[], &[])
        .replace(&format!(r#","verifier-name":"{ED}""#), "");
    assert!(!unnamed.contains("verifier-name"));
    assert_eq!(
        w.compile(&unnamed).err(),
        Some(DocCompilerError::DocInvalid)
    );
    assert_eq!(w.client().applied_doc_hash(), None, "nothing applied");
}

#[test]
fn a_recovery_target_may_not_name_a_verifier_by_contract_id() {
    let w = world();
    let controller = Address::generate(&w.env);
    let guardian = Address::generate(&w.env);
    let recovery = format!(
        r#""recovery":{{"profile":"loss","mode":{{"type":"guardian-only","guardians":["{}"],"quorum":1}},"controller":"{}","replaceable":["admin"],"delay-ledgers":10,"expiry-ledgers":100,"max-cancels":3}}"#,
        strkey(&guardian),
        strkey(&controller)
    );
    let with_recovery =
        |doc: std::string::String| format!("{},{recovery}}}", doc.strip_suffix('}').unwrap());
    let source = with_recovery(w.admin_doc(&[], &[]));
    let compiler = PerchDocCompilerClient::new(&w.env, &w.compiler);
    assert!(compiler
        .try_compile_doc(&Bytes::from_slice(&w.env, source.as_bytes()))
        .is_ok());

    // A lost-key target keeps the replaced signer's verifier and its name.
    let new_key = SigningKey::from_bytes(&[8u8; 32]);
    let replace = |verifier: &Address| ReplacementSet {
        signers: vec![
            &w.env,
            Replacement {
                signer_id: SString::from_str(&w.env, "admin"),
                credential: Credential::External(verifier.clone(), pubkey(&w.env, &new_key).into()),
            },
        ],
        zk_enrollment: soroban_sdk::Vec::new(&w.env),
    };
    let bytes = Bytes::from_slice(&w.env, source.as_bytes());
    let target = compiler
        .try_derive_target(
            &bytes,
            &bytes,
            &RecoveryAction::LostKey,
            &replace(&w.verifier),
        )
        .unwrap()
        .unwrap();
    let mut text = std::vec![0u8; target.canonical.len() as usize];
    target.canonical.copy_into_slice(&mut text);
    let text = std::string::String::from_utf8(text).unwrap();
    assert!(
        text.contains(&format!(r#""verifier-name":"{ED}""#)),
        "{text}"
    );
    assert!(text.contains(&key_hex(&new_key)));

    // A compromise baseline naming a verifier by contract id cannot be a
    // target, nor can an enrolled document.
    let raw_baseline = w.admin_doc(&[w.raw("ci", &new_key)], &[&w.target_rule(&["ci"])]);
    assert_eq!(
        compiler
            .try_derive_target(
                &Bytes::from_slice(&w.env, raw_baseline.as_bytes()),
                &bytes,
                &RecoveryAction::Compromise,
                &ReplacementSet {
                    signers: soroban_sdk::Vec::new(&w.env),
                    zk_enrollment: soroban_sdk::Vec::new(&w.env),
                },
            )
            .err(),
        Some(Ok(DocCompilerError::DocInvalid))
    );
    let raw_enrolled = with_recovery(w.admin_doc(&[w.raw("ci", &new_key)], &[]));
    assert_eq!(
        w.compile(&raw_enrolled).err(),
        Some(DocCompilerError::DocInvalid)
    );
}

#[test]
fn a_grant_document_may_name_one_and_is_flagged() {
    let w = world();
    let (a, b) = (
        SigningKey::from_bytes(&[21u8; 32]),
        SigningKey::from_bytes(&[22u8; 32]),
    );
    let doc = w.grant_doc(
        &[w.raw("app", &a), w.named("named", &b)],
        &[r#"{"type":"threshold","signers":["app","named"],"m":1}"#],
    );
    let c = w.compile(&doc).unwrap();
    assert_eq!(c.unverified, vec![&w.env, w.raw.clone()]);
    assert_eq!(
        c.verifier_names,
        vec![
            &w.env,
            SString::from_str(&w.env, ""),
            SString::from_str(&w.env, ED)
        ]
    );
    assert_eq!(w.apply_grant(1, &doc), Ok(c.doc_hash));
    assert_eq!(
        w.client().grant_verifier_names(&1),
        Some(c.verifier_names.clone())
    );

    // A grant naming no verifier keeps no names.
    let unnamed = w.grant_doc(
        &[w.raw("app", &a)],
        &[r#"{"type":"all","signers":["app"]}"#],
    );
    let c = w.compile(&unnamed).unwrap();
    assert_eq!(c.unverified, vec![&w.env, w.raw.clone()]);
    w.apply_grant(2, &unnamed).unwrap();
    assert_eq!(
        w.client().grant_verifier_names(&2),
        Some(soroban_sdk::Vec::new(&w.env))
    );
}

#[test]
fn a_rule_holds_one_signer_per_unverified_verifier() {
    let w = world();
    let (a, b) = (
        SigningKey::from_bytes(&[31u8; 32]),
        SigningKey::from_bytes(&[32u8; 32]),
    );
    let signers = [w.raw("a", &a), w.raw("b", &b)];
    // Two keys under one unverified verifier count once toward a threshold
    // only if the verifier is honest, so one rule may not hold both.
    for principals in [
        r#"{"type":"threshold","signers":["a","b"],"m":2}"#,
        r#"{"type":"all","signers":["a","b"]}"#,
    ] {
        let doc = w.grant_doc(&signers, &[principals]);
        assert_eq!(w.compile(&doc).err(), Some(DocCompilerError::DocInvalid));
        assert_eq!(
            w.apply_grant(1, &doc),
            Err(PerchAccountError::Compiler(DocCompilerError::DocInvalid))
        );
    }
    // One per rule is allowed.
    let split = w.grant_doc(
        &signers,
        &[
            r#"{"type":"all","signers":["a"]}"#,
            r#"{"type":"all","signers":["b"]}"#,
        ],
    );
    assert!(w.apply_grant(1, &split).is_ok());
    // Named signers under one verifier are not limited.
    let named = w.grant_doc(
        &[w.named("a", &a), w.named("b", &b)],
        &[r#"{"type":"all","signers":["a","b"]}"#],
    );
    assert!(w.apply_grant(2, &named).is_ok());
}

#[test]
fn a_repointed_name_leaves_an_applied_account_as_it_was() {
    let w = world();
    let doc = w.admin_doc(&[], &[]);
    let applied = w.apply(&doc).unwrap();
    let rules = w.client().rule_set();
    assert!(w.check_admin(&w.verifier, &w.admin_key, None));

    // The registry now answers the same name with a verifier that accepts
    // anything.
    let anything = verifiers::deploy(&w.env, AnyKeyVerifier);
    verifiers::name(&w.env, ED, &anything);

    // The account still holds, and calls, the verifier the name resolved to
    // when the document was applied.
    assert_eq!(w.client().applied_doc_hash(), Some(applied));
    assert_eq!(w.client().rule_set(), rules);
    assert!(w.check_admin(&w.verifier, &w.admin_key, None));
    assert!(!w.check_admin(&w.verifier, &w.admin_key, Some([0u8; 64])));
    assert!(!w.check_admin(&anything, &w.admin_key, Some([0u8; 64])));
    // Moving it is applying a document again, which now names another
    // contract than the one the name resolves to.
    assert_eq!(
        w.apply(&doc),
        Err(PerchAccountError::Compiler(DocCompilerError::DocInvalid))
    );
    assert_eq!(w.client().rule_set(), rules);
}

/// Construct an account with `signers` in a fresh world; `Err` with the
/// panic's message when the constructor refuses.
fn construct(
    signers: impl FnOnce(&Env) -> soroban_sdk::Vec<Signer>,
) -> Result<(), std::string::String> {
    let env = fresh_env();
    register_infra(&env);
    let signers = signers(&env);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.register(PerchAccount, (signers,));
    }))
    .map_err(|e| {
        e.downcast_ref::<std::string::String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

#[test]
fn creation_refuses_an_unverified_verifier() {
    let key = |env: &Env| -> Bytes { Bytes::from_array(env, &[5u8; 32]) };
    // Where `perch/verifiers` deploys it: admitted.
    assert!(construct(|env| vec![
        env,
        Signer::External(verifiers::deploy(env, PerchEd25519Verifier), key(env))
    ])
    .is_ok());
    // A delegated admin needs no verifier.
    assert!(construct(|env| vec![env, Signer::Delegated(Address::generate(env))]).is_ok());
    let code = format!(
        "Error(Contract, #{})",
        soroban_sdk::Error::from(PerchAccountError::UnverifiedVerifier).get_code()
    );
    for (what, signers) in [
        (
            "a verifier at an address of its own",
            Box::new(|env: &Env| {
                vec![
                    env,
                    Signer::External(env.register(PerchEd25519Verifier, ()), key(env)),
                ]
            }) as Box<dyn FnOnce(&Env) -> soroban_sdk::Vec<Signer>>,
        ),
        (
            "an address with no contract",
            Box::new(|env: &Env| vec![env, Signer::External(Address::generate(env), key(env))]),
        ),
        (
            "an unverified signer beside a verified one",
            Box::new(|env: &Env| {
                vec![
                    env,
                    Signer::External(verifiers::deploy(env, PerchEd25519Verifier), key(env)),
                    Signer::External(env.register(AnyKeyVerifier, ()), key(env)),
                ]
            }),
        ),
    ] {
        let err = construct(signers).expect_err(what);
        assert!(err.contains(&code), "{what}: {err}");
    }
}

#[test]
fn the_factory_creates_only_what_an_admin_document_could_hold() {
    let env = fresh_env();
    register_infra(&env);
    // The factory deploys its pinned account hash; run this source's account
    // under it, and the WebAuthn verifier where the factory pins it.
    env.upload_at(pins::account::hash(&env), PerchAccount);
    let webauthn = verifiers::deploy_at_hash(
        &env,
        &pins::perch_webauthn_verifier::hash(&env),
        PerchWebAuthnVerifier,
    );
    assert_eq!(webauthn, pins::perch_webauthn_verifier::address(&env));
    let factory = PerchAccountFactoryClient::new(&env, &env.register(PerchAccountFactory, ()));
    assert_eq!(factory.webauthn_verifier(), webauthn);

    let passkey = Bytes::from_slice(&env, &SoftPasskey::from_seed([5u8; 32]).key_data());
    let account = factory.create_passkey(&BytesN::from_array(&env, &[1; 32]), &passkey);
    assert_eq!(
        PerchAccountClient::new(&env, &account)
            .rule_set()
            .get_unchecked(0)
            .signers,
        vec![&env, factory.passkey_signer(&passkey)]
    );

    let raw = env.register(PerchEd25519Verifier, ());
    let refused = factory.try_create(
        &BytesN::from_array(&env, &[2; 32]),
        &vec![
            &env,
            Signer::External(raw, Bytes::from_array(&env, &[5u8; 32])),
        ],
    );
    assert!(refused.is_err(), "{refused:?}");
}

#[test]
fn a_grant_document_naming_verifiers_rebuilds_exactly() {
    let w = world();
    let keys: std::vec::Vec<SigningKey> = (40u8..43)
        .map(|s| SigningKey::from_bytes(&[s; 32]))
        .collect();
    let doc = w.grant_doc(
        &[
            w.named("a", &keys[0]),
            w.raw("b", &keys[1]),
            w.named("c", &keys[2]),
        ],
        &[
            r#"{"type":"threshold","signers":["a","b"],"m":1}"#,
            r#"{"type":"all","signers":["c"]}"#,
        ],
    );
    let hash = w.apply_grant(3, &doc).unwrap();
    let canonical = perch_ir::canonical_json(&perch_ir::from_json(&doc).unwrap());
    assert_eq!(hash.to_array(), sha256_hex(&canonical));
    assert_eq!(
        rebuild::grant_text(&w.env, &w.account, 3).unwrap(),
        canonical
    );
    // The same rules under the names read back in the wrong order rebuild
    // to another text, which the stored hash refuses.
    let mut st = rebuild::read(&w.env, &w.account, 3).unwrap().unwrap();
    st.verifier_names.swap(0, 1);
    assert!(rebuild::text(&w.env, &st).is_err());
}
