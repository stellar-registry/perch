//! The perch document compiler: a **stateless** deployable contract that turns
//! a policy document's JSON bytes into compiled rules, the document's model,
//! and the canonical `doc_hash` — nothing else. It reads no storage and
//! writes no storage; constructorless, deployed once per network, immutable,
//! and shared by every perch account.
//!
//! The split keeps state and computation apart: this contract owns *parsing
//! and validating* (the JSON parser and the checks live here, in one audited
//! place), while the smart account owns *the policy documents* — the stored
//! rule set and the applied `doc_hash`. Accounts call [`compile_doc`] from
//! `apply_doc` and `apply_grant` and lower the returned model with
//! rule-core's `rule_eval::lower` to the rules they enforce, so account wasm
//! carries no parser at all, and this contract no rule lowering.
//!
//! Fail-closed at every step: non-UTF-8, unparseable, invalid, wrong-network,
//! or unlowerable documents are typed errors, never partial output.
//!
//! **Verifiers.** A signer's `verifier-name` (`<name>@<version>`) names a
//! verifier in Perch's managed `perch/verifiers` registry: the compiler
//! resolves it on-chain, `deployer(perch/verifiers, fetch_hash(name,
//! version))`, and refuses the document unless that is the signer's
//! `verifier`. A verifier named by its contract id alone is *unverified*:
//! refused in an account document (one with a self-admin rule or a recovery
//! member, which covers every recovery target), and in a grant document
//! allowed at most once per rule and listed in [`CompiledDoc::unverified`]
//! (`perch_ir::verifier`). Each refusal is `DocInvalid`, which keeps every
//! other code where it was.
//!
//! [`compile_doc`]: PerchDocCompiler::compile_doc
#![no_std]

extern crate alloc;

use perch_account_types::Signer;
use perch_recovery_interface::credential::{Credential, ReplacementSet};
use perch_recovery_interface::RecoveryAction;
pub use perch_rule_eval::CompiledModel;
use perch_rule_eval::ModelPrincipals;
use perch_rule_eval::StoredAuthRoot;
use soroban_sdk::{contractclient, contracttype, Address, Bytes, BytesN, Env, String, Vec};
use soroban_sdk_tools::scerr;

/// The compiled recovery wire types, defined once in
/// `perch-recovery-interface` and re-exported here for the compiler's
/// consumers.
pub use perch_recovery_interface::config::{
    CompiledGuardianSet, CompiledRecoveryConfig, CompiledRecoveryMode, CompiledZkFactor,
    RecoveryProfile,
};

#[cfg(feature = "contract")]
use perch_recovery_interface::config;
#[cfg(feature = "contract")]
mod stored;
#[cfg(feature = "contract")]
use soroban_sdk::{contract, contractimpl, IntoVal, Map, TryFromVal, Val};
#[cfg(feature = "contract")]
pub use stored::grant_stored_bytes;

/// Account-document caps (`docs/recovery/spec.md` §7.5): the compiler
/// refuses an account document (one with a self-admin rule or a recovery
/// member, `perch_ir::is_account_document`) with more declared signers, more
/// rules, or longer canonical bytes than these, on every `compile_doc` and
/// `derive_target`. They bound the worst-case recovery completion (every
/// removed credential revoked, every rule replaced or edited by
/// `apply_doc`'s diff). Sized against the measured budget
/// (`docs/recovery/budgets.md`, "Document caps"): the costliest document
/// they admit stays within 75% of every per-transaction limit through
/// enrollment, a lost-key or compromise completion, and a reconfiguration,
/// whatever a thief who held the owner key changed. The binding limit is
/// CPU instructions: a thief who keeps every rule's name and changes every
/// program, whose rules the reconcile edits in place. Written entries are
/// next. A grant document has its own caps, [`MAX_GRANT_SIGNERS`].
pub const MAX_DOC_SIGNERS: u32 = 8;
/// See [`MAX_DOC_SIGNERS`].
pub const MAX_DOC_RULES: u32 = 10;
/// See [`MAX_DOC_SIGNERS`].
pub const MAX_DOC_CANONICAL_BYTES: u32 = 8_192;
/// Grant-document caps: the compiler refuses a grant document (any document
/// that is not an account document) with more declared signers, more rules,
/// or longer canonical bytes than these, or whose stored entry would pass
/// [`MAX_GRANT_STORED_BYTES`]. A recovery never compiles or installs a grant
/// document: a completion advances one counter whatever grant documents the
/// account holds (`docs/recovery/budgets.md`, "Grant documents"), so these
/// bound only the grant flows themselves. Sized against the measured budget
/// (`docs/recovery/budgets.md`, "Grant-document caps"): every grant document
/// they admit stays within 75% of every per-transaction limit, and of the
/// ledger's per-entry limit, through `apply_grant` (adding, editing, or
/// replacing every rule, and over a grant document a recovery wiped),
/// `remove_grant`, `gc_grant`, and a capped transfer every signer of a
/// 15-signer rule signs. The rule cap is the most rules the byte cap holds
/// (50 one-signer rules in 8 078 bytes), where written entries, at 52%,
/// come closest to the line; rules naming more signers fit fewer, and
/// instructions stay below 44%. The signer cap is OZ's per-rule limit, so a
/// rule naming every declared signer still installs.
pub const MAX_GRANT_SIGNERS: u32 = 15;
/// See [`MAX_GRANT_SIGNERS`].
pub const MAX_GRANT_RULES: u32 = 50;
/// See [`MAX_GRANT_SIGNERS`].
pub const MAX_GRANT_CANONICAL_BYTES: u32 = 8_192;
/// The largest ledger entry a grant document may make its account store,
/// in bytes: 75% of the ledger's 65 536-byte
/// `max_contract_data_entry_size_bytes`. The entry is the account's record
/// of the grant document: its signer table, and every rule with its
/// conditions and their values ([`grant_stored_bytes`]). The compiler
/// refuses a grant document whose entry would be larger (`DocTooLarge`). No
/// document within the other grant caps reaches it (the largest, one
/// `string-in` of one-character values filling the byte cap, stores about a
/// third of the entry limit), so it bounds the entry whatever those caps
/// become.
pub const MAX_GRANT_STORED_BYTES: u32 = 49_152;
/// The longest rule name, in bytes: OZ's context-rule name limit. Checked
/// here so that a document that compiles also installs: a compromise
/// baseline is only published, never applied, until its recovery completes.
pub const MAX_RULE_NAME_BYTES: u32 = 20;

/// The most constraints one rule may carry, counting each argument
/// constraint, a `functions` list and an `auth-root` as one each. A rule with more is
/// refused (`DocCompile`). It bounds the conditions one stored rule holds,
/// and so the work of deciding it, at what an interpreter program holds: an
/// interpreter-attached rule's program is a signer floor, one leaf per
/// constraint and one `All`, within the interpreter's stack of 128 values.
pub const MAX_RULE_CONSTRAINTS: u32 = 127;

/// Everything `compile_doc` can refuse. (`#[scerr]` assigns sequential codes
/// from 1, in variant order.)
#[scerr]
pub enum DocCompilerError {
    /// The submitted document bytes are not UTF-8.
    DocNotUtf8,
    /// The document failed fail-closed parsing (unknown field, bad shape,
    /// unsupported version, duplicate key, …).
    DocParse,
    /// The document failed semantic validation (dangling signer ref,
    /// malformed address or key, ambiguous empty list, …) or names its
    /// verifiers as the compiler does not take.
    // An unverified verifier in an account document, two signers under one in
    // a rule, or a `verifier-name` that does not resolve to its `verifier`:
    // docs/account-interface.md, "Verifiers".
    DocInvalid,
    /// The document names no network, or a network that is not this chain.
    WrongNetwork,
    /// The document cannot be lowered to rules: a rule with
    /// self-authenticating principals, or too many constraints.
    // More than [`MAX_RULE_CONSTRAINTS`].
    DocCompile,
    /// The document exceeds a cap on signers, rules, bytes, or name length.
    // [`MAX_DOC_SIGNERS`], [`MAX_DOC_RULES`], [`MAX_DOC_CANONICAL_BYTES`] for
    // an account document, [`MAX_GRANT_SIGNERS`], [`MAX_GRANT_RULES`],
    // [`MAX_GRANT_CANONICAL_BYTES`] and [`MAX_GRANT_STORED_BYTES`] for a
    // grant document, and [`MAX_RULE_NAME_BYTES`] for both. One code for
    // every cap: the account numbers the compiler's errors into its own, so a
    // new one would renumber every account error after it.
    DocTooLarge,
    /// A signer's external `key` is not its verifier-canonical form.
    // Why the compiler refuses rather than canonicalizing:
    // docs/account-interface.md, "Errors".
    KeyNotCanonicalizable,
    /// `derive_target`: the current document enrolls no recovery.
    NotEnrolled,
    /// `derive_target`: the replacement set breaks spec §7.3 rules 1-3, or
    /// the action is not a recovery attempt.
    // docs/account-interface.md, "Errors".
    ReplacementRefused,
    /// `derive_target`: the ZK enrollment is missing, unexpected, or reuses
    /// the enrolled id.
    // Missing for a ZK mode, present for a guardian-only mode.
    ZkEnrollmentMismatch,
    /// `derive_target`: the target has no constraint-free self-admin rule
    /// with a signer (the anti-brick check).
    AdminLockout,
}

/// Where a compiled rule applies. `SelfAdmin` is account-agnostic: the
/// applying account resolves it to its own address.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum RuleScope {
    /// Calls to the applying account itself (`CallContract(self)`).
    SelfAdmin,
    /// Calls to this contract.
    Contract(Address),
}

/// One rule, compiled to the shapes OZ's `add_context_rule` takes: its
/// name, resolved scope, its principals' OZ `Signer`s in the order the
/// document names them, and its last ledger. OZ's context rule is the
/// registry of the rule's id and signers; what the rule allows is its
/// document rule in [`CompiledDoc::model`], at the same index, as rule-eval
/// lowers it.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledRule {
    /// The rule's name in the document. The account matches installed rules
    /// by name and scope.
    pub name: String,
    pub scope: RuleScope,
    pub auth_root: Option<Vec<StoredAuthRoot>>,
    /// The rule's signers, with external keys as declared (already
    /// verifier-canonical).
    pub signers: Vec<Signer>,
    /// The last ledger the rule authorizes, if bounded: OZ's inclusive
    /// `valid_until`, one below the document's `not-after-ledger`.
    pub valid_until: Option<u32>,
}

/// A compiled document: its canonical identity and the rules it becomes.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledDoc {
    /// `sha256(canonical bytes)` — the hash the reviewer approved. Formatting
    /// of the submitted JSON is irrelevant: a pretty-printed file and its
    /// minified twin compile to the same hash.
    pub doc_hash: BytesN<32>,
    /// The canonical bytes `doc_hash` is the hash of. The account stores
    /// them so anyone, including the recovery controller, can read back the
    /// full applied document.
    pub canonical: Bytes,
    /// The fingerprint (`perch_recovery_interface::credential::Credential::
    /// fingerprint`) of every declared signer's credential, with external
    /// keys canonicalized by their verifier. What revocation compares
    /// (spec §8).
    pub fingerprints: Vec<BytesN<32>>,
    /// One compiled rule per document rule, in the submitted order.
    pub rules: Vec<CompiledRule>,
    /// The compiled `recovery` member: zero or one entries (a `Vec` because
    /// `#[contracttype]` has no conversion for an `Option` of a custom struct;
    /// `Option<u32>` on [`CompiledRule::valid_until`] works because `u32` is
    /// a host type). Present ⇒ the document enrolls account recovery, and the
    /// applier syncs this configuration to the controller instance it names
    /// (`docs/recovery/`).
    pub recovery: Vec<CompiledRecoveryConfig>,
    /// The document as rule-core's lowering reads it (`rule_eval::Doc`, in
    /// host types): one entry. A `Vec` for the same reason as `recovery`.
    /// The applying account lowers it with `rule_eval::lower` and stores the
    /// result as its installed rules; `model.rules[i]` is `rules[i]`'s
    /// document rule.
    pub model: Vec<CompiledModel>,
    /// Whether the document is in normal form as far as its text shows
    /// (`perch_ir::normal_form`): then the rules an account stores for it,
    /// with its signer ids and [`Self::verifier_names`], give back its
    /// canonical text. An account refuses a scoped document that is not.
    pub normal_form: bool,
    /// Every verifier the document names by contract id alone, once each, in
    /// declaration order: what a wallet warns about ("it can approve anything
    /// this rule allows"). Always empty for an admin document, which may name
    /// none.
    pub unverified: Vec<Address>,
    /// One entry per declared signer, in declaration order: the
    /// `verifier-name` its verifier was resolved from, or empty for a
    /// delegated signer and a verifier named by contract id alone.
    pub verifier_names: Vec<String>,
}

/// What `derive_target` returns: the recovery target the controller binds
/// into an attempt's statement (spec §7.1).
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct DerivedTarget {
    /// The target's canonical bytes: exactly what the completing `apply_doc`
    /// must submit.
    pub canonical: Bytes,
    /// `sha256` of `canonical`: the target's `doc_hash`.
    pub doc_hash: BytesN<32>,
    /// The target's recovery `config_hash` (the current one, or the current
    /// one with the declared ZK rotation).
    pub config_hash: BytesN<32>,
    /// Fingerprints of every credential in the target (spec §7.3 rule 7).
    pub fingerprints: Vec<BytesN<32>>,
    /// The credentials occupying the replaced signer slots in the source:
    /// the applied document's for lost-key, the baseline's for compromise.
    /// External keys are canonicalized by their verifier, so a credential's
    /// `fingerprint` is the one revocation compares. The controller records
    /// them at T1 and the completion revokes them (spec §8).
    pub replaced: Vec<Credential>,
}

/// The document caps a compiler enforces, as [`PerchDocCompiler::limits`]
/// returns them. Versioned: a later budget (a complexity-weighted one, say)
/// is a new variant, which a consumer that does not know it refuses rather
/// than misreads.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DocLimits {
    V1(FlatDocLimits),
}

/// Flat per-document caps: [`MAX_DOC_SIGNERS`], [`MAX_DOC_RULES`],
/// [`MAX_DOC_CANONICAL_BYTES`], [`MAX_RULE_NAME_BYTES`] for an account
/// document, and the `MAX_GRANT_*` ones with the same name cap for a grant
/// document.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlatDocLimits {
    pub max_signers: u32,
    pub max_rules: u32,
    pub max_canonical_bytes: u32,
    pub max_rule_name_bytes: u32,
}

/// The caps this crate enforces on an account document.
pub fn doc_limits() -> FlatDocLimits {
    FlatDocLimits {
        max_signers: MAX_DOC_SIGNERS,
        max_rules: MAX_DOC_RULES,
        max_canonical_bytes: MAX_DOC_CANONICAL_BYTES,
        max_rule_name_bytes: MAX_RULE_NAME_BYTES,
    }
}

/// The caps this crate enforces on a grant document.
pub fn grant_limits() -> FlatDocLimits {
    FlatDocLimits {
        max_signers: MAX_GRANT_SIGNERS,
        max_rules: MAX_GRANT_RULES,
        max_canonical_bytes: MAX_GRANT_CANONICAL_BYTES,
        max_rule_name_bytes: MAX_RULE_NAME_BYTES,
    }
}

/// The caps `doc` is held to: an account document's
/// (`perch_ir::is_account_document`), or else a grant document's.
#[cfg(feature = "contract")]
pub fn limits_of(doc: &perch_ir::PolicyDoc) -> FlatDocLimits {
    if perch_ir::is_account_document(doc) {
        doc_limits()
    } else {
        grant_limits()
    }
}

/// The canonical form and fragment hashes a compiler produces, as
/// [`PerchDocCompiler::capabilities`] returns them.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilerCapabilities {
    /// The CANON version `doc_hash` is `sha256` of (`CANONICAL.md`).
    pub canon_version: u32,
    /// The domain tag of a rule's `rule_hash` (spec §3.2).
    pub rule_hash_tag: String,
    /// The domain tag of a recovery member's `config_hash` (spec §3.2).
    pub config_hash_tag: String,
}

/// Whether a compiled document keeps a constraint-free, never-expiring
/// self-admin rule with at least one signer — the anti-brick check every
/// applied document and every recovery target must pass, so the admin path
/// never depends on a constraint and never lapses. A constraint-free rule
/// has `all` principals and no `functions`, `args`, `auth-root` or `cap`: it allows every
/// function of the account to all of its signers. A `threshold` rule never
/// counts, even one asking all of its signers. A document whose model does
/// not match its rules one for one keeps none.
///
/// The surviving admin rule must have no `valid_until`: a self-admin rule
/// bounded by `not-after-ledger` is a latent brick — once its bound passes,
/// `apply_doc` can no longer be authorized through it and the account can
/// never be managed again (nor can a bounded rule even be reinstalled: OZ
/// refuses a past `valid_until`). A bounded self-admin rule is therefore
/// never a surviving admin rule, whether its bound is already past or still
/// in the future. This keeps the "a document that compiles also installs"
/// invariant sound alongside the install-time drop of dead bounded rules
/// (`perch-smart-account`'s `rules::desired`): that drop can never remove the
/// account's only admin rule, because an admin rule that could ever be
/// dropped fails this check first.
pub fn admin_survives(compiled: &CompiledDoc) -> bool {
    let Some(model) = compiled.model.first() else {
        return false;
    };
    if model.rules.len() != compiled.rules.len() {
        return false;
    }
    // Regression: integration-tests/tests/recovery_installability.rs.
    compiled.rules.iter().zip(model.rules.iter()).any(|(r, m)| {
        matches!(r.scope, RuleScope::SelfAdmin)
            && r.valid_until.is_none()
            && !r.signers.is_empty()
            && matches!(m.principals, ModelPrincipals::All(_))
            && m.functions.is_none()
            && m.args.is_none()
            && m.cap.is_empty()
            && m.auth_root.is_none()
            && r.auth_root.is_none()
    })
}

/// Cross-contract client, generated independently of the deployable so
/// consumers (smart accounts) link no compiler code at all — the account's
/// wasm carries neither the JSON parser nor the lowering logic.
#[allow(unused)]
#[contractclient(name = "DocCompilerClient")]
trait DocCompilerClientInterface {
    fn compile_doc(e: &Env, doc_json: Bytes) -> Result<CompiledDoc, DocCompilerError>;

    fn derive_target(
        e: &Env,
        source_json: Bytes,
        current_json: Bytes,
        action: RecoveryAction,
        replacements: ReplacementSet,
    ) -> Result<DerivedTarget, DocCompilerError>;
}

/// The key-canonicalization half of OZ's verifier interface. Declared here
/// (OZ's own client trait is private) with the same entry point OZ's
/// duplicate-signer check calls, so fingerprints and OZ agree on what one
/// physical key is.
#[cfg(feature = "contract")]
#[allow(unused)]
#[contractclient(name = "KeyCanonicalizerClient")]
trait KeyCanonicalizerInterface {
    fn batch_canonicalize_key(e: &Env, key_data: Vec<Val>) -> Vec<Bytes>;
}

/// The `perch/verifiers` registry's `Publishable::fetch_hash`: the wasm hash
/// published under a name and exact version.
#[cfg(feature = "contract")]
#[allow(unused)]
#[contractclient(name = "VerifierRegistryClient")]
trait VerifierRegistryInterface {
    fn fetch_hash(e: &Env, wasm_name: String, version: Option<String>) -> BytesN<32>;
}

/// The registry a `verifier-name` resolves in, derived under the ledger's
/// network from the committed `wasm/verifiers.path`.
#[cfg(feature = "contract")]
pub mod verifiers {
    perch_registry_resolve::registry_contract! {
        mod: registry,
        path_file: "wasm/verifiers.path",
    }
    pub use registry::registry;
}

#[cfg(feature = "contract")]
#[contract]
pub struct PerchDocCompiler;

#[cfg(feature = "contract")]
#[contractimpl]
impl PerchDocCompiler {
    /// JSON bytes in → compiled rules + canonical `doc_hash` out. Pure:
    /// no auth, no storage. The document must name THIS network (its
    /// `network` string must hash to the chain's network id), so a testnet
    /// document can never compile on mainnet or vice versa. It must also fit
    /// its caps ([`Self::limits`] for an account document,
    /// [`Self::grant_limits`] for a grant document), and every external signer key
    /// must already be its verifier-canonical form: the compiler calls each
    /// named verifier's `batch_canonicalize_key` to check.
    pub fn compile_doc(e: &Env, doc_json: Bytes) -> Result<CompiledDoc, DocCompilerError> {
        compile_parsed(e, &parse(&doc_json)?)
    }

    /// The `perch/verifiers` registry a `verifier-name` resolves in, on this
    /// network.
    pub fn verifier_registry(e: &Env) -> Address {
        verifiers::registry(e)
    }

    /// The caps every `compile_doc` and `derive_target` enforces on an
    /// account document: one with a self-admin rule or a recovery member,
    /// which is every document `apply_doc` applies and every recovery
    /// target.
    pub fn limits(_e: &Env) -> DocLimits {
        DocLimits::V1(doc_limits())
    }

    /// The caps `compile_doc` enforces on a grant document: one with no
    /// self-admin rule and no recovery member, which is every document
    /// `apply_grant` applies.
    pub fn grant_limits(_e: &Env) -> DocLimits {
        DocLimits::V1(grant_limits())
    }

    /// The CANON version and the fragment hash domain tags this compiler
    /// produces.
    pub fn capabilities(e: &Env) -> CompilerCapabilities {
        CompilerCapabilities {
            canon_version: perch_ir::CANON_VERSION,
            rule_hash_tag: String::from_bytes(e, perch_recovery_interface::fragment::RULE_DOMAIN),
            config_hash_tag: String::from_bytes(e, perch_recovery_interface::config::CONFIG_DOMAIN),
        }
    }

    /// Derive a recovery target (`docs/recovery/spec.md` §7): `source_json`
    /// is the account's applied document (lost-key) or the published
    /// baseline (compromise); `current_json` is the applied document, whose
    /// recovery member the target keeps. The target is the source with
    /// exactly the declared replacements and ZK rotation, then validated,
    /// network-bound, capped, compiled, and anti-brick-checked like any
    /// applied document. Pure: no auth, no storage. The controller calls it
    /// when an attempt begins, and completers simulate it to obtain the
    /// canonical bytes.
    pub fn derive_target(
        e: &Env,
        source_json: Bytes,
        current_json: Bytes,
        action: RecoveryAction,
        replacements: ReplacementSet,
    ) -> Result<DerivedTarget, DocCompilerError> {
        use perch_ir::recovery::{self, DeriveAction, DeriveError, Replacement, ZkRotation};

        let action = match action {
            RecoveryAction::LostKey => DeriveAction::LostKey,
            RecoveryAction::Compromise => DeriveAction::Compromise,
            _ => return Err(DocCompilerError::ReplacementRefused),
        };
        let source = parse(&source_json)?;
        let current = parse(&current_json)?;

        let mut declared = alloc::vec::Vec::new();
        for r in replacements.signers.iter() {
            declared.push(Replacement {
                signer_id: to_std_string(&r.signer_id),
                method: to_signer_method(&r.credential),
            });
        }
        let rotation = match replacements.zk_enrollment.len() {
            0 => None,
            1 => {
                let z = replacements.zk_enrollment.get_unchecked(0);
                Some(ZkRotation {
                    enrollment_id: hex::encode(z.id.to_array()),
                    commitment: hex::encode(z.commitment.to_array()),
                })
            }
            _ => return Err(DocCompilerError::ZkEnrollmentMismatch),
        };

        let target =
            recovery::derive_target(&source, &current, action, &declared, rotation.as_ref())
                .map_err(|err| match err {
                    DeriveError::NotEnrolled => DocCompilerError::NotEnrolled,
                    DeriveError::ZkEnrollmentMismatch => DocCompilerError::ZkEnrollmentMismatch,
                    _ => DocCompilerError::ReplacementRefused,
                })?;

        let compiled = compile_parsed(e, &target)?;
        if !admin_survives(&compiled) {
            return Err(DocCompilerError::AdminLockout);
        }
        let replaced_slots: alloc::vec::Vec<perch_ir::SignerDecl> = source
            .signers
            .iter()
            .filter(|s| declared.iter().any(|r| r.signer_id == s.id))
            .cloned()
            .collect();
        let config_hash = compiled
            .recovery
            .first()
            .map(|r| r.config_hash)
            .ok_or(DocCompilerError::NotEnrolled)?;
        Ok(DerivedTarget {
            canonical: compiled.canonical,
            doc_hash: compiled.doc_hash,
            config_hash,
            fingerprints: compiled.fingerprints,
            replaced: canonical_credentials(e, &replaced_slots)?,
        })
    }
}

/// Bytes → validated-shape document, fail closed.
#[cfg(feature = "contract")]
fn parse(doc_json: &Bytes) -> Result<perch_ir::PolicyDoc, DocCompilerError> {
    let mut buf = alloc::vec![0u8; doc_json.len() as usize];
    doc_json.copy_into_slice(&mut buf);
    let json = core::str::from_utf8(&buf).map_err(|_| DocCompilerError::DocNotUtf8)?;
    // Anything not understood is an error, never a skip.
    perch_ir::from_json(json).map_err(|_| DocCompilerError::DocParse)
}

/// Validate, network-bind, cap, compile, canonicalize, and fingerprint a
/// parsed document. Shared by `compile_doc` and `derive_target`, so a derived target
/// passes exactly the checks an applied document does.
#[cfg(feature = "contract")]
fn compile_parsed(e: &Env, doc: &perch_ir::PolicyDoc) -> Result<CompiledDoc, DocCompilerError> {
    perch_ir::validate(doc).map_err(|_| DocCompilerError::DocInvalid)?;

    let net = doc.network.as_ref().ok_or(DocCompilerError::WrongNetwork)?;
    let named: BytesN<32> = e
        .crypto()
        .sha256(&Bytes::from_slice(e, net.as_bytes()))
        .to_bytes();
    if named != e.ledger().network_id() {
        return Err(DocCompilerError::WrongNetwork);
    }

    let caps = limits_of(doc);
    if doc.signers.len() > caps.max_signers as usize
        || doc.rules.len() > caps.max_rules as usize
        || doc
            .rules
            .iter()
            .any(|r| r.name.len() > caps.max_rule_name_bytes as usize)
    {
        return Err(DocCompilerError::DocTooLarge);
    }
    if !perch_ir::is_account_document(doc) && grant_stored_bytes(doc) > MAX_GRANT_STORED_BYTES {
        return Err(DocCompilerError::DocTooLarge);
    }

    // Verifiers: none unverified in an account document, one signer per
    // unverified verifier in a rule, and every name resolved.
    if perch_ir::is_account_document(doc) && !perch_ir::unverified_verifiers(doc).is_empty() {
        return Err(DocCompilerError::DocInvalid);
    }
    if perch_ir::unverified_reuse(doc).is_some() {
        return Err(DocCompilerError::DocInvalid);
    }
    let verifier_names = resolve_verifier_names(e, &doc.signers)?;

    let mut rules: Vec<CompiledRule> = Vec::new(e);
    for rule in &doc.rules {
        rules.push_back(to_compiled(e, doc, rule)?);
    }
    let model = perch_rule_eval::model_of(e, doc).map_err(|_| DocCompilerError::DocCompile)?;

    let canonical_text = perch_ir::canonical_json(doc);
    if canonical_text.len() > caps.max_canonical_bytes as usize {
        return Err(DocCompilerError::DocTooLarge);
    }
    let canonical = Bytes::from_slice(e, canonical_text.as_bytes());
    let doc_hash: BytesN<32> = e.crypto().sha256(&canonical).to_bytes();

    let mut recovery: Vec<CompiledRecoveryConfig> = Vec::new(e);
    if let Some(r) = &doc.recovery {
        recovery.push_back(to_compiled_recovery(e, r)?);
    }

    Ok(CompiledDoc {
        doc_hash,
        canonical,
        fingerprints: fingerprints(e, &canonical_credentials(e, &doc.signers)?)?,
        rules,
        recovery,
        model: Vec::from_array(e, [model]),
        normal_form: perch_ir::normal_form(doc).is_ok(),
        unverified: {
            let mut out = Vec::new(e);
            for v in perch_ir::unverified_verifiers(doc) {
                out.push_back(Address::from_str(e, v));
            }
            out
        },
        verifier_names,
    })
}

/// Resolve every signer's `verifier-name` in `perch/verifiers`: the wasm
/// hash published under the name and exact version, whose content address
/// there must be the signer's `verifier` (`DocInvalid` otherwise). One
/// `fetch_hash` per distinct name. Returns each signer's name, empty where
/// it has none.
#[cfg(feature = "contract")]
fn resolve_verifier_names(
    e: &Env,
    signers: &[perch_ir::SignerDecl],
) -> Result<Vec<String>, DocCompilerError> {
    let mut resolved: Map<String, Address> = Map::new(e);
    let mut names = Vec::new(e);
    for s in signers {
        let perch_ir::SignerMethod::External {
            verifier,
            verifier_name: Some(full),
            ..
        } = &s.method
        else {
            names.push_back(String::from_str(e, ""));
            continue;
        };
        let full_name = String::from_str(e, full);
        let address = match resolved.get(full_name.clone()) {
            Some(address) => address,
            None => {
                let (name, version) =
                    perch_ir::parse_verifier_name(full).ok_or(DocCompilerError::DocInvalid)?;
                let registry = verifiers::registry(e);
                let hash = VerifierRegistryClient::new(e, &registry)
                    .try_fetch_hash(
                        &String::from_str(e, name),
                        &Some(String::from_str(e, version)),
                    )
                    .map_err(|_| DocCompilerError::DocInvalid)?
                    .map_err(|_| DocCompilerError::DocInvalid)?;
                let address = e.deployer().with_address(registry, hash).deployed_address();
                resolved.set(full_name.clone(), address.clone());
                address
            }
        };
        if address != Address::from_str(e, verifier) {
            return Err(DocCompilerError::DocInvalid);
        }
        names.push_back(full_name);
    }
    Ok(names)
}

/// The credentials `signers` declare, with every external key canonicalized
/// by its verifier (one batch call per verifier, the call OZ's duplicate
/// signer check makes), so a revoked key cannot return under another
/// encoding of the same key (spec §8).
#[cfg(feature = "contract")]
fn canonical_credentials(
    e: &Env,
    signers: &[perch_ir::SignerDecl],
) -> Result<Vec<Credential>, DocCompilerError> {
    // Batch external keys by verifier, remembering each signer's slot.
    let mut batches: Map<Address, Vec<Val>> = Map::new(e);
    let mut slots: alloc::vec::Vec<(Address, Option<u32>)> = alloc::vec::Vec::new();
    for s in signers {
        match &s.method {
            perch_ir::SignerMethod::Delegated { address } => {
                slots.push((Address::from_str(e, address), None));
            }
            perch_ir::SignerMethod::External { verifier, key, .. } => {
                let verifier = Address::from_str(e, verifier);
                let mut batch = batches.get(verifier.clone()).unwrap_or(Vec::new(e));
                slots.push((verifier.clone(), Some(batch.len())));
                batch.push_back(hex_bytes(e, key)?.into_val(e));
                batches.set(verifier, batch);
            }
        }
    }
    let mut canonical: Map<Address, Vec<Bytes>> = Map::new(e);
    for (verifier, batch) in batches.iter() {
        let keys = KeyCanonicalizerClient::new(e, &verifier)
            .try_batch_canonicalize_key(&batch)
            .map_err(|_| DocCompilerError::KeyNotCanonicalizable)?
            .map_err(|_| DocCompilerError::KeyNotCanonicalizable)?;
        if keys.len() != batch.len() {
            return Err(DocCompilerError::KeyNotCanonicalizable);
        }
        // Refuse a key that is not already its verifier-canonical form, rather
        // than silently canonicalizing it. The declared bytes are what the
        // document hash — and a recovery attempt's `replacements_hash` — bind;
        // a non-canonical spelling would bind bytes the installed (canonical)
        // credential ignores, and could hide a second signer that resolves to
        // the same physical key. CANON refuses non-canonical input.
        // Regression: integration-tests/tests/key_canonicalization.rs.
        for i in 0..batch.len() {
            let declared = Bytes::try_from_val(e, &batch.get_unchecked(i))
                .map_err(|_| DocCompilerError::KeyNotCanonicalizable)?;
            if declared != keys.get_unchecked(i) {
                return Err(DocCompilerError::KeyNotCanonicalizable);
            }
        }
        canonical.set(verifier, keys);
    }
    let mut out = Vec::new(e);
    for (address, slot) in slots {
        out.push_back(match slot {
            None => Credential::Delegated(address),
            Some(i) => {
                let key = canonical
                    .get(address.clone())
                    .and_then(|keys| keys.get(i))
                    .ok_or(DocCompilerError::KeyNotCanonicalizable)?;
                Credential::External(address, key)
            }
        });
    }
    Ok(out)
}

/// The fingerprint of each credential (what revocation compares).
#[cfg(feature = "contract")]
fn fingerprints(
    e: &Env,
    credentials: &Vec<Credential>,
) -> Result<Vec<BytesN<32>>, DocCompilerError> {
    let mut out = Vec::new(e);
    for c in credentials.iter() {
        out.push_back(c.fingerprint(e).map_err(|_| DocCompilerError::DocInvalid)?);
    }
    Ok(out)
}

/// A soroban `String` as an owned Rust string (signer ids are validated
/// UTF-8 by `perch_ir` once the target is re-validated).
#[cfg(feature = "contract")]
fn to_std_string(s: &String) -> alloc::string::String {
    let mut buf = alloc::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    alloc::string::String::from_utf8_lossy(&buf).into_owned()
}

/// The document spelling of a replacement credential: strkeys and lowercase
/// hex, exactly what `perch_ir` validates and canonicalizes.
#[cfg(feature = "contract")]
fn to_signer_method(c: &Credential) -> perch_ir::SignerMethod {
    match c {
        Credential::Delegated(address) => perch_ir::SignerMethod::Delegated {
            address: to_std_string(&address.to_string()),
        },
        Credential::External(verifier, key) => {
            let mut raw = alloc::vec![0u8; key.len() as usize];
            key.copy_into_slice(&mut raw);
            perch_ir::SignerMethod::External {
                verifier: to_std_string(&verifier.to_string()),
                key: hex::encode(raw),
                verifier_name: None,
            }
        }
    }
}

/// Lower a validated [`perch_ir::RecoveryConfig`] to its wire form, with its
/// `config_hash` (spec §3.2). Precondition: `perch_ir::validate` accepted the
/// document, so every address is shape-valid and every hex field is 32
/// bytes; the decodes below still fail closed.
#[cfg(feature = "contract")]
fn to_compiled_recovery(
    e: &Env,
    r: &perch_ir::RecoveryConfig,
) -> Result<CompiledRecoveryConfig, DocCompilerError> {
    let profile = match r.profile {
        perch_ir::RecoveryProfile::Loss => RecoveryProfile::Loss,
        perch_ir::RecoveryProfile::Protected => RecoveryProfile::Protected,
    };
    let mode = match &r.mode {
        perch_ir::RecoveryMode::GuardianOnly(g) => {
            CompiledRecoveryMode::GuardianOnly(to_compiled_guardian_set(e, g))
        }
        perch_ir::RecoveryMode::ZkOnly(z) => CompiledRecoveryMode::ZkOnly(to_compiled_zk(e, z)?),
        perch_ir::RecoveryMode::Combined(g, z) => {
            CompiledRecoveryMode::Combined(to_compiled_guardian_set(e, g), to_compiled_zk(e, z)?)
        }
    };
    let baseline = match &r.baseline {
        Some(b) => Some(hex_bytes_32(e, &b.doc_hash)?),
        None => None,
    };
    let mut replaceable: Vec<String> = Vec::new(e);
    for id in &r.replaceable {
        replaceable.push_back(String::from_str(e, id));
    }
    let canonical = Bytes::from_slice(e, perch_ir::recovery_canonical_json(r).as_bytes());
    Ok(CompiledRecoveryConfig {
        config_hash: config::config_hash(e, &canonical),
        profile,
        mode,
        controller: Address::from_str(e, &r.controller),
        baseline,
        replaceable,
        delay_ledgers: r.delay_ledgers,
        expiry_ledgers: r.expiry_ledgers,
        max_cancels: r.max_cancels,
    })
}

#[cfg(feature = "contract")]
fn to_compiled_guardian_set(e: &Env, g: &perch_ir::GuardianSet) -> CompiledGuardianSet {
    let mut guardians: Vec<Address> = Vec::new(e);
    for addr in &g.guardians {
        guardians.push_back(Address::from_str(e, addr));
    }
    CompiledGuardianSet {
        guardians,
        quorum: g.quorum,
    }
}

#[cfg(feature = "contract")]
fn to_compiled_zk(e: &Env, z: &perch_ir::ZkFactor) -> Result<CompiledZkFactor, DocCompilerError> {
    Ok(CompiledZkFactor {
        adapter: Address::from_str(e, &z.adapter),
        circuit_id: hex_bytes_32(e, &z.circuit_id)?,
        pool: Address::from_str(e, &z.pool),
        enrollment_id: hex_bytes_32(e, &z.enrollment_id)?,
        commitment: hex_bytes_32(e, &z.commitment)?,
    })
}

/// A validated document rule → wire rule (resolved soroban types). Refuses
/// self-authenticating principals and more than [`MAX_RULE_CONSTRAINTS`]
/// constraints (`DocCompile`).
#[cfg(feature = "contract")]
fn to_compiled(
    e: &Env,
    doc: &perch_ir::PolicyDoc,
    rule: &perch_ir::Rule,
) -> Result<CompiledRule, DocCompilerError> {
    let ids = match &rule.principals {
        perch_ir::Principals::All(p) => &p.signers,
        perch_ir::Principals::Threshold(p) => &p.signers,
        perch_ir::Principals::SelfAuthenticating(_) => return Err(DocCompilerError::DocCompile),
    };
    let constraints = rule.args.as_ref().map_or(0, |a| a.len())
        + usize::from(rule.functions.is_some())
        + usize::from(rule.auth_root.is_some());
    if constraints > MAX_RULE_CONSTRAINTS as usize {
        return Err(DocCompilerError::DocCompile);
    }
    let scope = match &rule.scope {
        perch_ir::Scope::SelfAdmin(_) => RuleScope::SelfAdmin,
        perch_ir::Scope::Contract(c) => RuleScope::Contract(Address::from_str(e, &c.address)),
    };
    let mut signers: Vec<Signer> = Vec::new(e);
    for id in ids {
        let decl = doc
            .signers
            .iter()
            .find(|s| &s.id == id)
            .ok_or(DocCompilerError::DocCompile)?;
        signers.push_back(match &decl.method {
            perch_ir::SignerMethod::Delegated { address } => {
                Signer::Delegated(Address::from_str(e, address))
            }
            perch_ir::SignerMethod::External { verifier, key, .. } => {
                Signer::External(Address::from_str(e, verifier), hex_bytes(e, key)?)
            }
        });
    }
    // `not-after-ledger` is the first ledger the rule no longer authorizes
    // in; validation makes it at least 1.
    let valid_until = match rule.not_after_ledger {
        Some(x) => Some(x.checked_sub(1).ok_or(DocCompilerError::DocInvalid)?),
        None => None,
    };
    Ok(CompiledRule {
        auth_root: rule.auth_root.as_ref().map(|root| {
            Vec::from_array(
                e,
                [StoredAuthRoot {
                    contract: Address::from_str(e, &root.contract),
                    function: soroban_sdk::Symbol::new(e, &root.function),
                }],
            )
        }),
        name: String::from_str(e, &rule.name),
        scope,
        signers,
        valid_until,
    })
}

/// Decode a validated hex key. Validation already guarantees hex; still fail
/// closed here rather than trust it.
#[cfg(feature = "contract")]
fn hex_bytes(e: &Env, s: &str) -> Result<Bytes, DocCompilerError> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err(DocCompilerError::DocInvalid);
    }
    let nib = |c: u8| -> Result<u8, DocCompilerError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(DocCompilerError::DocInvalid),
        }
    };
    let mut out = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((nib(b[i])? << 4) | nib(b[i + 1])?);
        i += 2;
    }
    Ok(Bytes::from_slice(e, &out))
}

/// Decode a validated 64-hex-character string (a SHA-256 digest, e.g. a
/// recovery baseline's `doc-hash`) into fixed 32 bytes. Validation already
/// guarantees the length and hex-ness; still fail closed here rather than
/// trust it.
#[cfg(feature = "contract")]
fn hex_bytes_32(e: &Env, s: &str) -> Result<BytesN<32>, DocCompilerError> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(DocCompilerError::DocInvalid);
    }
    let nib = |c: u8| -> Result<u8, DocCompilerError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(DocCompilerError::DocInvalid),
        }
    };
    let mut out = [0u8; 32];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Ok(BytesN::from_array(e, &out))
}

/// Test-only compilers whose document identity is not the CANON v1 bytes
/// digest, so tests can check that the controller and the account never
/// assume it is (`docs/recovery/spec.md` §6.3 T1, T5). Behind the
/// `testutils` feature; never built into a deployable.
#[cfg(all(feature = "contract", feature = "testutils"))]
pub mod testutils {
    use super::*;

    /// A stand-in for a structured (CANON v2) identity: a different function
    /// of the same canonical document. Its tag cannot begin a canonical
    /// document, so it never equals the bytes digest.
    fn stand_in_identity(e: &Env, canonical: &Bytes) -> BytesN<32> {
        let mut preimage = Bytes::from_slice(e, b"perch/doc/test-v2");
        preimage.append(canonical);
        e.crypto().sha256(&preimage).to_bytes()
    }

    /// The compiler with [`stand_in_identity`] as every document's identity,
    /// consistently across `compile_doc` and `derive_target`.
    #[contract]
    pub struct StandInIdentityCompiler;

    #[contractimpl]
    impl StandInIdentityCompiler {
        pub fn compile_doc(e: &Env, doc_json: Bytes) -> Result<CompiledDoc, DocCompilerError> {
            let mut compiled = PerchDocCompiler::compile_doc(e, doc_json)?;
            compiled.doc_hash = stand_in_identity(e, &compiled.canonical);
            Ok(compiled)
        }

        pub fn derive_target(
            e: &Env,
            source_json: Bytes,
            current_json: Bytes,
            action: RecoveryAction,
            replacements: ReplacementSet,
        ) -> Result<DerivedTarget, DocCompilerError> {
            let mut derived = PerchDocCompiler::derive_target(
                e,
                source_json,
                current_json,
                action,
                replacements,
            )?;
            derived.doc_hash = stand_in_identity(e, &derived.canonical);
            Ok(derived)
        }
    }

    /// A faulty compiler: `derive_target` returns an identity that does not
    /// name the bytes it returns; `compile_doc` is the real one.
    #[contract]
    pub struct InconsistentPairCompiler;

    #[contractimpl]
    impl InconsistentPairCompiler {
        pub fn compile_doc(e: &Env, doc_json: Bytes) -> Result<CompiledDoc, DocCompilerError> {
            PerchDocCompiler::compile_doc(e, doc_json)
        }

        pub fn derive_target(
            e: &Env,
            source_json: Bytes,
            current_json: Bytes,
            action: RecoveryAction,
            replacements: ReplacementSet,
        ) -> Result<DerivedTarget, DocCompilerError> {
            let mut derived = PerchDocCompiler::derive_target(
                e,
                source_json,
                current_json,
                action,
                replacements,
            )?;
            let mut preimage = Bytes::from_slice(e, b"perch/test/bad-pair");
            preimage.append(&derived.canonical);
            derived.doc_hash = e.crypto().sha256(&preimage).to_bytes();
            Ok(derived)
        }
    }
}
