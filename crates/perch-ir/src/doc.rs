//! The policy document types.
//!
//! These are plain data types with no serialization framework attached: the
//! crate is serde-free so nothing can drag an `f64` into the on-chain wasm (the
//! Soroban VM rejects the wasm float feature outright, and serde's
//! internally-tagged-enum buffering carries an `f64` variant — see
//! [`crate::parse`]). The authoritative mapping between these types and JSON
//! lives entirely in [`crate::parse`] (reading) and [`crate::canon`] (writing).
//!
//! The wire surface, enforced there:
//!
//! - **Field names are kebab-case** throughout (`not-after-ledger`,
//!   `install-param-hex`), matching the kebab-case enum `type` tags so the
//!   document uses one consistent convention.
//! - **Unknown fields are rejected** anywhere in the tree. Tagged enums use an
//!   internal `"type"` tag; each variant is a newtype around a dedicated payload
//!   struct — empty for `self-admin` / `is-self` — so "no extra fields" is a
//!   uniform, per-object rule the parser applies even to the payload-less
//!   variants.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// A complete perch policy document — the reviewable artifact whose canonical
/// bytes are hashed by [`crate::doc_hash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDoc {
    /// Document format version. The only supported value is `1`;
    /// [`crate::from_json`] rejects anything else before looking at the rest
    /// of the document.
    pub version: u32,
    /// Optional network identifier (e.g. a network passphrase or short name).
    /// Omitted from the canonical form when `None`.
    pub network: Option<String>,
    /// Declared signers that rules may reference by id.
    pub signers: Vec<SignerDecl>,
    /// The policy rules. Order is preserved and significant to the hash.
    pub rules: Vec<Rule>,
    /// Opt-in account-recovery enrollment: restoring access after key loss, or
    /// an approved baseline after suspected admin compromise. Omitted from the
    /// canonical form when `None`, so a document that never enrolls recovery
    /// hashes exactly as it did before this field existed (see `CANONICAL.md`
    /// and the `ci-publish-recovery` conformance vector).
    pub recovery: Option<RecoveryConfig>,
}

/// A declared signer: an id local to the document plus how it authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerDecl {
    /// Document-local identifier rules use to reference this signer.
    /// Must be unique within the document.
    pub id: String,
    /// How this signer's authorization is verified on-chain.
    pub method: SignerMethod,
}

/// How a signer authenticates. Discriminated in JSON by field shape, not a
/// `type` tag: `{"verifier","key"}` is external, `{"address"}` is delegated —
/// anything else fails closed in [`crate::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerMethod {
    /// A raw key checked by a verifier contract (OZ `Signer::External`).
    External {
        /// Contract address (C-address strkey) of the verifier that checks
        /// this signer's signatures.
        verifier: String,
        /// Hex-encoded key material, opaque to perch and interpreted by the
        /// verifier. Decoded length must be 1..=256 bytes — the generous cap
        /// exists because commitment-style keys can be larger than raw curve
        /// points.
        key: String,
    },
    /// An address (G- or C-strkey) the host authenticates via CAP-0071
    /// authentication delegation (OZ `Signer::Delegated`): the delegate
    /// authorizes the same call tree inside the account's own auth entry.
    Delegated {
        /// The delegate's address (G… account or C… contract strkey).
        address: String,
    },
}

/// A single policy rule: who ([`Principals`]) may do what
/// ([`Rule::functions`], [`Rule::args`]) where ([`Scope`]) until when
/// ([`Rule::not_after_ledger`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Human-readable rule name, unique within the document.
    pub name: String,
    /// Where the rule applies.
    pub scope: Scope,
    /// Who the rule authorizes.
    pub principals: Principals,
    /// If present, the allowlist of function names this rule covers.
    /// `None` means all functions in scope; an explicit empty list is
    /// rejected by validation as ambiguous. An explicit JSON `null` is rejected
    /// by [`crate::parse`] rather than treated as `None` — otherwise
    /// `"functions": null` would silently authorize every function.
    pub functions: Option<Vec<String>>,
    /// If present, constraints on call arguments, keyed by argument index.
    /// `None` means unconstrained; an explicit empty list is rejected by
    /// validation as ambiguous. An explicit `null` is rejected (see
    /// `functions`).
    pub args: Option<Vec<ArgConstraint>>,
    /// If present, the **ledger sequence** at or after which this rule stops
    /// authorizing — not a Unix timestamp. The unit is explicit in the name
    /// because both lowering targets compare against the current ledger
    /// sequence (`env.ledger().sequence()`), and a timestamp fits in `u32`
    /// too, so an unlabelled field silently produces a rule that never
    /// expires. Rule expiry lowers to OZ's native `ContextRule.valid_until`
    /// (enforced before any policy runs); in-program ledger predicates are
    /// reserved for windows *within* a live rule. Must be non-zero; omitted
    /// from the canonical form when `None`.
    pub not_after_ledger: Option<u32>,
    /// If present, a cumulative spend cap over a rolling window, enforced by a
    /// stateful sibling policy (OZ `spending_limit`) attached alongside the
    /// interpreter — perch itself is stateless (see the crate-level "Stateless,
    /// per-invocation semantics" section). Omitted from the canonical form when
    /// `None`, so documents without a cap hash exactly as before this field
    /// existed.
    pub cap: Option<CapConstraint>,
}

/// A cumulative spend cap on a [`Rule`], over a rolling window of ledgers.
///
/// Perch is stateless (an [`ArgPred`] bounds a single call, never a running
/// total), so a cumulative cap cannot live in the interpreter. It lowers to OZ's
/// `spending_limit` policy, attached to the same OZ context rule alongside
/// perch's interpreter; OZ enforces every attached policy (AND), so both the
/// per-call constraints and the cumulative cap must pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapConstraint {
    /// The token contract (C-address strkey) the cap is denominated in. If
    /// omitted, the rule's scope contract is used (the scope must then be a
    /// `contract` scope). Omitted from the canonical form when `None`.
    pub token: Option<String>,
    /// Maximum cumulative amount over the window, as a decimal string. A string,
    /// not a number, because the canonical form carries only `u32` numbers (see
    /// `CANONICAL.md`) and an `i128` amount does not fit a JSON number safely.
    /// Must parse as a positive `i128`.
    pub limit: String,
    /// Rolling-window length in ledgers. Must be non-zero.
    pub period_ledgers: u32,
}

/// Where a rule applies. Tagged with `"type"`: `"contract"` or `"self-admin"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Calls into one specific contract.
    Contract(ContractScope),
    /// Administrative operations on the smart account itself
    /// (signer/rule changes, upgrades).
    SelfAdmin(SelfAdminScope),
}

impl Scope {
    /// Convenience constructor for the `self-admin` scope.
    #[must_use]
    pub fn self_admin() -> Scope {
        Scope::SelfAdmin(SelfAdminScope {})
    }

    /// Convenience constructor for a `contract` scope.
    #[must_use]
    pub fn contract(address: impl Into<String>) -> Scope {
        Scope::Contract(ContractScope {
            address: address.into(),
        })
    }
}

/// Payload of [`Scope::Contract`]: the target contract address
/// (C-address strkey).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractScope {
    /// The contract the rule scopes to (C-address strkey).
    pub address: String,
}

/// Payload of [`Scope::SelfAdmin`]. Deliberately an empty struct rather than a
/// unit variant so the scope stays a JSON object whose only member is its
/// `type` tag; [`crate::parse`] rejects any extra sibling field beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfAdminScope {}

/// Who a rule authorizes. Tagged with `"type"`: `"all"`, `"threshold"`, or
/// `"self-authenticating"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principals {
    /// All of the referenced signers must authorize (list must be non-empty
    /// and reference declared signer ids). This is N-of-N: the equivalent of
    /// [`Principals::Threshold`] with `m == signers.len()`, kept as its own
    /// variant so a plain N-of-N rule reads (and hashes) as `all`.
    All(AllPrincipals),
    /// Any `m` of the referenced signers must authorize — an M-of-N quorum
    /// (`1 <= m <= signers.len()`). Lowers to the interpreter's
    /// `MinSigners(m)` op over the OZ-matched signer subset, so perch expresses
    /// the quorum itself with no external threshold policy. Because `m` can be
    /// below the signer count, this rule can never lower policy-free: it always
    /// attaches the interpreter, whose `MinSigners(m)` floor is the quorum
    /// (see the compiler's INV-1/INV-2 notes).
    Threshold(ThresholdPrincipals),
    /// No document signer signs at all: an external policy contract
    /// authenticates the invocation itself. Because this removes every
    /// signature check, the author must acknowledge it explicitly via
    /// [`SelfAuthenticatingPrincipals::ack`].
    SelfAuthenticating(SelfAuthenticatingPrincipals),
}

impl Principals {
    /// Convenience constructor for an `all` (N-of-N) principals list.
    #[must_use]
    pub fn all(signers: impl IntoIterator<Item = impl Into<String>>) -> Principals {
        Principals::All(AllPrincipals {
            signers: signers.into_iter().map(Into::into).collect(),
        })
    }

    /// Convenience constructor for a `threshold` (M-of-N) principals list.
    #[must_use]
    pub fn threshold(signers: impl IntoIterator<Item = impl Into<String>>, m: u32) -> Principals {
        Principals::Threshold(ThresholdPrincipals {
            signers: signers.into_iter().map(Into::into).collect(),
            m,
        })
    }
}

/// Payload of [`Principals::All`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllPrincipals {
    /// Ids of declared signers, all of which must authorize.
    pub signers: Vec<String>,
}

/// Payload of [`Principals::Threshold`]: an M-of-N quorum over declared signers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdPrincipals {
    /// Ids of declared signers the quorum draws from (the N). Must be
    /// non-empty, reference declared signer ids, and contain no id twice.
    pub signers: Vec<String>,
    /// How many of `signers` must authorize (the M). Validation requires
    /// `1 <= m <= signers.len()`: `m == 0` would authorize with no signatures
    /// (INV-1), and `m > N` could never be met.
    pub m: u32,
}

/// Payload of [`Principals::SelfAuthenticating`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfAuthenticatingPrincipals {
    /// The policy contract (C-address strkey) that authenticates invocations.
    pub policy: String,
    /// Hex-encoded install parameter passed to the policy (may be empty).
    pub install_param_hex: String,
    /// Must equal [`crate::ACK_SENTINEL`]
    /// (`"this-policy-authenticates-or-anyone-can-fire-this-rule"`) exactly,
    /// or validation fails. This forces the document author to spell out that
    /// the rule carries no signature check of its own.
    pub ack: String,
}

/// A constraint on one call argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgConstraint {
    /// Zero-based argument index. Unique within a rule's `args` list.
    pub index: u32,
    /// The predicate the argument must satisfy.
    pub pred: ArgPred,
}

/// Predicate over a single call argument. Tagged with `"type"`: `"is-self"`,
/// `"address-eq"`, `"string-in"`, `"string-prefix"`, or `"u32-eq"`.
///
/// Every predicate here is **stateless**: it constrains *this* invocation's
/// argument, never a running total across invocations. A numeric bound is a
/// per-call bound, not a cumulative cap — a signer authorized for "≤ X per
/// call" can call repeatedly and exceed any intended total. Cumulative limits
/// (spend caps, rate limits) are not expressible in perch and must be enforced
/// by a stateful sibling policy (e.g. OZ `spending_limit`) attached to the same
/// context rule. Keep this in mind before adding any amount-shaped predicate:
/// its bound is per-call, and the doc must not read as a spend cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgPred {
    /// The argument must be the smart account's own address.
    IsSelf(IsSelfPred),
    /// The argument must equal this address (C- or G-address strkey).
    AddressEq(AddressEqPred),
    /// The argument must be one of these strings (list must be non-empty).
    StringIn(StringInPred),
    /// The argument must be a string with this prefix.
    StringPrefix(StringPrefixPred),
    /// The argument must equal this u32.
    U32Eq(U32EqPred),
}

impl ArgPred {
    /// Convenience constructor for the `is-self` predicate.
    #[must_use]
    pub fn is_self() -> ArgPred {
        ArgPred::IsSelf(IsSelfPred {})
    }
}

/// Payload of [`ArgPred::IsSelf`]. Empty struct rather than a unit variant for
/// the same reason as [`SelfAdminScope`]: the predicate stays a JSON object
/// with only its `type` tag, and no stray sibling field is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsSelfPred {}

/// Payload of [`ArgPred::AddressEq`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressEqPred {
    /// The address the argument must equal (C- or G-address strkey).
    pub address: String,
}

/// Payload of [`ArgPred::StringIn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringInPred {
    /// The allowed string values (must be non-empty).
    pub values: Vec<String>,
}

/// Payload of [`ArgPred::StringPrefix`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringPrefixPred {
    /// The required string prefix.
    pub prefix: String,
}

/// Payload of [`ArgPred::U32Eq`]. Equality on a single call's argument — a
/// per-invocation check, never a cumulative counter (see [`ArgPred`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U32EqPred {
    /// The exact u32 value the argument must equal.
    pub value: u32,
}

/// Opt-in account-recovery enrollment. This is *reviewable configuration* —
/// who may recover this account and how — never the recovery attempt itself;
/// an attempt's target document and evidence are supplied when recovery
/// starts, not predeclared here. Full design rationale lives in
/// `docs/recovery/`.
///
/// The whole document's `doc_hash` already covers every field here (recovery
/// configuration is authority-bearing data like any other field), so no
/// separate top-level commitment is needed in the document itself. A deployed
/// recovery controller separately commits to its own `config_hash` scoped to
/// just the compiled form of this sub-object, for on-chain comparison without
/// re-hashing the whole document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryConfig {
    /// Who may change this configuration going forward. A `Protected`
    /// downgrade requires the currently enrolled recovery condition in
    /// addition to ordinary admin authorization; `Loss` does not. See
    /// `docs/recovery/controller-governance.md`.
    pub profile: RecoveryProfile,
    /// How a recovery attempt is authorized: guardians, ZK, or both against
    /// the same proposal. Carries the mode-specific configuration directly,
    /// so a `guardian-only` document has no ZK-shaped field anywhere to leave
    /// unset — guardian-only recovery requires no ZK machinery to exist,
    /// verify, or even compile in.
    pub mode: RecoveryMode,
    /// The recovery controller instance this account has adopted (a
    /// constructorless, immutable contract's address, C-address strkey).
    /// "Upgrading" the controller means adopting a different, newly deployed
    /// immutable instance here through a new applied document — never a code
    /// change at this address. See `docs/recovery/vk-and-controller-immutability.md`.
    pub controller: String,
    /// Commitment to the approved baseline document that suspected-compromise
    /// recovery restores. Required to enroll suspected-compromise recovery;
    /// `None` restricts enrollment to lost-key recovery only.
    pub baseline: Option<BaselineCommitment>,
    /// Which declared signer ids (`doc.signers[].id`) a recovery attempt may
    /// replace. Must be non-empty and reference declared signers — recovery
    /// enrolled with nothing to replace can never restore access.
    pub replaceable: Vec<String>,
    /// Minimum ledgers between an attempt becoming authorized (its evidence
    /// satisfied) and it becoming completable — the timelock window a
    /// legitimate owner has to notice and cancel. A ledger-sequence delta,
    /// like [`Rule::not_after_ledger`], not a duration in seconds. Must be
    /// non-zero.
    pub delay_ledgers: u32,
    /// Ledgers after an attempt becomes authorized at which it lapses back to
    /// requiring a fresh attempt (see `docs/recovery/` for the full state
    /// machine). Must be non-zero.
    pub expiry_ledgers: u32,
    /// Cap on cancellations across this account's lifetime, bounding a
    /// cancel-then-reattempt griefing cycle. Must be non-zero — a cap of zero
    /// would forbid cancellation entirely, contradicting the guarantee that
    /// the enrolled condition can always cancel a live attempt.
    pub max_cancels: u32,
    /// What happens to ordinary account-authorized execution while a recovery
    /// attempt is pending. Deliberately has **no default** and no third
    /// "unspecified" variant — every enrollment must name one explicitly.
    /// This remains a release-blocking, explicitly recorded open decision;
    /// see `docs/recovery/section-7-gate.md`. The field exists so the choice
    /// is reviewable, inspectable configuration — not a library default.
    pub pending_activity: PendingActivityPolicy,
}

/// Routine recovery-configuration change authority for a [`RecoveryConfig`].
/// Orthogonal to [`RecoveryMode`]: any mode may pair with either profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryProfile {
    /// Ordinary admin can change or disable recovery on its own. Recovers
    /// from accidental key loss while enrollment remains valid; makes no
    /// promise that a compromised admin cannot disable it.
    Loss,
    /// Ordinary admin plus the currently enrolled recovery condition are both
    /// required to change or disable recovery. A stolen admin key alone
    /// cannot downgrade or remove protection.
    Protected,
}

/// How a recovery attempt is authorized. Tagged with `"type"`:
/// `"guardian-only"`, `"zk-only"`, or `"combined"`. Combined requires *both*
/// factors against the same proposal, never either alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryMode {
    /// Guardian quorum only. No ZK secret, Merkle membership, or proof
    /// generation is involved anywhere in this mode.
    GuardianOnly(GuardianSet),
    /// Zero-knowledge proof only. No independent guardian defense exists
    /// against compromise of the ZK recovery factor in this mode.
    ZkOnly(ZkVerifierConfig),
    /// Both a valid proof and guardian quorum are required, checked against
    /// the same proposal.
    Combined(GuardianSet, ZkVerifierConfig),
}

/// An M-of-N guardian quorum: independent principals (not document signers)
/// that approve a recovery proposal by their own on-chain authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianSet {
    /// Guardian addresses (G- or C-address strkey). Must be non-empty and
    /// contain no address twice.
    pub guardians: Vec<String>,
    /// How many of `guardians` must authorize. Must satisfy
    /// `1 <= quorum <= guardians.len()`.
    pub quorum: u32,
}

/// The zero-knowledge factor of a [`RecoveryMode`]: which constructorless
/// verifier instance checks proofs, and which circuit/proof-format identity
/// that instance's immutable artifact commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkVerifierConfig {
    /// The verifier contract's address (C-address strkey). Constructorless
    /// and immutable: its code, and the verification key it embeds, never
    /// change at this address. An "upgrade" is enrolling a different, newly
    /// deployed verifier address here.
    pub verifier: String,
    /// Hex-encoded circuit/proof-format identity the verifier's immutable
    /// artifact commits to. Defense-in-depth binding: a proof for a
    /// different circuit cannot be substituted even if a verifier address
    /// were ever confused with another.
    pub circuit_id: String,
    /// A membership-pool contract's address (C-address strkey), for ZK
    /// schemes that prove membership of a secret in a set rather than
    /// knowledge of one fixed secret. `None` for schemes with no pool.
    pub pool: Option<String>,
}

/// Commitment to a previously-approved policy document that suspected-
/// compromise recovery restores (with designated credentials replaced).
///
/// Deliberately just a pointer to a *different* document's identity, never
/// the enclosing document's own hash, so the commitment cannot recursively
/// contain itself: the baseline this document points to was applied (and
/// hashed) before this document existed, and can never be this document. See
/// `docs/recovery/` (the "reviewable configuration without circular hashes"
/// requirement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineCommitment {
    /// Canonical `doc_hash` (lowercase hex) of the previously-applied policy
    /// document that suspected-compromise recovery restores. Declared,
    /// reviewer-checked data — not verified against on-chain history by the
    /// compiler, since accounts do not retain applied-document history (only
    /// the current `applied_doc_hash`). Reviewing that this hash names a
    /// real, previously-approved document is part of enrollment review.
    pub doc_hash: String,
}

/// Whether ordinary account-authorized execution continues, or is frozen,
/// while a recovery attempt is pending. There is deliberately no `Default`
/// impl and no third "unspecified" variant — every [`RecoveryConfig`] must
/// name one explicitly (enforced by [`crate::parse::from_json`] requiring the
/// field). See [`RecoveryConfig::pending_activity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingActivityPolicy {
    /// Ordinary account-authorized execution is blocked while an attempt is
    /// pending (from authorized evidence through completion, cancellation,
    /// or expiry).
    Freeze,
    /// Ordinary account-authorized execution continues unimpeded while an
    /// attempt is pending.
    Continue,
}
