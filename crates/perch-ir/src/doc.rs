//! The policy document types.
//!
//! Every struct and enum-variant payload carries `deny_unknown_fields`, so a
//! document containing any field this model does not know about fails to parse
//! anywhere in the tree. Tagged enums use an internal `"type"` tag with
//! kebab-case values; because serde's internally-tagged representation cannot
//! enforce `deny_unknown_fields` on struct or unit variants, every variant is a
//! newtype around a dedicated payload struct (empty for `self-admin` /
//! `is-self`) that does enforce it.
//!
//! JSON field names are kebab-case throughout (`not-after-ledger`,
//! `install-param-hex`), matching the kebab-case enum tags so the document
//! surface uses one consistent convention.

use serde::{Deserialize, Serialize};

/// A complete perch policy document — the reviewable artifact whose canonical
/// bytes are hashed by [`crate::doc_hash`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PolicyDoc {
    /// Document format version. The only supported value is `1`;
    /// [`crate::from_json`] rejects anything else before looking at the rest
    /// of the document.
    pub version: u32,
    /// Optional network identifier (e.g. a network passphrase or short name).
    /// Omitted from the canonical form when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Declared signers that rules may reference by id.
    pub signers: Vec<SignerDecl>,
    /// The policy rules. Order is preserved and significant to the hash.
    pub rules: Vec<Rule>,
}

/// A declared signer: an id local to the document, the verifier contract that
/// checks its signatures, and the verifier-defined key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SignerDecl {
    /// Document-local identifier rules use to reference this signer.
    /// Must be unique within the document.
    pub id: String,
    /// Contract address (C-address strkey) of the verifier that checks this
    /// signer's signatures.
    pub verifier: String,
    /// Hex-encoded key material, opaque to perch and interpreted by the
    /// verifier. Decoded length must be 1..=256 bytes — the generous cap
    /// exists because commitment-style keys can be larger than raw curve
    /// points.
    pub key: String,
}

/// A single policy rule: who ([`Principals`]) may do what
/// ([`Rule::functions`], [`Rule::args`]) where ([`Scope`]) until when
/// ([`Rule::not_after_ledger`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Rule {
    /// Human-readable rule name, unique within the document.
    pub name: String,
    /// Where the rule applies.
    pub scope: Scope,
    /// Who the rule authorizes.
    pub principals: Principals,
    /// If present, the allowlist of function names this rule covers.
    /// `None` means all functions in scope; an explicit empty list is
    /// rejected by validation as ambiguous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<String>>,
    /// If present, constraints on call arguments, keyed by argument index.
    /// `None` means unconstrained; an explicit empty list is rejected by
    /// validation as ambiguous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_ledger: Option<u32>,
}

/// Where a rule applies. Tagged with `"type"`: `"contract"` or `"self-admin"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ContractScope {
    /// The contract the rule scopes to (C-address strkey).
    pub address: String,
}

/// Payload of [`Scope::SelfAdmin`]. Deliberately an empty struct rather than a
/// unit variant: serde's internally-tagged unit variants silently accept extra
/// sibling fields, which would break the fail-closed guarantee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAdminScope {}

/// Who a rule authorizes. Tagged with `"type"`: `"all"` or
/// `"self-authenticating"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Principals {
    /// All of the referenced signers must authorize (list must be non-empty
    /// and reference declared signer ids).
    All(AllPrincipals),
    /// No document signer signs at all: an external policy contract
    /// authenticates the invocation itself. Because this removes every
    /// signature check, the author must acknowledge it explicitly via
    /// [`SelfAuthenticatingPrincipals::ack`].
    SelfAuthenticating(SelfAuthenticatingPrincipals),
}

/// Payload of [`Principals::All`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AllPrincipals {
    /// Ids of declared signers, all of which must authorize.
    pub signers: Vec<String>,
}

/// Payload of [`Principals::SelfAuthenticating`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ArgConstraint {
    /// Zero-based argument index. Unique within a rule's `args` list.
    pub index: u32,
    /// The predicate the argument must satisfy.
    pub pred: ArgPred,
}

/// Predicate over a single call argument. Tagged with `"type"`: `"is-self"`,
/// `"address-eq"`, `"string-in"`, `"string-prefix"`, or `"u32-eq"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
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
/// the same fail-closed reason as [`SelfAdminScope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsSelfPred {}

/// Payload of [`ArgPred::AddressEq`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AddressEqPred {
    /// The address the argument must equal (C- or G-address strkey).
    pub address: String,
}

/// Payload of [`ArgPred::StringIn`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct StringInPred {
    /// The allowed string values (must be non-empty).
    pub values: Vec<String>,
}

/// Payload of [`ArgPred::StringPrefix`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct StringPrefixPred {
    /// The required string prefix.
    pub prefix: String,
}

/// Payload of [`ArgPred::U32Eq`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct U32EqPred {
    /// The exact u32 value the argument must equal.
    pub value: u32,
}
