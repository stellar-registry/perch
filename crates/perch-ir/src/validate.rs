//! Semantic validation of parsed policy documents.
//!
//! [`validate`] collects **all** violations rather than stopping at the first,
//! so a review tool can show the complete list in one pass. Every error names
//! the offending signer or rule.
//!
//! Address checks are *structural* strkey shape checks only (leading version
//! letter, base32 charset, length 56); the CRC16 checksum is deliberately not
//! verified here — full checksum validation belongs to the layer that actually
//! touches the network, and skipping it keeps this crate dependency-light.
//! This is noted per-variant below.
//!
//! Beyond the spec's enumerated checks, the same fail-closed rationale is
//! applied to a few additional ambiguity/sloppiness cases: empty signer ids
//! ([`ValidationError::EmptySignerId`]), empty rule names
//! ([`ValidationError::EmptyRuleName`]), repeated signer references within
//! an `all` or `threshold` principals list
//! ([`ValidationError::DuplicatePrincipalSigner`]), and repeated values in a
//! `string-in` predicate ([`ValidationError::DuplicateStringInValue`]).

use crate::doc::{ArgPred, PolicyDoc, Principals, Rule, Scope, SignerMethod};
use alloc::collections::{btree_map::Entry, BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

/// The exact acknowledgement sentinel required in
/// [`crate::SelfAuthenticatingPrincipals::ack`].
pub const ACK_SENTINEL: &str = "this-policy-authenticates-or-anyone-can-fire-this-rule";

/// Maximum decoded length, in bytes, of a signer key. Generous because keys
/// are verifier-defined opaque bytes and commitment-style keys can be large.
pub const MAX_SIGNER_KEY_LEN: usize = 256;

/// A single semantic violation found by [`validate`]. Each variant names the
/// signer or rule it concerns; `Display` renders a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// `doc.version` is not `1`. ([`crate::from_json`] already rejects this at
    /// parse time; this catches documents built in code.)
    UnsupportedVersion {
        /// The version the document declared.
        version: u32,
    },
    /// A signer's `id` is the empty string. Empty ids make principal
    /// references unreadable and are almost certainly authoring mistakes.
    EmptySignerId {
        /// The zero-based position of the offending signer in `doc.signers`.
        position: usize,
    },
    /// Two signers share the same id.
    DuplicateSignerId {
        /// The duplicated signer id.
        id: String,
    },
    /// Two signers with distinct ids resolve to the same physical key: same
    /// verifier and same decoded key material. This reads to a reviewer as
    /// two independent signers (e.g. a 2-of-2 rule) but is one key, so the
    /// rule's real threshold is lower than it appears. Compared on decoded
    /// bytes, so hex case does not hide the collision.
    DuplicateSignerKey {
        /// The later signer id that duplicates an earlier one's key.
        id: String,
        /// The earlier signer id sharing the same verifier and key.
        first_id: String,
    },
    /// A signer's `key` is not valid hex.
    InvalidSignerKeyHex {
        /// The offending signer id.
        id: String,
    },
    /// A signer's decoded key is empty or longer than
    /// [`MAX_SIGNER_KEY_LEN`] bytes.
    SignerKeyLength {
        /// The offending signer id.
        id: String,
        /// The decoded key length in bytes.
        len: usize,
    },
    /// A signer's `verifier` is not shaped like a C-address strkey
    /// (checksum not verified — see module docs).
    InvalidVerifierAddress {
        /// The offending signer id.
        id: String,
        /// The malformed address string.
        address: String,
    },
    /// A delegated signer's `address` is not shaped like a G- or C-address
    /// strkey (checksum not verified — see module docs).
    InvalidDelegatedAddress {
        /// The offending signer id.
        id: String,
        /// The malformed address string.
        address: String,
    },
    /// A rule's `name` is the empty string. Every other error names the
    /// offending rule, so a nameless rule would make reports unreadable.
    EmptyRuleName {
        /// The zero-based position of the offending rule in `doc.rules`.
        position: usize,
    },
    /// Two rules share the same name.
    DuplicateRuleName {
        /// The duplicated rule name.
        name: String,
    },
    /// A `contract` scope address is not shaped like a C-address strkey
    /// (checksum not verified — see module docs).
    InvalidContractAddress {
        /// The offending rule name.
        rule: String,
        /// The malformed address string.
        address: String,
    },
    /// An `all` or `threshold` principals list is empty — that would mean "no
    /// signature required", which must be said explicitly via
    /// `self-authenticating`.
    EmptyPrincipalSigners {
        /// The offending rule name.
        rule: String,
    },
    /// An `all` or `threshold` principals list references the same signer id
    /// twice. The duplicate is meaningless (a signer cannot co-sign with
    /// itself), and in a `threshold` rule it silently lowers the real quorum,
    /// so it is rejected.
    DuplicatePrincipalSigner {
        /// The offending rule name.
        rule: String,
        /// The duplicated signer id.
        id: String,
    },
    /// A principals list references a signer id that is not declared.
    UnknownSignerRef {
        /// The offending rule name.
        rule: String,
        /// The undeclared signer id that was referenced.
        id: String,
    },
    /// A `threshold` principals `m` is out of range. `m` must satisfy
    /// `1 <= m <= signers.len()`: `m == 0` would authorize with no signatures
    /// (INV-1), and an `m` above the referenced signer count can never be met.
    InvalidThreshold {
        /// The offending rule name.
        rule: String,
        /// The declared threshold `m`.
        m: u32,
        /// The referenced signer count (the N).
        n: u32,
    },
    /// A `self-authenticating` rule's `ack` is not exactly [`ACK_SENTINEL`].
    WrongAckSentinel {
        /// The offending rule name.
        rule: String,
    },
    /// A `self-authenticating` rule's `policy` is not shaped like a C-address
    /// strkey (checksum not verified — see module docs).
    InvalidPolicyAddress {
        /// The offending rule name.
        rule: String,
        /// The malformed address string.
        address: String,
    },
    /// A `self-authenticating` rule's `install-param-hex` is not valid hex
    /// (empty is allowed).
    InvalidInstallParamHex {
        /// The offending rule name.
        rule: String,
    },
    /// A rule's `functions` list is present but empty — ambiguous between
    /// "no functions" and "all functions", so rejected. Omit the field to
    /// mean "all functions".
    EmptyFunctions {
        /// The offending rule name.
        rule: String,
    },
    /// A rule's `functions` list contains an empty string.
    EmptyFunctionName {
        /// The offending rule name.
        rule: String,
    },
    /// A rule's `functions` list contains a duplicate name.
    DuplicateFunction {
        /// The offending rule name.
        rule: String,
        /// The duplicated function name.
        name: String,
    },
    /// A rule's `args` list is present but empty — ambiguous for the same
    /// reason as [`ValidationError::EmptyFunctions`]. Omit the field to mean
    /// "unconstrained".
    EmptyArgs {
        /// The offending rule name.
        rule: String,
    },
    /// A rule constrains the same argument index twice.
    DuplicateArgIndex {
        /// The offending rule name.
        rule: String,
        /// The duplicated argument index.
        index: u32,
    },
    /// A `string-in` predicate has an empty `values` list, which can never
    /// match.
    EmptyStringInValues {
        /// The offending rule name.
        rule: String,
        /// The argument index the predicate applies to.
        index: u32,
    },
    /// A `string-in` predicate lists the same value twice. The duplicate is
    /// meaningless and suggests a copy-paste mistake.
    DuplicateStringInValue {
        /// The offending rule name.
        rule: String,
        /// The argument index the predicate applies to.
        index: u32,
        /// The duplicated value.
        value: String,
    },
    /// An `address-eq` predicate's address is not shaped like a C- or
    /// G-address strkey (checksum not verified — see module docs).
    InvalidArgAddress {
        /// The offending rule name.
        rule: String,
        /// The argument index the predicate applies to.
        index: u32,
        /// The malformed address string.
        address: String,
    },
    /// A rule's `not-after-ledger` is `0`, which would make the rule dead on
    /// arrival. Omit the field for "no expiry".
    ZeroNotAfterLedger {
        /// The offending rule name.
        rule: String,
    },
    /// A `cap`'s `limit` does not parse as a positive `i128`.
    InvalidCapLimit {
        /// The offending rule name.
        rule: String,
        /// The malformed limit string.
        limit: String,
    },
    /// A `cap`'s `period-ledgers` is `0`, which the OZ spending-limit policy
    /// rejects on install.
    ZeroCapPeriod {
        /// The offending rule name.
        rule: String,
    },
    /// A `cap`'s `token` is present but not shaped like a C-address strkey
    /// (checksum not verified — see module docs).
    InvalidCapToken {
        /// The offending rule name.
        rule: String,
        /// The malformed token address string.
        address: String,
    },
    /// A `cap` omits `token` on a non-`contract` scope, so there is no token to
    /// denominate the cap in. Give the cap an explicit `token`.
    CapWithoutToken {
        /// The offending rule name.
        rule: String,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ValidationError as E;
        match self {
            E::UnsupportedVersion { version } => {
                write!(f, "unsupported document version {version} (expected 1)")
            }
            E::EmptySignerId { position } => {
                write!(f, "signer at position {position}: id is empty")
            }
            E::DuplicateSignerId { id } => write!(f, "duplicate signer id `{id}`"),
            E::DuplicateSignerKey { id, first_id } => write!(
                f,
                "signer `{id}` shares verifier and key material with `{first_id}` (same physical key under two ids)"
            ),
            E::InvalidSignerKeyHex { id } => {
                write!(f, "signer `{id}`: key is not valid hex")
            }
            E::SignerKeyLength { id, len } => write!(
                f,
                "signer `{id}`: decoded key length {len} outside 1..={MAX_SIGNER_KEY_LEN} bytes"
            ),
            E::InvalidVerifierAddress { id, address } => write!(
                f,
                "signer `{id}`: verifier `{address}` is not a C-address strkey"
            ),
            E::InvalidDelegatedAddress { id, address } => write!(
                f,
                "signer `{id}`: delegated address `{address}` is not a G- or C-address strkey"
            ),
            E::EmptyRuleName { position } => {
                write!(f, "rule at position {position}: name is empty")
            }
            E::DuplicateRuleName { name } => write!(f, "duplicate rule name `{name}`"),
            E::InvalidContractAddress { rule, address } => write!(
                f,
                "rule `{rule}`: contract scope address `{address}` is not a C-address strkey"
            ),
            E::EmptyPrincipalSigners { rule } => {
                write!(f, "rule `{rule}`: principals list is empty")
            }
            E::DuplicatePrincipalSigner { rule, id } => {
                write!(f, "rule `{rule}`: principals list repeats signer `{id}`")
            }
            E::UnknownSignerRef { rule, id } => {
                write!(f, "rule `{rule}`: references undeclared signer `{id}`")
            }
            E::InvalidThreshold { rule, m, n } => write!(
                f,
                "rule `{rule}`: threshold m={m} out of range 1..={n} (referenced signer count)"
            ),
            E::WrongAckSentinel { rule } => write!(
                f,
                "rule `{rule}`: self-authenticating ack must be exactly `{ACK_SENTINEL}`"
            ),
            E::InvalidPolicyAddress { rule, address } => write!(
                f,
                "rule `{rule}`: policy `{address}` is not a C-address strkey"
            ),
            E::InvalidInstallParamHex { rule } => {
                write!(f, "rule `{rule}`: install-param-hex is not valid hex")
            }
            E::EmptyFunctions { rule } => write!(
                f,
                "rule `{rule}`: functions list is present but empty (omit it for all functions)"
            ),
            E::EmptyFunctionName { rule } => {
                write!(f, "rule `{rule}`: functions list contains an empty name")
            }
            E::DuplicateFunction { rule, name } => {
                write!(f, "rule `{rule}`: duplicate function `{name}`")
            }
            E::EmptyArgs { rule } => write!(
                f,
                "rule `{rule}`: args list is present but empty (omit it for unconstrained)"
            ),
            E::DuplicateArgIndex { rule, index } => {
                write!(f, "rule `{rule}`: duplicate arg constraint for index {index}")
            }
            E::EmptyStringInValues { rule, index } => write!(
                f,
                "rule `{rule}`: string-in at arg {index} has an empty values list"
            ),
            E::DuplicateStringInValue { rule, index, value } => write!(
                f,
                "rule `{rule}`: string-in at arg {index} repeats value `{value}`"
            ),
            E::InvalidArgAddress {
                rule,
                index,
                address,
            } => write!(
                f,
                "rule `{rule}`: address-eq at arg {index}: `{address}` is not a C- or G-address strkey"
            ),
            E::ZeroNotAfterLedger { rule } => {
                write!(
                    f,
                    "rule `{rule}`: not-after-ledger is 0 (omit it for no expiry)"
                )
            }
            E::InvalidCapLimit { rule, limit } => {
                write!(f, "rule `{rule}`: cap limit `{limit}` is not a positive i128")
            }
            E::ZeroCapPeriod { rule } => {
                write!(f, "rule `{rule}`: cap period-ledgers is 0")
            }
            E::InvalidCapToken { rule, address } => {
                write!(f, "rule `{rule}`: cap token `{address}` is not a C-address")
            }
            E::CapWithoutToken { rule } => write!(
                f,
                "rule `{rule}`: cap omits token on a non-contract scope (give it an explicit token)"
            ),
        }
    }
}

impl core::error::Error for ValidationError {}

/// Structural strkey shape check: length 56, base32 alphabet (`A-Z2-7`), and
/// a leading version letter from `leads`. Does **not** verify the CRC16
/// checksum (see module docs).
fn is_strkey_shape(s: &str, leads: &[u8]) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 56
        && leads.contains(&bytes[0])
        && bytes.iter().all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
}

/// Whether `s` is shaped like a contract address strkey (`C...`, 56 chars,
/// base32 alphabet). Checksum is not verified.
#[must_use]
pub fn is_contract_address_shape(s: &str) -> bool {
    is_strkey_shape(s, b"C")
}

/// Whether `s` is shaped like a contract (`C...`) or account (`G...`) address
/// strkey. Checksum is not verified.
#[must_use]
pub fn is_address_shape(s: &str) -> bool {
    is_strkey_shape(s, b"CG")
}

/// Validate a document, collecting **every** violation.
///
/// # Errors
///
/// Returns the complete list of [`ValidationError`]s if any check fails; the
/// list is never empty on `Err`.
pub fn validate(doc: &PolicyDoc) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if doc.version != 1 {
        errors.push(ValidationError::UnsupportedVersion {
            version: doc.version,
        });
    }

    let mut seen_signer_ids: BTreeSet<&str> = BTreeSet::new();
    // Keyed on (verifier, decoded key bytes) so the same physical key under
    // two ids is caught regardless of hex case; maps to the first id seen.
    let mut seen_key_material: BTreeMap<(&str, Vec<u8>), &str> = BTreeMap::new();
    // Delegated identity is the address itself; maps to the first id seen.
    let mut seen_delegated: BTreeMap<&str, &str> = BTreeMap::new();
    for (position, signer) in doc.signers.iter().enumerate() {
        if signer.id.is_empty() {
            errors.push(ValidationError::EmptySignerId { position });
        } else if !seen_signer_ids.insert(&signer.id) {
            errors.push(ValidationError::DuplicateSignerId {
                id: signer.id.clone(),
            });
        }
        match &signer.method {
            SignerMethod::External { verifier, key } => {
                match hex::decode(key) {
                    Err(_) => errors.push(ValidationError::InvalidSignerKeyHex {
                        id: signer.id.clone(),
                    }),
                    Ok(decoded) => {
                        if decoded.is_empty() || decoded.len() > MAX_SIGNER_KEY_LEN {
                            errors.push(ValidationError::SignerKeyLength {
                                id: signer.id.clone(),
                                len: decoded.len(),
                            });
                        }
                        match seen_key_material.entry((verifier, decoded)) {
                            Entry::Occupied(first) => {
                                errors.push(ValidationError::DuplicateSignerKey {
                                    id: signer.id.clone(),
                                    first_id: (*first.get()).to_string(),
                                });
                            }
                            Entry::Vacant(slot) => {
                                slot.insert(&signer.id);
                            }
                        }
                    }
                }
                if !is_contract_address_shape(verifier) {
                    errors.push(ValidationError::InvalidVerifierAddress {
                        id: signer.id.clone(),
                        address: verifier.clone(),
                    });
                }
            }
            SignerMethod::Delegated { address } => {
                if !is_address_shape(address) {
                    errors.push(ValidationError::InvalidDelegatedAddress {
                        id: signer.id.clone(),
                        address: address.clone(),
                    });
                }
                // Same physical identity under two ids — the delegated
                // analogue of DuplicateSignerKey (an address IS the key).
                match seen_delegated.entry(address) {
                    Entry::Occupied(first) => {
                        errors.push(ValidationError::DuplicateSignerKey {
                            id: signer.id.clone(),
                            first_id: (*first.get()).to_string(),
                        });
                    }
                    Entry::Vacant(slot) => {
                        slot.insert(&signer.id);
                    }
                }
            }
        }
    }

    // All declared ids (duplicates included) are valid reference targets;
    // the duplication itself is already reported above.
    let declared: BTreeSet<&str> = doc.signers.iter().map(|s| s.id.as_str()).collect();

    let mut seen_rule_names: BTreeSet<&str> = BTreeSet::new();
    for (position, rule) in doc.rules.iter().enumerate() {
        if rule.name.is_empty() {
            errors.push(ValidationError::EmptyRuleName { position });
        } else if !seen_rule_names.insert(&rule.name) {
            errors.push(ValidationError::DuplicateRuleName {
                name: rule.name.clone(),
            });
        }
        validate_rule(rule, &declared, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Shared signer-list checks for `all` and `threshold` principals: the list is
/// non-empty, references no id twice, and every id is declared. A `threshold`
/// rule layers its `1 <= m <= N` range check on top of these.
fn validate_principal_signers(
    rule: &str,
    signers: &[String],
    declared: &BTreeSet<&str>,
    errors: &mut Vec<ValidationError>,
) {
    if signers.is_empty() {
        errors.push(ValidationError::EmptyPrincipalSigners {
            rule: rule.to_string(),
        });
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for id in signers {
        if !seen.insert(id) {
            errors.push(ValidationError::DuplicatePrincipalSigner {
                rule: rule.to_string(),
                id: id.clone(),
            });
        }
        if !declared.contains(id.as_str()) {
            errors.push(ValidationError::UnknownSignerRef {
                rule: rule.to_string(),
                id: id.clone(),
            });
        }
    }
}

/// Validate one rule's scope, principals, functions, args, and expiry.
fn validate_rule(rule: &Rule, declared: &BTreeSet<&str>, errors: &mut Vec<ValidationError>) {
    let name = || rule.name.clone();

    match &rule.scope {
        Scope::Contract(scope) => {
            if !is_contract_address_shape(&scope.address) {
                errors.push(ValidationError::InvalidContractAddress {
                    rule: name(),
                    address: scope.address.clone(),
                });
            }
        }
        Scope::SelfAdmin(_) => {}
    }

    match &rule.principals {
        Principals::All(all) => {
            validate_principal_signers(&rule.name, &all.signers, declared, errors);
        }
        Principals::Threshold(t) => {
            validate_principal_signers(&rule.name, &t.signers, declared, errors);
            // INV-1: `m` must be at least 1 (no zero-signature quorum) and at
            // most N (the referenced signer count), mirroring OZ
            // `simple_threshold`'s `1 <= M <= N` install invariant.
            if t.m == 0 || (t.m as usize) > t.signers.len() {
                errors.push(ValidationError::InvalidThreshold {
                    rule: name(),
                    m: t.m,
                    n: t.signers.len() as u32,
                });
            }
        }
        Principals::SelfAuthenticating(sa) => {
            if sa.ack != ACK_SENTINEL {
                errors.push(ValidationError::WrongAckSentinel { rule: name() });
            }
            if !is_contract_address_shape(&sa.policy) {
                errors.push(ValidationError::InvalidPolicyAddress {
                    rule: name(),
                    address: sa.policy.clone(),
                });
            }
            if hex::decode(&sa.install_param_hex).is_err() {
                errors.push(ValidationError::InvalidInstallParamHex { rule: name() });
            }
        }
    }

    if let Some(functions) = &rule.functions {
        if functions.is_empty() {
            errors.push(ValidationError::EmptyFunctions { rule: name() });
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for func in functions {
            if func.is_empty() {
                errors.push(ValidationError::EmptyFunctionName { rule: name() });
            }
            if !seen.insert(func) {
                errors.push(ValidationError::DuplicateFunction {
                    rule: name(),
                    name: func.clone(),
                });
            }
        }
    }

    if let Some(args) = &rule.args {
        if args.is_empty() {
            errors.push(ValidationError::EmptyArgs { rule: name() });
        }
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        for constraint in args {
            if !seen.insert(constraint.index) {
                errors.push(ValidationError::DuplicateArgIndex {
                    rule: name(),
                    index: constraint.index,
                });
            }
            match &constraint.pred {
                ArgPred::StringIn(pred) => {
                    if pred.values.is_empty() {
                        errors.push(ValidationError::EmptyStringInValues {
                            rule: name(),
                            index: constraint.index,
                        });
                    }
                    let mut seen: BTreeSet<&str> = BTreeSet::new();
                    for value in &pred.values {
                        if !seen.insert(value) {
                            errors.push(ValidationError::DuplicateStringInValue {
                                rule: name(),
                                index: constraint.index,
                                value: value.clone(),
                            });
                        }
                    }
                }
                ArgPred::AddressEq(pred) => {
                    if !is_address_shape(&pred.address) {
                        errors.push(ValidationError::InvalidArgAddress {
                            rule: name(),
                            index: constraint.index,
                            address: pred.address.clone(),
                        });
                    }
                }
                ArgPred::IsSelf(_) | ArgPred::StringPrefix(_) | ArgPred::U32Eq(_) => {}
            }
        }
    }

    if rule.not_after_ledger == Some(0) {
        errors.push(ValidationError::ZeroNotAfterLedger { rule: name() });
    }

    if let Some(cap) = &rule.cap {
        if cap.limit.parse::<i128>().map(|v| v <= 0).unwrap_or(true) {
            errors.push(ValidationError::InvalidCapLimit {
                rule: name(),
                limit: cap.limit.clone(),
            });
        }
        if cap.period_ledgers == 0 {
            errors.push(ValidationError::ZeroCapPeriod { rule: name() });
        }
        match &cap.token {
            Some(token) => {
                if !is_contract_address_shape(token) {
                    errors.push(ValidationError::InvalidCapToken {
                        rule: name(),
                        address: token.clone(),
                    });
                }
            }
            // No explicit token: the cap denominates in the scope contract, so
            // the scope must be a `contract` (not `self-admin`).
            None => {
                if !matches!(rule.scope, Scope::Contract(_)) {
                    errors.push(ValidationError::CapWithoutToken { rule: name() });
                }
            }
        }
    }
}
