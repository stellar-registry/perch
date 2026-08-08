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
//! one `all` principals list
//! ([`ValidationError::DuplicatePrincipalSigner`]), and repeated values in a
//! `string-in` predicate ([`ValidationError::DuplicateStringInValue`]).

use crate::doc::{ArgPred, PolicyDoc, Principals, Rule, Scope};
use std::collections::HashSet;
use std::fmt;

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
    /// An `all` principals list is empty — that would mean "no signature
    /// required", which must be said explicitly via `self-authenticating`.
    EmptyPrincipalSigners {
        /// The offending rule name.
        rule: String,
    },
    /// An `all` principals list references the same signer id twice. The
    /// duplicate is meaningless (a signer cannot co-sign with itself) and
    /// suggests the author meant a different signer.
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
            E::EmptyRuleName { position } => {
                write!(f, "rule at position {position}: name is empty")
            }
            E::DuplicateRuleName { name } => write!(f, "duplicate rule name `{name}`"),
            E::InvalidContractAddress { rule, address } => write!(
                f,
                "rule `{rule}`: contract scope address `{address}` is not a C-address strkey"
            ),
            E::EmptyPrincipalSigners { rule } => {
                write!(f, "rule `{rule}`: `all` principals list is empty")
            }
            E::DuplicatePrincipalSigner { rule, id } => {
                write!(f, "rule `{rule}`: principals list repeats signer `{id}`")
            }
            E::UnknownSignerRef { rule, id } => {
                write!(f, "rule `{rule}`: references undeclared signer `{id}`")
            }
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
        }
    }
}

impl std::error::Error for ValidationError {}

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

    let mut seen_signer_ids: HashSet<&str> = HashSet::new();
    for (position, signer) in doc.signers.iter().enumerate() {
        if signer.id.is_empty() {
            errors.push(ValidationError::EmptySignerId { position });
        } else if !seen_signer_ids.insert(&signer.id) {
            errors.push(ValidationError::DuplicateSignerId {
                id: signer.id.clone(),
            });
        }
        match hex::decode(&signer.key) {
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
            }
        }
        if !is_contract_address_shape(&signer.verifier) {
            errors.push(ValidationError::InvalidVerifierAddress {
                id: signer.id.clone(),
                address: signer.verifier.clone(),
            });
        }
    }

    // All declared ids (duplicates included) are valid reference targets;
    // the duplication itself is already reported above.
    let declared: HashSet<&str> = doc.signers.iter().map(|s| s.id.as_str()).collect();

    let mut seen_rule_names: HashSet<&str> = HashSet::new();
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

/// Validate one rule's scope, principals, functions, args, and expiry.
fn validate_rule(rule: &Rule, declared: &HashSet<&str>, errors: &mut Vec<ValidationError>) {
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
            if all.signers.is_empty() {
                errors.push(ValidationError::EmptyPrincipalSigners { rule: name() });
            }
            let mut seen: HashSet<&str> = HashSet::new();
            for id in &all.signers {
                if !seen.insert(id) {
                    errors.push(ValidationError::DuplicatePrincipalSigner {
                        rule: name(),
                        id: id.clone(),
                    });
                }
                if !declared.contains(id.as_str()) {
                    errors.push(ValidationError::UnknownSignerRef {
                        rule: name(),
                        id: id.clone(),
                    });
                }
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
        let mut seen: HashSet<&str> = HashSet::new();
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
        let mut seen: HashSet<u32> = HashSet::new();
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
                    let mut seen: HashSet<&str> = HashSet::new();
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
}
