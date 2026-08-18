//! Fail-closed JSON parsing for policy documents.
//!
//! [`from_json`] is the only supported way to read a document from bytes.
//! It rejects, in order:
//!
//! 1. malformed JSON ([`ParseError::Json`]);
//! 2. a `version` field that is a number other than `1`
//!    ([`ParseError::UnsupportedVersion`]) — checked *before* the rest of the
//!    document is even looked at, so future-version documents get a precise
//!    error rather than a pile of unknown-field noise;
//! 3. any structural mismatch, including unknown fields anywhere in the tree,
//!    unknown enum tags, and **duplicate object keys** at any nesting level
//!    ([`ParseError::Json`]).
//!
//! # Why hand-written, not serde
//!
//! Parsing is deliberately **not** delegated to a serde data format. This crate
//! builds for `wasm32v1-none` (on-chain, via soroban's bump allocator), and the
//! Soroban VM rejects any module that uses the wasm float feature at all — even
//! an unreachable `f64` value type fails validation at deploy. `serde_json`'s
//! number lexer always compiles an `f64` branch, and serde's internally-tagged
//! enum machinery buffers through `serde::__private::de::Content`, whose
//! `F64(f64)` variant puts an `f64` in the module regardless of what the model
//! actually holds. A `PolicyDoc` holds only `u32`s and strings, so both are pure
//! deadweight — but deadweight the validator still rejects.
//!
//! So [`from_json`] walks a [`hifijson`] value tree by hand. hifijson is a
//! float-free lexer: numbers stay as raw digit strings (`num::Parts` tells us
//! whether one is an integer), and *we* parse them into `u32`. The document
//! model keeps its `#[derive(Serialize, Deserialize)]` for off-chain serde
//! interop, but nothing on the on-chain path touches it.
//!
//! # Duplicate keys
//!
//! JSON parsers legitimately disagree on whether the first or the last
//! occurrence of a duplicated key wins, so a document containing duplicates can
//! display differently in a reviewer's tooling than in the tool that
//! canonicalizes and hashes it. That is a content-aliasing vector, so every
//! object is checked for repeated keys at every nesting level and any duplicate
//! is rejected — hifijson's `Value::Object` preserves every entry (it is a
//! `Vec`, not a map), so the duplicates are visible to us rather than silently
//! collapsed.
//!
//! Parsing does **not** run semantic validation — call [`crate::validate()`] on
//! the result.

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, format, string::String, vec::Vec};
use core::fmt;

use hifijson::token::Lex;
use hifijson::value::{self, Value};
use hifijson::SliceLexer;

use crate::doc::{
    AddressEqPred, AllPrincipals, ArgConstraint, ArgPred, CapConstraint, ContractScope, IsSelfPred,
    PolicyDoc, Principals, Rule, Scope, SelfAdminScope, SelfAuthenticatingPrincipals, SignerDecl,
    StringInPred, StringPrefixPred, U32EqPred,
};

/// Maximum JSON nesting depth accepted by [`from_json`]. A valid `PolicyDoc`
/// nests at most a handful of levels (`doc → rules → rule → args → arg → pred`),
/// so this generous cap only exists to bound stack use against adversarially
/// deep input — the whole value tree is built before any structural check, so a
/// document nested thousands deep in a soon-to-be-rejected position would still
/// recurse without it.
const MAX_DEPTH: usize = 64;

/// A structural or syntactic problem with a policy document, carrying a
/// human-readable message. Replaces the previous `serde_json::Error` payload now
/// that parsing is hand-written (see the module docs on why serde is off the
/// on-chain path); the `ParseError::Json` variant name is unchanged.
#[derive(Debug)]
pub struct JsonError(String);

impl JsonError {
    /// The error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for JsonError {}

/// Error returned by [`from_json`].
#[derive(Debug)]
pub enum ParseError {
    /// The input is not valid JSON, or does not match the document schema
    /// (missing/unknown fields, wrong types, unknown enum tags, duplicate
    /// keys, ...).
    Json(JsonError),
    /// The document declares a numeric `version` other than `1`. Reported
    /// before any other schema check.
    UnsupportedVersion(u64),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Json(e) => write!(f, "invalid policy document JSON: {e}"),
            ParseError::UnsupportedVersion(v) => {
                write!(f, "unsupported policy document version {v} (expected 1)")
            }
        }
    }
}

impl core::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ParseError::Json(e) => Some(e),
            ParseError::UnsupportedVersion(_) => None,
        }
    }
}

/// Construct a `ParseError::Json` from a message.
fn json_err(msg: impl Into<String>) -> ParseError {
    ParseError::Json(JsonError(msg.into()))
}

/// Parse a policy document from JSON, fail-closed.
///
/// Unknown fields anywhere in the tree, unknown enum tags, duplicate object
/// keys at any nesting level, and any `version` other than `1` are rejected.
/// See the module docs for the precedence of the version check and the
/// rationale for rejecting duplicate keys.
///
/// # Errors
///
/// Returns [`ParseError::UnsupportedVersion`] for a numeric `version != 1`,
/// and [`ParseError::Json`] for every other syntax or schema violation.
pub fn from_json(input: &str) -> Result<PolicyDoc, ParseError> {
    let mut lexer = SliceLexer::new(input.as_bytes());
    // `exactly_one` requires a single top-level value and rejects trailing
    // content; `parse_bounded` caps recursion so deep input cannot overflow the
    // stack. Whitespace before/after the value is tolerated.
    let value = lexer
        .exactly_one(Lex::ws_peek, |next, lex| {
            value::parse_bounded(MAX_DEPTH, next, lex)
        })
        .map_err(|e: hifijson::Error| json_err(format!("{e}")))?;

    // Distinct, early version check: any numeric integer `version` other than
    // `1` is `UnsupportedVersion`, reported before unknown-field/structural
    // errors (a bad version must win over a stray sibling field). A missing,
    // non-numeric, or non-integer version falls through to the typed walk
    // below, which reports it as a schema error. Duplicate `version` keys that
    // are all `1` also fall through — and are caught there as "duplicate field".
    if let Value::Object(entries) = &value {
        for (k, v) in entries {
            if k.as_ref() == "version" {
                if let Value::Number((n, parts)) = v {
                    if parts.is_int() {
                        // `n` is hifijson's raw digit string; deref to `&str`.
                        let digits: &str = n;
                        if let Ok(ver) = digits.parse::<u64>() {
                            if ver != 1 {
                                return Err(ParseError::UnsupportedVersion(ver));
                            }
                        }
                    }
                }
            }
        }
    }

    doc_from_value(&value)
}

// --- value-tree helpers ------------------------------------------------------
//
// All generic over hifijson's number (`N`) and string (`S`) carriers, both of
// which are `AsRef<str>` for every lexer; writing against the carriers by
// reference means the same code serves the `SliceLexer` used on- and off-chain.

/// An object's members as hifijson stores them — `(key, value)` pairs in source
/// order, with duplicates preserved (so this crate can reject them).
type Members<'v, N, S> = &'v [(S, Value<N, S>)];

/// Find field `name` in an object's entries. `Ok(None)` if absent; `Err` if it
/// appears more than once (a duplicate key at this level).
fn field<'v, N, S: AsRef<str>>(
    obj: Members<'v, N, S>,
    name: &str,
) -> Result<Option<&'v Value<N, S>>, ParseError> {
    let mut found = None;
    for (k, v) in obj {
        if k.as_ref() == name {
            if found.is_some() {
                return Err(json_err(format!("duplicate field `{name}`")));
            }
            found = Some(v);
        }
    }
    Ok(found)
}

/// A required field: absent → "missing field" error, duplicate → error.
fn req_field<'v, N, S: AsRef<str>>(
    obj: Members<'v, N, S>,
    name: &str,
) -> Result<&'v Value<N, S>, ParseError> {
    field(obj, name)?.ok_or_else(|| json_err(format!("missing field `{name}`")))
}

/// An optional field that must be *absent* to be `None`: an explicit `null` is
/// rejected. This is the fail-closed meaning — for `functions`/`args`, `None`
/// means "unconstrained / all", so a silent `null → None` would authorize
/// everything. Absent → `None`; present `null` → error; present value → `Some`.
fn opt_field<'v, N, S: AsRef<str>>(
    obj: Members<'v, N, S>,
    name: &str,
) -> Result<Option<&'v Value<N, S>>, ParseError> {
    match field(obj, name)? {
        None => Ok(None),
        Some(Value::Null) => Err(json_err(format!("field `{name}` must not be null"))),
        Some(v) => Ok(Some(v)),
    }
}

/// Reject any entry whose key is not in `known` — the hand-written equivalent of
/// serde's `deny_unknown_fields`, applied at every object in the tree.
fn deny_unknown<N, S: AsRef<str>>(
    obj: Members<'_, N, S>,
    known: &[&str],
) -> Result<(), ParseError> {
    for (k, _) in obj {
        if !known.contains(&k.as_ref()) {
            return Err(json_err(format!("unknown field `{}`", k.as_ref())));
        }
    }
    Ok(())
}

fn as_object<'v, N, S: AsRef<str>>(
    v: &'v Value<N, S>,
    ctx: &str,
) -> Result<Members<'v, N, S>, ParseError> {
    match v {
        Value::Object(o) => Ok(o),
        _ => Err(json_err(format!("expected object for {ctx}"))),
    }
}

fn as_array<'v, N, S>(v: &'v Value<N, S>, ctx: &str) -> Result<&'v [Value<N, S>], ParseError> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(json_err(format!("expected array for {ctx}"))),
    }
}

fn as_str<N, S: AsRef<str>>(v: &Value<N, S>, ctx: &str) -> Result<String, ParseError> {
    match v {
        Value::String(s) => Ok(s.as_ref().to_owned()),
        _ => Err(json_err(format!("expected string for {ctx}"))),
    }
}

/// Read a `u32`. hifijson keeps numbers as raw digit strings; `parts.is_int()`
/// rejects fractions/exponents (`1.0`, `1e3`) before we `parse`, and a value
/// outside `u32` fails the parse — no float ever materializes.
fn as_u32<N: AsRef<str>, S>(v: &Value<N, S>, ctx: &str) -> Result<u32, ParseError> {
    match v {
        Value::Number((n, parts)) if parts.is_int() => n
            .as_ref()
            .parse::<u32>()
            .map_err(|_| json_err(format!("expected u32 for {ctx}"))),
        _ => Err(json_err(format!("expected u32 for {ctx}"))),
    }
}

/// The `"type"` tag of an internally-tagged object, as a string.
fn tag<N, S: AsRef<str>>(obj: Members<'_, N, S>, ctx: &str) -> Result<String, ParseError> {
    as_str(req_field(obj, "type")?, ctx)
}

// --- document walk -----------------------------------------------------------

fn doc_from_value<N: AsRef<str>, S: AsRef<str>>(v: &Value<N, S>) -> Result<PolicyDoc, ParseError> {
    let obj = as_object(v, "document")?;
    deny_unknown(obj, &["version", "network", "signers", "rules"])?;
    // The version pre-check in `from_json` has already rejected any numeric
    // `version != 1`; here it must be the integer `1`, a duplicate (caught by
    // `req_field`), or a non-number (caught by `as_u32` as "expected u32").
    let version = as_u32(req_field(obj, "version")?, "version")?;
    let network = match opt_field(obj, "network")? {
        Some(v) => Some(as_str(v, "network")?),
        None => None,
    };
    let signers = as_array(req_field(obj, "signers")?, "signers")?
        .iter()
        .map(signer_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    let rules = as_array(req_field(obj, "rules")?, "rules")?
        .iter()
        .map(rule_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PolicyDoc {
        version,
        network,
        signers,
        rules,
    })
}

fn signer_from_value<N: AsRef<str>, S: AsRef<str>>(
    v: &Value<N, S>,
) -> Result<SignerDecl, ParseError> {
    let obj = as_object(v, "signer")?;
    deny_unknown(obj, &["id", "verifier", "key"])?;
    Ok(SignerDecl {
        id: as_str(req_field(obj, "id")?, "signer id")?,
        verifier: as_str(req_field(obj, "verifier")?, "verifier")?,
        key: as_str(req_field(obj, "key")?, "key")?,
    })
}

fn rule_from_value<N: AsRef<str>, S: AsRef<str>>(v: &Value<N, S>) -> Result<Rule, ParseError> {
    let obj = as_object(v, "rule")?;
    deny_unknown(
        obj,
        &[
            "name",
            "scope",
            "principals",
            "functions",
            "args",
            "not-after-ledger",
            "cap",
        ],
    )?;
    let name = as_str(req_field(obj, "name")?, "rule name")?;
    let scope = scope_from_value(req_field(obj, "scope")?)?;
    let principals = principals_from_value(req_field(obj, "principals")?)?;
    let functions = match opt_field(obj, "functions")? {
        Some(v) => Some(
            as_array(v, "functions")?
                .iter()
                .map(|e| as_str(e, "function"))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        None => None,
    };
    let args = match opt_field(obj, "args")? {
        Some(v) => Some(
            as_array(v, "args")?
                .iter()
                .map(arg_constraint_from_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        None => None,
    };
    let not_after_ledger = match opt_field(obj, "not-after-ledger")? {
        Some(v) => Some(as_u32(v, "not-after-ledger")?),
        None => None,
    };
    let cap = match opt_field(obj, "cap")? {
        Some(v) => Some(cap_from_value(v)?),
        None => None,
    };
    Ok(Rule {
        name,
        scope,
        principals,
        functions,
        args,
        not_after_ledger,
        cap,
    })
}

fn scope_from_value<N: AsRef<str>, S: AsRef<str>>(v: &Value<N, S>) -> Result<Scope, ParseError> {
    let obj = as_object(v, "scope")?;
    match tag(obj, "scope type")?.as_str() {
        "contract" => {
            deny_unknown(obj, &["type", "address"])?;
            Ok(Scope::Contract(ContractScope {
                address: as_str(req_field(obj, "address")?, "contract address")?,
            }))
        }
        "self-admin" => {
            deny_unknown(obj, &["type"])?;
            Ok(Scope::SelfAdmin(SelfAdminScope {}))
        }
        other => Err(json_err(format!(
            "unknown variant `{other}` for scope type"
        ))),
    }
}

fn principals_from_value<N: AsRef<str>, S: AsRef<str>>(
    v: &Value<N, S>,
) -> Result<Principals, ParseError> {
    let obj = as_object(v, "principals")?;
    match tag(obj, "principals type")?.as_str() {
        "all" => {
            deny_unknown(obj, &["type", "signers"])?;
            Ok(Principals::All(AllPrincipals {
                signers: as_array(req_field(obj, "signers")?, "signers")?
                    .iter()
                    .map(|e| as_str(e, "signer id"))
                    .collect::<Result<Vec<_>, _>>()?,
            }))
        }
        "self-authenticating" => {
            deny_unknown(obj, &["type", "policy", "install-param-hex", "ack"])?;
            Ok(Principals::SelfAuthenticating(
                SelfAuthenticatingPrincipals {
                    policy: as_str(req_field(obj, "policy")?, "policy")?,
                    install_param_hex: as_str(
                        req_field(obj, "install-param-hex")?,
                        "install-param-hex",
                    )?,
                    ack: as_str(req_field(obj, "ack")?, "ack")?,
                },
            ))
        }
        other => Err(json_err(format!(
            "unknown variant `{other}` for principals type"
        ))),
    }
}

fn arg_constraint_from_value<N: AsRef<str>, S: AsRef<str>>(
    v: &Value<N, S>,
) -> Result<ArgConstraint, ParseError> {
    let obj = as_object(v, "arg constraint")?;
    deny_unknown(obj, &["index", "pred"])?;
    Ok(ArgConstraint {
        index: as_u32(req_field(obj, "index")?, "arg index")?,
        pred: pred_from_value(req_field(obj, "pred")?)?,
    })
}

fn pred_from_value<N: AsRef<str>, S: AsRef<str>>(v: &Value<N, S>) -> Result<ArgPred, ParseError> {
    let obj = as_object(v, "predicate")?;
    match tag(obj, "predicate type")?.as_str() {
        "is-self" => {
            deny_unknown(obj, &["type"])?;
            Ok(ArgPred::IsSelf(IsSelfPred {}))
        }
        "address-eq" => {
            deny_unknown(obj, &["type", "address"])?;
            Ok(ArgPred::AddressEq(AddressEqPred {
                address: as_str(req_field(obj, "address")?, "address")?,
            }))
        }
        "string-in" => {
            deny_unknown(obj, &["type", "values"])?;
            Ok(ArgPred::StringIn(StringInPred {
                values: as_array(req_field(obj, "values")?, "values")?
                    .iter()
                    .map(|e| as_str(e, "value"))
                    .collect::<Result<Vec<_>, _>>()?,
            }))
        }
        "string-prefix" => {
            deny_unknown(obj, &["type", "prefix"])?;
            Ok(ArgPred::StringPrefix(StringPrefixPred {
                prefix: as_str(req_field(obj, "prefix")?, "prefix")?,
            }))
        }
        "u32-eq" => {
            deny_unknown(obj, &["type", "value"])?;
            Ok(ArgPred::U32Eq(U32EqPred {
                value: as_u32(req_field(obj, "value")?, "value")?,
            }))
        }
        other => Err(json_err(format!(
            "unknown variant `{other}` for predicate type"
        ))),
    }
}

fn cap_from_value<N: AsRef<str>, S: AsRef<str>>(
    v: &Value<N, S>,
) -> Result<CapConstraint, ParseError> {
    let obj = as_object(v, "cap")?;
    deny_unknown(obj, &["token", "limit", "period-ledgers"])?;
    let token = match opt_field(obj, "token")? {
        Some(v) => Some(as_str(v, "cap token")?),
        None => None,
    };
    Ok(CapConstraint {
        token,
        limit: as_str(req_field(obj, "limit")?, "cap limit")?,
        period_ledgers: as_u32(req_field(obj, "period-ledgers")?, "period-ledgers")?,
    })
}
