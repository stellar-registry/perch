//! The independent `perch-web/v1` policy profile.
//!
//! This crate does not change Perch PolicyDoc v1 or CANON v1. It defines a
//! separate WebMCP/WIT document, strict validation, stable canonical bytes,
//! and the SHA-256 identity of those bytes.

use std::collections::HashSet;
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;

/// The only policy profile supported by this crate.
pub const PROFILE: &str = "perch-web/v1";

/// The canonical form version for `perch-web/v1`.
pub const WEB_CANON_VERSION: u32 = 1;

/// A complete Web policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PolicyDoc {
    pub profile: String,
    pub origin: String,
    pub target: TargetIdentity,
    pub manifest_sha256: String,
    pub principal: String,
    pub expires_at: String,
    pub grants: Vec<Grant>,
}

/// The WIT package or component authorized by the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TargetIdentity {
    Package { id: String },
    Component { id: String },
}

impl TargetIdentity {
    fn id(&self) -> &str {
        match self {
            Self::Package { id } | Self::Component { id } => id,
        }
    }
}

/// One unambiguous grant for one WIT tool export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub tool_export: String,
    pub arguments: Vec<NamedArgumentConstraint>,
    pub effects: Vec<Effect>,
    pub approval: Approval,
    pub revocation_id: String,
}

/// A constraint for one named WIT argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NamedArgumentConstraint {
    pub name: String,
    pub predicate: ArgumentPredicate,
}

/// The closed predicate set supported by `perch-web/v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ArgumentPredicate {
    StringEq {
        value: String,
    },
    StringIn {
        values: Vec<String>,
    },
    BoolEq {
        value: bool,
    },
    /// A WIT `u64` encoded as an unsigned decimal string.
    U64Eq {
        value: String,
    },
}

/// The closed effect set supported by `perch-web/v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Effect {
    DomRead,
    DomWrite,
    NetworkRequest,
    UserDownload,
    PersistentStorage,
}

/// The approval requirement for every matching call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Approval {
    None,
    Required,
}

/// A parse or validation error. Invalid input never produces a policy value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

/// Parse a strict `perch-web/v1` document and run all semantic checks.
pub fn from_json(input: &str) -> Result<PolicyDoc, PolicyError> {
    validate_json_nesting(input)?;
    let initial: Value = serde_json::from_str(input)
        .map_err(|error| PolicyError(format!("invalid perch-web policy: {error}")))?;
    if let Some(profile) = initial.get("profile").and_then(Value::as_str) {
        if profile != PROFILE {
            return Err(PolicyError(format!(
                "unsupported profile `{profile}`; expected `{PROFILE}`"
            )));
        }
    }
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let doc = PolicyDoc::deserialize(&mut deserializer)
        .map_err(|error| PolicyError(format!("invalid perch-web policy: {error}")))?;
    deserializer
        .end()
        .map_err(|error| PolicyError(format!("invalid trailing data: {error}")))?;
    validate(&doc)?;
    Ok(doc)
}

fn validate_json_nesting(input: &str) -> Result<(), PolicyError> {
    let mut depth = 0_u32;
    let mut in_string = false;
    let mut escaped = false;
    for byte in input.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > 64 {
                    return Err(PolicyError("JSON nesting exceeds 64 levels".into()));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// Validate the document independently of parsing.
pub fn validate(doc: &PolicyDoc) -> Result<(), PolicyError> {
    if doc.profile != PROFILE {
        return Err(PolicyError(format!(
            "unsupported profile `{}`; expected `{PROFILE}`",
            doc.profile
        )));
    }
    validate_origin(&doc.origin)?;
    validate_identity(doc.target.id(), "target identity")?;
    validate_hash(&doc.manifest_sha256, "manifest-sha256")?;
    validate_text(&doc.principal, "principal", 256)?;
    validate_expiry(&doc.expires_at)?;
    if doc.grants.is_empty() {
        return Err(PolicyError("grants must not be empty".into()));
    }

    let mut ids = HashSet::new();
    let mut exports = HashSet::new();
    let mut revocations = HashSet::new();
    for grant in &doc.grants {
        validate_text(&grant.id, "grant id", 128)?;
        if !ids.insert(grant.id.as_str()) {
            return Err(PolicyError(format!("duplicate grant id `{}`", grant.id)));
        }
        validate_tool_export(&grant.tool_export)?;
        if !exports.insert(grant.tool_export.as_str()) {
            return Err(PolicyError(format!(
                "ambiguous grants for tool export `{}`",
                grant.tool_export
            )));
        }
        validate_text(&grant.revocation_id, "revocation-id", 256)?;
        if !revocations.insert(grant.revocation_id.as_str()) {
            return Err(PolicyError(format!(
                "duplicate revocation-id `{}`",
                grant.revocation_id
            )));
        }
        validate_arguments(&grant.arguments)?;
        if grant.effects.is_empty() {
            return Err(PolicyError(format!(
                "grant `{}` must declare at least one effect",
                grant.id
            )));
        }
        let mut effects = HashSet::new();
        for effect in &grant.effects {
            if !effects.insert(*effect) {
                return Err(PolicyError(format!(
                    "grant `{}` contains a duplicate effect",
                    grant.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), PolicyError> {
    let parsed = Url::parse(origin).map_err(|_| PolicyError("origin is not a valid URL".into()))?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(PolicyError(
            "origin must be a canonical HTTPS origin without a path, credentials, query, or fragment"
                .into(),
        ));
    }
    let canonical = parsed.origin().ascii_serialization();
    if canonical != origin {
        return Err(PolicyError(format!(
            "origin must use canonical form `{canonical}`"
        )));
    }
    Ok(())
}

fn validate_identity(value: &str, name: &str) -> Result<(), PolicyError> {
    validate_text(value, name, 256)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
    }) {
        return Err(PolicyError(format!(
            "{name} contains an unsupported character"
        )));
    }
    Ok(())
}

fn validate_hash(value: &str, name: &str) -> Result<(), PolicyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyError(format!(
            "{name} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_expiry(value: &str) -> Result<(), PolicyError> {
    if !is_canonical_utc_timestamp(value) {
        return Err(PolicyError(
            "expires-at must use YYYY-MM-DDTHH:MM:SSZ form".into(),
        ));
    }
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| PolicyError("expires-at must be an RFC 3339 timestamp".into()))?;
    let canonical = parsed
        .format(&Rfc3339)
        .map_err(|error| PolicyError(format!("cannot format expires-at: {error}")))?;
    if parsed.offset() != time::UtcOffset::UTC || canonical != value {
        return Err(PolicyError(
            "expires-at must use canonical UTC RFC 3339 form".into(),
        ));
    }
    if parsed <= OffsetDateTime::UNIX_EPOCH {
        return Err(PolicyError(
            "expires-at must be after the Unix epoch".into(),
        ));
    }
    Ok(())
}

/// Return true for the exact UTC whole-second timestamp syntax used by v1.
#[must_use]
pub fn is_canonical_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

fn validate_tool_export(value: &str) -> Result<(), PolicyError> {
    validate_text(value, "tool-export", 256)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+' | b'#')
    }) {
        return Err(PolicyError(
            "tool-export contains an unsupported character".into(),
        ));
    }
    let (owner, function) = value
        .split_once('#')
        .ok_or_else(|| PolicyError("tool-export must include `#function`".into()))?;
    let Some((package_id, interface)) = owner.split_once('/') else {
        return Err(PolicyError(
            "tool-export must use `namespace:package[@version]/interface#function` form".into(),
        ));
    };
    let Some((namespace, package_version)) = package_id.split_once(':') else {
        return Err(PolicyError(
            "tool-export must use `namespace:package[@version]/interface#function` form".into(),
        ));
    };
    let (package, version) = package_version
        .split_once('@')
        .map_or((package_version, None), |(package, version)| {
            (package, Some(version))
        });
    if !is_wit_name(namespace)
        || !is_wit_name(package)
        || !is_wit_name(interface)
        || !is_wit_name(function)
        || owner.matches('/').count() != 1
        || value.matches('#').count() != 1
        || value.matches(':').count() != 1
        || version.is_some_and(|version| !is_three_part_version(version))
    {
        return Err(PolicyError(
            "tool-export must use `namespace:package[@version]/interface#function` form".into(),
        ));
    }
    Ok(())
}

fn is_wit_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_three_part_version(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_arguments(arguments: &[NamedArgumentConstraint]) -> Result<(), PolicyError> {
    if arguments.is_empty() {
        return Err(PolicyError(
            "arguments must contain an exact constraint for each WIT argument".into(),
        ));
    }
    let mut names = HashSet::new();
    for argument in arguments {
        validate_wit_name(&argument.name)?;
        if !names.insert(argument.name.as_str()) {
            return Err(PolicyError(format!(
                "duplicate argument constraint `{}`",
                argument.name
            )));
        }
        match &argument.predicate {
            ArgumentPredicate::StringIn { values } => {
                if values.is_empty() {
                    return Err(PolicyError(format!(
                        "string-in for `{}` must not be empty",
                        argument.name
                    )));
                }
                let unique: HashSet<&str> = values.iter().map(String::as_str).collect();
                if unique.len() != values.len() {
                    return Err(PolicyError(format!(
                        "string-in for `{}` contains a duplicate value",
                        argument.name
                    )));
                }
            }
            ArgumentPredicate::U64Eq { value } => validate_u64(value)?,
            ArgumentPredicate::StringEq { .. } | ArgumentPredicate::BoolEq { .. } => {}
        }
    }
    Ok(())
}

fn validate_wit_name(value: &str) -> Result<(), PolicyError> {
    if !is_wit_name(value) {
        return Err(PolicyError(format!(
            "argument name `{value}` is not a canonical WIT name"
        )));
    }
    Ok(())
}

fn validate_u64(value: &str) -> Result<(), PolicyError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.parse::<u64>().is_err()
    {
        return Err(PolicyError(format!(
            "u64-eq value `{value}` is not a canonical u64"
        )));
    }
    Ok(())
}

fn validate_text(value: &str, name: &str, max: usize) -> Result<(), PolicyError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(PolicyError(format!(
            "{name} must contain 1 to {max} non-control UTF-8 bytes"
        )));
    }
    Ok(())
}

/// Return the stable canonical JSON bytes for a validated document.
pub fn canonical_bytes(doc: &PolicyDoc) -> Result<Vec<u8>, PolicyError> {
    validate(doc)?;
    let mut output = String::new();
    write_canonical(&doc_to_canonical(doc), &mut output);
    Ok(output.into_bytes())
}

/// Return the lowercase SHA-256 identity of the canonical bytes.
pub fn policy_hash(doc: &PolicyDoc) -> Result<String, PolicyError> {
    Ok(hex::encode(Sha256::digest(canonical_bytes(doc)?)))
}

enum CanonicalValue<'a> {
    String(&'a str),
    Bool(bool),
    Array(Vec<CanonicalValue<'a>>),
    Object(Vec<(&'static str, CanonicalValue<'a>)>),
}

fn doc_to_canonical(doc: &PolicyDoc) -> CanonicalValue<'_> {
    CanonicalValue::Object(vec![
        ("profile", CanonicalValue::String(&doc.profile)),
        ("origin", CanonicalValue::String(&doc.origin)),
        ("target", target_to_canonical(&doc.target)),
        (
            "manifest-sha256",
            CanonicalValue::String(&doc.manifest_sha256),
        ),
        ("principal", CanonicalValue::String(&doc.principal)),
        ("expires-at", CanonicalValue::String(&doc.expires_at)),
        (
            "grants",
            CanonicalValue::Array(doc.grants.iter().map(grant_to_canonical).collect()),
        ),
    ])
}

fn target_to_canonical(target: &TargetIdentity) -> CanonicalValue<'_> {
    let (kind, id) = match target {
        TargetIdentity::Package { id } => ("package", id),
        TargetIdentity::Component { id } => ("component", id),
    };
    CanonicalValue::Object(vec![
        ("type", CanonicalValue::String(kind)),
        ("id", CanonicalValue::String(id)),
    ])
}

fn grant_to_canonical(grant: &Grant) -> CanonicalValue<'_> {
    CanonicalValue::Object(vec![
        ("id", CanonicalValue::String(&grant.id)),
        ("tool-export", CanonicalValue::String(&grant.tool_export)),
        (
            "arguments",
            CanonicalValue::Array(grant.arguments.iter().map(argument_to_canonical).collect()),
        ),
        (
            "effects",
            CanonicalValue::Array(
                grant
                    .effects
                    .iter()
                    .map(|effect| CanonicalValue::String(effect_name(*effect)))
                    .collect(),
            ),
        ),
        (
            "approval",
            CanonicalValue::String(match grant.approval {
                Approval::None => "none",
                Approval::Required => "required",
            }),
        ),
        (
            "revocation-id",
            CanonicalValue::String(&grant.revocation_id),
        ),
    ])
}

fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::DomRead => "dom-read",
        Effect::DomWrite => "dom-write",
        Effect::NetworkRequest => "network-request",
        Effect::UserDownload => "user-download",
        Effect::PersistentStorage => "persistent-storage",
    }
}

fn argument_to_canonical(argument: &NamedArgumentConstraint) -> CanonicalValue<'_> {
    CanonicalValue::Object(vec![
        ("name", CanonicalValue::String(&argument.name)),
        ("predicate", predicate_to_canonical(&argument.predicate)),
    ])
}

fn predicate_to_canonical(predicate: &ArgumentPredicate) -> CanonicalValue<'_> {
    match predicate {
        ArgumentPredicate::StringEq { value } => CanonicalValue::Object(vec![
            ("type", CanonicalValue::String("string-eq")),
            ("value", CanonicalValue::String(value)),
        ]),
        ArgumentPredicate::StringIn { values } => CanonicalValue::Object(vec![
            ("type", CanonicalValue::String("string-in")),
            (
                "values",
                CanonicalValue::Array(
                    values
                        .iter()
                        .map(|value| CanonicalValue::String(value))
                        .collect(),
                ),
            ),
        ]),
        ArgumentPredicate::BoolEq { value } => CanonicalValue::Object(vec![
            ("type", CanonicalValue::String("bool-eq")),
            ("value", CanonicalValue::Bool(*value)),
        ]),
        ArgumentPredicate::U64Eq { value } => CanonicalValue::Object(vec![
            ("type", CanonicalValue::String("u64-eq")),
            ("value", CanonicalValue::String(value)),
        ]),
    }
}

fn write_canonical(value: &CanonicalValue<'_>, output: &mut String) {
    match value {
        CanonicalValue::String(value) => write_json_string(value, output),
        CanonicalValue::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        CanonicalValue::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical(value, output);
            }
            output.push(']');
        }
        CanonicalValue::Object(object) => {
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            output.push('{');
            for (index, (key, value)) in entries.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_json_string(key, output);
                output.push(':');
                write_canonical(value, output);
            }
            output.push('}');
        }
    }
}

fn write_json_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{000c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            character if character <= '\u{001f}' => {
                write!(output, "\\u{:04x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"{
      "profile":"perch-web/v1",
      "origin":"https://rescue.example",
      "target":{"type":"package","id":"site-rescue:tools@1.0.0"},
      "manifest-sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "principal":"user:site-owner",
      "expires-at":"2027-08-26T12:00:00Z",
      "grants":[{"id":"inspect","tool-export":"site-rescue:tools/rescue#inspect-site","arguments":[{"name":"url","predicate":{"type":"string-eq","value":"https://damaged.example/"}}],"effects":["dom-read"],"approval":"none","revocation-id":"site-rescue/inspect/1"}]
    }"#;

    #[test]
    fn parses_valid_document() {
        assert_eq!(from_json(BASE).unwrap().profile, PROFILE);
    }

    #[test]
    fn rejects_unknown_fields_and_predicates() {
        let unknown = BASE.replace("\"origin\":", "\"unknown\":true,\"origin\":");
        assert!(from_json(&unknown).is_err());
        let predicate = BASE.replace(
            "\"type\":\"string-eq\",\"value\":\"https://damaged.example/\"",
            "\"type\":\"any\"",
        );
        assert!(from_json(&predicate).is_err());
        let effect = BASE.replace("\"dom-read\"", "\"unsupported\"");
        assert!(from_json(&effect).is_err());
        for invalid in ["a:b/c#d/e", "a/b#c"] {
            let tool = BASE.replace("site-rescue:tools/rescue#inspect-site", invalid);
            assert!(from_json(&tool).is_err(), "accepted {invalid}");
        }
        let fractional = BASE.replace("2027-08-26T12:00:00Z", "2027-08-26T12:00:00.5Z");
        assert!(from_json(&fractional).is_err());
    }

    #[test]
    fn rejects_ambiguous_grants_and_missing_effects() {
        let doc = from_json(BASE).unwrap();
        let mut ambiguous = doc.clone();
        let mut duplicate = ambiguous.grants[0].clone();
        duplicate.id = "other".into();
        duplicate.revocation_id = "other".into();
        ambiguous.grants.push(duplicate);
        assert!(validate(&ambiguous).unwrap_err().0.contains("ambiguous"));

        let mut no_effects = doc;
        no_effects.grants[0].effects.clear();
        assert!(validate(&no_effects).is_err());
    }

    #[test]
    fn canonical_form_is_independent_of_input_order() {
        let first = from_json(BASE).unwrap();
        let reordered = from_json(&BASE.replace(
            "\"profile\":\"perch-web/v1\",\n      \"origin\":\"https://rescue.example\"",
            "\"origin\":\"https://rescue.example\",\n      \"profile\":\"perch-web/v1\"",
        ))
        .unwrap();
        assert_eq!(
            canonical_bytes(&first).unwrap(),
            canonical_bytes(&reordered).unwrap()
        );
        assert_eq!(
            policy_hash(&first).unwrap(),
            policy_hash(&reordered).unwrap()
        );
    }
}
