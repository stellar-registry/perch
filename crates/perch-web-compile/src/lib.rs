//! Data-only compilation and fail-closed call checks for `perch-web/v1`.
//!
//! Compilation emits no executable policy code. A host must compare its
//! trusted call context with one of the plans before it invokes a tool.

use std::collections::{BTreeMap, HashSet};

use perch_web_ir::{
    is_canonical_utc_timestamp, policy_hash, validate, Approval, ArgumentPredicate, Effect, Grant,
    PolicyDoc, PolicyError, TargetIdentity, PROFILE,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The BrowserPlan format emitted by this compiler.
pub const BROWSER_PLAN_PROFILE: &str = "perch-web-browser-plan/v1";

/// The ServerPlan format emitted by this compiler.
pub const SERVER_PLAN_PROFILE: &str = "perch-web-server-plan/v1";

/// A browser enforcement plan. The value contains data only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BrowserPlan {
    pub plan: String,
    pub policy_hash: String,
    #[serde(flatten)]
    pub policy: PlanPolicy,
}

/// A server enforcement plan. The value contains data only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ServerPlan {
    pub plan: String,
    pub policy_hash: String,
    #[serde(flatten)]
    pub policy: PlanPolicy,
}

/// The policy data that must match in both plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PlanPolicy {
    pub profile: String,
    pub origin: String,
    pub target: TargetIdentity,
    pub manifest_sha256: String,
    pub principal: String,
    pub expires_at: String,
    pub grants: Vec<Grant>,
}

/// Both matched plans produced from one policy document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPlans {
    pub browser: BrowserPlan,
    pub server: ServerPlan,
}

/// Compile a validated document into matched data-only plans.
pub fn compile(doc: &PolicyDoc) -> Result<CompiledPlans, PolicyError> {
    validate(doc)?;
    let hash = policy_hash(doc)?;
    let policy = PlanPolicy {
        profile: PROFILE.into(),
        origin: doc.origin.clone(),
        target: doc.target.clone(),
        manifest_sha256: doc.manifest_sha256.clone(),
        principal: doc.principal.clone(),
        expires_at: doc.expires_at.clone(),
        grants: doc.grants.clone(),
    };
    Ok(CompiledPlans {
        browser: BrowserPlan {
            plan: BROWSER_PLAN_PROFILE.into(),
            policy_hash: hash.clone(),
            policy: policy.clone(),
        },
        server: ServerPlan {
            plan: SERVER_PLAN_PROFILE.into(),
            policy_hash: hash,
            policy,
        },
    })
}

/// Verify that a plan pair is the exact output for a policy document.
pub fn verify_plans(doc: &PolicyDoc, plans: &CompiledPlans) -> Result<(), Denial> {
    let expected = compile(doc).map_err(|_| Denial::InvalidPlan)?;
    if &expected != plans {
        return Err(Denial::InvalidPlan);
    }
    validate_plan(&plans.browser.policy, &plans.browser.policy_hash)?;
    validate_plan(&plans.server.policy, &plans.server.policy_hash)?;
    Ok(())
}

/// A trusted host call context.
#[derive(Debug)]
pub struct CallContext<'a> {
    pub origin: &'a str,
    pub target: &'a TargetIdentity,
    pub manifest_sha256: &'a str,
    pub principal: &'a str,
    pub now: &'a str,
    pub tool_export: &'a str,
    /// The host must convert each named WIT argument to its JSON scalar form.
    /// A WIT `u64` uses a canonical unsigned decimal string.
    pub arguments: &'a BTreeMap<String, Value>,
    pub effects: &'a [Effect],
    pub approved: bool,
    /// The host supplies revoked identities from its trusted revocation store.
    pub revoked: &'a HashSet<String>,
}

/// A fail-closed denial reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    InvalidPlan,
    Origin,
    Target,
    Manifest,
    Principal,
    Expired,
    Tool,
    Arguments,
    Effects,
    Approval,
    Revoked,
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "call denied: {self:?}")
    }
}

impl std::error::Error for Denial {}

/// Check a browser call against a BrowserPlan.
pub fn check_browser_call(plan: &BrowserPlan, call: &CallContext<'_>) -> Result<(), Denial> {
    if plan.plan != BROWSER_PLAN_PROFILE {
        return Err(Denial::InvalidPlan);
    }
    validate_plan(&plan.policy, &plan.policy_hash)?;
    check_call(&plan.policy, call)
}

/// Check a server call against a ServerPlan.
pub fn check_server_call(plan: &ServerPlan, call: &CallContext<'_>) -> Result<(), Denial> {
    if plan.plan != SERVER_PLAN_PROFILE {
        return Err(Denial::InvalidPlan);
    }
    validate_plan(&plan.policy, &plan.policy_hash)?;
    check_call(&plan.policy, call)
}

fn validate_plan(plan: &PlanPolicy, expected_hash: &str) -> Result<(), Denial> {
    let doc = PolicyDoc {
        profile: plan.profile.clone(),
        origin: plan.origin.clone(),
        target: plan.target.clone(),
        manifest_sha256: plan.manifest_sha256.clone(),
        principal: plan.principal.clone(),
        expires_at: plan.expires_at.clone(),
        grants: plan.grants.clone(),
    };
    validate(&doc).map_err(|_| Denial::InvalidPlan)?;
    let actual_hash = policy_hash(&doc).map_err(|_| Denial::InvalidPlan)?;
    if actual_hash != expected_hash {
        return Err(Denial::InvalidPlan);
    }
    Ok(())
}

fn check_call(plan: &PlanPolicy, call: &CallContext<'_>) -> Result<(), Denial> {
    if plan.profile != PROFILE {
        return Err(Denial::InvalidPlan);
    }
    if plan.origin != call.origin {
        return Err(Denial::Origin);
    }
    if &plan.target != call.target {
        return Err(Denial::Target);
    }
    if plan.manifest_sha256 != call.manifest_sha256 {
        return Err(Denial::Manifest);
    }
    if plan.principal != call.principal {
        return Err(Denial::Principal);
    }
    if is_expired(&plan.expires_at, call.now)? {
        return Err(Denial::Expired);
    }
    let grant = plan
        .grants
        .iter()
        .find(|grant| grant.tool_export == call.tool_export)
        .ok_or(Denial::Tool)?;
    if call.revoked.contains(&grant.revocation_id) {
        return Err(Denial::Revoked);
    }
    check_arguments(grant, call.arguments)?;
    check_effects(grant, call.effects)?;
    if grant.approval == Approval::Required && !call.approved {
        return Err(Denial::Approval);
    }
    Ok(())
}

fn is_expired(expires_at: &str, now: &str) -> Result<bool, Denial> {
    if !is_canonical_utc_timestamp(expires_at) || !is_canonical_utc_timestamp(now) {
        return Err(Denial::InvalidPlan);
    }
    let expiry = OffsetDateTime::parse(expires_at, &Rfc3339).map_err(|_| Denial::InvalidPlan)?;
    let current = OffsetDateTime::parse(now, &Rfc3339).map_err(|_| Denial::InvalidPlan)?;
    Ok(current >= expiry)
}

fn check_arguments(grant: &Grant, arguments: &BTreeMap<String, Value>) -> Result<(), Denial> {
    if grant.arguments.len() != arguments.len() {
        return Err(Denial::Arguments);
    }
    for constraint in &grant.arguments {
        let value = arguments.get(&constraint.name).ok_or(Denial::Arguments)?;
        let matches = match (&constraint.predicate, value) {
            (ArgumentPredicate::StringEq { value: expected }, Value::String(actual)) => {
                actual == expected
            }
            (ArgumentPredicate::StringIn { values }, Value::String(actual)) => {
                values.contains(actual)
            }
            (ArgumentPredicate::BoolEq { value: expected }, Value::Bool(actual)) => {
                actual == expected
            }
            (ArgumentPredicate::U64Eq { value: expected }, Value::String(actual)) => {
                actual == expected
            }
            _ => false,
        };
        if !matches {
            return Err(Denial::Arguments);
        }
    }
    Ok(())
}

fn check_effects(grant: &Grant, effects: &[Effect]) -> Result<(), Denial> {
    let mut requested = HashSet::new();
    for effect in effects {
        if !requested.insert(*effect) || !grant.effects.contains(effect) {
            return Err(Denial::Effects);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use perch_web_ir::from_json;

    fn web_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/web")
    }

    fn fixture() -> PolicyDoc {
        from_json(&fs::read_to_string(web_dir().join("site-rescue.policy.json")).unwrap()).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn call<'a>(
        policy: &'a PlanPolicy,
        tool_export: &'a str,
        arguments: &'a BTreeMap<String, Value>,
        effects: &'a [Effect],
        approved: bool,
        revoked: &'a HashSet<String>,
        origin: &'a str,
        now: &'a str,
    ) -> CallContext<'a> {
        CallContext {
            origin,
            target: &policy.target,
            manifest_sha256: &policy.manifest_sha256,
            principal: &policy.principal,
            now,
            tool_export,
            arguments,
            effects,
            approved,
            revoked,
        }
    }

    fn write_or_compare(path: PathBuf, value: &str) {
        if std::env::var_os("UPDATE_WEB_GOLDEN").is_some() {
            fs::write(path, value).unwrap();
        } else {
            assert_eq!(fs::read_to_string(path).unwrap(), value);
        }
    }

    #[test]
    fn site_rescue_golden_values_are_stable() {
        let doc = fixture();
        let plans = compile(&doc).unwrap();
        let browser_json = serde_json::to_string_pretty(&plans.browser).unwrap();
        let server_json = serde_json::to_string_pretty(&plans.server).unwrap();
        assert_eq!(
            serde_json::from_str::<BrowserPlan>(&browser_json).unwrap(),
            plans.browser
        );
        assert_eq!(
            serde_json::from_str::<ServerPlan>(&server_json).unwrap(),
            plans.server
        );
        let canonical = String::from_utf8(perch_web_ir::canonical_bytes(&doc).unwrap()).unwrap();
        write_or_compare(
            web_dir().join("site-rescue.canonical.json"),
            &format!("{canonical}\n"),
        );
        write_or_compare(
            web_dir().join("site-rescue.policy-hash"),
            &format!("{}\n", plans.browser.policy_hash),
        );
        write_or_compare(
            web_dir().join("site-rescue.browser-plan.json"),
            &format!("{browser_json}\n"),
        );
        write_or_compare(
            web_dir().join("site-rescue.server-plan.json"),
            &format!("{server_json}\n"),
        );
        assert_eq!(plans.browser.policy_hash, plans.server.policy_hash);
        assert_eq!(plans.browser.policy, plans.server.policy);
        assert_eq!(verify_plans(&doc, &plans), Ok(()));
        assert_eq!(
            plans.browser.policy_hash,
            "874cf21112f5067d939b951570f6d7554db8b3f32e0d1e4c8c491bac1532f138"
        );
    }

    #[test]
    fn positive_call_and_denials_match_in_both_plans() {
        let plans = compile(&fixture()).unwrap();
        let mut arguments = BTreeMap::from([
            (
                "url".into(),
                Value::String("https://damaged.example/".into()),
            ),
            ("include-assets".into(), Value::Bool(true)),
            ("mode".into(), Value::String("safe".into())),
            ("max-bytes".into(), Value::String("1048576".into())),
        ]);
        let effects = [Effect::DomRead, Effect::NetworkRequest];
        let mut revoked = HashSet::new();
        let allowed = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#inspect-site",
            &arguments,
            &effects,
            false,
            &revoked,
            "https://rescue.example",
            "2027-01-01T00:00:00Z",
        );
        assert_eq!(check_browser_call(&plans.browser, &allowed), Ok(()));
        assert_eq!(check_server_call(&plans.server, &allowed), Ok(()));

        arguments.insert("extra".into(), Value::Bool(true));
        let extra = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#inspect-site",
            &arguments,
            &effects,
            false,
            &revoked,
            "https://rescue.example",
            "2027-01-01T00:00:00Z",
        );
        assert_eq!(
            check_browser_call(&plans.browser, &extra),
            Err(Denial::Arguments)
        );
        arguments.remove("extra");

        arguments.insert("url".into(), Value::String("https://other.example/".into()));
        let wrong_argument = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#inspect-site",
            &arguments,
            &effects,
            false,
            &revoked,
            "https://rescue.example",
            "2027-01-01T00:00:00Z",
        );
        assert_eq!(
            check_server_call(&plans.server, &wrong_argument),
            Err(Denial::Arguments)
        );
        arguments.insert(
            "url".into(),
            Value::String("https://damaged.example/".into()),
        );

        let wrong_origin = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#inspect-site",
            &arguments,
            &effects,
            false,
            &revoked,
            "https://evil.example",
            "2027-01-01T00:00:00Z",
        );
        assert_eq!(
            check_server_call(&plans.server, &wrong_origin),
            Err(Denial::Origin)
        );

        let other_target = TargetIdentity::Component { id: "other".into() };
        let mut wrong_binding = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#inspect-site",
            &arguments,
            &effects,
            false,
            &revoked,
            "https://rescue.example",
            "2027-01-01T00:00:00Z",
        );
        wrong_binding.target = &other_target;
        assert_eq!(
            check_browser_call(&plans.browser, &wrong_binding),
            Err(Denial::Target)
        );
        wrong_binding.target = &plans.browser.policy.target;
        wrong_binding.manifest_sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            check_server_call(&plans.server, &wrong_binding),
            Err(Denial::Manifest)
        );
        wrong_binding.manifest_sha256 = &plans.browser.policy.manifest_sha256;
        wrong_binding.principal = "user:other";
        assert_eq!(
            check_browser_call(&plans.browser, &wrong_binding),
            Err(Denial::Principal)
        );

        let expired = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#inspect-site",
            &arguments,
            &effects,
            false,
            &revoked,
            "https://rescue.example",
            "2027-08-26T12:00:00Z",
        );
        assert_eq!(
            check_browser_call(&plans.browser, &expired),
            Err(Denial::Expired)
        );
        let offset_now = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#inspect-site",
            &arguments,
            &effects,
            false,
            &revoked,
            "https://rescue.example",
            "2027-01-01T00:00:00+00:00",
        );
        assert_eq!(
            check_browser_call(&plans.browser, &offset_now),
            Err(Denial::InvalidPlan)
        );

        revoked.insert("site-rescue/inspection/2027-01".into());
        let revoked_call = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#inspect-site",
            &arguments,
            &effects,
            false,
            &revoked,
            "https://rescue.example",
            "2027-01-01T00:00:00Z",
        );
        assert_eq!(
            check_server_call(&plans.server, &revoked_call),
            Err(Denial::Revoked)
        );

        let mut tampered = plans.browser.clone();
        tampered.policy_hash = "0".repeat(64);
        let no_revocations = HashSet::new();
        let tampered_call = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#inspect-site",
            &arguments,
            &effects,
            false,
            &no_revocations,
            "https://rescue.example",
            "2027-01-01T00:00:00Z",
        );
        assert_eq!(
            check_browser_call(&tampered, &tampered_call),
            Err(Denial::InvalidPlan)
        );
    }

    #[test]
    fn approval_and_effects_are_enforced() {
        let plans = compile(&fixture()).unwrap();
        let arguments = BTreeMap::from([(
            "archive-name".into(),
            Value::String("site-rescue.zip".into()),
        )]);
        let revoked = HashSet::new();
        let effect = [Effect::UserDownload];
        let unapproved = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#download-archive",
            &arguments,
            &effect,
            false,
            &revoked,
            &plans.browser.policy.origin,
            "2027-01-01T00:00:00Z",
        );
        assert_eq!(
            check_browser_call(&plans.browser, &unapproved),
            Err(Denial::Approval)
        );
        let approved = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#download-archive",
            &arguments,
            &effect,
            true,
            &revoked,
            &plans.browser.policy.origin,
            "2027-01-01T00:00:00Z",
        );
        assert_eq!(check_browser_call(&plans.browser, &approved), Ok(()));
        let wrong_effect = [Effect::DomWrite];
        let effect_denied = call(
            &plans.browser.policy,
            "site-rescue:tools/rescue#download-archive",
            &arguments,
            &wrong_effect,
            true,
            &revoked,
            &plans.browser.policy.origin,
            "2027-01-01T00:00:00Z",
        );
        assert_eq!(
            check_browser_call(&plans.browser, &effect_denied),
            Err(Denial::Effects)
        );
    }
}
