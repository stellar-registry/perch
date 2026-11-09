//! Signature checks, signer identity, and the recovery completion's check.
//!
//! [`authenticate`] checks one payload signer's signature, and
//! [`check_distinct`] refuses two signers that are one key. The account's
//! authorization types are `perch-account-types`', the XDR and contract-spec
//! twins of OZ's. [`authorize_completion`] decides a recovery completion:
//! it calls the recovery controller's `enforce` as OZ's `do_check_auth`
//! called a policy, over the account's own record of the recovery rule.

use perch_account_types::{AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccountError};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::{
    contractclient, crypto::Hash, panic_with_error, Address, Bytes, Env, IntoVal, Map, Val, Vec,
};

use crate::rules::{expired, refuse, InstallError};
use crate::{InstalledRule, PerchStorage};

const DAY_IN_LEDGERS: u32 = 17280;
/// The TTL, in ledgers, that `__check_auth` extends an entry it reads to:
/// OZ's, so the account's entries live as long as the OZ entries beside them.
pub const SMART_ACCOUNT_EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
/// The TTL below which `__check_auth` extends an entry it reads.
pub const SMART_ACCOUNT_TTL_THRESHOLD: u32 = SMART_ACCOUNT_EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Fail the invocation with `error`. Raising the `#[contracterror]` type
/// itself puts its entry in the contract spec, so wallets read every code
/// `__check_auth` refuses with by name.
fn fail(e: &Env, error: SmartAccountError) -> ! {
    panic_with_error!(e, error)
}

/// A signature verifier's entry points, as the account calls them.
#[allow(unused)]
#[contractclient(name = "VerifierClient")]
trait Verifier {
    fn verify(e: &Env, hash: Bytes, key_data: Val, sig_data: Val) -> bool;
    fn batch_canonicalize_key(e: &Env, key_data: Vec<Val>) -> Vec<Bytes>;
}

/// The recovery controller's hooks, as the account calls them: `install`
/// checks the recovery rule it is installed on, and `enforce` decides a
/// completion. They are OZ's `Policy` hooks, called with the same values.
#[allow(unused)]
#[contractclient(name = "PolicyClient")]
trait Policy {
    fn install(e: &Env, install_params: Val, context_rule: ContextRule, smart_account: Address);
    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    );
}

/// Check `signer`'s signature over `digest`. An `External` signer's
/// verifier must accept `sig_data` for its key, or the invocation fails
/// with `ExternalVerificationFailed`. A `Delegated` signer is checked by the
/// host against the delegate list carried in this authorization entry's
/// credentials (CAP-0071), so it needs no auth entry of its own.
pub(crate) fn authenticate(e: &Env, digest: &Hash<32>, signer: &Signer, sig_data: &Bytes) {
    match signer {
        Signer::External(verifier, key_data) => {
            let payload = digest.to_bytes().to_bytes();
            if !VerifierClient::new(e, verifier).verify(
                &payload,
                &key_data.into_val(e),
                &sig_data.into_val(e),
            ) {
                fail(e, SmartAccountError::ExternalVerificationFailed)
            }
        }
        Signer::Delegated(addr) => e.custom_account().delegate_auth(addr),
    }
}

/// Refuse (`DuplicateSigner`) two of `signers` that are one key: two
/// delegated signers with one address, or two external signers whose
/// verifier canonicalizes their keys to the same bytes. Each verifier is
/// asked once, with every key it verifies, even a lone one, so a key its
/// verifier cannot read is refused too. This is OZ's check; the constructor
/// runs it, since a compiled document's signers already pass it (the
/// compiler refuses a key that is not its verifier's canonical form and two
/// signers with one verifier and key).
pub(crate) fn check_distinct(e: &Env, signers: &Vec<Signer>) {
    let mut groups: Map<Address, Vec<Val>> = Map::new(e);
    let mut delegated: Vec<Address> = Vec::new(e);
    for signer in signers.iter() {
        match signer {
            Signer::External(verifier, key) => {
                let mut group = groups.get(verifier.clone()).unwrap_or(Vec::new(e));
                group.push_back(key.into_val(e));
                groups.set(verifier, group);
            }
            Signer::Delegated(addr) => {
                if delegated.contains(&addr) {
                    refuse(e, InstallError::DuplicateSigner);
                }
                delegated.push_back(addr);
            }
        }
    }
    for (verifier, keys) in groups.iter() {
        let canonical = VerifierClient::new(e, &verifier).batch_canonicalize_key(&keys);
        let mut seen: Vec<Bytes> = Vec::new(e);
        for key in canonical.iter() {
            if seen.contains(&key) {
                refuse(e, InstallError::DuplicateSigner);
            }
            seen.push_back(key);
        }
    }
}

/// Decide a recovery completion, as OZ's `do_check_auth` decided one over a
/// registry holding the recovery rule `recovery` and no other rule. Every
/// chosen id must be `recovery` with the account's record of it
/// (`ContextRuleNotFound`), and every context a call on this account while
/// that rule is unexpired (`UnvalidatedContext`), as OZ checks each context in
/// turn; the payload must name no signer, since the rule has none
/// (`UnauthorizedSigner`). Then each of the rule's policies, the adopted
/// controller, is asked to `enforce` each context with no authenticated
/// signer, and its refusal fails the invocation. The rule it is shown is
/// the record's `ContextRule`, the value OZ's registry gave it.
pub fn authorize_completion(
    e: &Env,
    recovery: u32,
    payload: &AuthPayload,
    contexts: &Vec<Context>,
) -> Result<(), soroban_sdk::Error> {
    let ids = &payload.context_rule_ids;
    if ids.len() != contexts.len() {
        return Err(SmartAccountError::ContextRuleIdsLengthMismatch.into());
    }
    let me = e.current_contract_address();
    let rule = record(e, recovery);
    for (i, context) in contexts.iter().enumerate() {
        let rule = rule
            .as_ref()
            .filter(|r| r.id == ids.get_unchecked(i as u32))
            .ok_or(SmartAccountError::ContextRuleNotFound)?;
        let on_me = matches!(&context, Context::Contract(ContractContext { contract, .. }) if *contract == me);
        if expired(e, rule.valid_until)
            || !on_me
            || rule.context_type != ContextRuleType::CallContract(me.clone())
        {
            return Err(SmartAccountError::UnvalidatedContext.into());
        }
    }
    if !payload.signers.is_empty() {
        return Err(SmartAccountError::UnauthorizedSigner.into());
    }
    if let Some(rule) = rule {
        let rule = rule.context_rule(e);
        for context in contexts.iter() {
            for policy in rule.policies.iter() {
                PolicyClient::new(e, &policy).enforce(&context, &Vec::new(e), &rule, &me);
            }
        }
    }
    Ok(())
}

/// The account's record of its recovery rule, if `recovery` is its id. The
/// records' entry is extended, as OZ extends the rule entry it reads.
fn record(e: &Env, recovery: u32) -> Option<InstalledRule> {
    let rules = PerchStorage::get_installed_rules(e)?;
    PerchStorage::extend_installed_rules_ttl(
        e,
        SMART_ACCOUNT_TTL_THRESHOLD,
        SMART_ACCOUNT_EXTEND_AMOUNT,
    );
    rules.iter().find(|r| r.recovery && r.id == recovery)
}
