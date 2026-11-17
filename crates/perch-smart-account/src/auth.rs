//! Signature checks, and the boundary with OZ's context-rule registry.
//!
//! [`authenticate`] checks one payload signer's signature. The account's
//! authorization types are `perch-account-types`', the XDR and contract-spec
//! twins of OZ's; OZ's registry still holds the account's rule ids and
//! signers, and [`oz`] converts to and from its types at that boundary.

use perch_account_types::{AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccountError};
use soroban_sdk::unwrap::UnwrapInfallible;
use soroban_sdk::{
    contractclient, crypto::Hash, panic_with_error, Bytes, Env, IntoVal, Map, TryFromVal, Val, Vec,
};

const DAY_IN_LEDGERS: u32 = 17280;
/// The TTL, in ledgers, that `__check_auth` extends an entry it reads to:
/// OZ's, so the account's entries live as long as the OZ entries beside them.
pub const SMART_ACCOUNT_EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
/// The TTL below which `__check_auth` extends an entry it reads.
pub const SMART_ACCOUNT_TTL_THRESHOLD: u32 = SMART_ACCOUNT_EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Fail the invocation with `error`. While OZ's registry is linked, OZ's
/// own `SmartAccountError` (these codes and the registry's) is in the
/// contract spec. Raising the code as a plain `soroban_sdk::Error` keeps a
/// second spec entry of that name out, as only a `#[contracterror]` type
/// raised or returned at the boundary gets one.
fn fail(e: &Env, error: SmartAccountError) -> ! {
    panic_with_error!(e, soroban_sdk::Error::from(error))
}

/// A signature verifier's entry point, as `authenticate` calls it.
#[allow(unused)]
#[contractclient(name = "VerifierClient")]
trait Verifier {
    fn verify(e: &Env, hash: Bytes, key_data: Val, sig_data: Val) -> bool;
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

/// OZ's twins of the account's types, for its context-rule registry. Each
/// pair is the same host value, so a vector or map is passed by its handle
/// and a struct or enum is rebuilt from its parts: no conversion makes a
/// host call.
pub(crate) mod oz {
    use super::*;
    use stellar_accounts::smart_account as oz;

    pub(crate) fn signers(e: &Env, signers: &Vec<Signer>) -> Vec<oz::Signer> {
        Vec::try_from_val(e, &signers.to_object()).unwrap_infallible()
    }

    pub(crate) fn context_type(t: &ContextRuleType) -> oz::ContextRuleType {
        match t.clone() {
            ContextRuleType::Default => oz::ContextRuleType::Default,
            ContextRuleType::CallContract(a) => oz::ContextRuleType::CallContract(a),
            ContextRuleType::CreateContract(h) => oz::ContextRuleType::CreateContract(h),
            ContextRuleType::CreateContractExternalRef(owner, tag) => {
                oz::ContextRuleType::CreateContractExternalRef(owner, tag)
            }
        }
    }

    pub(crate) fn payload(e: &Env, p: &AuthPayload) -> oz::AuthPayload {
        oz::AuthPayload {
            signers: Map::try_from_val(e, &p.signers.to_object()).unwrap_infallible(),
            context_rule_ids: p.context_rule_ids.clone(),
        }
    }

    pub(crate) fn context_rule(e: &Env, r: oz::ContextRule) -> ContextRule {
        ContextRule {
            id: r.id,
            context_type: match r.context_type {
                oz::ContextRuleType::Default => ContextRuleType::Default,
                oz::ContextRuleType::CallContract(a) => ContextRuleType::CallContract(a),
                oz::ContextRuleType::CreateContract(h) => ContextRuleType::CreateContract(h),
                oz::ContextRuleType::CreateContractExternalRef(owner, tag) => {
                    ContextRuleType::CreateContractExternalRef(owner, tag)
                }
            },
            name: r.name,
            signers: Vec::try_from_val(e, &r.signers.to_object()).unwrap_infallible(),
            signer_ids: r.signer_ids,
            policies: r.policies,
            policy_ids: r.policy_ids,
            valid_until: r.valid_until,
        }
    }
}
