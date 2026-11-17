//! Signature checks, signer identity, and the boundary with OZ's
//! `do_check_auth`.
//!
//! [`authenticate`] checks one payload signer's signature, and
//! [`check_distinct`] refuses two signers that are one key. The account's
//! authorization types are `perch-account-types`', the XDR and contract-spec
//! twins of OZ's. OZ's `do_check_auth` still decides a recovery completion
//! over entries of its own registry, and [`oz`] keeps the ones it reads.

use perch_account_types::{AuthPayload, ContextRule, Signer, SmartAccountError};
use soroban_sdk::{
    contractclient, crypto::Hash, panic_with_error, Address, Bytes, Env, IntoVal, Map, Val, Vec,
};

use crate::rules::{refuse, InstallError};

const DAY_IN_LEDGERS: u32 = 17280;
/// The TTL, in ledgers, that `__check_auth` extends an entry it reads to:
/// OZ's, so the account's entries live as long as the OZ entries beside them.
pub const SMART_ACCOUNT_EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
/// The TTL below which `__check_auth` extends an entry it reads.
pub const SMART_ACCOUNT_TTL_THRESHOLD: u32 = SMART_ACCOUNT_EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Fail the invocation with `error`. While OZ's `do_check_auth` is linked,
/// OZ's own `SmartAccountError` (these codes and the registry's) is in the
/// contract spec. Raising the code as a plain `soroban_sdk::Error` keeps a
/// second spec entry of that name out, as only a `#[contracterror]` type
/// raised or returned at the boundary gets one.
fn fail(e: &Env, error: SmartAccountError) -> ! {
    panic_with_error!(e, soroban_sdk::Error::from(error))
}

/// A signature verifier's entry points, as the account calls them.
#[allow(unused)]
#[contractclient(name = "VerifierClient")]
trait Verifier {
    fn verify(e: &Env, hash: Bytes, key_data: Val, sig_data: Val) -> bool;
    fn batch_canonicalize_key(e: &Env, key_data: Vec<Val>) -> Vec<Bytes>;
}

/// A policy's install hook, as OZ's registry calls it: the recovery
/// controller's `install` checks the recovery rule it is installed on.
#[allow(unused)]
#[contractclient(name = "PolicyClient")]
trait Policy {
    fn install(e: &Env, install_params: Val, context_rule: ContextRule, smart_account: Address);
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

/// What OZ's `do_check_auth` reads to decide a recovery completion
/// (`check_auth`): the recovery rule's entry in OZ's registry and its one
/// policy's. The account writes exactly these two, in OZ's storage layout,
/// whenever its recovery rule is installed, moved to a new id, or given a
/// new controller, and removes them with it. Nothing else of OZ's registry
/// is written.
pub(crate) mod oz {
    use super::*;
    use soroban_sdk::{contracttype, String};
    use stellar_accounts::smart_account::{self as oz, ContextRuleEntry, SmartAccountStorageKey};

    /// The recovery rule's one policy's id in OZ's registry.
    const RECOVERY_POLICY: u32 = 0;

    /// OZ's registry entry for a policy (`stellar-accounts`' `PolicyEntry`,
    /// which it does not export): the same fields, so the same XDR.
    #[contracttype]
    struct PolicyEntry {
        policy: Address,
        count: u32,
    }

    pub(crate) fn payload(e: &Env, p: &AuthPayload) -> oz::AuthPayload {
        use soroban_sdk::{unwrap::UnwrapInfallible, TryFromVal};
        oz::AuthPayload {
            signers: Map::try_from_val(e, &p.signers.to_object()).unwrap_infallible(),
            context_rule_ids: p.context_rule_ids.clone(),
        }
    }

    /// Write the recovery rule `id` with policy `controller`, as OZ's
    /// `add_context_rule` would: a zero-signer rule scoped to the account.
    pub(crate) fn install_recovery(e: &Env, id: u32, controller: &Address) {
        let rule = SmartAccountStorageKey::ContextRuleData(id);
        let policy = SmartAccountStorageKey::PolicyData(RECOVERY_POLICY);
        let storage = e.storage().persistent();
        storage.set(
            &rule,
            &ContextRuleEntry {
                name: String::from_str(e, "recovery"),
                context_type: oz::ContextRuleType::CallContract(e.current_contract_address()),
                valid_until: None,
                signer_ids: Vec::new(e),
                policy_ids: Vec::from_array(e, [RECOVERY_POLICY]),
            },
        );
        storage.set(
            &policy,
            &PolicyEntry {
                policy: controller.clone(),
                count: 1,
            },
        );
        let ttl = e.storage().max_ttl();
        storage.extend_ttl(&rule, ttl, ttl);
        storage.extend_ttl(&policy, ttl, ttl);
    }

    /// Remove recovery rule `id`'s entries.
    pub(crate) fn remove_recovery(e: &Env, id: u32) {
        let storage = e.storage().persistent();
        storage.remove(&SmartAccountStorageKey::ContextRuleData(id));
        storage.remove(&SmartAccountStorageKey::PolicyData(RECOVERY_POLICY));
    }
}
