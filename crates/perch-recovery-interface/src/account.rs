//! Account-side constants `docs/recovery/spec.md` fixes, and the account
//! surface the recovery controller calls.

use soroban_sdk::{contractclient, contracttype, Address, Bytes, BytesN, Env, Symbol};

/// Ledgers in one day at the nominal 5-second close time. Used only to
/// *define* ledger-count constants below; nothing converts a duration a
/// user supplied in seconds.
pub const LEDGERS_PER_DAY_NOMINAL: u32 = 17_280;

/// The account-upgrade delay: ledgers between scheduling an upgrade and the
/// earliest ledger it may execute (`docs/recovery/spec.md` §12). Defined in
/// ledgers; it is seven days only while ledgers close every five seconds,
/// and the delay is enforced in ledgers regardless.
pub const ACCOUNT_UPGRADE_DELAY_LEDGERS: u32 = 7 * LEDGERS_PER_DAY_NOMINAL;

/// One pending account upgrade (spec §12).
///
/// Staleness is judged against the account's own **recovery generation**, a
/// `u64` the account keeps in its own storage. It starts at 0 and is never
/// reset. It advances on every `rcv_sync` outcome other than `Unchanged`
/// (`controller::SyncOutcome::bumps_generation`) and on every executed
/// upgrade.
///
/// The controller's epoch cannot play this role. It belongs to one
/// controller and does not exist while the account is unenrolled, so a
/// request scheduled unenrolled would survive enrolling recovery and
/// removing it again: the final state has no controller, just as at
/// scheduling.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeRequest {
    /// Per-account, never reused.
    pub request_id: u64,
    /// The exact Wasm the account will run.
    pub wasm_hash: BytesN<32>,
    /// The account's recovery generation when the request was scheduled.
    pub generation: u64,
    /// The adopted controller's epoch when scheduled, if a controller was
    /// adopted. Passed back as `UpgradeStep::Execute` so the controller can
    /// check it too.
    pub controller_epoch: Option<u64>,
    /// The first ledger at which the request may execute.
    pub executable_at: u32,
}

/// Whether a pending upgrade may execute now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeReadiness {
    /// The delay has passed and nothing invalidated the request.
    Ready,
    /// The delay has not passed yet.
    NotYet,
    /// The recovery generation moved since scheduling. The request is dead
    /// and is cleared.
    Stale,
}

impl UpgradeRequest {
    /// A request scheduled at ledger `now`, executable
    /// [`ACCOUNT_UPGRADE_DELAY_LEDGERS`] later. `None` if that overflows
    /// `u32`.
    pub fn schedule(
        request_id: u64,
        wasm_hash: BytesN<32>,
        generation: u64,
        controller_epoch: Option<u64>,
        now: u32,
    ) -> Option<Self> {
        Some(UpgradeRequest {
            request_id,
            wasm_hash,
            generation,
            controller_epoch,
            executable_at: now.checked_add(ACCOUNT_UPGRADE_DELAY_LEDGERS)?,
        })
    }

    /// Staleness first: a request from an older generation is dead whether
    /// or not its delay has passed.
    pub fn readiness(&self, now: u32, generation: u64) -> UpgradeReadiness {
        if generation != self.generation {
            UpgradeReadiness::Stale
        } else if now < self.executable_at {
            UpgradeReadiness::NotYet
        } else {
            UpgradeReadiness::Ready
        }
    }
}

/// Functions the account must only ever authorize as the **direct invoker**
/// (Soroban invoker-contract authorization), never through `__check_auth`,
/// and never reach through its `execute` wrapper.
///
/// Every one of these runs `account.require_auth()` to mean "this account's
/// own code is making this call as part of a controlled flow". A signature
/// can satisfy `require_auth()` too, so the account's `__check_auth` refuses
/// any context naming one of these functions on *any* contract, and
/// `execute` refuses to call one — otherwise a document rule scoped to a
/// controller, a policy, or the pool would let its signers call these
/// directly (perch issue #90). Matching by name rather than by contract
/// address also covers controllers and policies the account adopted in the
/// past.
///
/// - `install`, `uninstall`, `enforce`: OZ `Policy` lifecycle hooks, called
///   by the account while (re)installing rules and from `do_check_auth`.
/// - `rcv_sync`: the controller hook `apply_doc` calls to apply a recovery
///   configuration transition (enroll, reconfigure, remove, complete).
/// - `rcv_cancel`: the controller hook for a `Loss` owner's cancellation.
/// - `rcv_upgrade`: the controller hook that checks upgrade evidence.
/// - `rcv_insert`: the pool's account-bound leaf insertion.
/// - `rcv_gate`: the account's own hook through which its adopted
///   controller sets or clears the `Protected` freeze mirror. It requires
///   the controller's authorization, which only the controller's own code
///   can give; listing it here also stops the account from being steered
///   into calling another account's gate.
pub const RESERVED_INVOKER_ONLY_FNS: [&str; 8] = [
    "install",
    "uninstall",
    "enforce",
    "rcv_sync",
    "rcv_cancel",
    "rcv_upgrade",
    "rcv_insert",
    "rcv_gate",
];

/// Whether `fn_name` is in [`RESERVED_INVOKER_ONLY_FNS`].
pub fn is_reserved_invoker_only(e: &Env, fn_name: &Symbol) -> bool {
    RESERVED_INVOKER_ONLY_FNS
        .iter()
        .any(|name| Symbol::new(e, name) == *fn_name)
}

/// Whether the account is frozen at ledger `now` under a freeze mirror set
/// to `frozen_until` (spec §9). `0` means no freeze; the freeze ends on its
/// own at `frozen_until`, the authorized attempt's `expires_at`.
pub fn is_frozen(now: u32, frozen_until: u32) -> bool {
    now < frozen_until
}

/// The account surface the recovery controller calls. The views serve the
/// controller's external entry points (`begin_*`, `publish_baseline`,
/// promotion during evidence submission); no controller hook calls any of
/// them, because the account is already on the call stack whenever it calls
/// a hook and Soroban refuses re-entry.
#[allow(unused)]
#[contractclient(name = "RecoveryAccountClient")]
pub trait RecoveryAccountInterface {
    /// The applied document's canonical bytes (the lost-key snapshot).
    fn applied_doc(e: &Env) -> Option<Bytes>;
    /// `sha256` of [`Self::applied_doc`].
    fn applied_doc_hash(e: &Env) -> Option<BytesN<32>>;
    /// The doc compiler the account is built against; the controller runs
    /// `derive_target` and baseline compilation through it (spec §16).
    fn doc_compiler(e: &Env) -> Address;
    /// Whether a credential fingerprint is in the permanent revoked set.
    fn is_revoked(e: &Env, fingerprint: BytesN<32>) -> bool;
    /// Whether an enrollment id was ever enrolled by this account.
    fn is_enrolled_id(e: &Env, enrollment_id: BytesN<32>) -> bool;
    /// The `request_id` the next `schedule_upgrade` will use.
    fn next_upgrade_request_id(e: &Env) -> u64;
    /// Set (`frozen_until > 0`) or clear (`0`) the `Protected` freeze
    /// mirror for `attempt_id`. Requires the adopted controller's
    /// authorization; refuses any other caller.
    fn rcv_gate(e: &Env, attempt_id: u64, frozen_until: u32);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn upgrade_delay_is_seven_nominal_days_in_ledgers() {
        assert_eq!(ACCOUNT_UPGRADE_DELAY_LEDGERS, 120_960);
    }

    /// The sequence reproduced against the WS3 implementation: schedule
    /// while unenrolled, enroll `Loss` recovery, remove it, wait out the
    /// delay, execute. The final state has no controller, as at scheduling,
    /// but the account's generation moved twice, so the request is stale.
    #[test]
    fn enroll_then_remove_stales_an_unenrolled_upgrade() {
        use crate::controller::SyncOutcome;
        let e = Env::default();
        let mut generation = 0u64;
        let req = UpgradeRequest::schedule(
            0,
            BytesN::from_array(&e, &[0x77; 32]),
            generation,
            None,
            100,
        )
        .unwrap();
        assert_eq!(req.executable_at, 100 + ACCOUNT_UPGRADE_DELAY_LEDGERS);

        for outcome in [SyncOutcome::Enrolled, SyncOutcome::Removed] {
            if outcome.bumps_generation() {
                generation += 1;
            }
        }
        assert_eq!(generation, 2);
        assert_eq!(
            req.readiness(req.executable_at, generation),
            UpgradeReadiness::Stale
        );
    }

    #[test]
    fn unchanged_syncs_leave_a_request_executable() {
        use crate::controller::SyncOutcome;
        let e = Env::default();
        let req =
            UpgradeRequest::schedule(3, BytesN::from_array(&e, &[1; 32]), 5, Some(9), 10).unwrap();
        assert!(!SyncOutcome::Unchanged.bumps_generation());
        assert_eq!(req.readiness(10, 5), UpgradeReadiness::NotYet);
        assert_eq!(
            req.readiness(req.executable_at - 1, 5),
            UpgradeReadiness::NotYet
        );
        assert_eq!(req.readiness(req.executable_at, 5), UpgradeReadiness::Ready);
        assert_eq!(req.readiness(10, 6), UpgradeReadiness::Stale);
        assert!(
            UpgradeRequest::schedule(0, BytesN::from_array(&e, &[1; 32]), 0, None, u32::MAX)
                .is_none()
        );
    }

    #[test]
    fn every_transition_outcome_bumps_the_generation() {
        use crate::controller::{Completion, SyncOutcome};
        let e = Env::default();
        for outcome in [
            SyncOutcome::Enrolled,
            SyncOutcome::Reconfigured,
            SyncOutcome::Removed,
            SyncOutcome::Completed(Completion {
                attempt_id: 1,
                replaced: soroban_sdk::Vec::new(&e),
            }),
        ] {
            assert!(outcome.bumps_generation());
        }
    }

    #[test]
    fn freeze_mirror_ends_at_its_bound() {
        assert!(!is_frozen(5, 0), "0 is no freeze");
        assert!(is_frozen(99, 100));
        assert!(
            !is_frozen(100, 100),
            "frozen_until is exclusive, like expires_at"
        );
    }

    #[test]
    fn reserved_names_match_exactly() {
        let e = Env::default();
        for name in RESERVED_INVOKER_ONLY_FNS {
            assert!(is_reserved_invoker_only(&e, &Symbol::new(&e, name)));
        }
        for name in [
            "transfer",
            "apply_doc",
            "execute",
            "installs",
            "rcv",
            "enforce_",
        ] {
            assert!(!is_reserved_invoker_only(&e, &Symbol::new(&e, name)));
        }
    }

    #[test]
    fn reserved_names_are_valid_symbols() {
        // Symbol::new panics on an invalid symbol; constructing each proves
        // every name is usable as a contract function name.
        let e = Env::default();
        for name in RESERVED_INVOKER_ONLY_FNS {
            let _ = Symbol::new(&e, name);
            assert!(name.len() <= 32);
        }
    }
}
