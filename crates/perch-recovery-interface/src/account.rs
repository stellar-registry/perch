//! Account-side constants `docs/recovery/spec.md` fixes.

use soroban_sdk::{Env, Symbol};

/// Ledgers in one day at the nominal 5-second close time. Used only to
/// *define* ledger-count constants below; nothing converts a duration a
/// user supplied in seconds.
pub const LEDGERS_PER_DAY_NOMINAL: u32 = 17_280;

/// The account-upgrade delay: ledgers between scheduling an upgrade and the
/// earliest ledger it may execute (`docs/recovery/spec.md` §12). Defined in ledgers; it is seven days only while ledgers close
/// every five seconds, and the delay is enforced in ledgers regardless.
pub const ACCOUNT_UPGRADE_DELAY_LEDGERS: u32 = 7 * LEDGERS_PER_DAY_NOMINAL;

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
pub const RESERVED_INVOKER_ONLY_FNS: [&str; 7] = [
    "install",
    "uninstall",
    "enforce",
    "rcv_sync",
    "rcv_cancel",
    "rcv_upgrade",
    "rcv_insert",
];

/// Whether `fn_name` is in [`RESERVED_INVOKER_ONLY_FNS`].
pub fn is_reserved_invoker_only(e: &Env, fn_name: &Symbol) -> bool {
    RESERVED_INVOKER_ONLY_FNS
        .iter()
        .any(|name| Symbol::new(e, name) == *fn_name)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn upgrade_delay_is_seven_nominal_days_in_ledgers() {
        assert_eq!(ACCOUNT_UPGRADE_DELAY_LEDGERS, 120_960);
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
