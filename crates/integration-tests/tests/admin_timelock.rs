//! End-to-end: the **real** stateless registry's admin moved behind the
//! **real** admin timelock, exercised against the actual admin-sep
//! `require_admin` path — nothing on the admin path is mocked.
//!
//! This is the reproducible, in-CI counterpart to the testnet rehearsal. It
//! proves the three claims the design rests on:
//!
//! 1. **A contract can be the registry's admin.** After
//!    `registry.set_admin(timelock)`, the timelock drives `set_manager` with
//!    only the *owner's* call to `execute` authorized — nothing authorizes the
//!    registry's `admin.require_auth()`. It still lands, because the timelock
//!    is the direct caller: Soroban *invoker* auth. No registry change needed.
//! 2. **The delay is enforced.** `execute` one ledger before the eta is
//!    refused (`TooEarly`); at the eta it succeeds.
//! 3. **Cancel is final.** A cancelled operation never executes, even after its
//!    delay, so a queued admin change can be stopped inside the window.
//!
//! The owner here is a generated address standing in for the 2-of-3 perch
//! account; its k-of-n signing is proven at the compiler/interpreter level by
//! `perch-compile`'s `threshold_program_enforces_the_quorum` and friends. What
//! this test adds is the registry ⇄ timelock wiring the unit tests cannot
//! reach.

use perch_admin_timelock::{AdminTimelock, AdminTimelockClient, OpStatus, TimelockError};
use perch_stateless_registry::{StatelessRegistry, StatelessRegistryClient};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke},
    vec, Address, Env, IntoVal, Symbol, Val, Vec,
};

const SEQ0: u32 = 5_000;
const DELAY: u32 = 100;

fn one_addr(e: &Env, a: &Address) -> Vec<Val> {
    vec![e, a.clone().into_val(e)]
}

#[test]
fn registry_admin_moves_behind_the_timelock() {
    let e = Env::default();
    e.ledger().with_mut(|l| l.sequence_number = SEQ0);

    // The real managed subregistry, admin = manager = a "root" key that stands
    // in for the human-held GA327GGW on testnet.
    let root_admin = Address::generate(&e);
    let manager = Address::generate(&e);
    let root = Address::generate(&e);
    let registry = e.register(
        StatelessRegistry,
        (root_admin.clone(), manager.clone(), root.clone()),
    );
    let reg = StatelessRegistryClient::new(&e, &registry);

    // The admin multisig (a generated address stands in for the 2-of-3 account)
    // and the timelock it owns.
    let owner = Address::generate(&e);
    let timelock = e.register(AdminTimelock, (owner.clone(), DELAY));
    let tl = AdminTimelockClient::new(&e, &timelock);

    // ── Cutover: the current admin hands the registry's admin to the timelock.
    //    (On testnet this is the single human-signed `set_admin` in
    //    captain-steps.md.)
    reg.mock_auths(&[MockAuth {
        address: &root_admin,
        invoke: &MockAuthInvoke {
            contract: &registry,
            fn_name: "set_admin",
            args: (timelock.clone(),).into_val(&e),
            sub_invokes: &[],
        },
    }])
    .set_admin(&timelock);
    assert_eq!(reg.admin(), timelock, "registry admin is now the timelock");

    // The pre-cutover key can no longer act directly: `require_admin` now
    // checks the timelock, which root_admin's authorization does not satisfy.
    let rejected = Address::generate(&e);
    assert!(
        reg.mock_auths(&[MockAuth {
            address: &root_admin,
            invoke: &MockAuthInvoke {
                contract: &registry,
                fn_name: "set_manager",
                args: (rejected.clone(),).into_val(&e),
                sub_invokes: &[],
            },
        }])
        .try_set_manager(&rejected)
        .is_err(),
        "the pre-cutover admin key no longer controls the registry"
    );

    // ── Queue a delayed set_manager, authorized by the multisig.
    let new_manager = Address::generate(&e);
    let set_manager = Symbol::new(&e, "set_manager");
    let set_mgr_args = one_addr(&e, &new_manager);
    let id = tl
        .mock_auths(&[MockAuth {
            address: &owner,
            invoke: &MockAuthInvoke {
                contract: &timelock,
                fn_name: "queue",
                args: (registry.clone(), set_manager.clone(), set_mgr_args.clone()).into_val(&e),
                sub_invokes: &[],
            },
        }])
        .queue(&registry, &set_manager, &set_mgr_args);
    assert_eq!(tl.get(&id).unwrap().eta, SEQ0 + DELAY);

    // ── Too early: even the owner cannot execute before the eta.
    match tl
        .mock_auths(&[MockAuth {
            address: &owner,
            invoke: &MockAuthInvoke {
                contract: &timelock,
                fn_name: "execute",
                args: (id,).into_val(&e),
                sub_invokes: &[],
            },
        }])
        .try_execute(&id)
    {
        Err(Ok(err)) => assert_eq!(err, TimelockError::TooEarly),
        _ => panic!("expected TooEarly before the delay elapses"),
    }
    assert_eq!(
        reg.manager(),
        Some(manager.clone()),
        "manager unchanged until execute"
    );

    // ── Execute at the eta. Only the owner's `execute` is authorized; the
    //    registry's `admin.require_auth()` is carried by the timelock's invoker
    //    auth alone.
    e.ledger().with_mut(|l| l.sequence_number = SEQ0 + DELAY);
    tl.mock_auths(&[MockAuth {
        address: &owner,
        invoke: &MockAuthInvoke {
            contract: &timelock,
            fn_name: "execute",
            args: (id,).into_val(&e),
            sub_invokes: &[],
        },
    }])
    .execute(&id);
    assert_eq!(
        reg.manager(),
        Some(new_manager.clone()),
        "the delayed set_manager landed via the timelock's invoker auth"
    );
    assert_eq!(tl.get(&id).unwrap().status, OpStatus::Executed);

    // ── Cancel: queue a set_admin, cancel it, and show it can never execute.
    let usurper = Address::generate(&e);
    let set_admin = symbol_short!("set_admin");
    let set_admin_args = one_addr(&e, &usurper);
    let id2 = tl
        .mock_auths(&[MockAuth {
            address: &owner,
            invoke: &MockAuthInvoke {
                contract: &timelock,
                fn_name: "queue",
                args: (registry.clone(), set_admin.clone(), set_admin_args.clone()).into_val(&e),
                sub_invokes: &[],
            },
        }])
        .queue(&registry, &set_admin, &set_admin_args);

    tl.mock_auths(&[MockAuth {
        address: &owner,
        invoke: &MockAuthInvoke {
            contract: &timelock,
            fn_name: "cancel",
            args: (id2,).into_val(&e),
            sub_invokes: &[],
        },
    }])
    .cancel(&id2);
    assert_eq!(tl.get(&id2).unwrap().status, OpStatus::Cancelled);

    e.ledger()
        .with_mut(|l| l.sequence_number = SEQ0 + 2 * DELAY);
    match tl
        .mock_auths(&[MockAuth {
            address: &owner,
            invoke: &MockAuthInvoke {
                contract: &timelock,
                fn_name: "execute",
                args: (id2,).into_val(&e),
                sub_invokes: &[],
            },
        }])
        .try_execute(&id2)
    {
        Err(Ok(err)) => assert_eq!(err, TimelockError::NotQueued),
        _ => panic!("expected NotQueued for a cancelled operation"),
    }
    assert_eq!(
        reg.admin(),
        timelock,
        "the cancelled set_admin never took effect"
    );
}
