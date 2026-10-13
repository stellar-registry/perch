//! Unit tests for the timelock lifecycle, and a self-contained proof that a
//! target's `admin.require_auth()` is satisfied by the timelock's *invoker*
//! auth — the mechanism that lets the registry be governed by a timelock with
//! no registry code change. The full multisig → timelock → registry flow is in
//! `crates/integration-tests/tests/admin_timelock.rs`.

use crate::{AdminTimelock, AdminTimelockClient, OpStatus, TimelockError};
use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke},
    vec, Address, Env, IntoVal, Val, Vec,
};

/// A stand-in admin-gated target. `bump` is open; `admin_set` requires the
/// stored admin's auth, so a call to it only succeeds if the caller is (or is
/// authorized as) that admin.
#[contract]
struct Target;

#[contractimpl]
impl Target {
    pub fn __constructor(e: &Env, admin: Address) {
        e.storage().instance().set(&symbol_short!("ADMIN"), &admin);
    }

    pub fn bump(e: &Env, n: u32) -> u32 {
        let cur: u32 = e.storage().instance().get(&symbol_short!("N")).unwrap_or(0);
        let next = cur + n;
        e.storage().instance().set(&symbol_short!("N"), &next);
        next
    }

    pub fn admin_set(e: &Env, n: u32) {
        let admin: Address = e.storage().instance().get(&symbol_short!("ADMIN")).unwrap();
        admin.require_auth();
        e.storage().instance().set(&symbol_short!("N"), &n);
    }

    pub fn count(e: &Env) -> u32 {
        e.storage().instance().get(&symbol_short!("N")).unwrap_or(0)
    }
}

const SEQ0: u32 = 1_000;
const DELAY: u32 = 10;

struct Fixture {
    e: Env,
    owner: Address,
    timelock: Address,
    tl: AdminTimelockClient<'static>,
    target: Address,
}

/// A timelock at ledger `SEQ0` with a `DELAY`-ledger delay, owned by a fresh
/// address, plus an admin-gated `Target` whose admin is the timelock.
fn setup() -> Fixture {
    let e = Env::default();
    e.ledger().with_mut(|l| l.sequence_number = SEQ0);
    let owner = Address::generate(&e);
    let timelock = e.register(AdminTimelock, (owner.clone(), DELAY));
    let tl = AdminTimelockClient::new(&e, &timelock);
    let target = e.register(Target, (timelock.clone(),));
    Fixture {
        e,
        owner,
        timelock,
        tl,
        target,
    }
}

fn bump_args(e: &Env, n: u32) -> Vec<Val> {
    vec![e, n.into_val(e)]
}

/// Queue → wait out the delay → execute: the target runs, and the operation
/// moves Queued → Executed.
#[test]
fn queue_then_execute_after_delay() {
    let f = setup();
    f.e.mock_all_auths();
    let target_client = TargetClient::new(&f.e, &f.target);

    let id =
        f.tl.queue(&f.target, &symbol_short!("bump"), &bump_args(&f.e, 7));
    assert_eq!(id, 0);
    assert_eq!(f.tl.get(&id).unwrap().status, OpStatus::Queued);
    assert_eq!(f.tl.get(&id).unwrap().eta, SEQ0 + DELAY);
    assert_eq!(target_client.count(), 0, "nothing runs at queue time");

    f.e.ledger().with_mut(|l| l.sequence_number = SEQ0 + DELAY);
    f.tl.execute(&id);

    assert_eq!(target_client.count(), 7, "the target ran at execute time");
    assert_eq!(f.tl.get(&id).unwrap().status, OpStatus::Executed);
}

/// Execute before the eta ledger is refused, and leaves the operation Queued.
#[test]
fn execute_before_eta_is_too_early() {
    let f = setup();
    f.e.mock_all_auths();
    let id =
        f.tl.queue(&f.target, &symbol_short!("bump"), &bump_args(&f.e, 7));

    // One ledger short of the eta.
    f.e.ledger()
        .with_mut(|l| l.sequence_number = SEQ0 + DELAY - 1);
    match f.tl.try_execute(&id) {
        Err(Ok(e)) => assert_eq!(e, TimelockError::TooEarly),
        _ => panic!("expected TooEarly"),
    }
    assert_eq!(
        f.tl.get(&id).unwrap().status,
        OpStatus::Queued,
        "a too-early execute leaves the operation queued"
    );

    // Exactly at the eta it is allowed.
    f.e.ledger().with_mut(|l| l.sequence_number = SEQ0 + DELAY);
    f.tl.execute(&id);
    assert_eq!(f.tl.get(&id).unwrap().status, OpStatus::Executed);
}

/// A cancelled operation can never execute, even after its delay.
#[test]
fn cancel_blocks_execute() {
    let f = setup();
    f.e.mock_all_auths();
    let target_client = TargetClient::new(&f.e, &f.target);
    let id =
        f.tl.queue(&f.target, &symbol_short!("bump"), &bump_args(&f.e, 7));

    f.tl.cancel(&id);
    assert_eq!(f.tl.get(&id).unwrap().status, OpStatus::Cancelled);

    f.e.ledger().with_mut(|l| l.sequence_number = SEQ0 + DELAY);
    match f.tl.try_execute(&id) {
        Err(Ok(e)) => assert_eq!(e, TimelockError::NotQueued),
        _ => panic!("expected NotQueued"),
    }
    assert_eq!(target_client.count(), 0, "a cancelled op never runs");
}

/// An operation cannot execute twice.
#[test]
fn execute_is_single_shot() {
    let f = setup();
    f.e.mock_all_auths();
    let id =
        f.tl.queue(&f.target, &symbol_short!("bump"), &bump_args(&f.e, 7));
    f.e.ledger().with_mut(|l| l.sequence_number = SEQ0 + DELAY);
    f.tl.execute(&id);
    match f.tl.try_execute(&id) {
        Err(Ok(e)) => assert_eq!(e, TimelockError::NotQueued),
        _ => panic!("expected NotQueued on the second execute"),
    }
}

/// Executing or cancelling an id that was never queued is refused.
#[test]
fn unknown_operation_is_refused() {
    let f = setup();
    f.e.mock_all_auths();
    match f.tl.try_execute(&99) {
        Err(Ok(e)) => assert_eq!(e, TimelockError::UnknownOperation),
        _ => panic!("expected UnknownOperation on execute"),
    }
    assert_eq!(
        f.tl.try_cancel(&99),
        Err(Ok(TimelockError::UnknownOperation))
    );
}

/// Cancelling an already-cancelled operation is refused.
#[test]
fn cancel_is_single_shot() {
    let f = setup();
    f.e.mock_all_auths();
    let id =
        f.tl.queue(&f.target, &symbol_short!("bump"), &bump_args(&f.e, 7));
    f.tl.cancel(&id);
    assert_eq!(f.tl.try_cancel(&id), Err(Ok(TimelockError::NotQueued)));
}

/// Ids are monotonic and never reused across queues.
#[test]
fn ids_are_monotonic() {
    let f = setup();
    f.e.mock_all_auths();
    let a =
        f.tl.queue(&f.target, &symbol_short!("bump"), &bump_args(&f.e, 1));
    let b =
        f.tl.queue(&f.target, &symbol_short!("bump"), &bump_args(&f.e, 1));
    let c =
        f.tl.queue(&f.target, &symbol_short!("bump"), &bump_args(&f.e, 1));
    assert_eq!((a, b, c), (0, 1, 2));
}

/// A queued eta that overflows `u32` is refused rather than wrapping.
#[test]
fn eta_overflow_is_refused() {
    let e = Env::default();
    e.mock_all_auths();
    let owner = Address::generate(&e);
    // Max delay, and a ledger near the ceiling, so `sequence + delay` overflows.
    let timelock = e.register(AdminTimelock, (owner.clone(), u32::MAX));
    let tl = AdminTimelockClient::new(&e, &timelock);
    let target = e.register(Target, (timelock.clone(),));
    e.ledger().with_mut(|l| l.sequence_number = 5);
    assert_eq!(
        tl.try_queue(&target, &symbol_short!("bump"), &bump_args(&e, 1)),
        Err(Ok(TimelockError::TimingOverflow))
    );
}

/// The heart of the design: with ONLY the owner's `execute` authorized — and
/// nothing authorizing the target's `admin.require_auth()` — the admin call
/// still lands. The timelock is the direct caller of the target, so the
/// target's `require_auth` of the timelock passes by *invoker* auth. This is
/// why the registry can be governed by a timelock with no registry change.
#[test]
fn owner_invoker_auth_reaches_admin() {
    let f = setup();
    let target_client = TargetClient::new(&f.e, &f.target);

    // Queue the admin-gated call under permissive auth, then wait out the delay.
    f.e.mock_all_auths();
    let id =
        f.tl.queue(&f.target, &symbol_short!("admin_set"), &bump_args(&f.e, 42));
    f.e.ledger().with_mut(|l| l.sequence_number = SEQ0 + DELAY);

    // Execute authorizing ONLY the owner's call to `execute`. No entry
    // authorizes the Target's admin (= the timelock); if it still runs, invoker
    // auth is what carried it.
    f.tl.mock_auths(&[MockAuth {
        address: &f.owner,
        invoke: &MockAuthInvoke {
            contract: &f.timelock,
            fn_name: "execute",
            args: (id,).into_val(&f.e),
            sub_invokes: &[],
        },
    }])
    .execute(&id);

    assert_eq!(target_client.count(), 42);
    assert_eq!(f.tl.get(&id).unwrap().status, OpStatus::Executed);
}

/// Without the owner's authorization, `queue` is refused. (Combined with the
/// invoker-auth test above, this shows queue/execute/cancel are owner-gated.)
#[test]
fn queue_requires_owner_auth() {
    let f = setup();
    // Enforcing mock mode with no entries: no require_auth can be satisfied.
    f.e.set_auths(&[]);
    assert!(
        f.tl.try_queue(&f.target, &symbol_short!("bump"), &bump_args(&f.e, 1))
            .is_err(),
        "queue must fail without the owner's authorization"
    );
}
