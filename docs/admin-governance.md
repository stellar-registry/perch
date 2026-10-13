# Contract-admin governance: a 2-of-3 multisig behind a timelock

This document explains how the perch stack's mutable admin surfaces are placed
behind a **2-of-3 multisig** and a **visible upgrade delay**, so that an admin
action (a registry upgrade, a manager change, an admin handoff) is queued in
public, waits out a delay during which anyone can see it coming, and can be
cancelled inside that window.

It covers the admin-authority inventory, the account construction, the timelock
mechanism, the policy document the multisig applies, the cutover, and the one
tooling prerequisite the on-chain multisig path still needs.

## 1. Admin-authority inventory

What actually has a mutable admin/upgrade surface in the perch stack today:

| Surface | Admin entry points | Who holds it (testnet) | Delay today |
| --- | --- | --- | --- |
| `constructorless` registry `CDX2DMYM…` — **the** canonical publishing registry (`vars.PERCH_REGISTRY_CONTRACT_ID`) | `upgrade`, `set_admin`, `set_manager`, `remove_manager` | `GA327GGW` (= local CLI id `perch-demo`) | none — immediate |
| `unverified/perch` registry `CASB2M4J…` — parent namespace subregistry | same | `GA327GGW` | none |
| `stateless` registry `CC6ELNH6…` — **retired** | same | `GA327GGW` | none |
| Nido factory (nidohq/nido) | upgrade | Nido's deploy key | none — immediate (its own threat model flags this) |

Everything else is **immutable or already delayed**, and needs no admin:

- The recovery stack (`perch-recovery` controller, `perch-zk-pool`,
  `perch-zk-adapter`, the verifiers) and the `perch-account-factory` are
  **constructorless and immutable** — no admin, no setters, no upgrade. A new
  build is a new address, never a live mutation (`docs/recovery/migration.md`,
  the factory's module docs).
- `perch-account` already **self-upgrades only through its own timelock**
  (`schedule_upgrade` → `execute_upgrade`, 7-day delay, `docs/recovery/spec.md`
  §12).

So the only immediate, mutable admin surfaces are the three stateless
registries (all held by `GA327GGW`) and the Nido factory. The Nido factory is
in another repo — see §8. The registries are what this change hardens.

Verified read-only on testnet (`stellar contract invoke … --send=no -- admin`
/ `-- manager`): all three registries return `GA327GGW` for both `admin` and
`manager`.

## 2. Account construction: a perch 2-of-3 account (dogfooding)

The multisig is a **perch smart account** created with three admin signers
(`theahaco` + a second hardware key + an offline recovery key), carrying a
2-of-3 policy document. This dogfoods perch rather than using OZ's multisig
policy or a Stellar-native multisig. Why:

- **perch expresses k-of-n cleanly.** A rule's `principals` is
  `{ "type": "threshold", "signers": [...], "m": 2 }`, which the compiler
  lowers to the interpreter op `MinSigners(2)`; `perch-compile`'s
  `threshold_program_enforces_the_quorum` proves a 2-of-3 rule denies 1
  signature and allows 2 or 3. No external threshold policy, no OZ multisig
  policy contract.
- **The account address is permanent.** The factory salts the address with the
  signer set, and the account rotates its own signers via `apply_doc`. So the
  multisig can replace a lost or compromised hardware key **without changing
  its address** — the timelock's `owner` never has to move.
- **It is the same machinery users get.** The admin account is a perch account
  like any wallet, so it inherits perch's audit, recovery, and upgrade story.

Trade-off (see §7): driving the timelock *from* a perch 2-of-3 account
on-chain needs multi-sig OZ auth-entry tooling that does not exist yet. A
Stellar-native 2-of-3 would be signable by stock `stellar` today but would not
dogfood perch. The captain chose the perch account; this document records the
tooling prerequisite that choice carries.

### The policy document (the anti-brick shape)

A self-admin 2-of-3 **cannot be the only admin rule**: perch's `admin_survives`
anti-brick check requires at least one *policy-free* self-admin rule, and a
`threshold` rule is never policy-free (it always attaches the interpreter). So
the multisig's document has **three** rules:

```jsonc
{
  "version": 1,
  "network": "Test SDF Network ; September 2015",
  "signers": [
    { "id": "theahaco", "verifier": "<ed25519-verifier C…>", "key": "<theahaco pubkey hex>" },
    { "id": "hw2",      "verifier": "<ed25519-verifier C…>", "key": "<SECOND HARDWARE pubkey hex>" },
    { "id": "offline",  "verifier": "<ed25519-verifier C…>", "key": "<OFFLINE pubkey hex>" }
  ],
  "rules": [
    // 1. The point: any 2 of 3 drive the timelock (queue/execute/cancel).
    { "name": "timelock-ops",
      "scope": { "type": "contract", "address": "<TIMELOCK C…>" },
      "principals": { "type": "threshold", "signers": ["theahaco","hw2","offline"], "m": 2 },
      "functions": ["queue","execute","cancel"] },
    // 2. Any 2 of 3 may also rotate the account's own signers (so a lost key
    //    is recoverable by the other two).
    { "name": "admin-quorum",
      "scope": { "type": "self-admin" },
      "principals": { "type": "threshold", "signers": ["theahaco","hw2","offline"], "m": 2 } },
    // 3. Mandatory policy-free self-admin rule (anti-brick). It is 3-of-3, i.e.
    //    strictly STRONGER than the quorum, so it never lowers the floor.
    { "name": "admin-full",
      "scope": { "type": "self-admin" },
      "principals": { "type": "all", "signers": ["theahaco","hw2","offline"] } }
  ]
}
```

`theahaco`'s public key is `GAMPJROHOAW662FINQ4XQOY2ULX5IEGYXCI4SMZYE75EHQBR6PSTJG3M`
(convert the strkey to the 32-byte hex the signer `key` field wants). **The
captain must provide the other two public keys** — the second hardware key and
the offline recovery key — which do not exist yet. Until they do, the document
above is parameterized.

## 3. The timelock (`perch-admin-timelock`)

A minimal, owner-gated timelock — the external-call generalization of the
account's own `schedule_upgrade`/`execute_upgrade`/`cancel_upgrade`:

- `__constructor(owner, delay_ledgers)` — `owner` is the multisig; `delay` is in
  ledgers.
- `queue(target, function, args) -> id` — owner-auth. Records the call with
  `eta = ledger + delay`, emits `Queued{id, target, function, eta}` (public).
- `execute(id)` — owner-auth. Refuses before `eta` (`TooEarly`); invokes
  `target.function(args)` with the timelock as the direct caller.
- `cancel(id)` — owner-auth. A cancelled op can never execute.

All three steps require the multisig's authorization, so every admin action is
a **delayed, cancelable multisig action**. The delay is enforced in **ledgers**,
matching the account's convention: `17 280` ledgers ≈ 24h at the nominal
5-second close (mainnet); a few ledgers is seconds (testnet rehearsals).

### Why a contract can be the registry's admin

The registry gates its admin entry points with `admin.require_auth()`
(admin-sep `Administratable`). Soroban satisfies `require_auth` for a *contract*
address by **invoker auth**: when the timelock calls `registry.upgrade(..)`
directly, the registry's `require_auth` of the timelock passes because the
timelock is the direct caller. **No registry change is needed.** This is proven
twice:

- `perch-admin-timelock`'s `owner_invoker_auth_reaches_admin` unit test:
  with only the owner's `execute` authorized (nothing authorizing the target's
  admin), the admin call still lands.
- `integration-tests/tests/admin_timelock.rs`
  (`registry_admin_moves_behind_the_timelock`): against the **real** stateless
  registry — transfer admin to the timelock, then `set_manager` lands only
  through the timelock, one ledger early fails, a cancelled `set_admin` never
  takes effect, and the pre-cutover key can no longer act directly.

## 4. The cutover

Moving a registry behind the multisig is a single `set_admin`, signed by the
current admin (`GA327GGW` = `perch-demo`):

```
registry.set_admin(new_admin = <TIMELOCK>)
```

admin-sep's `set_admin` is **single-step** (no transfer/accept handshake), so it
is **irreversible once the timelock holds the key**: if the multisig keys are
all lost, the registry admin is bricked. Rehearse on testnet first (done, §6),
and keep the offline recovery key genuinely recoverable. To re-point later
(e.g. a new multisig), queue a `set_admin` through the *existing* timelock.

After the cutover, `set_manager`/`remove_manager` for the registry's manager
rotation also go through the timelock, so the `set_manager(smart account)`
publishing-manager rotation that `docs/testnet-deployment.md` still lists as
pending becomes a delayed, cancelable multisig action too.

## 5. Delay values

- **Mainnet: ~24h = `17280` ledgers.** Long enough for users and integrators to
  see an upgrade coming and react.
- **Testnet: minutes.** e.g. `12`–`120` ledgers (~1–10 min). The rehearsal used
  `10` ledgers (~50s) so the whole flow fits one session.

The delay is fixed at construction. A different delay is a new timelock (and a
new `set_admin` through the old one).

## 6. Testnet rehearsal

Rehearsed end-to-end on testnet with throwaway keys and a **fresh** registry
instance (never the canonical registries, never `GA327GGW`,
never `perch-beta-deployer` as admin) — see
[`admin-governance-rehearsal.md`](admin-governance-rehearsal.md) for the
recorded run, and `scripts/admin-timelock-rehearsal.sh` to reproduce it.

## 7. The one tooling prerequisite (on-chain multisig path)

The cutover (§4) is signed by a **classic** key (`perch-demo`), which stock
`stellar` handles. But **driving the timelock from the 2-of-3 perch account**
— the multisig authorizing `queue`/`execute`/`cancel` — needs an OZ
smart-account approval (an `AuthPayload` selecting a rule id, with 2 signatures
over the payload). Today:

- `perch-deploy apply` signs OZ approvals, but only for `apply_doc` and only
  with a **single** key (`PERCH_ADMIN_KEY`).
- Stock `stellar` cannot sign OZ smart-account approvals at all (the reason
  `perch-deploy` exists).

So before the real cutover there must be tooling to build a **2-of-3 OZ
auth-entry** for an arbitrary `timelock.{queue,execute,cancel}` call — a modest
extension of `perch-deploy`'s existing auth machinery (arbitrary
target/function + collect N signatures selecting the `timelock-ops` rule). This
is independent of the contract in this change and is a prerequisite the captain
must resolve (or substitute a Stellar-native multisig as owner) before the
multisig can operate the timelock on-chain. The rehearsal therefore uses a
classic stand-in key as the timelock `owner`; the 2-of-3 enforcement itself is
proven in the Rust tests (§2, §3).

## 8. Nido factory (follow-up)

The Nido factory's upgrade is immediate and lives in `nidohq/nido`, not here.
Routing it behind this same multisig + timelock is a **follow-up PR in
nidohq/nido**: point the factory's upgrade admin at a timelock owned by this
multisig (or re-use this one), exactly as the registry cutover does. It is
called out here so the stack-wide admin story is complete; it is out of scope
for this repo's PR.
