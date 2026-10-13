# Admin timelock — testnet rehearsal record

A full end-to-end rehearsal of the admin timelock + registry governance flow,
run on testnet on 2026-10-13 with **throwaway keys** and a **fresh** registry
instance. It never touched the canonical registries, `GA327GGW`/`perch-demo`,
or `perch-beta-deployer`. Reproduce with `scripts/admin-timelock-rehearsal.sh`.
(Testnet resets quarterly, so these addresses are ephemeral; re-run after a
reset.)

## Actors (all throwaway)

| Role | Key / address |
| --- | --- |
| deployer + timelock owner (classic stand-in for the multisig) | `m1-deployer` = `GABBV3WXSLJ5RG7MG3NMCCJ6IQ7QQQV37US52BYE4PDSVACDTEYVR7JC` |
| signer stand-in "theahaco" | `m1-sig-theahaco` = `GAKVPGZ72VV7YEIWIDQYK6O4U26ME2GY574C5SCOENRURHHWH6LIEUJQ` |
| signer stand-in "hw2" | `m1-sig-hw2` = `GAFCFL2V3574MEQOG534T5MS7LOG76QDMRFODSVWFTKPMJASCQJ2A4P5` |
| signer stand-in "offline" | `m1-sig-offline` = `GBKIX2U6M3MR2K3D2ILPVGOPLHF32D5EUL44P4P7YKX3CPQHJD5Z6QE3` |

## Contracts deployed

| Contract | Address |
| --- | --- |
| fresh stateless registry (admin=manager=deployer) | `CBO6Z77XIUVUUS4QZNI2G7VOMH5PZ4CCF5W5PQKCYEUC4D5L45RTMXJ4` |
| admin timelock (owner=deployer, delay=10 ledgers) | `CAPNIAIS5F2NQZ7MUAIN45ASC4IMSSMCIGAH7A2XGFDRBR2VKVQW5H67` |
| 2-of-3 perch account (3 throwaway signers, salt `aa…aa`) | `CDU4R4IXTZOVEHOW3LTRII5P3755VDTSRPFJMFJ2ETOOEECZQBI5UMV3` |

## Steps and outcomes

1. **Cutover.** `registry.set_admin(timelock)` — the registry's `admin` moved
   from `GABBV3WX…` (deployer) to `CAPNIAIS…` (the timelock). Confirmed by
   reading `admin` back.
   tx `cbc04ae2e47e98cddd5cfb0f785903238ca6478539df83f890249e1c436d5c94`.
2. **Old admin loses control** — a direct `set_manager` by the pre-cutover key
   now fails (its auth no longer satisfies `require_admin`). (Proven in the
   integration test; implied on-chain by the admin read above.)
3. **Queue.** `timelock.queue(registry, "remove_manager", [])` → op id `0`,
   `eta = 5177752`, `status = Queued` (current ledger was `5177742`, delay 10).
4. **Too early.** `timelock.execute(0)` at ledger `< eta` → `HostError:
   Error(Contract, #4)` = `TimelockError::TooEarly`. The operation stayed
   `Queued`.
5. **Execute after the delay.** At ledger `5177752`, `timelock.execute(0)` →
   Success, emitted `Executed{id:0}`; the registry's `manager` became `null`
   (the delayed `remove_manager` landed via the timelock's invoker auth, with
   only the owner's `execute` authorized). Op `status` → `Executed`.
   tx `5dcc13e027da8e22f6d1668bf72532965be43c6e32ddde9221f16bca62cf9fd0`.
6. **Cancel.** `timelock.queue(…)` → op id `1`; `timelock.cancel(1)` → Success,
   emitted `Cancelled{id:1}`, `status = Cancelled`. Then `timelock.execute(1)`
   → `Error(Contract, #3)` = `TimelockError::NotQueued`: a cancelled op can
   never execute.
7. **Multisig construction.** `factory.create(salt, [3 External ed25519
   signers])` deployed the 2-of-3 account at `CDU4R4IX…`, exactly the address
   `factory.address_of` predicted offline. `applied_doc_hash` is `null`: the
   account carries only its bootstrap 3-of-3 admin rule. Applying the 2-of-3
   document, and having the account sign the timelock calls, needs the
   multi-sig OZ auth-entry tooling described in
   [`admin-governance.md`](admin-governance.md) §7 — out of scope for the
   rehearsal, which used a classic stand-in owner.

Error codes are `perch_admin_timelock::TimelockError` in declaration order:
`TimingOverflow=1, UnknownOperation=2, NotQueued=3, TooEarly=4`.

Explorer: `https://stellar.expert/explorer/testnet/tx/<hash>`.
