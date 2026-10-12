# Testnet exercise of the stack

The deployed stack ([`deployments/testnet.json`](../../deployments/testnet.json))
run through every recovery profile and mode, on testnet, by
`cargo run -p perch-testnet`. Nothing is mocked.

- **Contracts**: the deployed wasm, at the addresses the manifest names.
  Accounts come from the deployed factory.
- **Owners**: passkeys, as software secp256r1 keys producing real WebAuthn
  assertions. The deployed WebAuthn verifier checks them inside the
  account's `__check_auth`.
- **Guardians**: fresh G-accounts that sign their own authorization entries.
- **Proofs**: real UltraHonk proofs from the pinned nargo/bb, over witnesses
  rebuilt from the deployed pool's on-chain leaves.
- **Activity**: ordinary activity is an XLM transfer from the account,
  authorized directly and through `execute`.
- **Refusals**: every step that must fail is simulated against live state
  and never submitted. Each records which simulation refused it. In the
  *recording* simulation the contract refuses before any signature matters
  (a rejected proof, a stale attempt). In the *enforcing* simulation every
  entry is signed and the account's `__check_auth` runs. Where the contract
  returns an error code, the code is checked. Each `Protected` freeze refusal
  is checked to be the account's own `AccountFrozen` (`#2`) from
  `__check_auth`, read from the host's diagnostics.
- **Keys**: every key derives from OS randomness that is never recorded, so
  the report's accounts cannot be taken over from it.

The raw record, with every transaction hash, is
[`deployments/testnet-exercise.json`](../../deployments/testnet-exercise.json).
The tables below are `scripts/exercise-report.py` of it.

| Scenario | Profile / mode | Covers |
| --- | --- | --- |
| zk-loss | `Loss` / `ZkOnly` | lost-key recovery with a real proof; another attempt's proof, a `Cancel` proof, a tampered proof, an unknown root, a replay, and the consumed credential all refused; activity during the window; completion after the delay with ZK rotation; the lost passkey revoked |
| combined | `Protected` / `Combined` | G-account guardians plus a proof authorize; the freeze on direct auth, `execute`, and `apply_doc`; cancellation by the condition (two guardians and a `Cancel` proof); reconfiguration needing both factors |
| zk-protected | `Protected` / `ZkOnly` | owner-only reconfiguration and upgrade refused; a proof for another configuration refused; `Reconfigure` and `Upgrade` proofs; the seven-day upgrade delay |
| guardian-loss | `Loss` / `GuardianOnly` | no ZK anywhere; the owner's veto of an authorized attempt; a guardian on an authorized attempt refused; completion |
| combined-loss | `Loss` / `Combined` | both factors, in either order; activity during the window; completion with ZK rotation |
| compromise | `Protected` / `GuardianOnly` | compromise recovery: a thief with the owner key adds a signer; `publish_baseline` of another document refused; the guardians restore the baseline with a new key; the stolen key and the thief's signer revoked, and re-adding the thief refused |
| relay | `Loss` / `GuardianOnly` | a perch account as a guardian, approving through a delegated key (CAP-0071 `AddressWithDelegates`) via `perch-relay`; three forged approvals refused at relay admission; the genuine one promotes the attempt, and the recovery completes |

Not on testnet: executing an upgrade (its 120 960-ledger delay is a week),
and an enrollment that seals a tree (a full tree takes 2^32 insertions). The
release-stack suite covers both on the same wasm, in-process: it upgrades
after the delay, and it enrolls into the last slot of a synthesized full
tree, then rotates into the next one and proves from it.

## Reproducibility

Building the stack from `source.commit` with the recorded toolchain gives
every hash in the manifest. For this record (`7ae915d`, a commit on `main`)
that was checked on 2026-10-09 on the deploying machine (macOS arm64). A
fresh clone of the commit at another path, built by `build-stack.sh` with
the manifest's builder (`scaffold`) and registry and the recorded toolchain
(rustc 1.97.1, stellar 27.0.0, scaffold 0.0.27), reproduced all ten
artifacts' hashes. Building on other hosts and toolchains has not been
checked: `stellar scaffold build` optimizes with the wasm-opt its version
ships.

## Findings

- **Completions must be simulated with their authorization entry.** In
  recording-mode simulation the controller's `enforce` never runs, so
  `rcv_sync` refuses the completion as a change during the window. See
  [`README.md`](README.md#simulating-a-recovery-completion). Wallets and
  relays (nidohq/nido) need to build the recovery-rule entry themselves.
- **The same version is different bytes in the canonical registry.** The
  infra contracts this record publishes into its own registry instance
  carry the versions `release.yml` also published canonically, into
  `unverified/perch/constructorless`. Interpreter 0.1.3, compiler 0.3.1,
  spending limit 0.1.2, and ed25519 verifier 10.0.0 all appear in both
  places, but the bytes differ. `release.yml` builds through
  stellar-registry/actions' attested release build, while
  `build-stack.sh` runs its own scaffold build. For example, interpreter
  0.1.3 is `2254f17d…` here and `e4d7fb8d…` canonically. Resolve infra by
  this manifest's hash or address, never by `(name, version)` across
  registries.
- **Rent dominates fees.** Enrollment writes the pool's leaf and enrollment
  entries, the controller's configuration, and the account's applied
  document, all extended to the maximum TTL (3 110 400 ledgers, about 180
  days), and costs about 6–7.5 XLM. A promoting proof or approval persists
  the authorized attempt, about 2.1 XLM. Resource fees alone are a few
  hundredths of an XLM.

## Results

Run `1791582053` against `deployments/testnet.json` (stack commit `7ae915dc1ac6`), ledgers 5111694–5111823: 81 transactions submitted, 31 refusals checked, 0 scenario failures. Fees paid: 78.9806 XLM.

### Against the budget

Worst measured transaction per row of `docs/recovery/budgets.md` §2, as a share of the protocol-29 per-transaction limits (400,000,000 instructions, 400 footprint entries, 200 written entries, 132,096 write bytes, 132,096 bytes of transaction). Budget: 75% of each. Memory is not reported by the RPC; the release-stack suite meters it locally.

| Row | Worst step | Instructions | Footprint entries | Written entries | Write bytes | Tx size | Fee (XLM) | Latency (s) | Within budget |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Enroll ZK through `apply_doc` | enroll Combined through apply_doc | 64,707,224 (16.2%) | 34 (8.5%) | 17 (8.5%) | 8,352 (6.3%) | 6,400 (4.8%) | 6.9056 | 4.7 | yes |
| `begin_lost_key` | begin_lost_key | 21,159,993 (5.3%) | 17 (4.2%) | 2 (1.0%) | 1,236 (0.9%) | 2,084 (1.6%) | 0.2254 | 4.7 | yes |
| `begin_compromise` | begin_compromise | 16,490,355 (4.1%) | 17 (4.2%) | 2 (1.0%) | 1,236 (0.9%) | 2,008 (1.5%) | 0.2250 | 3.1 | yes |
| `publish_baseline` | publish_baseline | 6,728,134 (1.7%) | 10 (2.5%) | 1 (0.5%) | 776 (0.6%) | 1,504 (1.1%) | 1.2293 | 4.7 | yes |
| `submit_guardian` | submit_guardian (2 of 2, promoting; a delegated perch guardian, relayed) | 3,941,974 (1.0%) | 16 (4.0%) | 5 (2.5%) | 1,532 (1.2%) | 2,240 (1.7%) | 2.4259 | 3.4 | yes |
| `submit_zk` | submit_zk (Combined, promoting; sets the freeze) | 124,928,841 (31.2%) | 17 (4.2%) | 5 (2.5%) | 2,388 (1.8%) | 18,176 (13.8%) | 2.3966 | 3.4 | yes |
| Completion `apply_doc` | completion apply_doc (Combined, ZK rotation) | 65,505,293 (16.4%) | 40 (10.0%) | 29 (14.5%) | 10,336 (7.8%) | 6,720 (5.1%) | 1.6390 | 3.1 | yes |
| Owner cancellation (`Loss`) | Loss owner cancel_recovery (the veto) | 6,942,176 (1.7%) | 14 (3.5%) | 4 (2.0%) | 1,252 (0.9%) | 2,084 (1.6%) | 0.0032 | 4.7 | yes |
| `approve_change` | approve_change (G-account, 2 of 2) | 1,627,842 (0.4%) | 8 (2.0%) | 2 (1.0%) | 404 (0.3%) | 1,468 (1.1%) | 0.0047 | 4.6 | yes |
| `submit_zk_change` | submit_zk_change (Reconfigure) | 123,088,802 (30.8%) | 12 (3.0%) | 1 (0.5%) | 240 (0.2%) | 17,832 (13.5%) | 0.0322 | 6.7 | yes |
| `Protected` reconfiguration `apply_doc` | Protected Combined reconfiguration apply_doc | 25,072,307 (6.3%) | 25 (6.2%) | 12 (6.0%) | 5,588 (4.2%) | 5,736 (4.3%) | 0.0422 | 4.7 | yes |
| `Protected` `schedule_upgrade` | Protected schedule_upgrade | 6,922,054 (1.7%) | 13 (3.2%) | 2 (1.0%) | 1,144 (0.9%) | 2,044 (1.5%) | 0.0187 | 4.7 | yes |
| Ordinary activity (direct authorization) | the new passkey after recovery | 5,376,465 (1.3%) | 10 (2.5%) | 3 (1.5%) | 440 (0.3%) | 1,752 (1.3%) | 0.0651 | 3.4 | yes |
| Ordinary activity (`execute`) | ordinary activity: execute | 6,006,083 (1.5%) | 10 (2.5%) | 3 (1.5%) | 440 (0.3%) | 1,888 (1.4%) | 0.0027 | 4.7 | yes |
| Factory `create_passkey` | factory create_passkey | 2,456,813 (0.6%) | 10 (2.5%) | 5 (2.5%) | 1,500 (1.1%) | 992 (0.8%) | 0.8684 | 3.1 | yes |

Native proving, 11 proofs (`nargo execute` + `bb prove`, the pinned toolchain): witness 68 ms median / 95 ms max, proof 97 ms median / 110 ms max, peak RSS 49 MiB.

### zk-only / loss: lost-key recovery with a real proof

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,452,960 | 0.8683 | [`e94db76f10…`](https://stellar.expert/explorer/testnet/tx/e94db76f10348c6adf7e78754aa2411d105021ad2ea755b414f0afc3b885c96a) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0605 | [`14db5d492e…`](https://stellar.expert/explorer/testnet/tx/14db5d492e0435a40d13614221e1b2c83a160cbdc54bdf1833d987884325dfa3) |
| enroll ZkOnly through apply_doc (pool insert) | ok | 62,471,419 | 8.5943 | [`eb83823b9e…`](https://stellar.expert/explorer/testnet/tx/eb83823b9e14ae5e57e8756036b55634a1a9133baa462b86cd43fee31b1041a3) |
| ordinary activity: direct authorization | ok | 5,375,625 | 0.0683 | [`0ae1ec1bec…`](https://stellar.expert/explorer/testnet/tx/0ae1ec1bec978d906f6b06579402863625ad18822df5949fe544a6f20c0e5d7e) |
| ordinary activity: execute | ok | 6,006,083 | 0.0027 | [`c6beaaa31f…`](https://stellar.expert/explorer/testnet/tx/c6beaaa31fa815156d4a68438e17615ec4e2e4a49ac43522b0cb60666a070b89) |
| begin_lost_key | ok | 18,736,080 | 0.2252 | [`6fd3e3a73f…`](https://stellar.expert/explorer/testnet/tx/6fd3e3a73f784be7fc4356eb011e17c856d3619739ed10d8993c1474dcdb3ddc) |
| begin_lost_key (a second, evidence-free attempt) | ok | 18,750,703 | 0.0038 | [`e40e98e746…`](https://stellar.expert/explorer/testnet/tx/e40e98e7462bd9d8f393992003addcb73242d08fcc96f9639c76e53e6b620763) |
| activity while attempts collect | ok | 5,374,336 | 0.0026 | [`78e49eee34…`](https://stellar.expert/explorer/testnet/tx/78e49eee34e4829d49487afa15aa287bb7d2d225378a7d4f08d5869f16951d3a) |
| another attempt's proof | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a Cancel proof submitted as Initiate | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a tampered proof | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a root the pool never had | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| submit_zk (real proof; authorizes the attempt) | ok | 124,177,562 | 2.2521 | [`fb821769cb…`](https://stellar.expert/explorer/testnet/tx/fb821769cb1d4737cf7aeb3aaf4c716e1ae4d756698787ec0340f06317e85494) |
| the same proof again | refused (recording simulation): `HostError: Error(Contract, #5)` | | | |
| Loss: activity during the authorized window | ok | 5,374,336 | 0.0026 | [`2973783f2b…`](https://stellar.expert/explorer/testnet/tx/2973783f2b44ef5f2ec2907f05a23df78d03fedda48f789f1b7c2fcf260995b5) |
| Loss: an owner policy change during the window | refused (recording simulation): `HostError: Error(Contract, #25)` | | | |
| completion before the delay | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #6` | | | |
| completion with other bytes than the target | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #7` | | | |
| completion apply_doc (spends the nullifier, rotates the leaf) | ok | 63,211,574 | 1.6383 | [`7f4eaff268…`](https://stellar.expert/explorer/testnet/tx/7f4eaff268656dea2eb69fcfae8dfedbd28db85938c9c5626f00e9bac05839e3) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,375,766 | 0.0651 | [`b58e3f45b7…`](https://stellar.expert/explorer/testnet/tx/b58e3f45b7931525c02c7f6914aa8daf0e436b8c947840c7053cfe9735517c92) |
| begin_lost_key (after recovery) | ok | 18,753,311 | 0.0038 | [`3cd5850379…`](https://stellar.expert/explorer/testnet/tx/3cd5850379852efcd6c49b2c61337546e812fbab489c0637b074ed6cfb1a997e) |
| a proof by the consumed credential | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
### combined / protected: freeze, cancellation, reconfiguration

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,452,960 | 0.8683 | [`914e82db34…`](https://stellar.expert/explorer/testnet/tx/914e82db346a5dce7ae820f65d3474635f21ada8dd7af82f5c4f7919a7692430) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0605 | [`077d9584be…`](https://stellar.expert/explorer/testnet/tx/077d9584be3cd865308718a15841824dca062ff496c9a4920f3fd974d0e95136) |
| enroll Combined through apply_doc | ok | 64,707,224 | 6.9056 | [`8dead878fc…`](https://stellar.expert/explorer/testnet/tx/8dead878fcc8e064110640b3c5f37ed0662190f824dd8aa04e6e84340972ddf0) |
| begin_lost_key | ok | 21,159,993 | 0.2254 | [`478c35dce8…`](https://stellar.expert/explorer/testnet/tx/478c35dce8d44406f0ae01470fde07f1cab90812a4839cf8e1a3446b5f8b8dcf) |
| submit_guardian (G-account, 1 of 2) | ok | 1,863,586 | 0.0020 | [`16bb7d1464…`](https://stellar.expert/explorer/testnet/tx/16bb7d1464ebc489a96a92a3f9bfedd21faeea019fa6443846b4416072dcaa41) |
| submit_guardian (G-account, 2 of 2) | ok | 1,867,389 | 0.0020 | [`29b3bcecb7…`](https://stellar.expert/explorer/testnet/tx/29b3bcecb7b809d9c7c1dcb4fe13083d8ee4b1762fdf85694252f7713dd765fa) |
| activity before the condition is met | ok | 5,375,625 | 0.0683 | [`1462409d3e…`](https://stellar.expert/explorer/testnet/tx/1462409d3e0688ce2269d1b6d11cef9faa1c288b112fbe8dc7d7e15993ec5417) |
| submit_zk (Combined, promoting; sets the freeze) | ok | 124,928,841 | 2.3966 | [`cae2c1fc47…`](https://stellar.expert/explorer/testnet/tx/cae2c1fc47e14fb2ee4b60ffa04c78764fcb0b246f35ce696bf0e87dfee65610) |
| frozen: direct authorization | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: execute | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: apply_doc | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| an Initiate proof submitted as Cancel | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| cancel: guardian 1 of 2 | ok | 1,979,696 | 0.0721 | [`0057671049…`](https://stellar.expert/explorer/testnet/tx/005767104929b2cb8efad9c765fa38b1ce0c387b390543f660dac6fd9d4ed8c8) |
| cancel: guardian 2 of 2 | ok | 1,983,809 | 0.0721 | [`31b4dc93f7…`](https://stellar.expert/explorer/testnet/tx/31b4dc93f78c5b21fa6aa85b2673e377d6f939b02d0d38b8f5194a06372ac400) |
| cancellation (Combined: the ZK Cancel proof completes it, clears the freeze) | ok | 124,323,348 | 0.2278 | [`92aa36f88c…`](https://stellar.expert/explorer/testnet/tx/92aa36f88c2452d9191c3ac42c5d659a7dcd22105d3e16bed036b8d47cd0aa6f) |
| activity after the cancellation | ok | 5,374,336 | 0.0026 | [`5207403a42…`](https://stellar.expert/explorer/testnet/tx/5207403a4263102308c5f0e7ddd09ee5addee442662424bcf6fd500b5d1612f2) |
| execute after the cancellation | ok | 6,006,083 | 0.0027 | [`afc3316e9b…`](https://stellar.expert/explorer/testnet/tx/afc3316e9b65b50cc024d26f8fbe5750a147a79f6059e064b8eabbf160889e76) |
| submit_zk_change (Reconfigure) | ok | 123,060,660 | 0.0322 | [`963875008a…`](https://stellar.expert/explorer/testnet/tx/963875008a5b9dbd270c8386016e3f46b2da472043682c698460aa0cf8d58741) |
| reconfiguration with ZK evidence alone | refused (recording simulation): `HostError: Error(Contract, #39)` | | | |
| approve_change (G-account, 1 of 2) | ok | 1,624,064 | 0.0046 | [`487abe8865…`](https://stellar.expert/explorer/testnet/tx/487abe8865d02d65cc74055f4e9376f1aeb0eb7aa50e9a8955463cce393f8f6d) |
| approve_change (G-account, 2 of 2) | ok | 1,627,842 | 0.0047 | [`ec8ed9cca3…`](https://stellar.expert/explorer/testnet/tx/ec8ed9cca3f9ff13589cce852d9a89c174f4a4bbf455583960ee9ef2bc6dee2a) |
| Protected Combined reconfiguration apply_doc | ok | 25,072,307 | 0.0422 | [`63d21e9c77…`](https://stellar.expert/explorer/testnet/tx/63d21e9c77e0b810444135335c74c19e33109ad3f5e6462395de85ada2f1c006) |
### zk-only / protected: reconfiguration and upgrade evidence

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,452,960 | 0.8683 | [`141c01c133…`](https://stellar.expert/explorer/testnet/tx/141c01c13365a088568946f23fa550037cfa7b32d450e206014cde22369c305a) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0605 | [`0438125d72…`](https://stellar.expert/explorer/testnet/tx/0438125d72ed8894feaa836e7514f7501765d6dc44332e2ce76f592d8c1ddca9) |
| enroll ZkOnly Protected | ok | 62,478,656 | 6.2664 | [`a16d72ee40…`](https://stellar.expert/explorer/testnet/tx/a16d72ee4087c31ee90803f2ff0fa35ddbc551077e6797fa765b1ac5e02adc07) |
| owner alone cannot reconfigure | refused (recording simulation): `HostError: Error(Contract, #39)` | | | |
| a proof for another configuration | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| submit_zk_change (Reconfigure) | ok | 123,088,802 | 0.0322 | [`0a2397a6e7…`](https://stellar.expert/explorer/testnet/tx/0a2397a6e70572a1617f73de7fdef3814ce49a2923d113c60ff30a2cff81364b) |
| Protected reconfiguration apply_doc | ok | 22,804,098 | 0.0418 | [`3b5a2f22fa…`](https://stellar.expert/explorer/testnet/tx/3b5a2f22fa82adb4eacf7399e41348d8f06cdeb5a7f4cc1ea67713e442cc84f0) |
| owner alone cannot schedule an upgrade | refused (recording simulation): `HostError: Error(Contract, #39)` | | | |
| submit_zk_change (Upgrade) | ok | 123,048,681 | 0.0322 | [`d39961d235…`](https://stellar.expert/explorer/testnet/tx/d39961d235c7a31f1872f4ed68fd31d29c34094850583862b8b397bcd268f305) |
| Protected schedule_upgrade | ok | 6,922,054 | 0.0187 | [`ff5cf5938a…`](https://stellar.expert/explorer/testnet/tx/ff5cf5938aa2325433fc55177e76be4863036f7eb9a3f344b24c7e29f0956ba8) |
| execute_upgrade before the seven-day delay | refused (recording simulation): `HostError: Error(Contract, #9)` | | | |
### guardian-only / loss: veto and completion, no ZK

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,452,960 | 0.8684 | [`a96ce01810…`](https://stellar.expert/explorer/testnet/tx/a96ce01810fed676ecf5182198cc8846b84c0167e5a0d8995b283c384d544613) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0606 | [`8cfd2d7659…`](https://stellar.expert/explorer/testnet/tx/8cfd2d7659b1daa8cc5dd0b370017f9629045fdd9e6157a9649cb06dd689cd7b) |
| enroll GuardianOnly through apply_doc | ok | 19,632,699 | 4.7668 | [`ce66eafde2…`](https://stellar.expert/explorer/testnet/tx/ce66eafde21429f850c920632f9500b6e7815cf34f4621b757dbe3a79829131a) |
| begin_lost_key | ok | 15,941,184 | 0.2249 | [`c84785900d…`](https://stellar.expert/explorer/testnet/tx/c84785900da0f97a02388c5bef9e356c7866c4300aca4473a85ee6cd388433b6) |
| submit_guardian (1 of 2) | ok | 1,835,327 | 0.0020 | [`4433927550…`](https://stellar.expert/explorer/testnet/tx/443392755030750e3ce9648fe231484a7659f9e0918a57244a7720794af537b6) |
| submit_guardian (2 of 2, promoting) | ok | 2,739,272 | 2.3195 | [`9f7f932b9a…`](https://stellar.expert/explorer/testnet/tx/9f7f932b9a8c2d6326157c96541846bf21afb256186d3585920cddcacf044c4c) |
| a third guardian on an authorized attempt | refused (recording simulation): `HostError: Error(Contract, #5)` | | | |
| Loss owner cancel_recovery (the veto) | ok | 6,942,176 | 0.0032 | [`e11db66216…`](https://stellar.expert/explorer/testnet/tx/e11db66216fe3876e96aaac606b6e30b0df67156bae3fb030cb02e1c9d200412) |
| begin_lost_key (again) | ok | 15,958,348 | 0.0035 | [`f36580af03…`](https://stellar.expert/explorer/testnet/tx/f36580af03386f62c62acbf3a0c35a70cd2f7a2f03851e93ad399c651763ce6a) |
| submit_guardian (1 of 2) | ok | 1,850,236 | 0.0020 | [`7a0d16ccf8…`](https://stellar.expert/explorer/testnet/tx/7a0d16ccf89ba2e835d7514c4f0b34ccdd7f76f450716a7faa6e8d14dfced47b) |
| submit_guardian (2 of 2, promoting) | ok | 2,756,880 | 2.0917 | [`56aea34546…`](https://stellar.expert/explorer/testnet/tx/56aea34546352b8882611187dd62f88a29247f3833b2f989638672d7f236d3b9) |
| completion apply_doc (GuardianOnly) | ok | 19,430,088 | 0.4458 | [`29d509cb31…`](https://stellar.expert/explorer/testnet/tx/29d509cb316ca7288f7b9eaacb0e6a78e3f0286803bdb1813bad4ae410e6aa4f) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,350,091 | 0.0651 | [`5c8d0ff8e2…`](https://stellar.expert/explorer/testnet/tx/5c8d0ff8e21202b681551b4accf7e20d0e08c31f35779150c02924b1369ee79e) |
### combined / loss: both factors, ZK rotation

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,456,813 | 0.8684 | [`210a5e342e…`](https://stellar.expert/explorer/testnet/tx/210a5e342e2eb64aba881ce895b7d63a0a2ecf64c97ec4ecd2f24148f082f5f9) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0606 | [`456a1ac6c1…`](https://stellar.expert/explorer/testnet/tx/456a1ac6c19602829dd2fa72fee8f5276bd4aa6f3862ed88613d6ed268a45f02) |
| enroll Combined Loss | ok | 64,649,445 | 6.8814 | [`2389f3ccf9…`](https://stellar.expert/explorer/testnet/tx/2389f3ccf97c78895f3df8f2238227354d3bd2c5c8245f27bf3f74bbf4082ae4) |
| begin_lost_key | ok | 21,117,065 | 0.2254 | [`58945a58a3…`](https://stellar.expert/explorer/testnet/tx/58945a58a3c29d25784c61a6d2fd0f3c9bde0ae99b654fa28ee9ae52284fa9b5) |
| submit_guardian (1 of 2) | ok | 1,863,619 | 0.0020 | [`9a33ca0b02…`](https://stellar.expert/explorer/testnet/tx/9a33ca0b02b6147ceb0f2aca931fcd7b834bab072e0950c51ea9ac332ae69095) |
| submit_zk (Combined, not yet promoting) | ok | 123,242,610 | 0.0172 | [`4169998495…`](https://stellar.expert/explorer/testnet/tx/41699984954941ad3d1277b1dd2c3e1a519a0eb1858cb68bc74733edff74c157) |
| submit_guardian (2 of 2, promoting: ZK already in) | ok | 2,798,402 | 2.3764 | [`a1c3708296…`](https://stellar.expert/explorer/testnet/tx/a1c3708296d5031f66b4c464de6fc5420a2323a012d04260b9de4b8507af8f0a) |
| Loss: activity during the authorized window | ok | 5,376,324 | 0.0683 | [`410722a853…`](https://stellar.expert/explorer/testnet/tx/410722a853745e969018db48eea29e7dd46f9568df09146c66b8e25c910df11e) |
| completion apply_doc (Combined, ZK rotation) | ok | 65,505,293 | 1.6390 | [`9f05041368…`](https://stellar.expert/explorer/testnet/tx/9f05041368c25f205d55cc19e1a4b587c6a0f5aa9ba694e9f98f3424170a3a4e) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,376,465 | 0.0651 | [`6907164405…`](https://stellar.expert/explorer/testnet/tx/6907164405fa80342777df5000031fa62dcd50d471617b5dbadedc90b430131c) |
### guardian-only / protected: compromise recovery from the baseline

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,450,690 | 0.8684 | [`98d40d8b56…`](https://stellar.expert/explorer/testnet/tx/98d40d8b5655bc2ce8cb51963dbecb55e39defefcd1b4992a461715b1e54be13) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0606 | [`7a28f4804a…`](https://stellar.expert/explorer/testnet/tx/7a28f4804a00f2bbfe91e5f3e530d360be2fe8ee0faf4c27a76e2cc482937628) |
| enroll GuardianOnly Protected with a baseline | ok | 20,699,294 | 4.9884 | [`bd16b986c1…`](https://stellar.expert/explorer/testnet/tx/bd16b986c12df01ee2dea744e9e52f0d695230d86a197fa24fec737552265429) |
| the thief adds a signer with the stolen owner key | ok | 23,439,475 | 1.4417 | [`289999c9ef…`](https://stellar.expert/explorer/testnet/tx/289999c9ef2f49f72e2cdf09d7ded9ca576ae6729d9e127e253c3a4bbe1f75fe) |
| the thief's signer moves XLM | ok | 5,350,722 | 0.1316 | [`1528a160b6…`](https://stellar.expert/explorer/testnet/tx/1528a160b6cf976703261a2d6b71f5bb3a25d5519e36e2d39c86c28a09026c16) |
| begin_compromise before the baseline is published | refused (recording simulation): `HostError: Error(Contract, #23)` | | | |
| publish_baseline of another document | refused (recording simulation): `HostError: Error(Contract, #24)` | | | |
| publish_baseline | ok | 6,728,134 | 1.2293 | [`13e7f3fcc4…`](https://stellar.expert/explorer/testnet/tx/13e7f3fcc4f0193acf3e0ea4e24c686c3aba18f9f1be67a7858f4ffb39e5d362) |
| begin_compromise | ok | 16,490,355 | 0.2250 | [`b537ea4d9a…`](https://stellar.expert/explorer/testnet/tx/b537ea4d9a23ba5bdb820e9332c291082f6ae381f607708d585a973ba1272367) |
| submit_guardian (1 of 2) | ok | 1,839,200 | 0.0020 | [`2866a7a7fa…`](https://stellar.expert/explorer/testnet/tx/2866a7a7faca6e34c4a01c158a6db90a45829e07d124747d44c0680fd1fa4124) |
| submit_guardian (2 of 2, promoting; sets the freeze) | ok | 2,830,201 | 2.3248 | [`e65235d5db…`](https://stellar.expert/explorer/testnet/tx/e65235d5dbb299d44651ed15e0234924c4eeca70517a2dc6b0d17578754b2478) |
| frozen: the thief's signer | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: the owner key | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| completion apply_doc (compromise: revokes the stolen and added keys) | ok | 21,482,954 | 0.6564 | [`9bd932d121…`](https://stellar.expert/explorer/testnet/tx/9bd932d121592bd8bbb9a626adf0217cbb04fd8bb040c0d9357b0b12c810f352) |
| the new owner after recovery | ok | 5,349,340 | 0.0651 | [`7b54b87276…`](https://stellar.expert/explorer/testnet/tx/7b54b8727661e7357355338d4b6ec19b7ce79186e6777333e855b437e74494ac) |
| the stolen owner key after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| re-adding the thief's key, signed by the new owner | refused (recording simulation): `HostError: Error(Contract, #2)` | | | |
### relay: a delegated perch guardian's approval, relayed

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,456,813 | 0.8684 | [`54b7f74a8a…`](https://stellar.expert/explorer/testnet/tx/54b7f74a8ac6ecd3cc16afedf5856f8df28a24a5577fef2647f5a49b50ff2bbe) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0606 | [`851d477887…`](https://stellar.expert/explorer/testnet/tx/851d4778874b05a11b2a2cd8569643b4cb5385fcb0856a1b219bfed5f7a6f650) |
| guardian account: a delegated approver for the controller | ok | 13,142,865 | 2.2146 | [`e56a014b92…`](https://stellar.expert/explorer/testnet/tx/e56a014b923a16e0b5d50553267d1e127b9e17e42d71caa6e7efa7de0b009ae5) |
| factory create_passkey | ok | 2,452,960 | 0.8686 | [`d1db460b17…`](https://stellar.expert/explorer/testnet/tx/d1db460b178b40b90f885d8f658fa19673793adac6781072592126bfe1d25aef) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0606 | [`802a81e614…`](https://stellar.expert/explorer/testnet/tx/802a81e6141d9f75d8605b7b7900f4181831f408b222fa47e1a8c6444121adec) |
| enroll GuardianOnly (a perch account among the guardians) | ok | 19,037,152 | 4.5966 | [`b2ad018f54…`](https://stellar.expert/explorer/testnet/tx/b2ad018f54d308b8ab9a0d9f4f358180cbd9d090db54e93b92f624483426b70b) |
| begin_lost_key | ok | 15,317,218 | 0.2249 | [`53f5fa3ad8…`](https://stellar.expert/explorer/testnet/tx/53f5fa3ad8b3f79094284b33ebc182c229e8c23420700a60070b92bb1bcaaf70) |
| submit_guardian (1 of 2) | ok | 1,833,098 | 0.0020 | [`3be19dd953…`](https://stellar.expert/explorer/testnet/tx/3be19dd9537b819c33f2f3b4f1d2e844671ff8791bbc39a20d6c968a48bee52c) |
| relay: forged approval, another delegate | refused (relay admission): `403 refused in simulation: HostError: Error(Auth, InvalidAction)` | | | |
| relay: forged approval, the approver under a rule it is not in | refused (relay admission): `403 refused in simulation: HostError: Error(Auth, InvalidAction)` | | | |
| relay: forged approval, a tampered delegate signature | refused (relay admission): `403 refused in simulation: HostError: Error(Auth, InvalidAction)` | | | |
| submit_guardian (2 of 2, promoting; a delegated perch guardian, relayed) | ok | 3,941,974 | 2.4259 | [`79d2b19974…`](https://stellar.expert/explorer/testnet/tx/79d2b199744b48ff28f669f84d7fc1e58576514cbc3ae5935dfb113686896729) |
| completion apply_doc (GuardianOnly) | ok | 18,827,766 | 0.4458 | [`c199e14af5…`](https://stellar.expert/explorer/testnet/tx/c199e14af5fc41a2307683311cccf14433278e320d1bfc9c05cb39a2477ffe20) |
| the new passkey after recovery | ok | 5,350,091 | 0.0651 | [`c955eca97f…`](https://stellar.expert/explorer/testnet/tx/c955eca97f1377bcf0148218729d104cbe92bf9d655c21be97135d59b0aba8a4) |
