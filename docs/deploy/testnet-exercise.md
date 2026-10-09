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
every hash in the manifest. For this record (`704aa23`) that was checked on
2026-10-08 on the deploying machine (macOS arm64). `build-stack.sh` with the
manifest's builder (`scaffold`) and registry, run on this branch's tree,
reproduced all ten artifacts' hashes; the tree's contract source is
identical to `704aa23`'s. The rebuild from a fresh `git archive` copy at
another path was done only for the first deployment (`c10a8f7`). Building on
other hosts and toolchains has not been checked: `stellar scaffold build`
optimizes with the wasm-opt its version ships.

## Findings

- **Completions must be simulated with their authorization entry.** In
  recording-mode simulation the controller's `enforce` never runs, so
  `rcv_sync` refuses the completion as a change during the window. See
  [`README.md`](README.md#simulating-a-recovery-completion). Wallets and
  relays (nidohq/nido) need to build the recovery-rule entry themselves.
- **Rent dominates fees.** Enrollment writes the pool's leaf and enrollment
  entries, the controller's configuration, and the account's applied
  document, all extended to the maximum TTL (3 110 400 ledgers, about 180
  days), and costs about 6–7.5 XLM. A promoting proof or approval persists
  the authorized attempt, about 2.1 XLM. Resource fees alone are a few
  hundredths of an XLM.

## Results

Run `1791397477` against `deployments/testnet.json` (stack commit `704aa23f3ceb`), ledgers 5074779–5074909: 81 transactions submitted, 31 refusals checked, 0 scenario failures. Fees paid: 68.2374 XLM.

### Against the budget

Worst measured transaction per row of `docs/recovery/budgets.md` §2, as a share of the protocol-29 per-transaction limits (400,000,000 instructions, 400 footprint entries, 200 written entries, 132,096 write bytes, 132,096 bytes of transaction). Budget: 75% of each. Memory is not reported by the RPC; the release-stack suite meters it locally.

| Row | Worst step | Instructions | Footprint entries | Written entries | Write bytes | Tx size | Fee (XLM) | Latency (s) | Within budget |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Enroll ZK through `apply_doc` | enroll Combined through apply_doc | 64,649,017 (16.2%) | 34 (8.5%) | 17 (8.5%) | 8,324 (6.3%) | 6,392 (4.8%) | 5.9601 | 3.2 | yes |
| `begin_lost_key` | begin_lost_key | 21,096,324 (5.3%) | 17 (4.2%) | 2 (1.0%) | 1,236 (0.9%) | 2,084 (1.6%) | 0.1950 | 3.3 | yes |
| `begin_compromise` | begin_compromise | 16,443,652 (4.1%) | 17 (4.2%) | 2 (1.0%) | 1,236 (0.9%) | 2,008 (1.5%) | 0.1947 | 4.7 | yes |
| `publish_baseline` | publish_baseline | 6,712,421 (1.7%) | 10 (2.5%) | 1 (0.5%) | 776 (0.6%) | 1,504 (1.1%) | 1.0615 | 4.7 | yes |
| `submit_guardian` | submit_guardian (2 of 2, promoting; a delegated perch guardian, relayed) | 3,915,180 (1.0%) | 16 (4.0%) | 5 (2.5%) | 1,532 (1.2%) | 2,240 (1.7%) | 2.0957 | 6.3 | yes |
| `submit_zk` | submit_zk (Combined, promoting; sets the freeze) | 124,849,758 (31.2%) | 17 (4.2%) | 5 (2.5%) | 2,360 (1.8%) | 18,176 (13.8%) | 2.0708 | 4.0 | yes |
| Completion `apply_doc` | completion apply_doc (Combined, ZK rotation) | 65,459,729 (16.4%) | 40 (10.0%) | 29 (14.5%) | 10,308 (7.8%) | 6,712 (5.1%) | 1.4178 | 3.4 | yes |
| Owner cancellation (`Loss`) | Loss owner cancel_recovery (the veto) | 6,923,881 (1.7%) | 14 (3.5%) | 4 (2.0%) | 1,252 (0.9%) | 2,084 (1.6%) | 0.0032 | 4.7 | yes |
| `approve_change` | approve_change (G-account, 2 of 2) | 1,627,621 (0.4%) | 8 (2.0%) | 2 (1.0%) | 404 (0.3%) | 1,468 (1.1%) | 0.0043 | 4.7 | yes |
| `submit_zk_change` | submit_zk_change (Reconfigure) | 123,076,702 (30.8%) | 12 (3.0%) | 1 (0.5%) | 240 (0.2%) | 17,832 (13.5%) | 0.0301 | 3.2 | yes |
| `Protected` reconfiguration `apply_doc` | Protected Combined reconfiguration apply_doc | 25,013,009 (6.3%) | 25 (6.2%) | 12 (6.0%) | 5,560 (4.2%) | 5,728 (4.3%) | 0.0379 | 3.2 | yes |
| `Protected` `schedule_upgrade` | Protected schedule_upgrade | 6,898,916 (1.7%) | 13 (3.2%) | 2 (1.0%) | 1,116 (0.8%) | 2,044 (1.5%) | 0.0165 | 4.7 | yes |
| Ordinary activity (direct authorization) | the new passkey after recovery | 5,363,152 (1.3%) | 10 (2.5%) | 3 (1.5%) | 440 (0.3%) | 1,752 (1.3%) | 0.0565 | 3.2 | yes |
| Ordinary activity (`execute`) | execute after the cancellation | 5,981,489 (1.5%) | 10 (2.5%) | 3 (1.5%) | 440 (0.3%) | 1,888 (1.4%) | 0.0027 | 4.8 | yes |
| Factory `create_passkey` | factory create_passkey | 2,434,056 (0.6%) | 10 (2.5%) | 5 (2.5%) | 1,500 (1.1%) | 992 (0.8%) | 0.7498 | 3.3 | yes |

Native proving on the deploying machine (Apple silicon; see [`docs/zk/measurements.md`](../zk/measurements.md) for the browser and the depth comparison), 11 proofs (`nargo execute` + `bb prove`, the pinned toolchain): witness 70 ms median / 154 ms max, proof 100 ms median / 173 ms max, peak RSS 53 MiB.

### zk-only / loss: lost-key recovery with a real proof

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,434,056 | 0.7498 | [`bf7a05b345…`](https://stellar.expert/explorer/testnet/tx/bf7a05b345899afb3ec8b10fb68bca27187b87a7f3ae72e1ca18452e8fd06d03) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0525 | [`66aab5391f…`](https://stellar.expert/explorer/testnet/tx/66aab5391f445985a21203c687689b2772962a7c0afd429da6076701dd065ea4) |
| enroll ZkOnly through apply_doc (pool insert) | ok | 62,426,302 | 7.4173 | [`1f275a4224…`](https://stellar.expert/explorer/testnet/tx/1f275a4224e0314d1afd5f396e28aa0988dd4ae1be97237979656fe8358e4759) |
| ordinary activity: direct authorization | ok | 5,363,011 | 0.0593 | [`88444c8de3…`](https://stellar.expert/explorer/testnet/tx/88444c8de3eae61b404f5f9a6fc0a1d61f22baeef0d4b5457225d004c4229279) |
| ordinary activity: execute | ok | 5,981,252 | 0.0027 | [`d3eac890fa…`](https://stellar.expert/explorer/testnet/tx/d3eac890fad4d562943ee9ee84ef09555c450002b17599b80150f53e7bd46b70) |
| begin_lost_key | ok | 18,672,643 | 0.1948 | [`4b03b0a8df…`](https://stellar.expert/explorer/testnet/tx/4b03b0a8df49278ef6888924dec2934cbb0f72a0b528362d281963c57b784b5f) |
| begin_lost_key (a second, evidence-free attempt) | ok | 18,685,301 | 0.0038 | [`2874754ce6…`](https://stellar.expert/explorer/testnet/tx/2874754ce60271a180a72930527fd0beff7fd0bfcfd250fa7103de84aa004129) |
| activity while attempts collect | ok | 5,361,722 | 0.0026 | [`004dab5db7…`](https://stellar.expert/explorer/testnet/tx/004dab5db720f70dda2e20075431bd1a6c469adb48d53ab06d9691fb57c94b2a) |
| another attempt's proof | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a Cancel proof submitted as Initiate | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a tampered proof | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a root the pool never had | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| submit_zk (real proof; authorizes the attempt) | ok | 124,179,933 | 1.9460 | [`31bd17ee94…`](https://stellar.expert/explorer/testnet/tx/31bd17ee9444cee4c8bbc8a17ea5e0af71e5b436e69feb23ba6934ae29d40916) |
| the same proof again | refused (recording simulation): `HostError: Error(Contract, #5)` | | | |
| Loss: activity during the authorized window | ok | 5,361,722 | 0.0026 | [`4f9735c29d…`](https://stellar.expert/explorer/testnet/tx/4f9735c29dba51f4b962dee544afd87be84e725f7ead14bd1c20a4e40fce6758) |
| Loss: an owner policy change during the window | refused (recording simulation): `HostError: Error(Contract, #25)` | | | |
| completion before the delay | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #6` | | | |
| completion with other bytes than the target | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #7` | | | |
| completion apply_doc (spends the nullifier, rotates the leaf) | ok | 63,202,465 | 1.4166 | [`5adf42dc25…`](https://stellar.expert/explorer/testnet/tx/5adf42dc25dd8a61e4f8befbbf3f666b127e768c66ca56af34bf4505c7fa2015) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,363,152 | 0.0565 | [`898383ca4f…`](https://stellar.expert/explorer/testnet/tx/898383ca4f5f5b2aa4ba5d27cbe03d222f75ff750b02e727cff97f140fb20e5c) |
| begin_lost_key (after recovery) | ok | 18,687,981 | 0.0038 | [`d37346cbb8…`](https://stellar.expert/explorer/testnet/tx/d37346cbb81106ebd4f2adcaf301c7533584ae8df19c727d70e025a0f24a8687) |
| a proof by the consumed credential | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
### combined / protected: freeze, cancellation, reconfiguration

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,427,933 | 0.7498 | [`9d86705cf0…`](https://stellar.expert/explorer/testnet/tx/9d86705cf040f44a67e508429e0b6c73e61fab6395fb69d5690ca74360d88106) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0525 | [`c5f0a1dc37…`](https://stellar.expert/explorer/testnet/tx/c5f0a1dc3760e624ff07307365b88e3b716ba17c03a091a4eedeada73e94a6b7) |
| enroll Combined through apply_doc | ok | 64,649,017 | 5.9601 | [`6f64a9b041…`](https://stellar.expert/explorer/testnet/tx/6f64a9b04157f0152a30f196c1e1f3b87bdeb3b7220d20f0912a309c5a853bc7) |
| begin_lost_key | ok | 21,096,324 | 0.1950 | [`e0dd971fd0…`](https://stellar.expert/explorer/testnet/tx/e0dd971fd08af528a2bd730db68e2a8f9a99097b66fd32d64ccb77b7f4b71e44) |
| submit_guardian (G-account, 1 of 2) | ok | 1,863,365 | 0.0020 | [`d99d54a7f4…`](https://stellar.expert/explorer/testnet/tx/d99d54a7f43192b0f2f6da0b5344fc372a1d538010063ebdf3baf39e211af115) |
| submit_guardian (G-account, 2 of 2) | ok | 1,867,169 | 0.0020 | [`8bfa1e30fe…`](https://stellar.expert/explorer/testnet/tx/8bfa1e30fede05241bd9674ac9896c3691109281b8fbd6553b0d06434df9fabc) |
| activity before the condition is met | ok | 5,362,312 | 0.0593 | [`4d981b732f…`](https://stellar.expert/explorer/testnet/tx/4d981b732f462da97929388711b5ca791d9d277df4418e86b699d55bf10a3460) |
| submit_zk (Combined, promoting; sets the freeze) | ok | 124,849,758 | 2.0708 | [`19f87826f2…`](https://stellar.expert/explorer/testnet/tx/19f87826f2019ad4c2f646e55411fc32629108e0b99f875828b40b4db04bf394) |
| frozen: direct authorization | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: execute | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: apply_doc | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| an Initiate proof submitted as Cancel | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| cancel: guardian 1 of 2 | ok | 1,979,475 | 0.0625 | [`4a0cf3a06f…`](https://stellar.expert/explorer/testnet/tx/4a0cf3a06f0afbaa18cd019809ebebab161ef11cdf290531cfbe9f3f2402bd3c) |
| cancel: guardian 2 of 2 | ok | 1,983,588 | 0.0625 | [`ac7227ce1a…`](https://stellar.expert/explorer/testnet/tx/ac7227ce1aa48323a0d3898cd41aa48cf0cad9e3c9d1b56043ba36722d4add47) |
| cancellation (Combined: the ZK Cancel proof completes it, clears the freeze) | ok | 124,277,809 | 0.1992 | [`bdac6e8186…`](https://stellar.expert/explorer/testnet/tx/bdac6e8186cd1cf68814646eaddcbcc566c4368b138e58e2d6b7f9b7816bb5b6) |
| activity after the cancellation | ok | 5,361,023 | 0.0026 | [`83d0dc335b…`](https://stellar.expert/explorer/testnet/tx/83d0dc335b043420d995d976e97d09275697ddd2f85f1ef91ee8b66120a1ad4c) |
| execute after the cancellation | ok | 5,981,489 | 0.0027 | [`16aaa0044c…`](https://stellar.expert/explorer/testnet/tx/16aaa0044ca89e32b110c4c243ca6fc21b22067c9443511c578f687d7c7ed3f5) |
| submit_zk_change (Reconfigure) | ok | 123,076,702 | 0.0301 | [`e20313bf96…`](https://stellar.expert/explorer/testnet/tx/e20313bf96d0698a5f78486610c2c5c365761325b0a150737d6e25cd300987df) |
| reconfiguration with ZK evidence alone | refused (recording simulation): `HostError: Error(Contract, #39)` | | | |
| approve_change (G-account, 1 of 2) | ok | 1,623,843 | 0.0043 | [`384e752caa…`](https://stellar.expert/explorer/testnet/tx/384e752caaaaaf8960b4fa5d2c374cf60d6810b9bbe18a7b4062757f9f0a2d07) |
| approve_change (G-account, 2 of 2) | ok | 1,627,621 | 0.0043 | [`3e3620ca1b…`](https://stellar.expert/explorer/testnet/tx/3e3620ca1b6de3bc46dcb33cc76eaf834b431378a572e29a98502406db29f294) |
| Protected Combined reconfiguration apply_doc | ok | 25,013,009 | 0.0379 | [`e64e632847…`](https://stellar.expert/explorer/testnet/tx/e64e632847fe8ee06f09452e513dbc5318b55dfe09f359ec5dc8adf6f2643b60) |
### zk-only / protected: reconfiguration and upgrade evidence

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,434,056 | 0.7502 | [`3d9798fe66…`](https://stellar.expert/explorer/testnet/tx/3d9798fe6613fe6549d0fa109fcfbcb18a7b9bca244dcf4ebe34a910b01231f2) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0525 | [`5c3d8aa3c0…`](https://stellar.expert/explorer/testnet/tx/5c3d8aa3c0cd05350c5cead663cda89c5e1b0d0eec0fa67b23a131d928d2f796) |
| enroll ZkOnly Protected | ok | 62,428,570 | 5.4113 | [`3421d2e435…`](https://stellar.expert/explorer/testnet/tx/3421d2e435b9ab6ebebb37d23fa1f9bcf020b6b9be988f6c9bebf1ce5c4bfec7) |
| owner alone cannot reconfigure | refused (recording simulation): `HostError: Error(Contract, #39)` | | | |
| a proof for another configuration | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| submit_zk_change (Reconfigure) | ok | 123,021,382 | 0.0301 | [`c174b8f6d3…`](https://stellar.expert/explorer/testnet/tx/c174b8f6d3be600b4f61c23e37080377a169386036a6acff01f44c1ed6b2c808) |
| Protected reconfiguration apply_doc | ok | 22,755,186 | 0.0375 | [`900348e08f…`](https://stellar.expert/explorer/testnet/tx/900348e08fbc813b7bac82e1737febd41e03db843276de3678fd1e986556b817) |
| owner alone cannot schedule an upgrade | refused (recording simulation): `HostError: Error(Contract, #39)` | | | |
| submit_zk_change (Upgrade) | ok | 123,034,472 | 0.0302 | [`ca7d606d78…`](https://stellar.expert/explorer/testnet/tx/ca7d606d783debf0ad13c229350587f087a0d0ab77e24502b42832ff4e7cb7f0) |
| Protected schedule_upgrade | ok | 6,898,916 | 0.0165 | [`9ed41c3f13…`](https://stellar.expert/explorer/testnet/tx/9ed41c3f135228d5c17f9c9cb13c1d41183f770086757bb9d5450ccac81d26e7) |
| execute_upgrade before the seven-day delay | refused (recording simulation): `HostError: Error(Contract, #9)` | | | |
### guardian-only / loss: veto and completion, no ZK

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,434,056 | 0.7502 | [`8c4a6e8eaa…`](https://stellar.expert/explorer/testnet/tx/8c4a6e8eaa2d16afdb54e2f6fc17186093c3b4c6787ab73da224910cdcc7aac9) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0525 | [`04736c38ad…`](https://stellar.expert/explorer/testnet/tx/04736c38ad391a3e01ad1d721a6531a84f3345b208b3b20ca051447a5502c2c4) |
| enroll GuardianOnly through apply_doc | ok | 19,591,315 | 4.1150 | [`1e79eddf04…`](https://stellar.expert/explorer/testnet/tx/1e79eddf0413d5718363eb4969c34ab09314db03b916f3abfdd749a5cb77562b) |
| begin_lost_key | ok | 15,887,463 | 0.1946 | [`3df8dba3e3…`](https://stellar.expert/explorer/testnet/tx/3df8dba3e377ac36f7e213b82ff801f2f974946b8caf14b61d5175946febcd90) |
| submit_guardian (1 of 2) | ok | 1,835,107 | 0.0020 | [`41ca735da1…`](https://stellar.expert/explorer/testnet/tx/41ca735da13f11ae675d406aa8f7ec81ed9d65bbaf4cc4c0ebf8b3b65d98d77b) |
| submit_guardian (2 of 2, promoting) | ok | 2,725,689 | 2.0029 | [`fe5e982424…`](https://stellar.expert/explorer/testnet/tx/fe5e982424bcc4cc09f6b4d5c96eba63b4e70c99447e515927064af556d309e3) |
| a third guardian on an authorized attempt | refused (recording simulation): `HostError: Error(Contract, #5)` | | | |
| Loss owner cancel_recovery (the veto) | ok | 6,923,881 | 0.0032 | [`e16c968691…`](https://stellar.expert/explorer/testnet/tx/e16c96869146bdc75f0b5c08b0fe93fed34cd11a6b127d6b8189b755d60da2e0) |
| begin_lost_key (again) | ok | 15,902,443 | 0.0035 | [`f887ec6e67…`](https://stellar.expert/explorer/testnet/tx/f887ec6e67850b1f234560bcc7536cd6a1b2ac962474a668d4a7e8cd2673724d) |
| submit_guardian (1 of 2) | ok | 1,850,016 | 0.0020 | [`6a7b060f4d…`](https://stellar.expert/explorer/testnet/tx/6a7b060f4d5e7bcd1aa3630df53e8890918f81013de00cea1fec5de8058203ad) |
| submit_guardian (2 of 2, promoting) | ok | 2,743,297 | 1.8063 | [`9b789d9b73…`](https://stellar.expert/explorer/testnet/tx/9b789d9b731f1044f1c4709304c9b0b0ddda53a43cde9c326285e0fa995fb779) |
| completion apply_doc (GuardianOnly) | ok | 19,388,262 | 0.3865 | [`db97a8746d…`](https://stellar.expert/explorer/testnet/tx/db97a8746d21d2cdd2e01b21c06698314086ef0af0eff6c86580c0fface53248) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,337,433 | 0.0566 | [`faac4a6a70…`](https://stellar.expert/explorer/testnet/tx/faac4a6a707be2113a2b03d7cf977be7eb3d7e652d3487422070d10cf6748cda) |
### combined / loss: both factors, ZK rotation

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,427,933 | 0.7502 | [`611d3513d6…`](https://stellar.expert/explorer/testnet/tx/611d3513d6fd4cf7ee0c02e813b82e4b90760627a19f221c3e11d13443bfc00a) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0525 | [`d03e6da800…`](https://stellar.expert/explorer/testnet/tx/d03e6da8004a821dddf1b3f241ba9d49fe3a945f462bb4c0f231953b97ec119b) |
| enroll Combined Loss | ok | 64,598,387 | 5.9415 | [`b38e6479f2…`](https://stellar.expert/explorer/testnet/tx/b38e6479f207b124cbed8cbfc75577c5a86a54e2e8cbbf0faaf0b63bc7a203b6) |
| begin_lost_key | ok | 21,055,586 | 0.1951 | [`9cd8025afd…`](https://stellar.expert/explorer/testnet/tx/9cd8025afd01ecb4d05984a547e166b3957e9a93e255bda0cb0197b17a0b3721) |
| submit_guardian (1 of 2) | ok | 1,863,399 | 0.0020 | [`afe79e52e6…`](https://stellar.expert/explorer/testnet/tx/afe79e52e6d1d6477873375f837af7530c5a8e6900f38b0122bf3ff63883cd16) |
| submit_zk (Combined, not yet promoting) | ok | 123,251,656 | 0.0172 | [`71fe80c015…`](https://stellar.expert/explorer/testnet/tx/71fe80c0156d41285903d17dd3a6e81f4d31c5f28498437af0039ef40689ba3e) |
| submit_guardian (2 of 2, promoting: ZK already in) | ok | 2,786,083 | 2.0521 | [`5326387afd…`](https://stellar.expert/explorer/testnet/tx/5326387afddaf9444eded04f027bbcc7ceb102126b317baccba3aae1b6e02cd0) |
| Loss: activity during the authorized window | ok | 5,361,561 | 0.0594 | [`46ac03e63e…`](https://stellar.expert/explorer/testnet/tx/46ac03e63ebfca257cf2a92a5783d19e53a01f983b45231bbb998d4b6758d03b) |
| completion apply_doc (Combined, ZK rotation) | ok | 65,459,729 | 1.4178 | [`a47cf6de75…`](https://stellar.expert/explorer/testnet/tx/a47cf6de7509080abe01bfce940fb1ab5c13d565c000f5a6b573a70778604ca7) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,361,702 | 0.0566 | [`981c43ffcf…`](https://stellar.expert/explorer/testnet/tx/981c43ffcf1a5f65feeed1304f15e6be0ade337ff4ac9e9d84f70004dc2f822c) |
### guardian-only / protected: compromise recovery from the baseline

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,427,933 | 0.7502 | [`cd434de5f8…`](https://stellar.expert/explorer/testnet/tx/cd434de5f8779970e79f45ffcf3a07249490e162fe7ec23c28193fdf7ca12d42) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0525 | [`a4c5deb981…`](https://stellar.expert/explorer/testnet/tx/a4c5deb981d17d0fd78d79402e83594365bd1c4ff2509230a83cdfd0b5f4a0ee) |
| enroll GuardianOnly Protected with a baseline | ok | 20,638,371 | 4.3064 | [`9ae6fdba62…`](https://stellar.expert/explorer/testnet/tx/9ae6fdba62d079b60c83ab2a92bce04693900a42947d00b47b8adf9fc3078a77) |
| the thief adds a signer with the stolen owner key | ok | 23,385,893 | 1.2458 | [`5d2fec8e25…`](https://stellar.expert/explorer/testnet/tx/5d2fec8e25bac8960be7a95b5de2dee8cb6e4d1e06005be26c5df2e297dd3481) |
| the thief's signer moves XLM | ok | 5,338,168 | 0.1141 | [`7cb01ba3a1…`](https://stellar.expert/explorer/testnet/tx/7cb01ba3a1efcb093a2e94e9ad2d8ef6efff6af70e6e5a79b17afb09529448f8) |
| begin_compromise before the baseline is published | refused (recording simulation): `HostError: Error(Contract, #23)` | | | |
| publish_baseline of another document | refused (recording simulation): `HostError: Error(Contract, #24)` | | | |
| publish_baseline | ok | 6,712,421 | 1.0615 | [`0ff8e5054a…`](https://stellar.expert/explorer/testnet/tx/0ff8e5054ac29697d5fc496b4baafb259b30cd9fdb50ad9ede48ea4e146e2062) |
| begin_compromise | ok | 16,443,652 | 0.1947 | [`ada4fe4be4…`](https://stellar.expert/explorer/testnet/tx/ada4fe4be4f64124e63a5e3aeaa06cd208915c4743b4cff4d1fa12edf1aedcac) |
| submit_guardian (1 of 2) | ok | 1,838,980 | 0.0020 | [`949a742e5d…`](https://stellar.expert/explorer/testnet/tx/949a742e5ddebbf6d455a612adcf7768d6969f244e2235f798d6ac1d4ebbaf29) |
| submit_guardian (2 of 2, promoting; sets the freeze) | ok | 2,813,708 | 2.0075 | [`ee9bed1182…`](https://stellar.expert/explorer/testnet/tx/ee9bed11826620d5d702ac1d412f0d2ba1ab4f3e5b8a2cefbf3b96b698c30a70) |
| frozen: the thief's signer | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: the owner key | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| completion apply_doc (compromise: revokes the stolen and added keys) | ok | 21,421,092 | 0.5688 | [`06178a157f…`](https://stellar.expert/explorer/testnet/tx/06178a157f4c1a3806a9c7adce2bd1f0236cfdb4dcdc25a6dcb2a374efa892a0) |
| the new owner after recovery | ok | 5,336,735 | 0.0566 | [`892af8fdc5…`](https://stellar.expert/explorer/testnet/tx/892af8fdc52a711979586e4bd454feeaf0c27706ce626469812f6707f9a79f8c) |
| the stolen owner key after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| re-adding the thief's key, signed by the new owner | refused (recording simulation): `HostError: Error(Contract, #2)` | | | |
### relay: a delegated perch guardian's approval, relayed

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,434,056 | 0.7506 | [`23bfac70bc…`](https://stellar.expert/explorer/testnet/tx/23bfac70bc96aef9e29cc4c3549c1d46831afd224fefc9441833f0525fa4efe6) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0525 | [`f54e954a93…`](https://stellar.expert/explorer/testnet/tx/f54e954a938114b83b1098a60e43d19750b4b17e8ea652ad04c3dbf5ffcf72ae) |
| guardian account: a delegated approver for the controller | ok | 13,095,043 | 1.9124 | [`6ec9205a66…`](https://stellar.expert/explorer/testnet/tx/6ec9205a661aad9359f5ecd8b818e45b097e9cd0bc085510abc0b26b0903edfd) |
| factory create_passkey | ok | 2,427,933 | 0.7506 | [`162c12c64c…`](https://stellar.expert/explorer/testnet/tx/162c12c64cfba781d3eec5c556383b6cee62dce212d50c96067ea299ca0bf804) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0525 | [`e162f5880e…`](https://stellar.expert/explorer/testnet/tx/e162f5880e748aff10a7c0153f24262cf793323e905dc314bc36438e54956962) |
| enroll GuardianOnly (a perch account among the guardians) | ok | 18,985,055 | 3.9696 | [`f061aae625…`](https://stellar.expert/explorer/testnet/tx/f061aae625e99ea13de871185e70d5e7ad5d2f6c0b5f269c4796162d180d493d) |
| begin_lost_key | ok | 15,261,410 | 0.1947 | [`af9015ea92…`](https://stellar.expert/explorer/testnet/tx/af9015ea923a24a6afba0443f5d4886a3ae44200e6c6c7db0d50a80f319729c6) |
| submit_guardian (1 of 2) | ok | 1,832,878 | 0.0020 | [`6409477f38…`](https://stellar.expert/explorer/testnet/tx/6409477f38a49888360c11881f17a568fa64f37dceebd2c94fcb3730263d80e4) |
| relay: forged approval, another delegate | refused (relay admission): `403 refused in simulation: HostError: Error(Auth, InvalidAction)` | | | |
| relay: forged approval, the approver under a rule it is not in | refused (relay admission): `403 refused in simulation: HostError: Error(Auth, InvalidAction)` | | | |
| relay: forged approval, a tampered delegate signature | refused (relay admission): `403 refused in simulation: HostError: Error(Auth, InvalidAction)` | | | |
| submit_guardian (2 of 2, promoting; a delegated perch guardian, relayed) | ok | 3,915,180 | 2.0957 | [`56a6ed4384…`](https://stellar.expert/explorer/testnet/tx/56a6ed438495f4ac20473f065f79c76bbff38876b517394f9bf2278af9a80078) |
| completion apply_doc (GuardianOnly) | ok | 18,791,526 | 0.3866 | [`5a8c67e625…`](https://stellar.expert/explorer/testnet/tx/5a8c67e6251b1627f1368ad9ca24644d95bd2965dc5ce83690d133723cf7e195) |
| the new passkey after recovery | ok | 5,335,984 | 0.0566 | [`673a67283d…`](https://stellar.expert/explorer/testnet/tx/673a67283d6761bcaa909523f1e9668562e07ed9e3a7ecdf6d87872529f90fbd) |
