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
every hash in the manifest. For this record (`aa5a78f`) that was checked on
2026-10-08 on the deploying machine (macOS arm64). `build-stack.sh` with the
manifest's builder (`scaffold`) and registry, run on this branch's tree,
reproduced all ten artifacts' hashes; the tree's contract source is
identical to `aa5a78f`'s. The rebuild from a fresh `git archive` copy at
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

Run `1791409227` against `deployments/testnet.json` (stack commit `aa5a78f13be1`), ledgers 5077129–5077253: 81 transactions submitted, 31 refusals checked, 0 scenario failures. Fees paid: 67.3314 XLM.

### Against the budget

Worst measured transaction per row of `docs/recovery/budgets.md` §2, as a share of the protocol-29 per-transaction limits (400,000,000 instructions, 400 footprint entries, 200 written entries, 132,096 write bytes, 132,096 bytes of transaction). Budget: 75% of each. Memory is not reported by the RPC; the release-stack suite meters it locally.

| Row | Worst step | Instructions | Footprint entries | Written entries | Write bytes | Tx size | Fee (XLM) | Latency (s) | Within budget |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Enroll ZK through `apply_doc` | enroll Combined through apply_doc | 64,695,405 (16.2%) | 34 (8.5%) | 17 (8.5%) | 8,352 (6.3%) | 6,400 (4.8%) | 5.8832 | 4.7 | yes |
| `begin_lost_key` | begin_lost_key | 21,164,956 (5.3%) | 17 (4.2%) | 2 (1.0%) | 1,236 (0.9%) | 2,084 (1.6%) | 0.1925 | 4.7 | yes |
| `begin_compromise` | begin_compromise | 16,484,854 (4.1%) | 17 (4.2%) | 2 (1.0%) | 1,236 (0.9%) | 2,008 (1.5%) | 0.1922 | 4.8 | yes |
| `publish_baseline` | publish_baseline | 6,730,453 (1.7%) | 10 (2.5%) | 1 (0.5%) | 776 (0.6%) | 1,504 (1.1%) | 1.0471 | 4.8 | yes |
| `submit_guardian` | submit_guardian (2 of 2, promoting; a delegated perch guardian, relayed) | 3,940,614 (1.0%) | 16 (4.0%) | 5 (2.5%) | 1,532 (1.2%) | 2,240 (1.7%) | 2.0662 | 3.2 | yes |
| `submit_zk` | submit_zk (Combined, promoting; sets the freeze) | 124,921,826 (31.2%) | 17 (4.2%) | 5 (2.5%) | 2,388 (1.8%) | 18,176 (13.8%) | 2.0438 | 3.2 | yes |
| Completion `apply_doc` | completion apply_doc (Combined, ZK rotation) | 65,548,738 (16.4%) | 40 (10.0%) | 29 (14.5%) | 10,336 (7.8%) | 6,720 (5.1%) | 1.3989 | 3.2 | yes |
| Owner cancellation (`Loss`) | Loss owner cancel_recovery (the veto) | 6,953,421 (1.7%) | 14 (3.5%) | 4 (2.0%) | 1,252 (0.9%) | 2,084 (1.6%) | 0.0032 | 4.7 | yes |
| `approve_change` | approve_change (G-account, 2 of 2) | 1,627,621 (0.4%) | 8 (2.0%) | 2 (1.0%) | 404 (0.3%) | 1,468 (1.1%) | 0.0042 | 4.7 | yes |
| `submit_zk_change` | submit_zk_change (Reconfigure) | 123,040,919 (30.8%) | 12 (3.0%) | 1 (0.5%) | 240 (0.2%) | 17,832 (13.5%) | 0.0300 | 3.3 | yes |
| `Protected` reconfiguration `apply_doc` | Protected Combined reconfiguration apply_doc | 25,068,364 (6.3%) | 25 (6.2%) | 12 (6.0%) | 5,588 (4.2%) | 5,736 (4.3%) | 0.0375 | 4.8 | yes |
| `Protected` `schedule_upgrade` | Protected schedule_upgrade | 6,925,867 (1.7%) | 13 (3.2%) | 2 (1.0%) | 1,144 (0.9%) | 2,044 (1.5%) | 0.0163 | 4.7 | yes |
| Ordinary activity (direct authorization) | activity before the condition is met | 5,376,318 (1.3%) | 10 (2.5%) | 3 (1.5%) | 440 (0.3%) | 1,752 (1.3%) | 0.0586 | 4.7 | yes |
| Ordinary activity (`execute`) | ordinary activity: execute | 6,006,074 (1.5%) | 10 (2.5%) | 3 (1.5%) | 440 (0.3%) | 1,888 (1.4%) | 0.0027 | 3.2 | yes |
| Factory `create_passkey` | factory create_passkey | 2,456,655 (0.6%) | 10 (2.5%) | 5 (2.5%) | 1,500 (1.1%) | 992 (0.8%) | 0.7400 | 4.7 | yes |

Native proving on the deploying machine (Apple silicon; see [`docs/zk/measurements.md`](../zk/measurements.md) for the browser and the depth comparison), 11 proofs (`nargo execute` + `bb prove`, the pinned toolchain): witness 68 ms median / 77 ms max, proof 97 ms median / 108 ms max, peak RSS 51 MiB.

### zk-only / loss: lost-key recovery with a real proof

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,450,532 | 0.7400 | [`82825b8ab0…`](https://stellar.expert/explorer/testnet/tx/82825b8ab012a4a38a2bb59bb67e9769f57129273a3b2d1b767b7b5a2b5f9a66) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0518 | [`2badd5de7d…`](https://stellar.expert/explorer/testnet/tx/2badd5de7dba46a8186fdafba5adb7c7c65360a458dbc90a5b8e51de062fbe97) |
| enroll ZkOnly through apply_doc (pool insert) | ok | 62,464,028 | 7.3211 | [`a20302ccc3…`](https://stellar.expert/explorer/testnet/tx/a20302ccc31d39ba7bad787affd3770f52bb2084e9569f836b62dc06a7c09fc1) |
| ordinary activity: direct authorization | ok | 5,375,619 | 0.0586 | [`da6b81493a…`](https://stellar.expert/explorer/testnet/tx/da6b81493ae49e54837b4cda702932f9e968c40c8d2fd86d3ecd98893bb82e4b) |
| ordinary activity: execute | ok | 6,006,074 | 0.0027 | [`dba6c8538b…`](https://stellar.expert/explorer/testnet/tx/dba6c8538bee50dd04a753331b8aeaf221eb12e12ef25e93dcb1ba2c9c666d4d) |
| begin_lost_key | ok | 18,742,788 | 0.1923 | [`6c02dab78c…`](https://stellar.expert/explorer/testnet/tx/6c02dab78c9496bd9e083a027d38836be42140e7bb74ceff00463ae3b88ff3fb) |
| begin_lost_key (a second, evidence-free attempt) | ok | 18,757,879 | 0.0038 | [`b9b8c624b4…`](https://stellar.expert/explorer/testnet/tx/b9b8c624b4a465d5b86e01ae23e455f1c3d0cbbadc4641c9942d1315c4e49ad6) |
| activity while attempts collect | ok | 5,374,330 | 0.0026 | [`b5799be171…`](https://stellar.expert/explorer/testnet/tx/b5799be17132d8732436a10b35c3e316fed684b785c608b14ef0af7f1af0de95) |
| another attempt's proof | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a Cancel proof submitted as Initiate | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a tampered proof | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a root the pool never had | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| submit_zk (real proof; authorizes the attempt) | ok | 124,193,102 | 1.9206 | [`0f50a7c652…`](https://stellar.expert/explorer/testnet/tx/0f50a7c6523ebbdab9f806f5bc2086b6f2e4e6a3ef9403339d07a1dc5380ca8c) |
| the same proof again | refused (recording simulation): `HostError: Error(Contract, #5)` | | | |
| Loss: activity during the authorized window | ok | 5,374,330 | 0.0026 | [`4385f32be7…`](https://stellar.expert/explorer/testnet/tx/4385f32be7049af33216d798b6f4a9b2f9846a64c2b95c72b47793c64fa91319) |
| Loss: an owner policy change during the window | refused (recording simulation): `HostError: Error(Contract, #25)` | | | |
| completion before the delay | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #6` | | | |
| completion with other bytes than the target | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #7` | | | |
| completion apply_doc (spends the nullifier, rotates the leaf) | ok | 63,270,441 | 1.3983 | [`1b98b4a5bb…`](https://stellar.expert/explorer/testnet/tx/1b98b4a5bb00a91f9268a08c32438b013f7f5b60d88f78eba73bf1520d192378) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,375,760 | 0.0558 | [`b7d362acb6…`](https://stellar.expert/explorer/testnet/tx/b7d362acb661894b481f429ec73ac7623a615b9c9c791de413e43723dd88dca0) |
| begin_lost_key (after recovery) | ok | 18,760,393 | 0.0038 | [`3d015bca54…`](https://stellar.expert/explorer/testnet/tx/3d015bca547fb01ef7eb11a9c645732319bb1a5891fb41185359a174bd4db817) |
| a proof by the consumed credential | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
### combined / protected: freeze, cancellation, reconfiguration

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,456,655 | 0.7400 | [`ab9ec44567…`](https://stellar.expert/explorer/testnet/tx/ab9ec44567b68d2d4beeae35c35cec75d41dbe9b1bae95aa6ce476f465425ddc) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0518 | [`9b59ae8d0a…`](https://stellar.expert/explorer/testnet/tx/9b59ae8d0a31e860d691e535311d776ae81ff8e86ca5385a672ebeae0766533f) |
| enroll Combined through apply_doc | ok | 64,695,405 | 5.8832 | [`ecf9c5ed31…`](https://stellar.expert/explorer/testnet/tx/ecf9c5ed31c5c8f9b43b798bc03d8274d6efad0677bdd0958da94ce65902d44c) |
| begin_lost_key | ok | 21,164,956 | 0.1925 | [`8c3dc2ff21…`](https://stellar.expert/explorer/testnet/tx/8c3dc2ff21bed2fe4aa1b3222526e2160a08e00f49982e4f7b11a8cb5e7e0631) |
| submit_guardian (G-account, 1 of 2) | ok | 1,863,365 | 0.0020 | [`e2e49bc9c9…`](https://stellar.expert/explorer/testnet/tx/e2e49bc9c927e4e50247d9d688283362713fadbf84dff7b5044481d367f1e4d4) |
| submit_guardian (G-account, 2 of 2) | ok | 1,867,169 | 0.0020 | [`8e88a536da…`](https://stellar.expert/explorer/testnet/tx/8e88a536dac05a00fe87288b07395c0f9760b78e77128151f240ddf83d4217e7) |
| activity before the condition is met | ok | 5,376,318 | 0.0586 | [`da587ec0c4…`](https://stellar.expert/explorer/testnet/tx/da587ec0c476d5d770b5cfe2f675c775aa04192840ccd57d50b8fd15a105864e) |
| submit_zk (Combined, promoting; sets the freeze) | ok | 124,921,826 | 2.0438 | [`17b1a2b37e…`](https://stellar.expert/explorer/testnet/tx/17b1a2b37e318668d1236a0f8bf3d46efb67af82354ae56bf9068bb5873c608d) |
| frozen: direct authorization | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: execute | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: apply_doc | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| an Initiate proof submitted as Cancel | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| cancel: guardian 1 of 2 | ok | 1,979,475 | 0.0617 | [`b4a99637b1…`](https://stellar.expert/explorer/testnet/tx/b4a99637b1f8e8b954f0702955016361409a7a6652aa62d06ba2c60b5a7e6fc1) |
| cancel: guardian 2 of 2 | ok | 1,983,588 | 0.0617 | [`9718af21ec…`](https://stellar.expert/explorer/testnet/tx/9718af21ecfd590451199580cb7c1368aceb5487bd05a8f92433402756602eb8) |
| cancellation (Combined: the ZK Cancel proof completes it, clears the freeze) | ok | 124,333,828 | 0.1968 | [`ccf8a7ffce…`](https://stellar.expert/explorer/testnet/tx/ccf8a7ffce7186f0e3556bd9f396fae8bdd3b6b66cd42f0bb4ab9f3297d7b694) |
| activity after the cancellation | ok | 5,375,028 | 0.0026 | [`a4f0e6b130…`](https://stellar.expert/explorer/testnet/tx/a4f0e6b1305d5317f1027fc0bcbcc4598b6a51ed78a4295178d4c5eb037a9b97) |
| execute after the cancellation | ok | 6,005,837 | 0.0027 | [`378fd530b1…`](https://stellar.expert/explorer/testnet/tx/378fd530b14fa747c144fe6d2f46be7cf8c2535049809e2167250abef889bac0) |
| submit_zk_change (Reconfigure) | ok | 123,040,919 | 0.0300 | [`d11966472f…`](https://stellar.expert/explorer/testnet/tx/d11966472fe572719de5317d552e4cfdd19d6574e576f23404925e699f58bd72) |
| reconfiguration with ZK evidence alone | refused (recording simulation): `HostError: Error(Contract, #39)` | | | |
| approve_change (G-account, 1 of 2) | ok | 1,623,843 | 0.0042 | [`6ecd1856c6…`](https://stellar.expert/explorer/testnet/tx/6ecd1856c6fc68b1c5a5e0e1fd9dd7ebb3640c47bebf125488a65a17aef46348) |
| approve_change (G-account, 2 of 2) | ok | 1,627,621 | 0.0042 | [`3dab197ab8…`](https://stellar.expert/explorer/testnet/tx/3dab197ab8da118843e33a31b1318ad0bfe1090b1c4a8ecd34c56120c9eb4bbf) |
| Protected Combined reconfiguration apply_doc | ok | 25,068,364 | 0.0375 | [`e5e9f6196b…`](https://stellar.expert/explorer/testnet/tx/e5e9f6196b0c5fd0c9672732d9f77319b91faf886c208c9758549e06accd03df) |
### zk-only / protected: reconfiguration and upgrade evidence

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,450,532 | 0.7400 | [`59ed899793…`](https://stellar.expert/explorer/testnet/tx/59ed8997933c581147bbd56af2e6ee29f49595e7374dfc98c8753f7972787a51) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0518 | [`ced7d9dbac…`](https://stellar.expert/explorer/testnet/tx/ced7d9dbac9feabb857e67b18f1cc9e5346587dd2865616700d67bdc75aaeb47) |
| enroll ZkOnly Protected | ok | 62,458,217 | 5.3387 | [`c61189c48a…`](https://stellar.expert/explorer/testnet/tx/c61189c48a04d5c43087d5db0f45112233193d639ed83804ac430398c4e9beb0) |
| owner alone cannot reconfigure | refused (recording simulation): `HostError: Error(Contract, #39)` | | | |
| a proof for another configuration | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| submit_zk_change (Reconfigure) | ok | 123,001,045 | 0.0300 | [`a4057bd540…`](https://stellar.expert/explorer/testnet/tx/a4057bd54000a3ce6c9b7fd045b71815bce969067a9db09e09a61cc7538a3ab6) |
| Protected reconfiguration apply_doc | ok | 22,805,309 | 0.0371 | [`39f70fd046…`](https://stellar.expert/explorer/testnet/tx/39f70fd046032c0dc52591c30a6cc93d5b8a7dbee056fc825677243367e73fd4) |
| owner alone cannot schedule an upgrade | refused (recording simulation): `HostError: Error(Contract, #39)` | | | |
| submit_zk_change (Upgrade) | ok | 123,021,647 | 0.0300 | [`84e4708177…`](https://stellar.expert/explorer/testnet/tx/84e47081772c29752efc98d6126e0e0d232f06a1818cc6dd6c466845e4440541) |
| Protected schedule_upgrade | ok | 6,925,867 | 0.0163 | [`b3bd22e03d…`](https://stellar.expert/explorer/testnet/tx/b3bd22e03d044297546bede87778298032ad5fbe9afb932156a8a49b2f746d18) |
| execute_upgrade before the seven-day delay | refused (recording simulation): `HostError: Error(Contract, #9)` | | | |
### guardian-only / loss: veto and completion, no ZK

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,450,532 | 0.7400 | [`e80a2b7bc1…`](https://stellar.expert/explorer/testnet/tx/e80a2b7bc124a26fe6168491c44c882d93e54af74319254cd89d5c6af6b597d7) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0518 | [`b10e99095a…`](https://stellar.expert/explorer/testnet/tx/b10e99095a3f688af4a87a420efd531f7308bd8386e6d2949d484e0c1c61d864) |
| enroll GuardianOnly through apply_doc | ok | 19,635,878 | 4.0602 | [`0e17b56cdf…`](https://stellar.expert/explorer/testnet/tx/0e17b56cdfd78b6aea85a5c3fd151810dbd60ddf05aae4baf4412ac0d977e354) |
| begin_lost_key | ok | 15,946,797 | 0.1920 | [`46a7d3462e…`](https://stellar.expert/explorer/testnet/tx/46a7d3462e6c7d44302233b5dadb8bf09e6317782bae1c485b09e54d52ec937d) |
| submit_guardian (1 of 2) | ok | 1,835,107 | 0.0020 | [`88ece7efcc…`](https://stellar.expert/explorer/testnet/tx/88ece7efcc63b9a65dbbb09cee80516e5e8fb4bcebbf007b9a49ba39647d38fa) |
| submit_guardian (2 of 2, promoting) | ok | 2,740,180 | 1.9754 | [`5f030c9ba4…`](https://stellar.expert/explorer/testnet/tx/5f030c9ba4679f9cec5b15bdbb56a5dc84e9b302232bc6bb6963452975042801) |
| a third guardian on an authorized attempt | refused (recording simulation): `HostError: Error(Contract, #5)` | | | |
| Loss owner cancel_recovery (the veto) | ok | 6,953,421 | 0.0032 | [`80cc4e28fc…`](https://stellar.expert/explorer/testnet/tx/80cc4e28fc9d2680581668387b52b3daca292710271b9cfbce2003b6584519b8) |
| begin_lost_key (again) | ok | 15,964,481 | 0.0035 | [`a61ca80b45…`](https://stellar.expert/explorer/testnet/tx/a61ca80b45a25975c3be14c5fc928cf076b36d54e6b143f298304bde97ab1325) |
| submit_guardian (1 of 2) | ok | 1,850,016 | 0.0020 | [`50278bcdf7…`](https://stellar.expert/explorer/testnet/tx/50278bcdf7da33871ece8064dfca33e02c7767e8804206fa47226026fb8caeda) |
| submit_guardian (2 of 2, promoting) | ok | 2,758,626 | 1.7818 | [`a9cf46d71a…`](https://stellar.expert/explorer/testnet/tx/a9cf46d71ae0028aa00754d3e031f345876a8b1ab4e5e78b6e25c4e629ab32a7) |
| completion apply_doc (GuardianOnly) | ok | 19,473,859 | 0.3815 | [`63b2d274eb…`](https://stellar.expert/explorer/testnet/tx/63b2d274eb7b94a923d4abc5a1b614e33c6a73a0b7c92b5dc1bda18630e5d7b5) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,350,085 | 0.0558 | [`160b1d3798…`](https://stellar.expert/explorer/testnet/tx/160b1d3798d464b9c22ce0ca0512b35a47e5c4154466346e0c22f549c4fd42e6) |
### combined / loss: both factors, ZK rotation

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,450,532 | 0.7401 | [`20ad9c5321…`](https://stellar.expert/explorer/testnet/tx/20ad9c53218e55e8aeb6925f35ff2bbffcfb78b1677975d3509ebb788774c05b) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0518 | [`ee2ace80cc…`](https://stellar.expert/explorer/testnet/tx/ee2ace80cc55826d3d75a0b66faaed6c640cd668abf85696a2a2bcdcbc608a0c) |
| enroll Combined Loss | ok | 64,632,523 | 5.8627 | [`f5c775fdbf…`](https://stellar.expert/explorer/testnet/tx/f5c775fdbf6736cc215b188c2ff45cf720d4290d54ed8be8b3610e959c687cf8) |
| begin_lost_key | ok | 21,125,514 | 0.1925 | [`db634c7f05…`](https://stellar.expert/explorer/testnet/tx/db634c7f054c596a707cfffcda91fea8adfa3723a409d6ad9824f6fbc69505a3) |
| submit_guardian (1 of 2) | ok | 1,863,399 | 0.0020 | [`d2bac9c5e7…`](https://stellar.expert/explorer/testnet/tx/d2bac9c5e7841a43f80fc6664daf8ce72768fc351864ceafeaf031491d985dbb) |
| submit_zk (Combined, not yet promoting) | ok | 123,253,645 | 0.0172 | [`66a4d3248a…`](https://stellar.expert/explorer/testnet/tx/66a4d3248ab26b7f532796072daa801f960daa9f4a347ea51d7049820d6920ec) |
| submit_guardian (2 of 2, promoting: ZK already in) | ok | 2,799,310 | 2.0243 | [`267f3521c9…`](https://stellar.expert/explorer/testnet/tx/267f3521c960bb85c7f71b21165be78e90212a406eb3d6ed967d1dca0a53fa71) |
| Loss: activity during the authorized window | ok | 5,375,619 | 0.0586 | [`c169bde126…`](https://stellar.expert/explorer/testnet/tx/c169bde126ec18cc2d7f99fd7ec44f0a303e147c7572eac2252c59dd8bf000e4) |
| completion apply_doc (Combined, ZK rotation) | ok | 65,548,738 | 1.3989 | [`0c522757a3…`](https://stellar.expert/explorer/testnet/tx/0c522757a30ff67287d2da291ee09c9bf47d13cf9116b7021adddeacdf706edf) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,375,760 | 0.0558 | [`bf570ed11d…`](https://stellar.expert/explorer/testnet/tx/bf570ed11d55b44fe41951288b44f226db6c3b295f13859d97043cb2d224908d) |
### guardian-only / protected: compromise recovery from the baseline

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,452,802 | 0.7401 | [`08174c749c…`](https://stellar.expert/explorer/testnet/tx/08174c749c2699a1c8f7279f82092befd726ef92b4ea1ed1dea7b4030212bc9c) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0518 | [`71f72d335e…`](https://stellar.expert/explorer/testnet/tx/71f72d335edd46dba473675bccd78595ef9cfb0e508ab679cff9390ff50b189c) |
| enroll GuardianOnly Protected with a baseline | ok | 20,692,321 | 4.2497 | [`5bb16141d2…`](https://stellar.expert/explorer/testnet/tx/5bb16141d2fa3517efa72caeb41752fcb976a757c0c883235dc6bda64c08be11) |
| the thief adds a signer with the stolen owner key | ok | 23,438,484 | 1.2291 | [`c152b0279a…`](https://stellar.expert/explorer/testnet/tx/c152b0279a8f942613a5eb53cc3284e1d8a31f83f366a0ca061b9ede26c392f4) |
| the thief's signer moves XLM | ok | 5,351,518 | 0.1126 | [`94e5cef985…`](https://stellar.expert/explorer/testnet/tx/94e5cef985610871f192ad625dbbe9133a5cf1e61eff8e671bbbf41632f4c64f) |
| begin_compromise before the baseline is published | refused (recording simulation): `HostError: Error(Contract, #23)` | | | |
| publish_baseline of another document | refused (recording simulation): `HostError: Error(Contract, #24)` | | | |
| publish_baseline | ok | 6,730,453 | 1.0471 | [`c800667644…`](https://stellar.expert/explorer/testnet/tx/c800667644961898fd87f9e8ef71f58f024323df926873f981e2e916947997a3) |
| begin_compromise | ok | 16,484,854 | 0.1922 | [`5f34d910d1…`](https://stellar.expert/explorer/testnet/tx/5f34d910d1421cbfb8d3134c794df0f0150803823b462983ba70814039fd705d) |
| submit_guardian (1 of 2) | ok | 1,838,980 | 0.0020 | [`50330bf543…`](https://stellar.expert/explorer/testnet/tx/50330bf543a8fcfa5f80fbfc67699976522252bf986230c017d679890ccab2c5) |
| submit_guardian (2 of 2, promoting; sets the freeze) | ok | 2,829,975 | 1.9804 | [`1b6a7fa8fc…`](https://stellar.expert/explorer/testnet/tx/1b6a7fa8fc42f378d2de43b0dc225064b9cc19004bb54af3ac647d3a1f5bfef9) |
| frozen: the thief's signer | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: the owner key | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| completion apply_doc (compromise: revokes the stolen and added keys) | ok | 21,478,223 | 0.5610 | [`abc5528691…`](https://stellar.expert/explorer/testnet/tx/abc5528691305535c47ac8d53752a56ebf55733b2d0738cbc120783d4d51b704) |
| the new owner after recovery | ok | 5,350,085 | 0.0558 | [`bd3e9eb931…`](https://stellar.expert/explorer/testnet/tx/bd3e9eb931d1698905cb00ca8733185f95bd89df3712f1547a94a4f61e84497a) |
| the stolen owner key after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| re-adding the thief's key, signed by the new owner | refused (recording simulation): `HostError: Error(Contract, #2)` | | | |
### relay: a delegated perch guardian's approval, relayed

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,450,532 | 0.7401 | [`3c26c7a1f1…`](https://stellar.expert/explorer/testnet/tx/3c26c7a1f10c3f9bffad5e926b5ef715b6ffe5dd62ec41d1d36102c16a62b7a0) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0518 | [`c6dfe3751d…`](https://stellar.expert/explorer/testnet/tx/c6dfe3751dfa6d17088ffa59eff8bcc9b3a9c08394a7881b49b3fefa5841df83) |
| guardian account: a delegated approver for the controller | ok | 13,131,868 | 1.8870 | [`ff47bc56af…`](https://stellar.expert/explorer/testnet/tx/ff47bc56afde8372b87ab83235c969f7ffe032652e58b85f13f82434be505c7e) |
| factory create_passkey | ok | 2,450,532 | 0.7401 | [`ada71c3dda…`](https://stellar.expert/explorer/testnet/tx/ada71c3ddaf4a7da0921df07ad2e2c9909ebbcaa305415a4ae8b26893c9d5bcb) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0518 | [`3ded7f83ca…`](https://stellar.expert/explorer/testnet/tx/3ded7f83cab1d46af054806b41ed9f2a983c4a317b4538e30cc1c0a76f98a6b5) |
| enroll GuardianOnly (a perch account among the guardians) | ok | 19,039,989 | 3.9154 | [`8d4736804b…`](https://stellar.expert/explorer/testnet/tx/8d4736804b463ef7dc513f1d63993469779773d67be17bf776f46bad1652fd17) |
| begin_lost_key | ok | 15,321,500 | 0.1920 | [`9b3824060a…`](https://stellar.expert/explorer/testnet/tx/9b3824060a5135364853c861c391311fdf23a34ef1d52f34d75dd7a34d3c656f) |
| submit_guardian (1 of 2) | ok | 1,832,878 | 0.0020 | [`c00eefacad…`](https://stellar.expert/explorer/testnet/tx/c00eefacad3b980d1ca98f373707127bbd3ccb1c5b25c6380cab4805fad1a546) |
| relay: forged approval, another delegate | refused (relay admission): `403 refused in simulation: HostError: Error(Auth, InvalidAction)` | | | |
| relay: forged approval, the approver under a rule it is not in | refused (relay admission): `403 refused in simulation: HostError: Error(Auth, InvalidAction)` | | | |
| relay: forged approval, a tampered delegate signature | refused (relay admission): `403 refused in simulation: HostError: Error(Auth, InvalidAction)` | | | |
| submit_guardian (2 of 2, promoting; a delegated perch guardian, relayed) | ok | 3,940,614 | 2.0662 | [`a16332b200…`](https://stellar.expert/explorer/testnet/tx/a16332b200ce968946c2350ea3cfa1196d1fbe5fcd7c998f7a9cd272676103f1) |
| completion apply_doc (GuardianOnly) | ok | 18,866,766 | 0.3815 | [`74a6a7328e…`](https://stellar.expert/explorer/testnet/tx/74a6a7328eaf8b811048252375e6ac7162544dcd67297a53a311b151950edbcb) |
| the new passkey after recovery | ok | 5,350,085 | 0.0559 | [`fa53065ac6…`](https://stellar.expert/explorer/testnet/tx/fa53065ac6a6362d1b82924d93fd988c0041dc75dec003534245369a041ed564) |
