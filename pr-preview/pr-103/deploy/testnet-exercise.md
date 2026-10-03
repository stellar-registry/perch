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
  under enforcing authorization (never submitted), and checked for the exact
  error where the contract returns one. Each `Protected` freeze refusal is
  checked to be the account's own `AccountFrozen` (`#2`) from `__check_auth`,
  read from the host's diagnostics.

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

Not on testnet: executing an upgrade (its 120 960-ledger delay is a week),
and an enrollment that seals a tree (a full tree takes 2^32 insertions). The
release-stack suite covers both on the same wasm, in-process: it upgrades
after the delay, and it enrolls into the last slot of a synthesized full
tree, then rotates into the next one and proves from it.

## Reproducibility

Building the stack from `source.commit` with the recorded toolchain gives
every hash in the manifest. This was checked twice on the deploying machine
(macOS arm64): a rebuild in the working tree, and a rebuild from a fresh
`git archive` copy at another path with an empty target directory. Building
on other hosts and toolchains has not been checked: `stellar scaffold build`
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
  days), and costs about 4–4.5 XLM. A promoting proof or approval persists
  the authorized attempt, about 1.5 XLM. Resource fees alone are a few
  hundredths of an XLM.

## Results

Run `1791022208` against `deployments/testnet.json` (stack commit `c10a8f7986bb`), ledgers 4999725–4999854: 70 transactions submitted, 28 refusals checked, 0 scenario failures. Fees paid: 40.5914 XLM.

### Against the budget

Worst measured transaction per row of `docs/recovery/budgets.md` §2, as a share of the protocol-29 per-transaction limits (400,000,000 instructions, 400 footprint entries, 200 written entries, 132,096 write bytes, 132,096 bytes of transaction). Budget: 75% of each. Memory is not reported by the RPC; the release-stack suite meters it locally.

| Row | Worst step | Instructions | Footprint entries | Written entries | Write bytes | Tx size | Fee (XLM) | Latency (s) | Within budget |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Enroll ZK through `apply_doc` | enroll Combined through apply_doc | 72,833,830 (18.2%) | 35 (8.8%) | 20 (10.0%) | 7,448 (5.6%) | 6,496 (4.9%) | 4.5160 | 1.8 | yes |
| `begin_lost_key` | begin_lost_key | 27,064,384 (6.8%) | 17 (4.2%) | 2 (1.0%) | 996 (0.8%) | 2,084 (1.6%) | 0.1839 | 2.4 | yes |
| `begin_compromise` | begin_compromise | 21,587,912 (5.4%) | 17 (4.2%) | 2 (1.0%) | 996 (0.8%) | 2,008 (1.5%) | 0.1836 | 3.2 | yes |
| `publish_baseline` | publish_baseline | 9,826,394 (2.5%) | 10 (2.5%) | 1 (0.5%) | 776 (0.6%) | 1,504 (1.1%) | 0.9984 | 4.8 | yes |
| `submit_guardian` | submit_guardian (2 of 2, promoting; sets the freeze) | 2,965,053 (0.7%) | 13 (3.2%) | 6 (3.0%) | 1,796 (1.4%) | 1,816 (1.4%) | 1.5798 | 4.7 | yes |
| `submit_zk` | submit_zk (Combined, promoting; sets the freeze) | 91,222,055 (22.8%) | 17 (4.2%) | 5 (2.5%) | 2,080 (1.6%) | 16,544 (12.5%) | 1.6372 | 6.6 | yes |
| Completion `apply_doc` | completion apply_doc (Combined, ZK rotation) | 71,156,998 (17.8%) | 42 (10.5%) | 30 (15.0%) | 8,728 (6.6%) | 6,908 (5.2%) | 1.3686 | 4.9 | yes |
| Owner cancellation (`Loss`) | Loss owner cancel_recovery (the veto) | 7,281,471 (1.8%) | 14 (3.5%) | 4 (2.0%) | 1,012 (0.8%) | 2,084 (1.6%) | 0.1080 | 2.2 | yes |
| `approve_change` | approve_change (G-account, 2 of 2) | 1,754,040 (0.4%) | 8 (2.0%) | 2 (1.0%) | 404 (0.3%) | 1,468 (1.1%) | 0.0041 | 3.5 | yes |
| `submit_zk_change` | submit_zk_change (Reconfigure) | 89,260,087 (22.3%) | 12 (3.0%) | 1 (0.5%) | 240 (0.2%) | 16,200 (12.3%) | 0.0263 | 3.5 | yes |
| `Protected` reconfiguration `apply_doc` | Protected Combined reconfiguration apply_doc | 33,542,818 (8.4%) | 30 (7.5%) | 18 (9.0%) | 5,316 (4.0%) | 6,212 (4.7%) | 0.0880 | 6.5 | yes |
| `Protected` `schedule_upgrade` | Protected schedule_upgrade | 7,272,429 (1.8%) | 13 (3.2%) | 2 (1.0%) | 1,096 (0.8%) | 2,044 (1.5%) | 0.1215 | 1.7 | yes |
| Ordinary activity (direct authorization) | activity before the condition is met | 5,554,361 (1.4%) | 10 (2.5%) | 3 (1.5%) | 440 (0.3%) | 1,752 (1.3%) | 0.1067 | 3.3 | yes |
| Ordinary activity (`execute`) | execute after the cancellation | 6,246,538 (1.6%) | 10 (2.5%) | 3 (1.5%) | 440 (0.3%) | 1,888 (1.4%) | 0.0567 | 6.5 | yes |
| Factory `create_passkey` | factory create_passkey | 2,737,802 (0.7%) | 9 (2.2%) | 4 (2.0%) | 992 (0.8%) | 924 (0.7%) | 0.0528 | 2.0 | yes |

Native proving on the deploying machine, while other builds ran, so slower than the uncontended numbers in [`docs/zk/measurements.md`](../zk/measurements.md): 11 proofs (`nargo execute` + `bb prove`, the pinned toolchain): witness 378 ms median / 611 ms max, proof 426 ms median / 1244 ms max, peak RSS 54 MiB.

### zk-only / loss: lost-key recovery with a real proof

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,737,802 | 0.0528 | [`1fdc98eb48…`](https://stellar.expert/explorer/testnet/tx/1fdc98eb482b6c318f24056405850804ee33fee5c4c2da2b07262e6167624c00) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0494 | [`1e09c2ded3…`](https://stellar.expert/explorer/testnet/tx/1e09c2ded360d61ceb5466cfc415d86b02f63a871842715693b4e54eb779415b) |
| enroll ZkOnly through apply_doc (pool insert) | ok | 69,567,673 | 3.9795 | [`ea047753e9…`](https://stellar.expert/explorer/testnet/tx/ea047753e92db1f88b62c8691ccac6fc5d2b6fcde864e89c604a0965ddb903fa) |
| ordinary activity: direct authorization | ok | 5,549,207 | 0.1067 | [`c5059be4dc…`](https://stellar.expert/explorer/testnet/tx/c5059be4dcf15c3470dee6c5fbb19f2fc144d662b0f660dc7b232c60d8e8b731) |
| ordinary activity: execute | ok | 6,237,900 | 0.0567 | [`7e37717e07…`](https://stellar.expert/explorer/testnet/tx/7e37717e07aee38c0c2d5ee96625f8615c3e805a545cb4e59b4ea17d6ac3118e) |
| begin_lost_key | ok | 23,662,334 | 0.1836 | [`146ac4cb68…`](https://stellar.expert/explorer/testnet/tx/146ac4cb689bb1d2c35593e1b73d1b4689d176b58b615378f97b55a2c4d22d00) |
| begin_lost_key (a second, evidence-free attempt) | ok | 23,677,426 | 0.0040 | [`fe92c216d3…`](https://stellar.expert/explorer/testnet/tx/fe92c216d3857731dd0bf3c121fa7b97e9129fdd962b1116221857903a31000f) |
| activity while attempts collect | ok | 5,546,487 | 0.0026 | [`af6985f99d…`](https://stellar.expert/explorer/testnet/tx/af6985f99d067a63ea15840fae35e1dab0ade58f4690029830e561a830a44227) |
| another attempt's proof | refused: `HostError: Error(Contract, #12)` | | | |
| a Cancel proof submitted as Initiate | refused: `HostError: Error(Contract, #12)` | | | |
| a tampered proof | refused: `HostError: Error(Contract, #12)` | | | |
| a root the pool never had | refused: `HostError: Error(Contract, #12)` | | | |
| submit_zk (real proof; authorizes the attempt) | ok | 90,373,914 | 1.5190 | [`ba85231772…`](https://stellar.expert/explorer/testnet/tx/ba8523177249aa2f49d5be256e7293a9fdbd516eb17ec795b1cf619df85fc014) |
| the same proof again | refused: `HostError: Error(Contract, #5)` | | | |
| Loss: activity during the authorized window | ok | 5,546,487 | 0.0026 | [`3b8da3558e…`](https://stellar.expert/explorer/testnet/tx/3b8da3558e8875ce57fc48d632ca8c2b521b5d725f045a0569101129d3257bf2) |
| Loss: an owner policy change during the window | refused: `HostError: Error(Contract, #23)` | | | |
| completion before the delay | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #6` | | | |
| completion with other bytes than the target | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #7` | | | |
| completion apply_doc (spends the nullifier, rotates the leaf) | ok | 67,934,773 | 1.3674 | [`faee496ca6…`](https://stellar.expert/explorer/testnet/tx/faee496ca63abc966aaa9abec6c01b3e5aeed9f6d2da41429c627749f33894d9) |
| the lost passkey after recovery | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,549,207 | 0.1067 | [`1db06cf1ec…`](https://stellar.expert/explorer/testnet/tx/1db06cf1ecf2ea66798d80a0e42220c1115bc1d8832b912e51db354722559991) |
| begin_lost_key (after recovery) | ok | 23,683,396 | 0.0040 | [`5e82daf56f…`](https://stellar.expert/explorer/testnet/tx/5e82daf56fcce30176445c6d09f3c968e007946e786b5552a5abc8f4ac5019be) |
| a proof by the consumed credential | refused: `HostError: Error(Contract, #12)` | | | |
### combined / protected: freeze, cancellation, reconfiguration

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,733,487 | 0.0528 | [`bb62379518…`](https://stellar.expert/explorer/testnet/tx/bb62379518039132818390c5064bea6ba7f472389444c05fbf42132c22b9df28) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0494 | [`ab02dcb874…`](https://stellar.expert/explorer/testnet/tx/ab02dcb874fd7d0c5d491e9f277ab4faf0c8cf1acedb77ee1c0087741e89d0be) |
| enroll Combined through apply_doc | ok | 72,833,830 | 4.5160 | [`0e673867d0…`](https://stellar.expert/explorer/testnet/tx/0e673867d0b713854364f307a106eb14e14b1e3392a2632c2fb4f45d74e9e0b6) |
| begin_lost_key | ok | 27,064,384 | 0.1839 | [`94f9ec5579…`](https://stellar.expert/explorer/testnet/tx/94f9ec55793766c79394ab6e504387ea2cb469662c8b78f5b446b6ff318d0b4d) |
| submit_guardian (G-account, 1 of 2) | ok | 1,954,536 | 0.0019 | [`e0a214b929…`](https://stellar.expert/explorer/testnet/tx/e0a214b929d81a513c09f9190a52f527ec8013fdaf8af309ce83dfbcc18d6da8) |
| submit_guardian (G-account, 2 of 2) | ok | 1,958,339 | 0.0019 | [`0960f270e5…`](https://stellar.expert/explorer/testnet/tx/0960f270e57d513677762ece2b93d538c42afa8c791ff7dafe27329575d6a5fa) |
| activity before the condition is met | ok | 5,554,361 | 0.1067 | [`9b9c01413e…`](https://stellar.expert/explorer/testnet/tx/9b9c01413ed1193eceacdfc6622f40dbb5e57c513e5546f18b8bfe3a0b82a9aa) |
| submit_zk (Combined, promoting; sets the freeze) | ok | 91,222,055 | 1.6372 | [`be509a9677…`](https://stellar.expert/explorer/testnet/tx/be509a9677460d4bc2c8294072d9142c4b84ce0aa5070a60a07967425023e167) |
| frozen: direct authorization | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: execute | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: apply_doc | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| an Initiate proof submitted as Cancel | refused: `HostError: Error(Contract, #12)` | | | |
| cancel: guardian 1 of 2 | ok | 2,072,642 | 0.0589 | [`080e5d5450…`](https://stellar.expert/explorer/testnet/tx/080e5d545002560edee5240a0d4fa47b7d04405021993ba5a410c7cd07d21070) |
| cancel: guardian 2 of 2 | ok | 2,074,476 | 0.0589 | [`8abfa4fbdb…`](https://stellar.expert/explorer/testnet/tx/8abfa4fbdb0ab354fd4ad1a907e35da507b57e556bd12b89fbdab68295144fe2) |
| cancellation (Combined: the ZK Cancel proof completes it, clears the freeze) | ok | 90,546,459 | 0.1854 | [`6e13473bcd…`](https://stellar.expert/explorer/testnet/tx/6e13473bcd19107c78bfeace300da3cf51124fbf89e44486761d25776dfff3cc) |
| activity after the cancellation | ok | 5,551,745 | 0.0026 | [`459d7d3f9e…`](https://stellar.expert/explorer/testnet/tx/459d7d3f9e11b080f904686b6a07648ded8f360b67ad781b694e4f44016f7604) |
| execute after the cancellation | ok | 6,246,538 | 0.0567 | [`494a9be949…`](https://stellar.expert/explorer/testnet/tx/494a9be94934583e6d6c967174391d091446287a9d8ef68c81c6134e89f33221) |
| submit_zk_change (Reconfigure) | ok | 89,260,087 | 0.0263 | [`2d0e05d786…`](https://stellar.expert/explorer/testnet/tx/2d0e05d78649929b2a0fc7042f69dc51e99f8a00dcd76593ade9b306280a9912) |
| reconfiguration with ZK evidence alone | refused: `HostError: Error(Contract, #37)` | | | |
| approve_change (G-account, 1 of 2) | ok | 1,750,261 | 0.0041 | [`82930443be…`](https://stellar.expert/explorer/testnet/tx/82930443bead7be862e4fe65faaf85e7c63264b1f4954b647970e36da1321422) |
| approve_change (G-account, 2 of 2) | ok | 1,754,040 | 0.0041 | [`35dbcde8be…`](https://stellar.expert/explorer/testnet/tx/35dbcde8beafdad6059ef95037fbf6f90e112647a610cdade9ee13252f953d69) |
| Protected Combined reconfiguration apply_doc | ok | 33,542,818 | 0.0880 | [`ae6acbfd79…`](https://stellar.expert/explorer/testnet/tx/ae6acbfd7973d520f61038c555d33fcc087876dc5cafbef56f1a7ef56c421060) |
### zk-only / protected: reconfiguration and upgrade evidence

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,737,802 | 0.0528 | [`148e354d0b…`](https://stellar.expert/explorer/testnet/tx/148e354d0b21f7a0f61a8473ab6041d508da74a5d9c1b6e808673fc1cf47633f) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0494 | [`300e513e32…`](https://stellar.expert/explorer/testnet/tx/300e513e325714b45137913f5b24a1e6b67fb55af4ca0d958b906ecdf3f9b805) |
| enroll ZkOnly Protected | ok | 69,668,924 | 3.9972 | [`df0c9d51ed…`](https://stellar.expert/explorer/testnet/tx/df0c9d51ed434c35cd3e17049d5fb0564de8a674c42f79ade4ef9024eae3353a) |
| owner alone cannot reconfigure | refused: `HostError: Error(Contract, #37)` | | | |
| a proof for another configuration | refused: `HostError: Error(Contract, #12)` | | | |
| submit_zk_change (Reconfigure) | ok | 89,237,050 | 0.0263 | [`8c299c0e09…`](https://stellar.expert/explorer/testnet/tx/8c299c0e095fa4a5fb82f2db08bbc92ddd539486b116d536f26e30df82026453) |
| Protected reconfiguration apply_doc | ok | 30,318,511 | 0.0875 | [`19bccf7c05…`](https://stellar.expert/explorer/testnet/tx/19bccf7c053a466bf63b12aa53edab6d043e8615f5135bed2a99aa70f5402108) |
| owner alone cannot schedule an upgrade | refused: `HostError: Error(Contract, #37)` | | | |
| submit_zk_change (Upgrade) | ok | 89,232,333 | 0.0263 | [`5fcdea2f61…`](https://stellar.expert/explorer/testnet/tx/5fcdea2f61a1d69cd47ede3f5205d60cce3f5031ec2173ace8a24955f8fd936c) |
| Protected schedule_upgrade | ok | 7,272,429 | 0.1215 | [`9c76ef60d7…`](https://stellar.expert/explorer/testnet/tx/9c76ef60d7dc246da71cd2df7a880228c935a5d7e0a29f39e7bab703594d2622) |
| execute_upgrade before the seven-day delay | refused: `HostError: Error(Contract, #9)` | | | |
### guardian-only / loss: veto and completion, no ZK

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,737,802 | 0.0528 | [`dccf87c0cc…`](https://stellar.expert/explorer/testnet/tx/dccf87c0cc7f17894c13e638f3c498c2d668eb183a955051173dc94b2f4180c7) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0494 | [`0c8c6533bc…`](https://stellar.expert/explorer/testnet/tx/0c8c6533bcee3298fc77f2dc8e30cc81424a4f4513e67ee7478683e8f178ca39) |
| enroll GuardianOnly through apply_doc | ok | 25,471,248 | 2.7785 | [`dfafdacc0b…`](https://stellar.expert/explorer/testnet/tx/dfafdacc0b76bdef10736be97b59d26c3c9160c4948dd6bd19e5c35b3cf1bb30) |
| begin_lost_key | ok | 20,001,091 | 0.1833 | [`48f8295a99…`](https://stellar.expert/explorer/testnet/tx/48f8295a99bd27cb42a1d1cfac6aeb04a4218789cefe6d054606cf7c40a5c3fc) |
| submit_guardian (1 of 2) | ok | 1,926,277 | 0.0019 | [`d69e68b9dc…`](https://stellar.expert/explorer/testnet/tx/d69e68b9dcc24195e48d236f4341c7e56041c0c8f4ee8b250ac2b1aaea0be6d1) |
| submit_guardian (2 of 2, promoting) | ok | 2,883,916 | 1.5745 | [`c609074015…`](https://stellar.expert/explorer/testnet/tx/c609074015b5d81e660a7b3e8c77ef0c2af5dd9d8f77fb84325ac970626191ab) |
| a third guardian on an authorized attempt | refused: `HostError: Error(Contract, #5)` | | | |
| Loss owner cancel_recovery (the veto) | ok | 7,281,471 | 0.1080 | [`b0a71400df…`](https://stellar.expert/explorer/testnet/tx/b0a71400df562523358c1bc147d860e0c5780bd10fe02bf788925ec711b583ef) |
| begin_lost_key (again) | ok | 20,018,775 | 0.0037 | [`5bf7fe1a4f…`](https://stellar.expert/explorer/testnet/tx/5bf7fe1a4f3abbae0519f2ae3b248edf25f6fe4353737e6f62e9bc8d2ae542e1) |
| submit_guardian (1 of 2) | ok | 1,941,187 | 0.0019 | [`799f8bfed3…`](https://stellar.expert/explorer/testnet/tx/799f8bfed3d7627507266e1f98163502beb1af5f4321da2d2c7c4de542e9079f) |
| submit_guardian (2 of 2, promoting) | ok | 2,902,362 | 1.3897 | [`39536331a7…`](https://stellar.expert/explorer/testnet/tx/39536331a72aab864d35f00363397bece581823dc0feb9e5aff4e952652e4f3a) |
| completion apply_doc (GuardianOnly) | ok | 25,087,045 | 0.2876 | [`5a96e21d4c…`](https://stellar.expert/explorer/testnet/tx/5a96e21d4ca9705d57884e5d2ed6425776a0c73cd2ab8655d87a1276fe90b38c) |
| the lost passkey after recovery | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,523,360 | 0.1068 | [`2eda9d2a0a…`](https://stellar.expert/explorer/testnet/tx/2eda9d2a0ad47fcaa01c1fab8aa2409d6bf98c6921fbd608ee6235e0c0ab5828) |
### combined / loss: both factors, ZK rotation

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,733,487 | 0.0529 | [`2f9135404b…`](https://stellar.expert/explorer/testnet/tx/2f9135404bf38e572855645f06c7a2ee1c27ca3f2c8880a9610b7be4e578a78b) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0494 | [`3004d9452a…`](https://stellar.expert/explorer/testnet/tx/3004d9452aee998e1ba66385ca8644736098db28280ee452bbbf681b4374e569) |
| enroll Combined Loss | ok | 72,761,967 | 4.4981 | [`e996738bf4…`](https://stellar.expert/explorer/testnet/tx/e996738bf453e449ca43ef7a678c86676e65ae6387ff0ff3d2091ec0bfcc2651) |
| begin_lost_key | ok | 27,000,629 | 0.1840 | [`5cac97f036…`](https://stellar.expert/explorer/testnet/tx/5cac97f036c5aee172bc7c6a4ba420a787ef21a85e85779cd6681303301ea1c4) |
| submit_guardian (1 of 2) | ok | 1,954,569 | 0.0019 | [`bf7ced67b1…`](https://stellar.expert/explorer/testnet/tx/bf7ced67b15cbdc161d09687f6a06bf9bda237ac848098b6aceab248542c2290) |
| submit_zk (Combined, not yet promoting) | ok | 89,391,744 | 0.0141 | [`259a38708f…`](https://stellar.expert/explorer/testnet/tx/259a38708fcbfe359782395af4ee5112cfb3c3d70541ddc4ca9b0d202387338f) |
| submit_guardian (2 of 2, promoting: ZK already in) | ok | 2,943,644 | 1.6216 | [`e391ae357d…`](https://stellar.expert/explorer/testnet/tx/e391ae357dbd9d0a3fdaf1e1ba9749646e705796b45a0bb3f3e49e72c27f7cbb) |
| Loss: activity during the authorized window | ok | 5,554,361 | 0.1068 | [`115edc4334…`](https://stellar.expert/explorer/testnet/tx/115edc4334bd8ae2f39d75b8cde6c19c7059feb89d4b16b10ec8746a73c81340) |
| completion apply_doc (Combined, ZK rotation) | ok | 71,156,998 | 1.3686 | [`fc27a368e8…`](https://stellar.expert/explorer/testnet/tx/fc27a368e8a45c6d30a9f8e327ccf3fa377d6089e54f99cd9a59f20010509626) |
| the lost passkey after recovery | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,554,361 | 0.1068 | [`c5f7eed97c…`](https://stellar.expert/explorer/testnet/tx/c5f7eed97caf5ec5d869bddd1094ad98738b4d5a0d0e0ae9473b8eebecce16c3) |
### guardian-only / protected: compromise recovery from the baseline

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,737,802 | 0.0529 | [`2b531f6765…`](https://stellar.expert/explorer/testnet/tx/2b531f6765445b0d485f5636cf708d16367be08cbeed7f4d42938f7702a6c4c3) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0494 | [`614b0238d7…`](https://stellar.expert/explorer/testnet/tx/614b0238d7b5f55e4afa9c911258a763dfdacde25073d8d2cb531b2e006bb08a) |
| enroll GuardianOnly Protected with a baseline | ok | 26,993,420 | 2.9601 | [`aafe1c6bde…`](https://stellar.expert/explorer/testnet/tx/aafe1c6bde648c0bfc22ce2ae883fbb7d8cf1e77f5259ab6200a3ff0af23241d) |
| the thief adds a signer with the stolen owner key | ok | 34,434,568 | 0.7181 | [`c3e0892318…`](https://stellar.expert/explorer/testnet/tx/c3e08923187199fdd48734ca0b3c31947f887eacad70da62cf7b5b2f55739664) |
| the thief's signer moves XLM | ok | 5,523,504 | 0.1074 | [`06a3d834f5…`](https://stellar.expert/explorer/testnet/tx/06a3d834f5ee8a9bea6607088fbede14fbc39c2b130edae8bc49d5e2a773e640) |
| begin_compromise before the baseline is published | refused: `HostError: Error(Contract, #23)` | | | |
| publish_baseline of another document | refused: `HostError: Error(Contract, #24)` | | | |
| publish_baseline | ok | 9,826,394 | 0.9984 | [`8c9bd7f665…`](https://stellar.expert/explorer/testnet/tx/8c9bd7f6655048725284346125d346368a1ae57552477561d58358783894fd27) |
| begin_compromise | ok | 21,587,912 | 0.1836 | [`611b591c45…`](https://stellar.expert/explorer/testnet/tx/611b591c4517fbb39096e86cc044c10e3bcf30b1a8db71116465b49d412fd852) |
| submit_guardian (1 of 2) | ok | 1,930,150 | 0.0019 | [`95748d27f1…`](https://stellar.expert/explorer/testnet/tx/95748d27f1cf7abcbc571bd17185683295c79592f5c2173226a665adc33e1c7a) |
| submit_guardian (2 of 2, promoting; sets the freeze) | ok | 2,965,053 | 1.5798 | [`719ce5c784…`](https://stellar.expert/explorer/testnet/tx/719ce5c784b6a96224dbfe6d0451f41ad1d6ede5c9a3fd70d58b77b67ccb1f7a) |
| frozen: the thief's signer | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: the owner key | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| completion apply_doc (compromise: revokes the stolen and added keys) | ok | 27,686,499 | 0.4593 | [`bff45acaef…`](https://stellar.expert/explorer/testnet/tx/bff45acaeff46a974147b3832c2436b5a2841becca012a376e3676a9d9032e90) |
| the new owner after recovery | ok | 5,523,360 | 0.1068 | [`e99ce3ef40…`](https://stellar.expert/explorer/testnet/tx/e99ce3ef4078af5fab792c5df0629c044b40c4361cd3d95c2846dda1c5a5470d) |
| the stolen owner key after recovery | refused: `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| re-adding the thief's key, signed by the new owner | refused: `HostError: Error(Contract, #2)` | | | |

