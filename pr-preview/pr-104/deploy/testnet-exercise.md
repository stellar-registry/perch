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

Run `1791023560` against `deployments/testnet.json` (stack commit `c10a8f7986bb`), ledgers 4999995–5000108: 70 transactions submitted, 28 refusals checked, 0 scenario failures. Fees paid: 40.6604 XLM.

### Against the budget

Worst measured transaction per row of `docs/recovery/budgets.md` §2, as a share of the protocol-29 per-transaction limits (400,000,000 instructions, 400 footprint entries, 200 written entries, 132,096 write bytes, 132,096 bytes of transaction). Budget: 75% of each. Memory is not reported by the RPC; the release-stack suite meters it locally.

| Row | Worst step | Instructions | Footprint entries | Written entries | Write bytes | Tx size | Fee (XLM) | Latency (s) | Within budget |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Enroll ZK through `apply_doc` | enroll Combined through apply_doc | 72,843,565 (18.2%) | 35 (8.8%) | 20 (10.0%) | 7,448 (5.6%) | 6,496 (4.9%) | 4.5248 | 3.2 | yes |
| `begin_lost_key` | begin_lost_key | 27,067,336 (6.8%) | 17 (4.2%) | 2 (1.0%) | 996 (0.8%) | 2,084 (1.6%) | 0.1843 | 3.2 | yes |
| `begin_compromise` | begin_compromise | 21,581,196 (5.4%) | 17 (4.2%) | 2 (1.0%) | 996 (0.8%) | 2,008 (1.5%) | 0.1838 | 4.7 | yes |
| `publish_baseline` | publish_baseline | 9,829,940 (2.5%) | 10 (2.5%) | 1 (0.5%) | 776 (0.6%) | 1,504 (1.1%) | 0.9996 | 3.2 | yes |
| `submit_guardian` | submit_guardian (2 of 2, promoting; sets the freeze) | 2,968,474 (0.7%) | 13 (3.2%) | 6 (3.0%) | 1,796 (1.4%) | 1,816 (1.4%) | 1.5816 | 4.8 | yes |
| `submit_zk` | submit_zk (Combined, promoting; sets the freeze) | 91,161,336 (22.8%) | 17 (4.2%) | 5 (2.5%) | 2,080 (1.6%) | 16,544 (12.5%) | 1.6404 | 3.2 | yes |
| Completion `apply_doc` | completion apply_doc (Combined, ZK rotation) | 71,169,029 (17.8%) | 42 (10.5%) | 30 (15.0%) | 8,728 (6.6%) | 6,908 (5.2%) | 1.3702 | 1.9 | yes |
| Owner cancellation (`Loss`) | Loss owner cancel_recovery (the veto) | 7,276,754 (1.8%) | 14 (3.5%) | 4 (2.0%) | 1,012 (0.8%) | 2,084 (1.6%) | 0.1082 | 3.2 | yes |
| `approve_change` | approve_change (G-account, 2 of 2) | 1,754,040 (0.4%) | 8 (2.0%) | 2 (1.0%) | 404 (0.3%) | 1,468 (1.1%) | 0.0042 | 4.8 | yes |
| `submit_zk_change` | submit_zk_change (Upgrade) | 89,278,468 (22.3%) | 12 (3.0%) | 1 (0.5%) | 240 (0.2%) | 16,236 (12.3%) | 0.0263 | 6.4 | yes |
| `Protected` reconfiguration `apply_doc` | Protected Combined reconfiguration apply_doc | 33,537,680 (8.4%) | 30 (7.5%) | 18 (9.0%) | 5,316 (4.0%) | 6,212 (4.7%) | 0.0881 | 3.3 | yes |
| `Protected` `schedule_upgrade` | Protected schedule_upgrade | 7,272,429 (1.8%) | 13 (3.2%) | 2 (1.0%) | 1,096 (0.8%) | 2,044 (1.5%) | 0.1217 | 3.2 | yes |
| Ordinary activity (direct authorization) | ordinary activity: direct authorization | 5,554,361 (1.4%) | 10 (2.5%) | 3 (1.5%) | 440 (0.3%) | 1,752 (1.3%) | 0.1069 | 3.3 | yes |
| Ordinary activity (`execute`) | ordinary activity: execute | 6,246,538 (1.6%) | 10 (2.5%) | 3 (1.5%) | 440 (0.3%) | 1,888 (1.4%) | 0.0568 | 3.2 | yes |
| Factory `create_passkey` | factory create_passkey | 2,737,802 (0.7%) | 9 (2.2%) | 4 (2.0%) | 992 (0.8%) | 924 (0.7%) | 0.0529 | 3.4 | yes |

Native proving on the deploying machine (Apple silicon; see [`docs/zk/measurements.md`](../zk/measurements.md) for the browser and the depth comparison), 11 proofs (`nargo execute` + `bb prove`, the pinned toolchain): witness 67 ms median / 71 ms max, proof 69 ms median / 72 ms max, peak RSS 47 MiB.

### zk-only / loss: lost-key recovery with a real proof

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,733,487 | 0.0529 | [`df6e150f6c…`](https://stellar.expert/explorer/testnet/tx/df6e150f6c104976fabea6bb7803553532e947c3d9dea68e182e30ba03ca0441) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0495 | [`283dedd0ff…`](https://stellar.expert/explorer/testnet/tx/283dedd0ff2beb9dcfedf642813c10b067de3cb394147d6a65c6c05cfb35d40d) |
| enroll ZkOnly through apply_doc (pool insert) | ok | 69,584,320 | 3.9888 | [`dd4af12b2a…`](https://stellar.expert/explorer/testnet/tx/dd4af12b2a76782d902f378ec7e59a436f314b570f719be93d5159ed469ecd0d) |
| ordinary activity: direct authorization | ok | 5,554,361 | 0.1069 | [`c636a403d4…`](https://stellar.expert/explorer/testnet/tx/c636a403d412ccdbce872d5b4396a0adcf88b26e12acafca6cc2c0af21b9175f) |
| ordinary activity: execute | ok | 6,246,538 | 0.0568 | [`d9239f001c…`](https://stellar.expert/explorer/testnet/tx/d9239f001c02335a708d16bf250c6ebadd7e5416e8bffd98c6544e8b104ce149) |
| begin_lost_key | ok | 23,663,162 | 0.1840 | [`6400e07481…`](https://stellar.expert/explorer/testnet/tx/6400e074817420f01bb8b30a58992b4d811ae8c9a2556754f3bcaca988f42fcb) |
| begin_lost_key (a second, evidence-free attempt) | ok | 23,678,254 | 0.0040 | [`562b5fc073…`](https://stellar.expert/explorer/testnet/tx/562b5fc073dee84d779c8880afb521dee648e7e474bb523e18af0a0024971ca4) |
| activity while attempts collect | ok | 5,551,745 | 0.0026 | [`b32b07b611…`](https://stellar.expert/explorer/testnet/tx/b32b07b611402a470a7363260e83b23e4877d24d77d879053134474588e1742d) |
| another attempt's proof | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a Cancel proof submitted as Initiate | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a tampered proof | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| a root the pool never had | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| submit_zk (real proof; authorizes the attempt) | ok | 90,427,233 | 1.5228 | [`6700c9a2da…`](https://stellar.expert/explorer/testnet/tx/6700c9a2daa2e84c527e75236e03fa6c324bd89aee68543f4a9f3743568ed924) |
| the same proof again | refused (recording simulation): `HostError: Error(Contract, #5)` | | | |
| Loss: activity during the authorized window | ok | 5,551,745 | 0.0026 | [`e9ae46dbc1…`](https://stellar.expert/explorer/testnet/tx/e9ae46dbc14e98b8d9a7971493d465cf7c3662d70c9dcf1bf166d4f86268845c) |
| Loss: an owner policy change during the window | refused (recording simulation): `HostError: Error(Contract, #23)` | | | |
| completion before the delay | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #6` | | | |
| completion with other bytes than the target | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #7` | | | |
| completion apply_doc (spends the nullifier, rotates the leaf) | ok | 67,925,899 | 1.3700 | [`1d77729f55…`](https://stellar.expert/explorer/testnet/tx/1d77729f55cb235f0c7dfed93d287556cb68cc54fcaa70829ce17c0c6ab71110) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,554,361 | 0.1069 | [`1adb8b1bc8…`](https://stellar.expert/explorer/testnet/tx/1adb8b1bc83306bdde7ba073e0e1859dccf05bdd5188140380a1b07791b32737) |
| begin_lost_key (after recovery) | ok | 23,682,078 | 0.0040 | [`a04fc50d2c…`](https://stellar.expert/explorer/testnet/tx/a04fc50d2c76972a8ae32cb4aaaa4f07467a8f5a708807e20f52c4c7a078f541) |
| a proof by the consumed credential | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
### combined / protected: freeze, cancellation, reconfiguration

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,737,802 | 0.0529 | [`60e6be2e7f…`](https://stellar.expert/explorer/testnet/tx/60e6be2e7fd8ea65b2534de143d82bd9b7702a76a9df7b852614774c3c6a2242) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0495 | [`0078ac2694…`](https://stellar.expert/explorer/testnet/tx/0078ac26947d67e19a964039c20ca9ea4ea898642bc659dd959f52aa1eac30dd) |
| enroll Combined through apply_doc | ok | 72,843,565 | 4.5248 | [`c4073b5b62…`](https://stellar.expert/explorer/testnet/tx/c4073b5b62bff51c60de054bb40f7a92a0997003eb425f69f09d6b18e71de348) |
| begin_lost_key | ok | 27,067,336 | 0.1843 | [`958695c30c…`](https://stellar.expert/explorer/testnet/tx/958695c30cbd36a0b3b698df47ec44db85aaad8cc021a056a905c8b3d29d697b) |
| submit_guardian (G-account, 1 of 2) | ok | 1,954,536 | 0.0019 | [`771b82ce01…`](https://stellar.expert/explorer/testnet/tx/771b82ce0113deda6de38b19e9a9da1f24a2d57fc219d977ac2cf802093ad511) |
| submit_guardian (G-account, 2 of 2) | ok | 1,958,339 | 0.0019 | [`cd66b0e602…`](https://stellar.expert/explorer/testnet/tx/cd66b0e60238669546708a1ad2b139908ece642fcd10a5b9994caa066ec63b25) |
| activity before the condition is met | ok | 5,549,207 | 0.1069 | [`07762cf3c3…`](https://stellar.expert/explorer/testnet/tx/07762cf3c3347e5f233430155533571045e629c2fa1d383af378478f546ee9d7) |
| submit_zk (Combined, promoting; sets the freeze) | ok | 91,161,336 | 1.6404 | [`d3604e48a4…`](https://stellar.expert/explorer/testnet/tx/d3604e48a4c7216bb1b8a41113286eeb6f743c7023c1b3dbd4ad7fcb689be8fa) |
| frozen: direct authorization | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: execute | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: apply_doc | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| an Initiate proof submitted as Cancel | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| cancel: guardian 1 of 2 | ok | 2,070,363 | 0.0590 | [`9e8e8a5207…`](https://stellar.expert/explorer/testnet/tx/9e8e8a5207fca1b5e7c4b37602949fc23b5cde018cb03fcdd0fd99378a50f8eb) |
| cancel: guardian 2 of 2 | ok | 2,074,476 | 0.0590 | [`20677fbc2b…`](https://stellar.expert/explorer/testnet/tx/20677fbc2b4c90cd0a033c3fefb17cf45115f877488fde52f56957386d51393e) |
| cancellation (Combined: the ZK Cancel proof completes it, clears the freeze) | ok | 90,538,842 | 0.1857 | [`f18dad9ec5…`](https://stellar.expert/explorer/testnet/tx/f18dad9ec54a306f5b8492acfbea2ea04a84fdc56fc25d55ccc8f272f2417303) |
| activity after the cancellation | ok | 5,546,487 | 0.0026 | [`174a8c374c…`](https://stellar.expert/explorer/testnet/tx/174a8c374cc50280405251f83ad18e1667985c7d9af036d1d5dbeac666fb393a) |
| execute after the cancellation | ok | 6,237,900 | 0.0568 | [`4cc2a11e67…`](https://stellar.expert/explorer/testnet/tx/4cc2a11e672253b635e0bd95ef848997b300c19e7fa5686495177001e1af4853) |
| submit_zk_change (Reconfigure) | ok | 89,214,169 | 0.0263 | [`953e703704…`](https://stellar.expert/explorer/testnet/tx/953e70370459b0a881592ffe52d364ab23d2b6f6cfba5b38865df87cbf5206d2) |
| reconfiguration with ZK evidence alone | refused (recording simulation): `HostError: Error(Contract, #37)` | | | |
| approve_change (G-account, 1 of 2) | ok | 1,750,261 | 0.0041 | [`14530789c9…`](https://stellar.expert/explorer/testnet/tx/14530789c9d99caee604386339ca957f7365445a2a688c163fbe15158d7158b2) |
| approve_change (G-account, 2 of 2) | ok | 1,754,040 | 0.0042 | [`a215ef7442…`](https://stellar.expert/explorer/testnet/tx/a215ef7442ac12e2b2b9519c9fe9a019e4724951509991d31697a8f529af260e) |
| Protected Combined reconfiguration apply_doc | ok | 33,537,680 | 0.0881 | [`091104980e…`](https://stellar.expert/explorer/testnet/tx/091104980eebb771a36a03d70d404393ee8aa40bd2adac2700602d362b296974) |
### zk-only / protected: reconfiguration and upgrade evidence

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,737,802 | 0.0529 | [`8301b8900e…`](https://stellar.expert/explorer/testnet/tx/8301b8900e2696684beada4a3e9b1092635ebc5d9b7bbe26f7e09964ba42e4a5) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0495 | [`82441fe02b…`](https://stellar.expert/explorer/testnet/tx/82441fe02bfdbccac3439c3130193f2a53d7b823f54ac33aaf8ba85415c052ef) |
| enroll ZkOnly Protected | ok | 69,661,527 | 4.0049 | [`0c26669b7f…`](https://stellar.expert/explorer/testnet/tx/0c26669b7f447ce5e037441caa93df13d9af39d1b10d2e10fa7a69c7d8cf9f5d) |
| owner alone cannot reconfigure | refused (recording simulation): `HostError: Error(Contract, #37)` | | | |
| a proof for another configuration | refused (recording simulation): `HostError: Error(Contract, #12)` | | | |
| submit_zk_change (Reconfigure) | ok | 89,229,325 | 0.0263 | [`888e961dd4…`](https://stellar.expert/explorer/testnet/tx/888e961dd46808554715487839f35ae26d82fb4f3d24a78c868a3a76e6dd24ec) |
| Protected reconfiguration apply_doc | ok | 30,318,503 | 0.0877 | [`27dea1cb3a…`](https://stellar.expert/explorer/testnet/tx/27dea1cb3aca727df567febf08dafdda536d7c71ccc2a494fbcb242835024435) |
| owner alone cannot schedule an upgrade | refused (recording simulation): `HostError: Error(Contract, #37)` | | | |
| submit_zk_change (Upgrade) | ok | 89,278,468 | 0.0263 | [`6f3eb42188…`](https://stellar.expert/explorer/testnet/tx/6f3eb42188889af0f4e133318ef62370bba4a39eecd7a83cdbeec98b06f6a62d) |
| Protected schedule_upgrade | ok | 7,272,429 | 0.1217 | [`cfaea84c56…`](https://stellar.expert/explorer/testnet/tx/cfaea84c56bdaee1ec8b45936a3d0db4386151909871033ff16a1deee190e02c) |
| execute_upgrade before the seven-day delay | refused (recording simulation): `HostError: Error(Contract, #9)` | | | |
### guardian-only / loss: veto and completion, no ZK

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,737,802 | 0.0529 | [`37297a6e02…`](https://stellar.expert/explorer/testnet/tx/37297a6e0285cba327dccbcccde5dcf028b4bc883feaf24e4e9dad0db794ac38) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0495 | [`bed5837595…`](https://stellar.expert/explorer/testnet/tx/bed58375956fd4a8457844803c3e089ae907c3ff697b364b392df8455af332ea) |
| enroll GuardianOnly through apply_doc | ok | 25,461,572 | 2.7839 | [`8d618e1676…`](https://stellar.expert/explorer/testnet/tx/8d618e1676fb562a71639150384813457b14c537b92d47f2c07d6ceead1386cc) |
| begin_lost_key | ok | 20,001,414 | 0.1837 | [`40789da9be…`](https://stellar.expert/explorer/testnet/tx/40789da9be7b2efab9290afd42542f5afb9215ab3909bc1d8c9da0ce899cdf41) |
| submit_guardian (1 of 2) | ok | 1,926,277 | 0.0019 | [`e14fc6ba7a…`](https://stellar.expert/explorer/testnet/tx/e14fc6ba7ad6938086617a019efde5fd6229f5fe7dacbaf263d92b91ed875514) |
| submit_guardian (2 of 2, promoting) | ok | 2,882,744 | 1.5775 | [`e3e06fba52…`](https://stellar.expert/explorer/testnet/tx/e3e06fba5269d28ace00ad153179a861eea34081ab1e6e2cdd0d88320c6cc29f) |
| a third guardian on an authorized attempt | refused (recording simulation): `HostError: Error(Contract, #5)` | | | |
| Loss owner cancel_recovery (the veto) | ok | 7,276,754 | 0.1082 | [`c5e89639eb…`](https://stellar.expert/explorer/testnet/tx/c5e89639eb8747287cdf8e662c0f217a8577a0dbf25fdc1677a2431d1edecf1f) |
| begin_lost_key (again) | ok | 20,018,588 | 0.0037 | [`f179cf5e20…`](https://stellar.expert/explorer/testnet/tx/f179cf5e20e894ee0493072add5c8d26b16fdc5ea835f277453e5bc07bfbc748) |
| submit_guardian (1 of 2) | ok | 1,941,187 | 0.0019 | [`df4b02bd74…`](https://stellar.expert/explorer/testnet/tx/df4b02bd743ad9ec49481d6093a2ffefedec066a30ded93034eddfc83ce26697) |
| submit_guardian (2 of 2, promoting) | ok | 2,900,353 | 1.3924 | [`3c56618b79…`](https://stellar.expert/explorer/testnet/tx/3c56618b79648e918fdcc8ca703023a75411b1b033155ef23a1ba85a8167d309) |
| completion apply_doc (GuardianOnly) | ok | 25,069,705 | 0.2881 | [`c321cb2d9e…`](https://stellar.expert/explorer/testnet/tx/c321cb2d9e09cb42495e3cc59a3d4bde137717327ee90e0e45551207dd9a7080) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,523,360 | 0.1069 | [`5632947115…`](https://stellar.expert/explorer/testnet/tx/56329471157f79bea55ef7703f8b43b9b86d637da2d456ca42ec6922adc6003d) |
### combined / loss: both factors, ZK rotation

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,737,802 | 0.0529 | [`0d6e457dff…`](https://stellar.expert/explorer/testnet/tx/0d6e457dff0e180ee34808d773390e89a40d1500929e75e7e380254523bab89c) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0495 | [`051d87ed05…`](https://stellar.expert/explorer/testnet/tx/051d87ed0503a16f889f3b880b4a60862a76cebe71d08291c6b1b7941323b28c) |
| enroll Combined Loss | ok | 72,766,463 | 4.5033 | [`d84ae09526…`](https://stellar.expert/explorer/testnet/tx/d84ae09526b4f19bae82ce89a2d0a2be943d8b514b982fc2b4ffba929788fb5b) |
| begin_lost_key | ok | 27,004,979 | 0.1842 | [`e6c8dba710…`](https://stellar.expert/explorer/testnet/tx/e6c8dba710f61b5a2e007224c2130d6dfe19b251e56962f1398642c0b826914b) |
| submit_guardian (1 of 2) | ok | 1,954,569 | 0.0019 | [`9c3e784a3a…`](https://stellar.expert/explorer/testnet/tx/9c3e784a3a44a89cf4dc88512e6b556436e4dca3e74c2a50cae12cffd6a3a13f) |
| submit_zk (Combined, not yet promoting) | ok | 89,429,612 | 0.0141 | [`fda09fc914…`](https://stellar.expert/explorer/testnet/tx/fda09fc914178bebd1c46d8cf7dc35d77addf35dee2054b5144524b89a3fa92a) |
| submit_guardian (2 of 2, promoting: ZK already in) | ok | 2,943,644 | 1.6235 | [`f71bd02fde…`](https://stellar.expert/explorer/testnet/tx/f71bd02fdeda252c088fe23a2735179cfb587cef9ea53240338172051bddb2ab) |
| Loss: activity during the authorized window | ok | 5,549,207 | 0.1069 | [`40257bcde6…`](https://stellar.expert/explorer/testnet/tx/40257bcde6de5e7486890399caef59269188333f8c72215bca11668888366d9a) |
| completion apply_doc (Combined, ZK rotation) | ok | 71,169,029 | 1.3702 | [`34cd6d2658…`](https://stellar.expert/explorer/testnet/tx/34cd6d26585b523fd2bf24944f2102da4c065074ec6e9c3874f34178793f8dcd) |
| the lost passkey after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| the new passkey after recovery | ok | 5,549,207 | 0.1069 | [`3aa1d72d35…`](https://stellar.expert/explorer/testnet/tx/3aa1d72d3518ef09f850bdc5f2eef0c36189bf2a24930963ad86c6592cee3bfa) |
### guardian-only / protected: compromise recovery from the baseline

| Step | Result | Instructions | Fee (XLM) | Transaction |
| --- | --- | --- | --- | --- |
| factory create_passkey | ok | 2,737,802 | 0.0529 | [`c864a6e26b…`](https://stellar.expert/explorer/testnet/tx/c864a6e26b02a4ec0e36004dc0c6c156fc9db5bf7c77a27ed80aac7f79a947e8) |
| fund the account (XLM transfer) | ok | 245,621 | 0.0495 | [`957ea45ca9…`](https://stellar.expert/explorer/testnet/tx/957ea45ca92635a61c332062a5184d95a5015e3c3f4c625aa927f343f0cd1005) |
| enroll GuardianOnly Protected with a baseline | ok | 27,008,935 | 2.9635 | [`5e3ff5b22e…`](https://stellar.expert/explorer/testnet/tx/5e3ff5b22eba521eb9a41bd6bb4c94d33d92c5271edbb060e21e766206b33982) |
| the thief adds a signer with the stolen owner key | ok | 34,430,659 | 0.7189 | [`4e958d5264…`](https://stellar.expert/explorer/testnet/tx/4e958d52641f4ab187360f4fa1dfbf99616389db61829bb7e795bcbd3e417428) |
| the thief's signer moves XLM | ok | 5,523,504 | 0.1076 | [`875eb262a1…`](https://stellar.expert/explorer/testnet/tx/875eb262a11111bc3bc967ee364c6778fe650348a83454d822d5c5ce97e2d495) |
| begin_compromise before the baseline is published | refused (recording simulation): `HostError: Error(Contract, #23)` | | | |
| publish_baseline of another document | refused (recording simulation): `HostError: Error(Contract, #24)` | | | |
| publish_baseline | ok | 9,829,940 | 0.9996 | [`5c64dca234…`](https://stellar.expert/explorer/testnet/tx/5c64dca2344f4a7ea555bc7089dd651b323f8bb6d93fe80420889a8efb70dd07) |
| begin_compromise | ok | 21,581,196 | 0.1838 | [`6c97ac846d…`](https://stellar.expert/explorer/testnet/tx/6c97ac846ddca2bbd4022855ba6bcb36dcbd4e02f098a6d3d2e7889dfb5a57c6) |
| submit_guardian (1 of 2) | ok | 1,930,150 | 0.0019 | [`7b814a8805…`](https://stellar.expert/explorer/testnet/tx/7b814a88054097193f4153cf74e8e7b5df50ee3cd34f98761b8da20ba37fda36) |
| submit_guardian (2 of 2, promoting; sets the freeze) | ok | 2,968,474 | 1.5816 | [`eaf1af33c1…`](https://stellar.expert/explorer/testnet/tx/eaf1af33c15710053324c9a95bf35df396d019729333461b81a02f9b7e4dc738) |
| frozen: the thief's signer | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| frozen: the owner key | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #2` | | | |
| completion apply_doc (compromise: revokes the stolen and added keys) | ok | 27,673,966 | 0.4598 | [`4b530418f6…`](https://stellar.expert/explorer/testnet/tx/4b530418f62a2bf247c6e791bdde4f7815438c3f8114235740ab02d0b7fa0da6) |
| the new owner after recovery | ok | 5,523,360 | 0.1069 | [`fe26c443d6…`](https://stellar.expert/explorer/testnet/tx/fe26c443d621702bcb55b12453dfdc73f500e0a18353557ac51379b056f3d1f1) |
| the stolen owner key after recovery | refused (enforcing simulation): `HostError: Error(Auth, InvalidAction), `__check_auth` #3002` | | | |
| re-adding the thief's key, signed by the new owner | refused (recording simulation): `HostError: Error(Contract, #2)` | | | |

