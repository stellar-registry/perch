# perch-review-core

A Perch account's verdict on an authorization entry, computed off-chain
from a ledger snapshot, before anyone signs. It runs the account's own
`__check_auth` checks and rule-core's `rule_eval::check_auth`, reports what
each chosen capped rule has left to spend, and replays attenuation
witnesses. It has no dependency on the Soroban host, so it builds to a small
wasm module with no imports. A wallet's sign dialog takes the verdict and
the budgets from it instead of re-deriving them in JavaScript.

## What the verdict means

For the ledger entries given and the ledger sequence given, assuming every
payload signer that the request does not mark unverified authenticates, the
verdict equals the account's `__check_auth` result on that state at that
ledger. The account here is `perch_smart_account::check_auth` on the fork's
`dev` branch, which `perch-account` deploys.

The verdict depends on five assumptions:

- **Signatures.** The core does not verify signatures. It accepts a
  `verified` flag for each payload signer (`no`, `yes`, or `assumed`, the
  default), and every verdict lists the signers it assumed (`assumed`).
  If rule-eval accepts and a signer is marked `no`, the core refuses, as the
  account would. The error code then comes from the signer's side:
  - an `External` signer's verifier that returns `false` gives
    `ExternalVerificationFailed` (3003);
  - an ed25519 verifier traps on a bad signature, so the code is the
    verifier's own;
  - a `Delegated` signer's code is that of its own authorization.

  The core reports this as `SignerRefused`, without a code. A `Delegated`
  signer that has no delegate in the entry's CAP-0071 credentials fails
  with a host error, because the host's delegate check finds nothing to
  check.
- **Snapshot.** The ledger entries must include every entry `__check_auth`
  reads for this authorization, and each must be live:
  - the account's instance entry;
  - `RuleSet`;
  - `GrantTags(id)` and `SpendRecords(id)` for each chosen id;
  - `Grants(g)` for each grant those tags name.

  `Snapshot::keys` and `Snapshot::grant_keys` list these keys. The core
  treats an entry missing from the snapshot as absent from the ledger.
- **Ledger.** The verdict holds at the given ledger sequence and nowhere
  else. Expiry, the freeze and spending windows all depend on the sequence.
  Storage can also change between review and inclusion: another spend, an
  `apply_doc` or `apply_grant`, or a recovery completion that advances the
  grant generation. Any of these can change the answer. So can a sibling
  entry: a review covers one authorization entry, and two entries of one
  account in one transaction that charge the same cap are not composed. Each
  is judged on the snapshot as given, without the other's charge. The npm
  wrapper's `perchPreview` reports the later one as unknown rather than
  accepted.
- **Network limits.** The core does not model the network's resource
  limits, so a transaction can fail on them even when the account accepts.
  These include instructions, footprint, and the size of a contract-data
  entry. One case is reachable through the account's own state: a capped
  rule's spending record holds up to 1,000 spends in its window
  (rule-eval's `MAX_HISTORY_ENTRIES`), but at about 72 bytes per spend, the
  network's 64 KiB entry limit is reached at about 900. A charge that grows
  a record past that limit fails when the account stores it.
- **Recovery completion.** The account checks a completion against its own
  record of the recovery rule, and the core ports those checks. The
  recovery controller then decides through `rcv_complete`, and that verdict
  depends on the controller's own storage. When the account's checks pass,
  the core answers `controller` and names the controllers to ask.

Out of scope:

- Mainnet's `c135aca` account. It decides with OpenZeppelin's code, not
  this gate.
- Whether the compiled wasm matches rule-core's Lean translation. Nothing
  checks that for this build either, as for the chain build.

## Checks

`gate::review` performs the account's reads and checks in the account's
order. Line numbers refer to `fork/dev` `fc0fb2b`.

| # | Check | Contract source | Error | Core |
|---|---|---|---|---|
| 1 | No context names an invoker-only hook | `perch-smart-account/src/lib.rs:1122-1128`; names at `perch-recovery-interface/src/account.rs:119` | `ReservedFunction` (1) | `gate.rs` step 1, `RESERVED_INVOKER_ONLY_FNS` |
| – | Read the recovery rule; is this one `apply_doc` on the account choosing it? | `lib.rs:1129-1130`, `is_completion` `lib.rs:1176-1193` | – | `is_completion` |
| 2 | Under the `Protected` freeze (`ledger < until`), only a completion | `lib.rs:1131-1135`, `is_frozen` `account.rs:167` | `AccountFrozen` (2) | step 2 |
| 3 | A rule with a grant tag is never chosen for the recovery controller, the ZK adapter or pool, a guardian approval or a token-admin function | `lib.rs:1142-1162`, `excluded_contract` `lib.rs:1417-1421`, `TOKEN_ADMIN_FNS` `lib.rs:1397`, `GUARDIAN_APPROVAL_FNS` `account.rs:155` | `GrantEscalation` (4) | step 3 |
| 4a | A completion is checked against the stored recovery rule: ids match contexts, the id is the recovery rule, each context is on the account while the rule is unexpired, and no signer is named. Then the controllers decide | `lib.rs:1163-1165`, `authorize_completion` `perch-smart-account/src/auth.rs:110-144` | `ContextRuleIdsLengthMismatch` (3014), `ContextRuleNotFound` (3000), `UnvalidatedContext` (3002), `UnauthorizedSigner` (3016) | `completion_review`; `Outcome::Controller` |
| – | The account stores a rule set | `lib.rs:1166` | `RuleEvalRefused` (5) | `NoRuleSet` |
| 4b | The recovery rule is not chosen outside a completion | `perch-smart-account/src/gate.rs:85-87` | `RuleEvalRefused` (5) | `RecoveryRuleChosen` |
| 5 | Each chosen id names a stored rule: in its grant's record when tagged, otherwise in `RuleSet` | `gate.rs:91`, `stored_rule` `gate.rs:173-182`, `rule_of` `gate.rs:185-195` | `ContextRuleNotFound` (3000) | `RuleNotFound`, `stored_rule`, `rule_of` |
| – | The stored rule and a capped rule's record are readable | `gate.rs:92-97`, `record` `gate.rs:198-207`, `perch-rule-eval/src/mirror.rs` | `RuleEvalRefused` (5) | `stored::rule`, `stored::record` |
| – | Every context is a call the account can read | `gate.rs:105` (`convert::calls`) | `RuleEvalRefused` (5) | `UnreadableContexts` |
| 6 | A capped rule, or a grant rule for an owner function, acts only when argument 0 is the account | `gate.rs:107-113`, `OWNER_FNS` `lib.rs:1412` | `RuleEvalRefused` (5) | `NotOwnFunds` |
| – | rule-eval's `check_auth` over the chosen rules, their records, the payload's signers, the ledger and the grant generation | `gate.rs:114-127` | `StaleGrant` (3) for `StaleGeneration`; otherwise `RuleEvalRefused` (5) | `rule_eval::check_auth`, unchanged |
| 7 | Each payload signer authenticates, in payload order (not verified here; see above) | `gate.rs:130-135`, `authenticate` `auth.rs:47-60` | `ExternalVerificationFailed` (3003), or a host error | `verified` flags and the delegate list |
| 8 | The records the charges changed are stored | `gate.rs:136-143` | – | `Review::records` |

The core reads stored values in `stored.rs`, which is
`perch_rule_eval::mirror` applied to facade values. It accepts the same
layout (a rule the tuple of its nine fields, its signers positions in its
document's signer table, which it reads beside the rules), and refuses the
same values, the maps earlier builds stored among them. The checks' name lists are copies; `perch-integration-tests`
checks each copy against its source.

## What is left to spend

`remaining(record, limit, period, now)` gives the largest amount a spend
may have. For every amount `a >= 0`:

```text
check_spend(record, limit, period, now, a).is_ok()  <=>  a <= remaining(record, limit, period, now).amount
```

A spend at ledger `L` counts through ledger `L + period - 1` and leaves the
window at `L + period`. `remaining` returns `0` when the record is ahead of
`now`, when an eviction sum overflows, or when the history is full;
`blocked` says which. `tests/remaining.rs` checks the equivalence on the
window's edges by name and on a sweep of 24,000 record, cap and ledger
cases.

Each review gives, for each chosen capped rule:

- its budget before this authorization;
- the amount this authorization requests from it (charges are summed, so
  two contexts charging one rule are counted together, as rule-eval charges
  them);
- its budget after, when the account accepts.

For a subagent's grant, the bound that rule-core proves is per chain
(`spend_accepts_iff`), so what a subagent has left is the minimum over its
ancestors, not its own cap alone.

## Attenuation witnesses

`replay_witness(parent, steps, child)` replays rule-core's ten attenuation
steps from the parent, using rule-eval's own functions. It accepts exactly
when the replay reaches the child, rule for rule (the exact root
included). rule-core proves that each step narrows (`attenuate_narrower`,
`Derives.narrower`), so an accepted child allows nothing its parent does
not. The witness does not decide whether two unrelated rule sets are
ordered. `tests/witness.rs` replays all 425 attenuation cases in rule-core's
vectors.

## Differential tests

`perch-integration-tests` compares the core with the account on the same
state, using the account's native build through the host:

- The account's contract-data entries are read from the host
  (`rule_core::account_entries`), as `getLedgerEntries` would return them.
- The core runs on those entries and the authorization entry.
- The same authorization then goes through the account's real
  `__check_auth`, with real ed25519 signatures and CAP-0071 delegates.

The core must give the account's verdict and error code, and after an
acceptance, the records the account stored.

| Suite (`tests/`) | What runs | Compared | Agree |
|---|---|---|---|
| `review_core_differential.rs`, document traces | rule-core's 58 document traces and Perch's 3, each on a fresh account and after a predecessor document, applied with the real `apply_doc`/`apply_grant`; each authorization is a real invocation under `set_auths` | 390 (128 accepted, 10 record writes checked) | 390 |
| `review_core_differential.rs`, authorization traces | rule-core's 77 authorization traces, with rules installed as stored rules and starting records written; each authorization goes through `try_invoke_contract_check_auth` | 350 (73 accepted, 38 record writes checked) | 350 |
| `review_core_differential.rs`, gate cases | reserved functions; the freeze and completions; a stale grant generation; a wiped credential; guardian approvals and token-admin functions under a grant; the excluded set (controller, ZK adapter, pool); unknown ids; own funds under a cap and under a grant, with the window's edges; a creation; a missing delegate; external signatures | 52 (14 accepted, 3 record writes checked, 1 completion deferred to the controller) | 52 |
| `review_core_reader.rs` | stored rules and records read by `stored` and by `perch_rule_eval::mirror`, generated and changed | 1,500 rules + 12,000 changed values; 500 records + 1,500 changed values | all |

Where the account refuses an authorization that rule-core's model accepts,
the refusal comes from Perch's checks outside rule-eval:

- 11 by own funds under a cap;
- 11 by a delegated signer that a direct `__check_auth` call carries no
  delegate for.

One authorization trace does not run: its starting record is 72,076 bytes,
over the 64 KiB entry limit, so no ledger can hold it. Two authorizations
in other traces sit at ledgers within the host's entry TTL of `u32::MAX`,
where the host cannot extend an entry. The authorization traces rename
opaque `other` payloads and symbols the host does not hold onto host
values injectively; rule-eval only compares those for equality. Each batch
is checked to be read by the account exactly as the renamed trace states it.
`a_wrong_snapshot_or_ledger_is_reported` checks that the comparison is not
vacuous: a snapshot without the freeze entry, or another ledger, gives a
reported difference.

## Interface

The pure Rust API:

- `review_entry(entry, ledger_entries, ledger, verified)`;
- `review(&Snapshot, &Request)`;
- `remaining`;
- `replay` and `replay_witness`;
- `Snapshot::keys` and `Snapshot::grant_keys`, the entries to fetch.

The byte interface (`envelope`) takes a binary envelope and returns JSON:

- **review:** the ledger sequence, the account's `SorobanAuthorizationEntry`
  XDR, the account's `LedgerEntryData` XDRs as `getLedgerEntries` returns
  them, and the verified flags;
- **chosen:** an entry's account and rule ids;
- **witness:** parent rules, steps and child rules, each as `ScVal` XDR;
- **budget:** a `StoredRecord`, a `StoredCap` and a ledger sequence.

The entry parser reads `Address`, `AddressV2` and `AddressWithDelegates`
credentials, plus every kind of invocation. It treats any union arm it does
not know as unreadable rather than guessing. A snapshot skips temporary
entries, such as the host's nonces, which `__check_auth` never reads.

`npm/` holds the TypeScript wrapper, `@stellar-registry/perch-review-core`
(private, not published). It includes:

- the typed API;
- the ledger keys to fetch;
- strkeys;
- `sign-dialog`, which builds the soroban-sign-dialog preview result's
  `verdicts` and `budgets` from the core.

Its README covers the details.

## Wasm builds

The browser builds use `wasm32v1-none` and `cargo rustc --crate-type cdylib`
(`npm/scripts/build-wasm.mjs`). There are two modules, so the signing path
loads only what it needs:

| Module | Exports | Raw | gzip -9 | brotli -q 11 | Imports |
|---|---|---|---|---|---|
| review (`--features abi-review`) | `review`, `budget`, `chosen` | 47,607 | 19,598 | 17,115 | 0 |
| review, after `wasm-opt -Oz` | | 40,229 | 18,668 | 16,462 | 0 |
| witness (`--features abi-witness`) | `witness` | 27,543 | 10,840 | 9,386 | 0 |
| witness, after `wasm-opt -Oz` | | 23,760 | 10,315 | 8,976 | 0 |
| all four exports in one module, after `wasm-opt -Oz` | | 51,344 | 22,807 | 19,773 | 0 |

These are rustc 1.97.1 and wasm-opt 131 sizes, with the workspace's
release profile (`opt-level = "z"`, LTO, `panic = "abort"`, overflow checks
on). Each module exports `memory` and `alloc`. `alloc` resets an arena at
the start of each call, so memory does not grow across calls.

In Node 24, the review module instantiates in 0.53 ms. A review of a real
account's 3 to 4 KB snapshot (a recovery rule, a capped rule and a grant)
takes 10 to 12 µs per call. The npm tests hold the review module to 18,000
bytes brotli and the witness module to 10,500. CI builds without wasm-opt.

## Placement

This is a crate in the Perch repository rather than in rule-core:

- The core ports Perch's own gate (`perch-smart-account`), reads Perch's
  storage layout (`PerchStorage` keys, `RuleRecord`, `StoredGrant`,
  `FreezeGate`, the ZK factor), and reads stored rules exactly as
  `perch-rule-eval`'s mirror does. All of these are Perch's, not rule-core's.
- rule-core stays account-agnostic: it provides `rule_eval::check_auth` and
  the facade's codec, and this crate pins both through the workspace's
  rule-core rev.
- The differential tests need the real account at the same commit.
  `perch-integration-tests` already runs rule-core's document traces through
  it (`tests/rule_core/mod.rs`), and the core's differential is built on
  that harness.

The npm wrapper lives beside the crate (`npm/`), not under `packages/`. Every
directory under `packages/` must appear in `release.yml`'s three
`NPM_PACKAGES` lists (`scripts/test-release-scripts.py`,
`test_every_list_names_every_package`), and a listed package publishes its
manifest version on the next merge (`release.yml`, "Detect released npm
packages"). This package is not published, so it stays out of `packages/`
until the decision to publish it is made.
