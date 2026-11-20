# @stellar-registry/perch-review-core (private)

A Perch account's verdict on an authorization entry, from a ledger snapshot,
before anyone signs. This is a thin TypeScript wrapper over the
`perch-review-core` crate's two import-free wasm modules. The package is
private and is not published; see the crate's README, "Placement".

```ts
import { ReviewCore, ledgerKeys, grantKeys } from '@stellar-registry/perch-review-core';
import { perchPreview } from '@stellar-registry/perch-review-core/sign-dialog';

const core = await ReviewCore.load(); // or ReviewCore.load(bytes | URL | fetch(...))
const chosen = core.chosen(entryXdr); // the account and the rule ids its payload chooses
if ('unreadable' in chosen) throw new Error(chosen.unreadable);
const first = await getLedgerEntries(ledgerKeys(chosen.account, chosen.ruleIds));
const second = await getLedgerEntries(grantKeys(chosen.account, chosen.ruleIds, first));
const review = core.review({ entry: entryXdr, ledgerEntries: [...first, ...second], ledger });
```

Inputs are XDR, as bytes or standard base64:

- the account's `SorobanAuthorizationEntry`;
- the account's `LedgerEntryData`, as `getLedgerEntries` returns it.

## What a verdict means

For the ledger entries given and the ledger sequence given, assuming every
payload signer that the input does not mark unverified authenticates, the
verdict equals what the account's `__check_auth` returns on that state at
that ledger.

It does not cover the following:

- **Signatures.** They are not verified. Every review lists the signers it
  assumed (`assumed`).
- **Other state.** The answer can change at another ledger, or after state
  changes the entries do not hold: another spend, an apply, a recovery
  completion. That includes another entry of the same account in the same
  transaction: each review covers one entry.
- **Network limits.** These include entry size, instructions and footprint.
- **Recovery completion.** The recovery controller decides it
  (`status: 'controller'`).

The crate's README, "What the verdict means", states each assumption.
"Differential tests" there lists the tests against the account's real
`__check_auth` behind the statement.

## API

- `ReviewCore.load(source?)` loads the review module
  (`wasm/perch_review_core.wasm`). It provides:
  - `review(input)`: the verdict, the refusal (`check`, the account's
    error `code` and `error`, rule-eval's `detail`), each chosen rule, each
    capped rule's `budgets` before and after, and the `records` the account
    would store;
  - `chosen(entry)`: the entry's account and chosen rule ids;
  - `budget(record, cap, ledger)`: what a capped rule has left. For every
    amount `a >= 0`, `check_spend` accepts `a` exactly when
    `a <= remaining`.
- `WitnessCore.load(source?)` loads the witness module
  (`wasm/perch_review_witness.wasm`). Its `witness(parent, steps, child)`
  checks whether rule-core's attenuation steps replay from the parent to
  exactly the child.
- `ledgerKeys(account, ruleIds)` and `grantKeys(account, ruleIds, fetched)`
  give the `LedgerKey`s `__check_auth` reads.
- `strkeyOfScAddress` and `scAddressOfStrkey` convert between addresses
  and their XDR.

`./sign-dialog` builds the soroban-sign-dialog preview result's `verdicts`
and `budgets` from the core (`perchPreview`, `perchVerdict`,
`perchBudgets`), in place of the dialog's Perch adapter's JavaScript
re-derivation. A budget adds two exact fields to the dialog's shape:
`remaining`, and `remainingAfter` when the account accepts. Its `amount`
sums every context the entry charges to the rule, and is `null` when the
core cannot read that sum (a context with no amount, or an overflow).

`perchPreview` does not compose entries: it reviews each one on the ledger
entries as fetched. When an entry chooses a capped rule that an earlier
accepted entry of the same account in the same call charges, the earlier
charge is not counted, so that budget's `remaining` and `remainingAfter` are
`null` with the reason in `uncomposed`, and a verdict that would be accepted
alone is unknown instead (`allowed: null`, `reasonCode: 'uncomposed'`). A
refusal stays a refusal.

## Building and testing

```sh
npm ci
npm run build:wasm   # cargo, wasm32v1-none; then wasm-opt -Oz when on PATH
npm run check && npm run build && npm test
```

The tests check that:

- each module imports nothing and stays within its size budget;
- the wasm gives the native core's answer on every committed input
  (`test/fixtures.json`, gate cases the account itself decided);
- the wrapper writes the envelope the core reads and names the keys the
  account reads;
- the sign dialog's verdicts are the account's own.

`perch-integration-tests` regenerates the fixtures:

```sh
cargo test -p perch-integration-tests --test review_core_differential write_npm_fixtures -- --ignored
```

The crate's `tests/fixtures.rs` checks them against the native core.
