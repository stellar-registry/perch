# API reference

Types for everything here are in `types/` and ship with the package.

## Entry points

| Import | What |
|---|---|
| `@theahaco/soroban-sign-dialog` | Side-effect free: `SorobanSignDialog`, `define`, `request`, `STRINGS`, the decoder |
| `@theahaco/soroban-sign-dialog/embed` (`dist/soroban-sign-dialog.js`) | The same, plus it registers the element and sets `globalThis.SorobanSignDialog` |
| `@theahaco/soroban-sign-dialog/preview` (`dist/preview/soroban-sim-preview.js`) | The engine: `createPreview`, `preview`, `rpcProvider`, `fixtureProvider`, `BUILDS` |
| `@theahaco/soroban-sign-dialog/react` | `<SignDialog>` for React 18 and 19 |
| `@theahaco/soroban-sign-dialog/vue`, `/svelte` | Template typings only |

`define(tag = 'soroban-sign-dialog')` registers the element. It is idempotent
and does nothing where `customElements` does not exist. `request(options)`
defines on first use, creates one shared dialog, and opens it.

## `<soroban-sign-dialog>`

### Attributes and properties

| Attribute | Property | Meaning |
|---|---|---|
| `transaction` | `transaction` | Base64 `TransactionEnvelope` (v1, or a fee bump around one). Its single Soroban operation is reviewed. |
| `auth-entries` | `authEntries` (array) | Base64 `SorobanAuthorizationEntry` list, space-separated, for a bare `signAuthEntry` request. |
| `network` | `network`, `networkPassphrase` | `testnet`, `mainnet`, `futurenet`, `local`, or a passphrase. Default `testnet`. Both properties read back the passphrase. |
| `signer` | `signer` | The address the wallet signs for. Its entries read "(you)" and get `forSigner: true`. |
| `dapp` | `dapp` | Who is asking, shown in the header. |
| `preview` | | `auto` (default: simulate on open when an engine or provider is set), `manual` (a "Check outcome" button in the status line), `off`. |
| `engine` | `engine` | URL of the engine module, imported on the first preview when no `previewProvider` is set. |
| `rpc-url` | `rpcUrl` | Passed to the preview provider. |
| `theme` | | `light`, `dark`, or absent to follow `prefers-color-scheme`. |
| `inline` | | Render in place, not as a modal (a wallet's own signing page). |
| `details` | | `open` to show the Details disclosure expanded on open. |
| `strict` | `strict` | Keep Approve disabled while any flag is raised. |
| `open` | `open` (read-only) | Setting the attribute opens the dialog; removing it closes it with reason `closed`. |
| | `labels` | `{ [address]: name \| { name, token: { code, decimals } } }`: the wallet's address book and the token metadata it trusts. Only the native asset contract is derived by the dialog itself. |
| | `strings` | Overrides for user-facing text, merged over `STRINGS`. |
| | `previewProvider` | `async (request) => PreviewResult`. |
| | `previewResult` | The latest `PreviewResult` (read-only). |
| | `flags` | The flags currently raised (read-only). |
| | `dialog` | The inner `<dialog>` (read-only). |

### Methods

- `show()` opens the dialog (modal unless `inline`), focusing Reject.
- `close()` closes it; a pending request resolves `{ approved: false, reason: 'closed' }`.
- `request(options)` sets the given options, opens the dialog, and resolves
  with `{ approved: true, ...ApproveDetail }` or `{ approved: false, reason }`.
  A second `request` while one is pending resolves the first as `superseded`.
  Options: `transaction`, `authEntries`, `network`, `signer`, `dapp`, `engine`,
  `rpcUrl`, `theme`, `preview`, `strict`, `labels`, `strings`, `previewProvider`.
  The per-request options (`transaction` or `authEntries`, `network`, `signer`,
  `dapp`) describe this request only: any the call leaves out is cleared, so
  `network` returns to testnet and no signer or dapp carries over from the
  previous request. The rest are dialog configuration a wallet sets once
  (`engine`, `rpcUrl`, `theme`, `preview`, `strict`, `labels`, `strings`,
  `previewProvider`); they persist until a later call sets them again.
- `runPreview()` runs the preview now.

### Events

All bubble and cross the shadow boundary (`composed`).

| Event | `detail` |
|---|---|
| `approve` (cancelable) | `ApproveDetail`: `{ transaction, transactionHash, networkPassphrase, signer, entries, flags, preview }` |
| `reject` | `{ reason: 'rejected' \| 'dismissed' \| 'closed' \| 'superseded', flags }` (`dismissed` is Escape) |
| `preview` | `{ result: PreviewResult, flags }` |
| `open`, `close` | none |

Each of `ApproveDetail.entries` is
`{ index, address, credentials, nonce, entryXdr, invocationXdr, invocationHash, forSigner }`.
Sign exactly `entryXdr` for the entries that are yours, and check that the
invocation you sign hashes (sha256, hex) to `invocationHash`. The detail is
computed when the request is decoded, so `approve` fires within the click
and a passkey prompt opened from it keeps its user activation. Calling
`preventDefault()` on `approve` keeps the dialog open.

Flags: `{ kind: 'extra', entry }` (the transaction does not use this entry),
`{ kind: 'differs', entry }`, `{ kind: 'missing', recorded }`,
`{ kind: 'refused', address, code }`, `{ kind: 'fails', error }`. While any is
raised, Approve reads "Approve anyway" and needs a second click; with `strict` it is
disabled.

### Theming, parts and slots

See the README: tokens `--ssd-*`, parts for `::part()`, slots `logo`,
`header`, `footer`.

## Preview providers

A provider is any `async (request) => PreviewResult`. The request is
`{ transaction, authEntries, networkPassphrase, signer, rpcUrl, decoded, signal }`;
honour `signal` to stop work when the dialog closes or the request changes.

### PreviewResult (version 1)

```js
{
  version: 1,
  status: 'ok' | 'fallback' | 'error',   // anything but 'ok' shows only a notice under the tree
  code, params,                           // machine-readable notice: a key of strings.notices
  notice,                                 // English text for the same
  engine: { name, host, protocol, builds },
  ledger: { sequence, protocol },
  stateSource,                            // shown in the footnote
  recordedAuth: [base64 SorobanAuthorizationEntry] | null,  // the independent recording; null when it failed, so used/unused is unknown
  outcome: { ok, error, codes: [{ contract, code }] },  // contract: who raised it, null for the host
  verdicts: [{ address, kind, allowed, rule: { id, name, grant }, code, reasonCode, params, reason }],
  budgets: [{ address, rule, token: { code, decimals }, limit, periodLedgers, spentInWindow, amount, ledger, nextReleaseLedger }],
  balances: [{ address, asset: { code, decimals }, before, after }],
  events: [base64 ContractEvent],
  resources: { instructions },
  timings: { ... },                       // engine-specific
}
```

Notice codes from the engine: `protocol` (`{ protocol, builds }`), `no-rpc`,
`no-transaction`, `fee-bump`, `not-invoke` (`{ operation }`), `no-hint`, and
`error` (`{ error }`) from the dialog when a provider throws. Verdict reason
codes: `accepted` (`{ rule, grant }`), `refused` and `refused-over-cap`
(`{ code, cause }`), and, with `allowed: null` (verdict unknown),
`unsigned-others` (the request also needs other parties' signatures, which
are not there yet; balances and events come from the recording) and `failed`
(`{ error }`, the enforcing run failed outside this account). Only a verdict
with `allowed: false` raises a `refused` flag: the account's own contract
raised the error.

## The engine (`/preview`)

```js
createPreview({ rpcUrl, stateProvider, hints, tokens, wasm, inline }) // => PreviewProvider
```

- `rpcUrl`: Stellar RPC to read state from. Testnet defaults to
  `https://soroban-testnet.stellar.org`; other networks need one.
- `stateProvider`: instead of `rpcUrl`, any
  `{ getLatestLedger(), getLedgerEntries(keys), describe?() }`.
  `rpcProvider(url)` and `fixtureProvider({ ledger, latest, latency })` are
  included.
- `hints`: `{ [account]: { verifier, key, grantId?, ruleId?, ruleIds? } }`
  enables the enforcing run and the account's verdict (README, "Smart-account
  verdicts").
- `tokens`: `{ [contract]: { code, decimals } }` for balance rows and caps.
- `wasm`: `(protocol) => URL | bytes`, to load reactor builds from somewhere
  other than beside the engine module.
- `inline`: run the reactor on the calling thread instead of a Worker.

`BUILDS` maps each supported protocol to its host version and file name:
`soroban-sim-preview-p29.wasm` (soroban-env-host 29.0.2) and
`soroban-sim-preview-p30.wasm` (soroban-env-host 30.0.0). The engine refuses
a build whose `np_host_protocol()` differs from the protocol it was loaded
for.

## The decoder

`decodeEnvelope`, `decodeAuthEntry`, `decodeEvent`, `decodeLedgerEntry`,
`decodeLedgerKey` and `decodeScVal` take base64 or bytes and return plain
objects. They read the subset of XDR a signing review needs, including
protocol 27's `AddressV2` and `AddressWithDelegates` credentials and protocol
30's muxed contract addresses. They refuse truncated input, trailing bytes,
non-zero padding and nesting deeper than 64.

`compareAuth(requested, recorded)` pairs entries by signer and
byte-identical invocation tree, ignoring nonces, expirations and signatures,
and returns `{ entries: [{ index, status: 'match' | 'extra' | 'differs' }], missing }`.

Also: `authPayloadHash(entry, passphrase, expirationLedger?)`,
`transactionHash(decoded, passphrase)`, `nativeAssetContract(passphrase)`,
`networkId`, `formatAmount(value, decimals)`, `strkeyFor`, `fromStrkey`
(checks the checksum), `NETWORKS`.
