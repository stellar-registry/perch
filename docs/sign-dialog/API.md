# `<soroban-sign-dialog>` API (v0.1)

One ES module, no dependencies, no build step. It registers the element and
also exposes `globalThis.SorobanSignDialog`.

```html
<script type="module" src="soroban-sign-dialog.js"></script>
<soroban-sign-dialog engine="soroban-sim-preview.js" network="testnet"></soroban-sign-dialog>
```

Or open a shared dialog with one call, without any markup:

```js
const r = await SorobanSignDialog.request({ transaction, signer, dapp: location.host });
if (r.approved) await wallet.signEntries(r.entries); // the wallet signs; the dialog has no keys
```

## Attributes

| Attribute | Meaning |
|---|---|
| `transaction` | Base64 `TransactionEnvelope` (v1, or a fee bump around one). Its single Soroban operation is reviewed. |
| `auth-entries` | Base64 `SorobanAuthorizationEntry` list, space-separated, for a bare `signAuthEntry` request. |
| `network` | `testnet`, `mainnet`, `futurenet`, `local`, or a full network passphrase. Default `testnet`. |
| `signer` | The address the wallet signs for. Its entries are marked "(you)", and approval sets `forSigner` on them. |
| `dapp` | The requesting origin or name, shown in the header. The wallet sets this, not the dapp. |
| `preview` | `manual` (default: a "Preview effects" button), `auto` (run on open), or `off`. |
| `engine` | URL of the preview engine module. It is imported only when a preview runs. |
| `rpc-url` | Passed to the engine, which reads ledger state from it. |
| `theme` | `light`, `dark`, or absent to follow `prefers-color-scheme`. |
| `inline` | Render in place without a modal, for a wallet's own signing page. |
| `strict` | Disable Sign while a flag is raised (extra, missing or different entries; a refusal; a failure). |
| `open` | Reflects whether the dialog is open. Setting it opens the dialog. |

## Properties and methods

- `labels`: `{ [address]: name | { name, token: { code, decimals } } }`. The
  wallet's address book and any token metadata it trusts. The component
  derives only the native asset contract itself.
- `previewProvider`: `async (request) => PreviewResult`. It overrides `engine`.
  The request carries `{ transaction, authEntries, networkPassphrase, signer,
  rpcUrl, decoded, signal }`.
- `request(opts)` opens the dialog and resolves to `{ approved: true,
  ...approveDetail }` or `{ approved: false, reason }`.
- `show()`, `close()`, `runPreview()`. `previewResult` holds the latest
  preview, read-only.

## Events (bubbling, composed)

- `approve` (cancelable). Its detail is `{ transaction, transactionHash,
  networkPassphrase, signer, entries: [{ index, address, credentials, nonce,
  entryXdr, invocationXdr, invocationHash, forSigner }], flags, preview }`.
  The wallet must sign exactly these entries and should check that the
  invocation it signs hashes to `invocationHash`.
- `reject`: `{ reason: 'rejected' | 'dismissed' | 'closed' | 'superseded', flags }`.
- `preview`: `{ result, flags }`.
- `open`, `close`.

Flags are `{ kind: 'extra' | 'differs' | 'missing' | 'refused' | 'fails', ... }`.
While any flag is raised, Sign becomes "Sign anyway" and needs a second
click. With `strict`, it is disabled.

## PreviewResult (version 1)

```js
{
  version: 1,
  status: 'ok' | 'fallback' | 'error',  // anything but 'ok' renders `notice`; the tree stays
  notice,                                // e.g. a protocol mismatch
  engine: { name, host, protocol }, ledger: { sequence, protocol }, stateSource,
  recordedAuth: [base64 SorobanAuthorizationEntry],  // the independent recording
  outcome: { ok, error, codes },
  verdicts: [{ address, kind, allowed, rule: { id, name, grant }, code, reason }],
  budgets: [{ address, rule, token: { code, decimals }, limit, periodLedgers,
              spentInWindow, amount, ledger, nextReleaseLedger }],
  balances: [{ address, asset: { code, decimals }, before, after }],
  events: [base64 ContractEvent],
  resources: { instructions },
}
```

## Theming

Custom properties on the element: `--ssd-font`, `--ssd-mono`, `--ssd-bg`,
`--ssd-surface`, `--ssd-fg`, `--ssd-muted`, `--ssd-border`, `--ssd-accent`,
`--ssd-accent-fg`, `--ssd-ok`, `--ssd-ok-bg`, `--ssd-warn`, `--ssd-warn-bg`,
`--ssd-danger`, `--ssd-danger-bg`, `--ssd-radius`, `--ssd-width`,
`--ssd-backdrop`, `--ssd-shadow`.

Parts for `::part()`: `dialog`, `header`, `network`, `title`, `summary`,
`tree`, `entry`, `node`, `node-details`, `doc`, `preview`, `preview-button`,
`auth-check`, `verdict`, `budget`, `balances`, `events`, `notice`, `footer`,
`approve`, `reject`.

## Accessibility

- The modal is a native `<dialog>` opened with `showModal()`, which makes the
  rest of the page inert. Tab also wraps within the dialog.
- Escape rejects with `reason: 'dismissed'`. Focus starts on Reject.
- The dialog's accessible name and description come from its title and summary.
- Tree nodes are `<details>`, so each is keyboard-operable.
- Preview results sit in a polite live region.
- Status is always written in words as well as colour.
- At 560 px and narrower, the dialog becomes a bottom sheet.
