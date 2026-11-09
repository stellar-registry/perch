# Café Perch sign mock: what is real and what is canned

Open `index.html` over HTTP, or open `standalone.html` straight from disk: it
holds the same three modules inlined, so it works from `file://`.

## Real

- `soroban-sign-dialog.js` is the component itself, not a mock. The element
  name, attributes, properties, methods, events, `::part` names and `--ssd-*`
  custom properties are the API the real component keeps (see `API.md`).
- Each order's transaction is a real `TransactionEnvelope`, built the way a
  dapp builds one: a recording simulation, then an unsigned envelope with the
  recorded authorization entries and resources. The dialog decodes the tree
  from that XDR in the browser, with no simulator and no network.
- The approve event's `invocationHash` is sha256 of each entry's
  `SorobanAuthorizedInvocation` XDR, computed in the page.

## Canned

**Preview effects** does not run a simulator in this mock. The page sets
`previewProvider` to a function that returns a stored `PreviewResult` for the
transaction after an artificial 0.7 s delay. Each stored result was captured
from a native soroban-sim run (`perch-capture capture`):

- soroban-sim d029384 (soroban-env-host 29.0.2, protocol 29), recording-mode
  host; network passphrase `Standalone Network ; February 2017`;
- the Perch contracts pinned by the Perch paper (stellar-registry__perch
  f0275f4: account, doc compiler, interpreter, spending limit, ed25519
  verifier, recovery), deployed on a local fixture ledger;
- grant 1 on the account: rule `spend`, `transfer` on the native asset contract,
  signed by an app ed25519 key, capped at 10 XLM per 100 ledgers. 3 XLM was
  spent at ledger 10000013; the preview runs at ledger 10000019.

For each order the capture ran an independent recording (the dialog compares
it with the request's entries), then an enforcing simulation with the entries
signed by the grant key, which gives Perch's verdict, the events and the ledger
diffs. To get balances and the spend window after the transaction, it applied
the signed transaction on a checkpoint, read the results, and rolled back.

| Order | Verdict | Cap left before → after |
|---|---|---|
| 5 XLM | accepted | 7 → 2 XLM |
| 8 XLM | refused: `PerchAuthError::RuleEvalRefused` (contract error 5) | 7 XLM, unchanged |
| 2 XLM + a hidden 4 XLM entry to another address | accepted | 7 → 5 XLM |

The hidden entry is a real finding of the capture. The host accepted the 2 XLM
transaction with the extra signed entry left unconsumed. Submitting that
entry alone afterwards, in its own transaction, moved 4 XLM to the other
address.

The verdict's wording ("the cap has 7 XLM left and the request is 8 XLM")
combines the contract error with the spend window that the capture read from the
account's `SpendRecords(1)` entry. The contract reports only error 5.

## Not the current Perch

The captured contracts are the paper's pinned build: grants installed with
`apply_scope` (since renamed `apply_grant`), and spends recorded in the
account's own storage. The current Perch release that Nido uses installs
rules through `apply_doc` and keeps the spend window in OpenZeppelin's
spending-limit policy contract
(`AccountContext(account, rule_id)`). The dialog renders both. The engine's
Perch adapter has to read whichever layout the account has.

## Regenerate

From the prototype sources (`../prototype/`): build `perch-fixture`, run
`perch-capture capture > capture.json`, then run
`python3 mock/make-canned.py capture.json > mock/canned-previews.js` and
`python3 mock/build.py <out-dir>`.
