# Café Perch sign demo: what is real and what is recorded

Open `index.html` over HTTP, or open `standalone.html` straight from disk: it
holds the same three modules inlined, so it works from `file://`. `nido.html`
is the same page in Nido's look (`nido/NOTICE.md`).

## Real

- `soroban-sign-dialog.js` is the `@theahaco/soroban-sign-dialog` component,
  vendored unchanged from theahaco/soroban-sim at commit
  `fb38b9c835e66dcaacf293d1f166bf2da45c1a91`
  (`packages/soroban-sign-dialog`, version 0.1.0): its `dist/soroban-sign-dialog.js`,
  SHA-256 `a5239ec1a2e49ec5491c968d19eb62a975f5188e868cd2213bf296f98de072ee`,
  which `node scripts/build.mjs --js-only` reproduces byte for byte from that
  commit. `API.md` is the package's, from the same commit. Both are under the
  Apache License 2.0 (`LICENSE`, soroban-sim's licence at that commit). Its
  default layout leads with what the user approves in plain words, the grant
  budget left, and the simulated outcome, with the full authorization tree,
  arguments and events under one Details disclosure.
- Each order's transaction is a real `TransactionEnvelope`, built the way a
  dapp builds one: a recording simulation, then an unsigned envelope with the
  recorded authorization entries and resources. The dialog decodes the tree
  from that XDR in the browser, with no simulator and no network.
- The approve event's `invocationHash` is sha256 of each entry's
  `SorobanAuthorizedInvocation` XDR, computed in the page.

## Recorded

The outcome preview does not run a simulator in this demo. The page sets
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

## The design it previews

The captured contracts are the Perch design the paper presents. Grant 1 was
installed through the account's own grant flow, and its spend window is kept
in the account's own storage: the `SpendRecords(1)` entry that the capture read
before and after each order.

## Regenerate

`canned-previews.js` is a fixed snapshot generated outside this repository from
the soroban-sim run named above, and is not regenerated here.
`build-standalone.py` writes `standalone.html` from `index.html` and the three
modules, and `nido/build.py` writes `nido.html` from `standalone.html`.
