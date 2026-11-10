# Review: the sign dialog and the Nido simulation

How we reviewed: we used `docs/nido-sim/index.html` in full and with `?embed=1`, at 1440×900, 1300×600 (the deck's frame) and 390×844, keyboard included. We ran create, install the grant, guess, coffee, and each refusal, and read the dialog's text, its parts and its tab order. We also looked at the decks' drawn dialog (pitch deck slide 12). The dialog is the vendored `soroban-sign-dialog` (soroban-sim fb38b9c), unchanged. Where a fix needs the component, it is listed as a request, not a fork.

## What a first-time viewer sees

**The dialog, collapsed (its default).** Header: Nido, "Local network", "Request from Guess & Coffee (simulation)", "Authorize this call", and "Fee up to 0.0895275 XLM, paid by relayer GCY2…BG4O". Then a line such as "Call guess on game CANY…OZAJ", then "1 of 2 XLM left this window after this". Then a status box: "Will succeed. Accepted under grant 1, rule 'pay-game', assuming a valid signature from this key". Then "▸ Details", and Reject and Approve. Focus starts on Reject, and Enter on Details opens it.

**The dialog, expanded.** The decoded tree with per-call argument toggles. Then "Effects": the recorded-tree check, the verdict again, the spending-cap card, a balance table, events, and a ledger and protocol footnote. All of it in one scroll, about 780 px tall on a phone.

**The simulation page.** An intro paragraph and a five-bullet "Simulated here" box (one line in the embed), then four numbered steps, a status line, the account panel (balances, the grant's windows), and a request log. In the log every card is fully open: seven checks per node, rule-core file and line references, "off the reference path: no native record", and nested host-trace and signed-payload toggles.

## What is too much or unclear

1. **The sentence that matters is missing.** For a guess, the default line is the outer call ("Call guess on game"). The money, "1 XLM from your account", is only inside Details. The budget line hints at it.
2. **A grant install says the least.** "Install grant #1 on your account" is the most consequential approval. What it allows (2 XLM per 100 ledgers to the game inside `guess`, 10 EURC to the shop inside `order`) is only behind Details. Its fee line, "up to 9.52 XLM", is the loudest number on the screen, and the relayer pays it.
3. **The verdict reads like a log.** "Accepted under grant 1, rule 'pay-game', assuming a valid signature from this key", and for a refusal "because of node 1 (transfer, rule 'pay-game'): the entry's root must be game.guess; it is XLM.transfer (contract error 5)". The reason is right but technical: node numbers, "entry's root", error codes.
4. **Noise in the default view.** Short contract addresses after names that already have labels ("game CANY…OZAJ"). A fee the user does not pay. "this window", which is unexplained.
5. **Details is easy to miss and stays open.** A small "▸ Details" in body text. Once opened, every later request opens expanded too: Details stays open across requests.
6. **On the page, results are off screen.** In the 1300×600 embed the outcome of a press (the status line, the new card) sits below the fold, about 700 px and 1,190 px down. Each card opens with every check, so one refusal fills a screen. Reference-run jargon ("no native record") sits in the default view.
7. **Small defects.** The "simulated" pill renders as a tall ellipse when it wraps at narrow widths. Scripted runs label a transfer "Pay the game 1.00 directly", with no unit.

## What is missing

- A one-line result next to the button that caused it, with "why" one click away.
- What the grant allows, in plain words, at install time.
- Grouping inside Details: the tree, the rule that matched, the simulation and the addresses are one long column with no sub-headings to jump to.

## Spec: minimal by default, details on demand

### Sign dialog, default view (in order)

1. Header: logo, network chip, "Request from {dapp}". No second title line when the sentence below says it.
2. **One plain sentence of what the user approves, with the amount:** "Play guess on the game, paying 1 XLM", "Pay the coffee shop 3.50 EURC", or for a grant "Let Guess & Coffee pay the game up to 2 XLM and the shop up to 10 EURC per 100 ledgers, only inside guess and order".
3. **Budget left:** "After this: 1 of 2 XLM left in this period", or in the danger colour "Over the cap: 0 of 2 XLM left".
4. **Verdict, one line:** "✓ Your account will accept this", or "✕ Your account will refuse this: the payment must happen inside game.guess". The refusal reason always shows, in plain words.
5. **Warnings always visible** (an unused or extra entry, a tree that differs from the simulation, a missing entry), as today (`part="warning"`, `role="alert"`). Minimal never hides risk.
6. Fee: one short line only when the user pays it. When a relayer pays, "Network fee paid by Nido", and the amount moves into Details.
7. **The Details control** (below).
8. Reject and Approve. A refusal keeps "Approve anyway" with a second confirming click in the simulation; a production wallet uses `strict`.

### Behind Details (grouped, each with a small heading)

1. What you authorize: the decoded tree, calls nested, arguments collapsed per call (as now).
2. Why it is allowed: per node, the grant and rule matched, the cap meter, "assuming a valid signature from this key".
3. Simulation: the recorded-tree check, balance changes, events, ledger and protocol.
4. Addresses and fee: full contract IDs, the signer key, the exact fee and its payer.

### The Details control

- A full-width row that reads as a control: "Details: calls, rules, simulation" with a chevron that turns when open, a visible border on hover and focus, and a 44 px touch target.
- Keyboard: it is the native `<summary>`, so Tab reaches it and Enter or Space toggles it. The focus ring must be visible (`::part(details-summary):focus-visible`).
- Tab order today is Reject, Approve, Details. Keep focus starting on Reject; Details stays reachable.
- Collapsed again for each new request, unless the wallet sets `details="open"`.

### The simulation page

- Keep the four numbered steps and the account panel (balances and windows) as the default view; they are the minimal story.
- After each press, put a one-line result directly under the step that caused it, and in the embed scroll it into view (`block: 'nearest'`). Examples: "✓ Applied: you lost 1 XLM; 1 of 2 XLM left", "✕ Refused by your account: the payment must happen inside game.guess". Add "Show the checks" next to it.
- Request cards are collapsed to that same line by default. Expanded, they show the node-by-node checks, with the failing node open and passing nodes collapsed to "✓ all 7 checks". Host trace, signed payload, rule-core references and reference-run status ("matches the recorded run") sit one level deeper.
- "Simulated here": one visible line ("Simulated in this page: no network, no real account or asset") plus "What is simulated" for the bullets. The embed already does this.
- Fix the pill and the "1.00" label. Every toggle is a `<details>`/`<summary>` or a button with `aria-expanded`. After the dialog closes, focus returns to the button that opened it.

### What the host page can do today, through the component's public API

- `strings.summary` (the fee line, given `fee` and `payer`): "Network fee paid by {payer}" when the payer is the relayer.
- `strings.summaryBudget`: the "in this period" wording.
- `strings.details`: the control's label.
- `::part(details-summary)` and `::part(fee)` from the page's CSS: the affordance and the fee line's weight.
- The `header` slot: the plain grant sentence at install time.
- The verdict `reason`, which the page's preview provider writes: the plain accept and refuse lines, with rule names kept for Details.

### Requests for the component (soroban-sign-dialog), not forks

1. Reset Details to collapsed on each new request (today the open state carries over).
2. Name the signer's outgoing payments in the summary line ("…, paying 1 XLM"), for example as a `summaryCall` string given the call and the signer's transfers.
3. Summarize a grant install's rules and caps in the summary line (an `installGrant` string given the decoded policy).
4. Drop the short address after a labelled name in the default view, or expose it as a part.
5. Let the Details label differ when open and closed ("Show details" and "Hide details").
