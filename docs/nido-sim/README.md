# Nido in soroban-sim

`index.html` is one self-contained, offline page (5.4 MB; the 3.4 MB
simulator inside it is compiled only on the first press). The reader creates
a Nido account in soroban-sim the way Nido does, gives an app a Perch grant,
then plays a guessing game and buys a coffee. Each request opens an approval
sheet in Nido's look, which checks the transaction in the page's simulator
first. After an approval the page shows Perch checking every node of the
authorization tree.

## The approval sheet: minimal by default

The sheet shows only what a first-time viewer needs to decide; everything
else is behind one Details control.

- **Header:** Nido, the network chip ("Local network") and the requesting
  app. No fee line and no title line.
- **Grant install:** a short lead ("Let Guess & Coffee spend without asking
  you"), then one row per asset with the amount, the recipient, the window in
  human time and the call it is allowed inside ("2 XLM to Game every ~8 min ·
  in Game › guess", "10 EURC to Coffee shop every ~8 min · in Coffee shop ›
  order"). The rows describe only what the rules enforce: each transfer rule
  pins its recipient with `address-eq` on the transfer's `to` argument.
  Caution chips mark the risky facts the rules contain ("no end date", "any
  function on Game"). An "Ends" row appears only when a rule has an end.
- **Payment or contract call:** the amount and the recipient of the signed
  transfer large ("1 XLM", "to Game"), one line for what the call does ("Play
  guess 3 on Game"), and the budget left in small type ("1 of 2 XLM left for
  ~8 min after this"; "Over the limit: …" in the danger colour). A call that
  moves no money says so. When the account makes more than one payment, the
  others are listed right under the first ("+ 1 more payment: 3.50 EURC to
  Coffee shop"), and the primary label gives the total, or "Approve 2
  payments" across tokens. The budget line counts every payment a request
  charges to one rule against that rule's window, one line per rule. Units
  come from the token's contract (the driver's token addresses, or a cap's
  `token`), never from a display name. The simulation's own requests make one
  payment each; the browser checks cover these cases on hand-built facts
  (`window.nidoSheetCheck`).
- **Verdict:** a quiet "✓ Checked" line when the check passes. A filled box
  only on refusal or failure ("✕ Your account would refuse this: the payment
  must happen inside Game › guess", "… the payment must go to Game"); then
  Reject is the filled primary and "Sign anyway" a text button that asks to
  confirm. Warnings from the decoder's comparison of the signed tree with the
  simulation's recording (an extra, differing or missing entry) are always
  shown as alerts.
- **Primary labels** name the action: "Install grant", "Play, pay 1 XLM",
  "Pay 3.50 EURC", "Pay 1 XLM", "Play".
- **Details** (collapsed for every request): what you sign (the decoded
  calls), the grant's rules in full (functions, conditions including the
  pinned recipient, root, cap in ledgers and time, end, signer, how to remove
  it), the account's checks (the rule matched per node and the result of its
  checks), the simulation (balances, events, ledger and protocol) and the
  addresses (full ids, the signer key, the network fee). The checks are
  headed "Why it is allowed" or "Why it is refused" once the verdict is in,
  and "The account's checks" while the check runs or when it could not run.
- **Keyboard:** a native modal `<dialog>` labelled by the lead and described
  by the verdict; focus starts on Reject and returns to the button that opened
  the sheet; when the check's result redraws the sheet, focus stays on the
  control that had it (an action or Details); Details is a native `<details>`
  with a 44 px target; Escape rejects.

Windows convert ledgers to time at about 5 s per ledger (100 ledgers is about
eight minutes), as the paper and the decks say.

**Which parts are which.** The sheet is this simulation's own presentation.
Its facts come from the transaction bytes, decoded with the vendored
soroban-sign-dialog's exported decoder (`decodeEnvelope`, `decodeAuthEntry`,
`compareAuth`, `decodeEvent`; soroban-sim `fb38b9c`, unchanged,
`docs/sign-dialog/`), and from the page's simulator: the request signed with
the stand-in keys, run with enforcing authorization and, when the host
accepts it, applied on a checkpoint of the ledger, read, and rolled back. The
component's own dialog element is not used on this page, because the layout
above needs more than its public options (`strings`, slots, `::part()`,
`details`); the requests below say what it would need. The page's step
results, cards and checks are as before: a one-line result under each step
with "Show the checks", collapsed cards whose failing node opens first, and
the host trace, signed payload, sources and recorded-run comparison one level
deeper.

## Requests for the component

From a design review of this page and its dialog, for `@theahaco/soroban-sign-dialog`, as requests, not forks:

1. Reset Details to collapsed on each new request (today the open state
   carries over).
2. Name the signer's outgoing payments in the summary line ("…, paying 1
   XLM"), for example a `summaryCall` string given the call and the signer's
   transfers.
3. Summarize a grant install's rules and caps in the summary line (an
   `installGrant` string given the decoded policy).
4. Drop the short address after a labelled name in the default view, or
   expose it as a part.
5. Let the Details label differ when open and closed ("Show details" and
   "Hide details").

From the approval-screen design applied in this version (the page renders
its own sheet until the component offers these):

6. Layouts per kind of request: for a grant install, a lead and a limits
   block decoded from the policy (one row per asset: amount, pinned
   recipient, window in human time, the root call it is allowed inside;
   caution chips for no end date, any function or any recipient); for a
   payment or call, the amount and the recipient of the signer's transfer as
   the lead, one line for the call, and the budget left as a secondary line.
7. A quiet success state (a one-line "✓ Checked", no filled box) beside the
   loud refused and failed states, for example the state reflected on the
   host (`data-state`) or a part per state.
8. On a refusal or failure, Reject as the primary button and the risky path
   as a text button behind a second confirm, with its labels as strings
   ("Sign anyway", "Confirm: sign anyway").
9. Specific primary labels per request (a string given the request kind and
   its amount: "Install grant", "Play, pay 1 XLM", "Pay 3.50 EURC").
10. An option to drop the fee line when someone other than the signer pays,
    keeping the exact fee in Details; and windows in human time from a ledger
    close time, with the ledger count in Details.

## What it runs

1. **Create your Nido account.** A one-time setup key; Nido's factory
   `get_c_address(setup_pk)` gives the address before any passkey exists; a
   passkey stand-in (soroban-sim's software P-256 key) is created; the setup
   key signs `sha256("nido/bind/v1" ‖ network id ‖ factory id ‖ passkey)`;
   the relayer submits `create_account(setup_pk, passkey, setup_sig)`; the
   relayer funds the account with 10 XLM and the test issuer mints 20 test
   EURC. The account's constructor installs one rule, `admin`: the passkey
   through Perch's WebAuthn verifier, over the account itself.
2. **Install the grant.** The passkey signs `apply_scope(1, document)` under
   the admin rule. The grant: `game` (any game function), `pay-game` (XLM
   `transfer`, argument 0 is the account, argument 1 is the game
   (`address-eq`), `auth-root {game, guess}`, 2 XLM per 100 ledgers), `shop`
   (`order`), `pay-shop` (test-EURC `transfer`, argument 0 is the account,
   argument 1 is the shop (`address-eq`), `auth-root {shop, order}`, 10 EURC
   per 100 ledgers). The account enforces the recipient, so each cap can pay
   only the game or only the shop. The app key is Ed25519, checked by Perch's
   Ed25519 verifier.
3. **Use it.** `game.guess(n, account)`: a loss is the tree `game.guess` →
   `XLM.transfer(account, game, 1 XLM)`; a win (7) is `game.guess` alone, the
   game paying the prize itself. `shop.order(account, 3.50 EURC)` →
   `EURC.transfer(account, shop, 3.50)`.
4. **Refusals.** A direct `XLM.transfer` (root is the transfer, not
   `game.guess`); a loss through `game.other` (root `game.other`); a loss the
   game sends to its owner (recipient: the transfer inside `game.guess` pays
   the owner, not the game); a loss once the window holds 2 XLM (cap). Choose
   "Sign anyway" in the sheet to see the account refuse it (contract error 5);
   the page shows which node and which check failed. For the recipient case
   the game's owner, a throwaway key, first sends lost stakes to its own
   address (`set_house`, the one addition to the fixture's game, written for
   this simulation), and sends them back to the game once the request is
   submitted or rejected; both setup transactions are listed on the request's
   card.

Each node's checks are rule-core `5a689a5`'s own functions (`functions_match`,
`cond_holds`, `signers_met`, `auth_root_matches`, `check_spend`, and
`authorize` over the batch), run by the page's driver beside the host on the
same contexts, stored rules and spending records. The verdict shown is the
host's; the recorded run checks that rule-core's `authorize` agrees with it on
every request.

## Embedding

- `index.html?embed=1`: the steps, the account panel and the request log,
  without the page's chrome; a one-line list of what is simulated stays. It
  fits a 1300×600 or 360×650 frame without horizontal scroll; the approval
  sheet opens inside the frame as an in-page modal (a bottom sheet on a phone).
- `?theme=light` or `?theme=dark` sets `data-theme` on `<html>`; otherwise the
  page follows `prefers-color-scheme`. (The sheet keeps Nido's light look.)
- `?autostart=1`: creates the account on load (starts the simulator), so a
  frame the reader opened needs no second press. Nothing takes focus.
- `?scenario=<base64url JSON array>`: creates the account, installs the
  grant, then sends each request approved, without opening the sheet.
  Requests: `{op:"guess", number:0–9, entry?:"guess"|"other",
  stake_to?:"owner"}`,
  `{op:"order", cents:1–5000}`, `{op:"transfer", token:"xlm"|"eurc",
  cents:1–5000}`, `{op:"advance", ledgers:1–10000}`, `{op:"install_grant",
  grant?:"shop"}`;
  at most 40. Anything else is ignored.
- `&review=<base64url JSON request>`: starts from a new ledger, runs
  `scenario` (if any) as above, then opens the sheet for this one request and
  leaves it open: nothing is approved and nothing takes focus (the sheet opens
  without a modal, over a backdrop drawn by its shadow). A review of
  `{op:"install_grant"}` needs only the account; any other review installs
  the grant first if the scenario did not. A refusal shows its refusal sheet.
  If the presenter presses Approve, Reject or "Sign anyway", the request is
  applied or discarded as usual. `&step=<name>` names the state in the ready
  message.
- `&present=sheet` (implies `embed=1`): for a 16:9 slide frame (about 1300×620
  or 360×640, light or dark): only the sheet, over a quiet backdrop, under one
  small line: "Simulated · Your Nido account: 10 XLM · 20 EURC (test) · Left
  this period: 2 of 2 XLM, 10 of 10 EURC". With no sheet open (after
  `autostart`, or once the presenter decides) it shows the latest step result
  instead, such as "✓ Created: your Nido account, with 10 XLM and 20 EURC
  (test)".
- In an iframe the page posts `{type:"nido-sim:height", height}` to its parent
  when its height changes, and accepts `{type:"nido-sim:load", commands:[…],
  review?, step?, fresh?}`: the same requests; `commands: []` only creates
  the account; `review` as above; `fresh: true` starts from a new ledger
  without a review. A new load closes a sheet left open by the last one
  (rejecting it). After each load the page posts `{type:"nido-sim:ready",
  step, verdict}` (`step`: the load's `step`, or the reviewed request's
  `op`) and sets `data-nido-ready` on `<html>` to the verdict, or to `done`
  when it is `null`. `verdict` is one of:
  - `ok`: the sheet is showing and its check passed;
  - `refused`: the sheet is showing the account's refusal;
  - `failed`: the call itself fails before any authorization (for example an
    order or a transfer above the account's balance), so no sheet opens and
    the step result says why; also the sheet's own state when the check
    finds that an authorized call would fail;
  - `unknown`: the sheet is showing but its check could not run;
  - `null`: a load without a review, once its requests are done.

  An invalid load or an error posts `{type:"nido-sim:error", step, error}`
  and sets `data-nido-ready` to `error`. The URL forms do the same; an
  invalid `scenario` or `review` parameter is also named in a note on the
  page ("The review parameter is not one valid request, so it was ignored.
  Not started."), and the page does not start.
- One state per slide, as `index.html?embed=1&present=sheet&theme=dark&…`,
  for stills (the recorder's frames, and the fallback when the live frame
  below cannot load); each opens in under a second once the reactor is
  compiled:

  | Slide | Parameters |
  | --- | --- |
  | Account created | `autostart=1&step=create` |
  | Install the grant | `review=eyJvcCI6Imluc3RhbGxfZ3JhbnQifQ&step=grant` |
  | Play a guess (3) | `review=eyJvcCI6Imd1ZXNzIiwibnVtYmVyIjozfQ&step=guess` |
  | Buy a coffee | `review=eyJvcCI6Im9yZGVyIiwiY2VudHMiOjM1MH0&step=coffee` |
  | Pay the game directly | `review=eyJvcCI6InRyYW5zZmVyIiwidG9rZW4iOiJ4bG0iLCJjZW50cyI6MTAwfQ&step=direct` |
  | Lose through game.other | `review=eyJvcCI6Imd1ZXNzIiwibnVtYmVyIjoyLCJlbnRyeSI6Im90aGVyIn0&step=other` |
  | Lose past the cap | `scenario=W3sib3AiOiJndWVzcyIsIm51bWJlciI6M30seyJvcCI6Imd1ZXNzIiwibnVtYmVyIjo1fV0&review=eyJvcCI6Imd1ZXNzIiwibnVtYmVyIjoxfQ&step=overcap` |
  | Lose to the game's owner | `review=eyJvcCI6Imd1ZXNzIiwibnVtYmVyIjoyLCJzdGFrZV90byI6Im93bmVyIn0&step=owner` |

  The same states by message to one frame loaded with
  `index.html?embed=1&present=sheet`: `{type:"nido-sim:load", commands:[],
  fresh:true, step:"create"}`; `{…, commands:[], review:{op:"install_grant"},
  step:"grant"}`; `review:{op:"guess", number:3}`; `review:{op:"order",
  cents:350}`; `review:{op:"transfer", token:"xlm", cents:100}`;
  `review:{op:"guess", number:2, entry:"other"}`; `commands:[{op:"guess",
  number:3}, {op:"guess", number:5}], review:{op:"guess", number:1}`;
  `review:{op:"guess", number:2, stake_to:"owner"}`.
- `index.html?embed=1&present=live&preload=1&theme=dark|light`: one
  continuous session for slides (one frame, kept across them; not reloaded,
  not reset). It shows the one-line balances and windows, the controls the
  embedding page names, and a sheet where one opens (not modal; it takes no
  focus; the controls hide under it), at 1300×620 and 360×640. `preload=1`
  compiles the reactor and sets up the ledger without an account, then posts
  `{type:"nido-sim:preloaded"}`. Messages to the frame:
  - `{type:"nido-sim:show", controls:[…], step}` shows those controls. Names:
    `create`, `grant`, `guess` (the number picker, at 3, a loss, and Play
    guess), `coffee`, `direct`, `other`, `owner`, `overcap`, `shopcap`
    ("Order past the cap", shown only in this view), `advance`;
    `&controls=create` sets the first. Showing never resets, never runs
    anything and never closes a sheet: a sheet left open stays open on the
    next step until the presenter decides. A control that has done its job
    (`create`, `grant`) shows its result instead ("✓ Created: your Nido
    account, with 10 XLM and 20 EURC (test)"); the others show their latest
    result under them. A control not possible yet stays disabled under "Create
    the account first" or "Install the grant first".
  - `{type:"nido-sim:act", control, step}` presses that control as a click
    would: `create` opens the passkey prompt; `grant`, `guess`, `coffee`,
    `direct`, `other`, `owner`, `shopcap` open their sheets; `overcap`
    presses once; `advance` closes 100 ledgers. An undecided prompt or sheet
    is rejected first, so nothing stacks. A one-shot step already done
    (`create`, `grant`) shows its result and opens nothing. A step not
    possible yet shows its hint and posts `{type:"nido-sim:error", step,
    error:"not-ready"}`; a press that fails posts the error's text. During
    preload it waits, as a press does. Once a dialog is on screen (a sheet
    once its check is in) the frame posts `{type:"nido-sim:dialog", step,
    kind:"passkey"|"sheet", verdict}` and sets `data-nido-dialog` on `<html>`;
    when it closes, it removes the attribute and posts `kind: null`.
  - `{type:"nido-sim:reset"}` starts a new ledger without an account (the
    compiled reactor is kept), rejecting an open sheet.

  Create opens a simulated passkey prompt in Nido's look first ("Create a
  passkey for Nido"; "Simulated: a software key in this page, not your
  device"; Cancel, Continue); the account is created only after Continue. A
  press during preload waits for it. Lose past the cap is refused once the
  window holds 2 XLM: after one guess, the first press is a loss that fills
  the window and the second is refused. Order past the cap orders 1.50 EURC
  more than `pay-shop` has left this period (at most the balance), so the cap
  refuses it after any number of coffees: 11.50 EURC with none, 8 EURC after
  one. The dialog stays inside the frame's visible area: the sheet's height
  is capped to the frame (its body scrolls, its buttons stay), and an
  `IntersectionObserver` keeps it above any part of the frame the embedding
  page clips; checked at 1300×620, 808×489, 637×397 and 360×640. After every
  change (preload, create,
  each decision, reset) and every `show`, the frame posts
  `{type:"nido-sim:state", step, controls, done:{create, grant, guess, coffee,
  direct, other, owner, overcap, shopcap, advance}, balances:{xlm, eurc} | null,
  left:{"pay-game", "pay-shop"}, last:{control, ok, text} | null}`
  (`done.create` and `done.grant` from the ledger; `done.advance` once it has
  run; the others true once that control's request was applied or refused,
  not rejected). Slide keys
  (ArrowLeft, ArrowRight, PageUp, PageDown) pressed inside the frame are posted
  as `{type:"nido-sim:key", key}`. `load`, `ready`, `error` and `height` work
  as above.
- `&grant=shop` (with `present=live` or `present=sheet`): the grant the page
  installs holds only the shop's two rules, `shop` (`order`) and `pay-shop`
  (test-EURC `transfer` from the account to the shop, `auth-root {shop,
  order}`, 10 EURC per 100 ledgers); its sheet shows one limits row ("10 EURC
  to Coffee shop every ~8 min · in Coffee shop › order"), and the requesting
  app is "Coffee shop" ("Let Coffee shop spend without asking you"; "Guess &
  Coffee" otherwise). The driver request
  is `{op:"install_grant", grant:"shop"}`; the default grant, the reference
  run and the full page are unchanged. Stills for the shop-only slides, as
  `index.html?embed=1&present=sheet&theme=dark&grant=shop&…`:

  | Slide | Parameters |
  | --- | --- |
  | Account created | `autostart=1&step=create` |
  | Install the shop grant | `review=eyJvcCI6Imluc3RhbGxfZ3JhbnQifQ&step=grant` |
  | Buy a coffee | `review=eyJvcCI6Im9yZGVyIiwiY2VudHMiOjM1MH0&step=coffee` |
  | Order past the cap (8 EURC after a coffee) | `scenario=W3sib3AiOiJvcmRlciIsImNlbnRzIjozNTB9XQ&review=eyJvcCI6Im9yZGVyIiwiY2VudHMiOjgwMH0&step=shopcap` |

  The live frame for them: `index.html?embed=1&present=live&preload=1&grant=shop&theme=…`,
  with `act` on `create`, `grant`, `coffee` and `shopcap`.
- Without a parameter the page loads nothing heavy: the 3.4 MB reactor is
  compiled on the first press.
- Element ids: `#nido-controls`, `#nido-result-1` to `#nido-result-4` (each
  step's one-line result), `#nido-status` (visually hidden polite live
  region), `#nido-totals`, `#nido-log` (collapsed cards `#nido-request-N`),
  `#nido-reference`, `#nido-sources`, `#nido-notices`, `#nido-sheet` (the
  approval sheet, a native `<dialog>`), `#nido-present-line` and
  `#nido-present-result` (the `present=sheet` line and result),
  `#nido-live-hint` and `#nido-live-result` (the `present=live` hint and
  results, which replace `#nido-present-result` there).

## Pins

| Source | Revision |
| --- | --- |
| theahaco/soroban-sim | d02938430f0ac41f34e5e3e4c8c48d85b871bd68 (soroban-env-host 29.0.2, protocol 29) |
| bitswell-hq/stellar-registry__perch | 2c64fe483f00e38061dd777bc9194f285b19721d (exact authorization roots) |
| bitswell/soroban-rule-core | 5a689a5760d9a94ef92e5182b15653bed21f7670 |
| nidohq/nido | 97105a0b54763d27f70d65c0d54239fe33bf777f |
| soroban-sign-dialog | theahaco/soroban-sim fb38b9c835e66dcaacf293d1f166bf2da45c1a91, `dist/soroban-sign-dialog.js` a5239ec1…72ee |

Rust 1.97.1 (Perch, driver, game, shop), 1.96.0 (Nido's factory, its
toolchain), stellar-cli 27.0.0 (`stellar contract build`).

## Hashes

| Artifact | SHA-256 |
| --- | --- |
| perch_account.wasm | a6d7604e8b24eb91007dcd0a1c51d00842be342ab096dde422e1dc2434f5a2c8 |
| perch_doc_compiler.wasm | aa5a3eaa271620df9a3ee996af66c1836c11127fb6537cebcd1da792056cb72e |
| perch_interpreter.wasm (pinned, never called) | 4191ce8271035711c7bf9822d7cb20fcd0f300bf772b8defcc2279992440da6f |
| perch_spending_limit.wasm (pinned, never called) | ccaa8f0404279aab8005791bffcbc819d8325c7abc114366cb6ef3472643f59b |
| perch_ed25519_verifier.wasm | 27a733ceb0bda62fc9f645f3a708de73afccfdde9d4b2ffb30f44a2b1b862e7c |
| perch_webauthn_verifier.wasm | bc38017e9281839ebd683341088f5e3550881b97873d350161fa4881bc3070c3 |
| nido_factory.wasm (rebuilt, account pin a6d7604e…) | d5a6aa11569db6ca2d49ea98e579d20ce71f53f309b5b5d1ea5ce121c714f2f6 |
| nido_sim_game.wasm | ca125b953a82692ea9bc7b78c354fbb83ef2e83a249aef6ac792a893afde1d27 |
| nido_sim_shop.wasm | d433a64029bf2b09a86bc7b1fd18a7dbf0d1015f557684b82e21215daad6efd4 |
| reactor (driver, wasm32-wasip1) | 52a302fd288a55865bd2b634ee51834532ac7f3927a20b3614d06cf05e89d7eb |
| reference replies minus timings (native = WASI = browser) | 5ec17f91692e417a25990f84547e25b7228624fa0ac7e4ce13c872aacfad47e2 |
| recorded run `evidence/native-golden.jsonl` | 5fe0796a1118eda818384ff889b4e02ac24d6eaf2a84c2a57e018d68ed1a2b30 |
| index.html (5388257 bytes) | 5fbfba50c0938c0d0f2e8e72f8549b41f2fafaa9a456ab6aac672238fa98be6c |

None of the Perch artifacts is a deployed contract: the account is built
from 2c64fe4 with its compiler, interpreter and spending-limit pins staged
from the same build, in `scripts/build-stack.sh` order. The interpreter,
spending limit and Ed25519 verifier have the same bytes as the f0275f4 builds
of the dual simulation (`../perch-paper/sim/`).

## Rebuild

The page carries its build sources ("Download the build sources"). Their
`BUILD.md` fetches the pinned trees by commit and rebuilds the contracts, the
driver (native and WASI), the reference run, the page and the run record
`fig-nido.run.json`, both written by `make.sh`:

```sh
./fetch-sources.sh
python3 build-contracts.py
./make.sh index.html fig-nido.run.json
```

A plain `make.sh` records a fresh run, whose wall-clock timings differ. To
rebuild this `index.html` byte for byte, keep the recorded run:
`KEEP_EVIDENCE=1 SOURCE_DATE_EPOCH=1794182400 ./make.sh index.html
fig-nido.run.json`. It still runs the scenario natively and under WASI and
checks both against the recorded run, minus timings.
