# Perch Agent Grants deck

`index.html` is the deck for The Aha Company's SCF Build Award submission (Open Track): "Perch Agent Grants: subagent budgets enforced by Stellar smart accounts". Its 10 timed slides are cut to fit SCF's three-minute video, and an appendix of 8 background slides follows the close, outside the timed run and the recording. It uses the Perch deck's engine, palette and seals and is a separate deck, so `../perch-deck/` is unchanged. Everything is in one file, with inline SVG, CSS and JS and system fonts, and the deck makes no network requests, except that it loads the sibling page `../nido-sim/index.html?embed=1&present=live&preload=1&grant=shop` into one frame for slide 8 (a moment after it opens), and the stills in `stills-2/`, and nothing else. The arXiv and GitHub links, and the appendix's deployment-record and stellar.expert links, are plain links.

Controls:

- Navigation: arrows, Space or Shift+Space, PageUp/PageDown, and Home/End; swipe, or tap either side of the stage. On slide 8, Next and Prev move through its four steps first, and Next opens each step's dialog.
- `N` shows the speaker script in a panel beside the slide, and the slide shrinks to the rest of the window at 16:9; on a narrow, square or portrait window, where that would leave the slide smaller, the panel goes below it instead. The panel shows the lines to say aloud, a timer against 3:00 with Reset, the time on this slide (or step) against its target, and the next slide's title (or the next step). The timer runs while the panel is shown. `S` shows the slide's sources. `T` switches between light and dark; until then the deck follows the OS.
- `R` records a video of the deck (below); `P` pauses and resumes a recording.
- On slide 8, "Reset demo" in the corner, or `D`, starts the Nido demo over: a new ledger with no account, back on step 1 with no dialog open (below).
- Layout: each slide has a wide and a tall drawing, and the deck uses the one that shows it larger in the space the slide has (its stage taller than about 0.81 of its width, after any panel, gets the tall one). When the bottom bar is too narrow for a dot per slide, it shows a progress line instead.
- The counter shows `n / 10` on the timed slides and `A1 / 8` to `A8 / 8` in the appendix, where each slide is labelled "Appendix".
- `#n` opens slide n, and `#8.k` opens step k of slide 8; `?still=1` shows every slide's final drawing without motion, and turns the recorder off. Reduced motion also stops the motion; the recorder stays available.

| # | Slide |
| --- | --- |
| 1 | Perch Agent Grants (title) |
| 2 | What Perch is |
| 3 | An agent raised its own cap (a cited study) |
| 4 | A contained policy runtime |
| 5 | Example: a mail assistant |
| 6 | A cap the agent cannot raise |
| 7 | Narrowing a grant |
| 8 | Perch, in a shipping wallet: Nido's status and traction, beside the live Nido demo (the shop only) |
| 9 | Our ask: three tranches |
| 10 | Team: why Stellar, and the closing line |
| 11 (A1) | Appendix: Agents with keys |
| 12 (A2) | Appendix: Where the policy lives |
| 13 (A3) | Appendix: The sandbox and the gate |
| 14 (A4) | Appendix: Example: a news and data reader |
| 15 (A5) | Appendix: What exists today |
| 16 (A6) | Appendix: Tranche 1: MVP |
| 17 (A7) | Appendix: Tranche 2: testnet |
| 18 (A8) | Appendix: Tranche 3: mainnet |

The whole deck is the proposal, drawn in one solid style with no status coding; honesty is in the words. What is live is said as such: Perch contracts on mainnet and Nido creating Perch accounts (slides 2 and 8, and appendix slide 15). What is merged in the repository is said as such too: grants, `apply_grant`, `rule_eval::check_auth`, recovery and the Lean proofs, with grants reaching mainnet in Tranche 3. Everything about the runtime, the Cedar compiler and engine, the example and the tranches reads as what we will build. Slide 3, marked "a cited study", draws another team's published experiment and links the paper. On slide 8 Nido's status, the npm figures and the mainnet deployment are marked "context": they are reported under Nido's SCF #41 award, not claimed for this ask. Theorem numbers appear only in the sources view; the slides, script and aria-labels say what is proven in plain words.

The arc introduces Perch (slide 2) and the problem (slide 3). What we will build follows, a contained policy runtime (slide 4): one Cedar policy, checked off chain in a sandbox and on chain by the account. A mail assistant is the example (slide 5). Slide 6 shows the account's two separate documents in Cedar-style pseudocode (the authoring form we will compile to the account's rules, not valid Cedar): the account document, which lists no grants, and beside it the agent's grant document, installed by the owner's passkey with `apply_grant`, while the agent's own key is refused; "Show the document fields" maps each line to Perch's JSON fields. Slide 7 narrows a grant for a subagent. Slide 8 leads with Nido's status (pre-release on Stellar mainnet; the current version on testnet, at nido.fyi) and the traction facts, beside one live session of the Nido simulation with the shop grant only, in four steps: create the account behind a simulated passkey prompt, install the shop grant, buy a coffee, and an order past the cap, refused. Slide 9 is the ask, the three tranches with their dates and deliverables, and slide 10 says why Stellar and closes. The appendix (slides 11–18) gives the background the timed run leaves out: why an agent's key is the problem, where agent-payment policy usually lives, the runtime's sandbox and its Cedar gate, a second example (a news and data reader), what exists today on mainnet and in the repository, and each tranche's four deliverables with how each completes. Only the account's decision function is called proved; the runtime will be tested, not proven.

The deck is written as if release PR #168 has merged. Grants (`apply_grant`), `rule_eval::check_auth`, recovery and the verifiers are the merged baseline, and the award does not fund them. Mainnet still runs the earlier account design (`c135aca`). Deploying the account changes to mainnet is Tranche 3, deliverable 1.

On the contained policy runtime slide, the fragment proof and the size measurements (in its sources view) are stated as fact; the rest of the Cedar work is what we will build.

## Speaker script

The script is the one recorded for the submission: plain spoken sentences, 283 words over the 10 timed slides. The appendix slides have notes for the presenter but no spoken lines and no targets, and the script panel's 3:00 clock stops while it shows them. Its citations are in the sources view (`S`), not in the spoken text. Each slide's notes carry a target time (`data-sec`); on slide 8 each step has its own line and target (`<p data-k data-sec>`). The script panel and the recording's presenter panel show the current one beside a running timer.

The targets are timed for real speech, not reading: each line at 130 words a minute, plus 5 s for each live dialog on slide 8 (the click and the sheet's check), plus 1 s for each slide change, rounded up. They add up to 2:47, inside SCF's three-minute limit.

| # | Slide | Words | Speech at 130 wpm | Dialogs | Target |
| --- | --- | --- | --- | --- | --- |
| 1 | Perch Agent Grants | 16 | 7.4 s | | 9 s |
| 2 | What Perch is | 20 | 9.2 s | | 11 s |
| 3 | An agent raised its own cap | 26 | 12.0 s | | 13 s |
| 4 | A contained policy runtime | 28 | 12.9 s | | 14 s |
| 5 | Example: a mail assistant | 22 | 10.2 s | | 12 s |
| 6 | A cap the agent cannot raise | 14 | 6.5 s | | 8 s |
| 7 | Narrowing a grant | 19 | 8.8 s | | 10 s |
| 8 | Perch, in a shipping wallet | 56 | 25.8 s | 4 × 5 s | 49 s |
| 9 | Our ask: three tranches | 42 | 19.4 s | | 21 s |
| 10 | Team | 40 | 18.5 s | | 20 s |
| | Total | 283 | 2:11 | 20 s | 2:47 |

## Recording a video

The Record button in the controls, or `R`, records the deck with your voice and saves a video file. Everything happens in the browser: nothing is uploaded and there is no server.

1. Use a desktop browser. Press `R` and allow the microphone. If it is blocked, the deck says so and records nothing; allow it in the site settings and press `R` again.
2. The deck prepares the slides, then counts down 3, 2, 1. `R` or `Escape` cancels the countdown.
3. Present as usual with the arrow keys; on slide 8 each Next opens the next dialog, and you approve or reject it with a click. A presenter panel beside the slide shows the script for the current slide or step, the time against 3:00, the time on this slide or step against its target, and the next slide or step. The panel is not in the video. The script panel (`N`) stays closed while recording, since the presenter panel shows the same script; open it again after you stop.
4. The recording covers slides 1–10. Next on slide 10 ends it and saves it, as does any move into the appendix; `R` pressed on an appendix slide starts the recording from slide 1. The recording never draws an appendix slide.
5. `P` pauses and resumes. `R`, or "Stop and save", ends the recording and downloads `perch-agent-grants-<date>-<time>.mp4`, or `.webm`. The message names the format, size and length.

The video is 1920×1080 at 30 frames a second. The deck lays itself out at 1920×1080 in a hidden frame and paints each slide in its final state onto a canvas: the drawings as images, the text at the positions the browser laid out. The recording is that canvas plus the microphone, through `MediaRecorder`. Slides change with a short crossfade; the arrival animations are not recorded. On the Nido slide (8) the recorder draws each step's still as the steps advance (see "Nido stills"). Once you click inside the live frame, the arrow and Page keys still move the deck (the frame passes them on); the deck's other keys (Space, `P`, `R`) wait until focus returns, so click the slide outside the frame first.

The file is MP4 (H.264 and AAC) where the browser can write it, as in Safari and recent Chrome, and WebM (VP9 or VP8 with Opus) otherwise. YouTube and Vimeo accept both. The deck sets the duration that WebM files from `MediaRecorder` lack or leave at zero. The recording uses the theme in effect when it starts.

## Nido, live

Slide 8 runs one continuous session of the Nido simulation (`../nido-sim/`) with the shop grant only (`grant=shop`), in four steps. The deck makes one frame, `../nido-sim/index.html?embed=1&present=live&preload=1&grant=shop&theme=<light|dark>`, a moment after it opens (at once on or near slide 8). It never reloads it or moves it to another parent, which would lose the session. The frame sits in a fixed layer over the slide's slot, with the slot's size and the slide's scale, and it does not move or resize between steps. It is hidden, not removed, on the other slides.

Once the frame posts `{type:"nido-sim:preloaded"}`, each step sends `{type:"nido-sim:show", controls, step}` with its control (the slide's `data-steps`). A Next that moves to a step also sends `{type:"nido-sim:act", control, step}`, which presses that control as a click would and opens its dialog: the passkey prompt or the sign sheet. A Next on a step whose dialog it has not opened yet opens it before moving on, so after Reset the first Next opens the passkey prompt. Prev, the step list and `#8.k` only show a step. The frame rejects a dialog left undecided before it opens the next one, and a step already done (the account, the grant) shows its result and opens nothing. Next on step 4 leaves the slide; entering it with Prev lands on step 4.

| Step | `control` | The dialog Next opens | What the presenter does |
| --- | --- | --- | --- |
| 1, create | `create` | "Create a passkey for Nido" (simulated) | Continue |
| 2, grant | `grant` | the shop grant: 10 EURC to Coffee shop every ~8 min, in Coffee shop › order | Install grant |
| 3, coffee | `coffee` | 3.50 EURC to Coffee shop, within the cap | Pay 3.50 EURC |
| 4, refused | `shopcap` | an order 1.50 EURC more than is left this period, refused by the cap | Reject |

Arrow and Page keys pressed in the frame arrive as `{type:"nido-sim:key"}` and move through the steps the same way, and after each change the deck takes its other keys back. "Reset demo" or `D` sends `{type:"nido-sim:reset"}` (a new ledger, no account, the reactor kept) and returns to step 1 with no dialog open.

The slide leads with Nido's status, as context: pre-release on Stellar mainnet (its mainnet factory is deployed, on Perch's earlier account design, and its launch checklist is open), and the current version on testnet, as the hosted wallet at nido.fyi. One small note says the demo is simulated in this page (a software passkey and a test token); the rest is in the notes and sources.

## Nido stills

If the frame never posts `preloaded` (a copy without `../nido-sim`, a slow device), each step shows its still instead and the slide stays usable. The recording always draws the stills, because a canvas cannot capture a live frame, and print shows the current step's still beside the list of steps. Each step has four, `stills-2/<light|dark>-shop-<state>-<wide|narrow>.webp`, for the states `account`, `grant`, `coffee` and `cap`: 16 files, about 400 KB.

They are screenshots of the simulation page in its shop-only `present=sheet` URL form. For each theme and state:

1. Open `../nido-sim/index.html?embed=1&present=sheet&grant=shop&theme=<light|dark>&<parameters>` in Chromium, with the parameters from the shop-only table in `../nido-sim/README.md` ("Embedding"): `autostart=1&step=create` for `account`, then the shop grant's review, the coffee's review, and the order past the cap (8 EURC after a coffee) for `cap`.
2. Size it wide or narrow: wide is 900×620 CSS px at device scale 1.5; narrow is 360×640 at device scale 2.
3. Wait until `<html data-nido-ready>` is set, which is `done`, `ok` or `refused` here; `error` means a bad URL. Then wait 700 ms and screenshot the viewport.
4. Convert each PNG with `cwebp -quiet -q 80 -m 6 <in>.png -o stills-2/<theme>-shop-<state>-<wide|narrow>.webp`.

The current set was captured from `docs/nido-sim/index.html` with SHA-256 `5fbfba50…`, the page whose shop-only sheet names the app "Coffee shop".

## Tests

Two browser checks, both with Playwright, in `test/`. Each serves `docs/` itself on a free local port and exits 1 on a failure:

    cd docs/perch-scf-deck/test
    npm install && npx playwright install chromium firefox webkit
    npm test

- `side-panel.test.mjs`, in Chromium with a fake microphone: it opens the script (`N`), records (`R`), presses `N` while recording, stops, then opens the script and the sources again, and checks which panels show, the layout around them and the script panel's timer. It also checks that the clock stops in the appendix, and that a recording started on slide 10 ends there on Next, prepares pictures of the timed slides only and never shows an appendix slide.
- `nido-dialog.test.mjs`, in Chromium, Firefox and WebKit: from a fresh load, by the keyboard's Next only, it checks that every Nido step opens its dialog on screen: open, not empty, inside the frame and the viewport, and topmost at its centre. It then approves each approvable step with a real click and checks that the balances line moves, and rejects the refusal. `BROWSERS=chromium,firefox,webkit` picks the engines.

Set `CHROMIUM` to a browser binary to use one Playwright did not download.

## Sources

The source is the SCF Build submission prepared for this award (its form answers); its section names are given below.

Tranche 1 items 2 and 3 carry the titles and scope agreed on 2026-11-09. The deck states tranches, deliverables and completion dates only.

| Slides | Source |
| --- | --- |
| 1 | the SCF Build submission, Submission Title, Build Award Track, Products & Services. The dial and seal P are the Perch deck's title drawing (`../perch-deck/thumbnail.py`). |
| 2 | the SCF Build submission, Products & Services (items 1–3), Traction Evidence, Tranche #3 item 1; `docs/perch-paper/source/statements.json` (P1). |
| 3 | Breckenridge, Vilardell, Wang, Zhang and Juels, "I-HITL: Inalienable Human-in-the-Loop", [arXiv:2610.35835](https://arxiv.org/abs/2610.35835) (v3, 30 October 2026): p. 4 (Setup, Experiments, Key Findings), p. 5 (Results), Appendix D (p. 18). The paper names the ten models; the deck does not. |
| 4 | the SCF Build submission, Products & Services (items 1 and 3, and the funded work), Tranche #1 items 1–3 (items 2 and 3 as agreed 2026-11-09) and Tranche #2 items 1 and 2; `docs/cedar-walkthrough/` ("Why not upload the full Cedar evaluator?", measured 2026-11-06); the vision paper, §08 and §09 (`docs/perch-paper/source/papers/vision/html/sections/agents.html`, `cedar.html`). |
| 5 | What we will build: the SCF Build submission, Products & Services (the funded work; item 2, grants), Tranche #1 items 1 and 3; arXiv:2610.35835, p. 4; `docs/cedar-walkthrough/` (the Cedar dialect). The action and entity names are the request vocabulary we will give the runtime, and mail is modelled as web requests to two named hosts. The grant is 5 USDC per 518,400 ledgers, about 30 days. |
| 6 | `crates/perch-ir/src/doc.rs` (`PolicyDoc`, `SignerDecl`, `Rule`: `scope` contract or self-admin, `principals`, `functions`, `args`/`pred`, `auth-root`, `cap {limit, period-ledgers}`, `not-after-ledger`, `RecoveryConfig`); `docs/schema.md`; `docs/account-interface.md` (Constructor, `apply_doc`, `apply_grant`, Removing grants); `crates/perch-smart-account/src/lib.rs` (`PerchSmartAccount`: `apply_doc`, `apply_grant`, `remove_grant`, and the grant map that stores grant documents apart from the account document); the grant `crates/integration-tests/tests/auth_root.rs` installs, with a shop in place of the game; `docs/perch-paper/source/statements.json` (T8, grant target containment). Cedar-style pseudocode, not valid Cedar; values are illustrative. |
| 7 | The Perch deck, slide 4, and its sources (`docs/perch-paper/source/statements.json` T4 and T5, `source/facts/example.json`, `source/facts/proofs.json`). The SCF Build submission, Tranche #1 item 1 and Tranche #2 item 1. |
| 8 | the SCF Build submission, Traction Evidence (mainnet, Nido's factory, npm 1,662 downloads 2026-10-10 to 2026-11-08, the 2026-11-05 testnet run) and its notes; Nido's repository: README (the hosted testnet wallet at nido.fyi, not for real funds), `packages/passkey-sdk/src/perch/factory.mainnet.json` (the mainnet factory, 2026-10-26, on Perch's earlier account design), `docs/MAINNET_READINESS.md` (the open launch checklist); the paper's section "A Nido wallet run used a grant end to end"; the Nido simulation (`docs/nido-sim/index.html` and `README.md`), live, with the shop grant only (`grant=shop`), in four steps of one session; each still is a screenshot of that page with its sheet open ("Nido stills"). |
| 9 | the SCF Build submission, Tranche #1, #2 and #3 Deliverables and Completion Dates. Tranche 1 items 2 and 3 are as agreed 2026-11-09. The deliverables per tranche: Tranche #1 Deliverables and Completion Date. Items 2 and 3 are as agreed 2026-11-09.; Tranche #2 Deliverables and Completion Date; Tranche #3 Deliverables and Completion Date |
| 10 | the SCF Build submission, Team Description and Project URL; Stellar's developer documentation (custom accounts authorize in their own `__check_auth`; fees: a base fee per operation plus Soroban resource fees), for why Stellar. |
| 11 (A1) | the SCF Build submission, Products & Services (items 1 and 2, and the funded work) |
| 12 (A2) | arXiv:2610.35835, p. 4 (the emailed-code finding); the SCF Build submission, Products & Services (the funded work), Tranche #1 items 2 and 3 (as agreed 2026-11-09). The common setups are described, not named. |
| 13 (A3) | What we will build: the vision paper, §08 "Agents, budgets and payments (proposed)" and §05 "Recovery and the end of authority" (guardians, quorum, delay); `docs/account-interface.md` (Constructor, `apply_grant`, Removing grants); `docs/perch-paper/source/statements.json` (T8); the SCF Build submission, Products & Services (the funded work), Tranche #1 items 1 and 3. The request shown is illustrative. |
| 14 (A4) | What we will build: the SCF Build submission, Products & Services (the funded work), Tranche #1 items 1 and 3; `docs/cedar-walkthrough/`. No money moves, so there is no grant. |
| 15 (A5) | the SCF Build submission, Traction Evidence (`deployments/mainnet.json`, the Registry, Document compiler and Account factory on stellar.expert, Nido's factory), Products & Services, and SCF Build Tranche Deliverables ("Baseline"). Nido's counts are context reported under Nido's SCF #41 award and are not shown. |
| 16 (A6) | the SCF Build submission, Tranche #1 Deliverables and Completion Date. Items 2 and 3 are as agreed 2026-11-09. |
| 17 (A7) | the SCF Build submission, Tranche #2 Deliverables and Completion Date |
| 18 (A8) | the SCF Build submission, Tranche #3 Deliverables and Completion Date |

`REVIEW.md` reviews the sign dialog and the Nido simulation and gives a minimal-by-default spec for both.
