# Nido in soroban-sim: notices

`index.html` is a self-contained, offline page: it creates a Nido account in
soroban-sim with Nido's factory, installs a Perch grant, and runs a guessing
game and a coffee order through the soroban-sign-dialog in Nido's look. It
repeats these notices, with the full licence texts, in its "Third-party
notices" section, and carries its own build sources ("Download the build
sources").

## What is simulated

- The passkey: a software P-256 key (soroban-sim's stand-in), not an
  authenticator.
- Nido's factory: rebuilt from nidohq/nido `97105a0b` with its account pin set
  to the Perch account built for this page; Nido's deployed factory deploys an
  older Perch account.
- EURC: a test token, a Stellar Asset Contract for an asset coded EURC issued
  by a throwaway key in the simulator. It is not Circle's EURC.
- The game and the coffee shop: two contracts written for this page
  (`sim-contracts/` in the build sources).

## Third-party software in the page

| Project | Revision | Used here | Licence |
| --- | --- | --- | --- |
| theahaco/soroban-sim | `d02938430f0ac41f34e5e3e4c8c48d85b871bd68` | the simulator, in the reactor; its software P-256 key | Apache-2.0 |
| theahaco/soroban-sim, soroban-sign-dialog 0.1.0 | `fb38b9c835e66dcaacf293d1f166bf2da45c1a91` | the signing dialog, `dist/soroban-sign-dialog.js` unchanged (as vendored in `docs/sign-dialog/`) | Apache-2.0 |
| stellar/rs-soroban-env (soroban-env-host 29.0.2) | crates.io release | the Soroban host, in the reactor | Apache-2.0 |
| bitswell-hq/stellar-registry__perch | `2c64fe483f00e38061dd777bc9194f285b19721d` | account, document compiler, interpreter, spending limit, Ed25519 and WebAuthn verifiers (Wasm) | Apache-2.0 |
| bitswell/soroban-rule-core | `5a689a5760d9a94ef92e5182b15653bed21f7670` | rule-eval and soroban-facade, in the account and the reactor | MIT OR Apache-2.0, used under Apache-2.0 |
| nidohq/nido | `97105a0b54763d27f70d65c0d54239fe33bf777f` | the factory (Wasm, rebuilt with another account pin); `buildPolicyDoc` for the baseline document shown; the dialog theme's tokens and mark (`docs/sign-dialog/nido/`) | Apache-2.0; the Nido name and mark belong to their owner, and the licence grants no trademark rights (section 6) |
| Fraunces, Hanken Grotesk, JetBrains Mono | Google Fonts Latin subsets (`docs/sign-dialog/nido/fonts/`) | the dialog's fonts, inlined | SIL Open Font License 1.1 |

The Apache-2.0 text is in this repository's `LICENSE` and in the page; the
font licences are in `docs/sign-dialog/nido/fonts/` and in the page.
