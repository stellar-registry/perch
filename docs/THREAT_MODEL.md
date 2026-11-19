# Threat model

What Perch protects, against whom, what it trusts, and where the audited
behaviour stops protecting. This covers the source at the top of the
`stack/*` series (bitswell-hq/stellar-registry__perch#105–#121, the split of
stellar-registry/perch#168): accounts that own their authorization types and
decide every authorization with rule-core's evaluator (`rule-eval`), grant
documents, named verifiers, exact authorization-entry roots, and the
off-chain review core. Companion to [audit-scope.md](./audit-scope.md),
[DEFERRED.md](./DEFERRED.md), and
[account-interface.md](./account-interface.md).

[recovery/spec.md](./recovery/spec.md) is normative. "§", "D", "T", and "I"
numbers below are that spec's sections, requirements (Summary of
requirements), transitions (§6.3), and invariants (§15). INV-1 is the
"every rule but the recovery rule names a signer" check (`UnguardedRule`).
Recovery's own threat model, by profile, is the spec's §2; this file adds
what the account, its grant documents, the evaluator, the verifiers, and the
registries bring. A consumer such as Nido adds its own wallet, factory, and
infrastructure threats on top (its `docs/THREAT_MODEL.md`).

**This source is not what is deployed.** `deployments/testnet.json` and
`deployments/mainnet.json` (build `c135aca`, 2026-10-26) record earlier
builds that decide authorizations with OpenZeppelin's `stellar-accounts`
code. Nothing below describes those accounts unless it says so. See
[Several account builds](#several-account-builds).

## STRIDE summary

One row per threat. The analysis is in the section each row names: a
number is an [adversary](#adversaries), an L number a
[limit](#limits-within-the-audited-behaviour). "Bounded by" lists the spec
requirements and account checks that limit the threat; "Deferred" links
the [DEFERRED.md](./DEFERRED.md) entry whose exit criterion would close it.

STRIDE: **S** spoofing, **T** tampering, **R** repudiation, **I** information
disclosure, **D** denial of service, **E** elevation of privilege.

Status: **Open**, no shipped mitigation; **Partial**, mitigated with a named
residual; **Mitigated**, closed by the listed checks within their evidence's
limits; **Accepted**, inherent in the design at this revision.

| Threat | STRIDE | Section | Bounded by | Deferred | Status |
| --- | --- | --- | --- | --- | --- |
| Admin-key thief, `Loss` account | E | 1 | D5 (uncapped veto) | none | Accepted: under `Loss` the key holder is the owner, upgrades included after the seven-day delay. |
| Admin-key thief, `Protected` account | E | 1, L1 | D1, D3, D4, D5, D11 | none | Partial: the condition gates recovery changes, upgrades, and the authorized window; without an enrolled baseline the thief can invalidate every lost-key attempt. |
| Admin-key thief installs grants for their own keys | E | 1 | D1; `grant_generation`, `WipedCredential` | none | Mitigated: grant rules are frozen with the account, wiped by a completion, and their credentials can never be named again. |
| Grant-key thief reaches beyond the grant | E | 2, L7 | `GrantEscalation` at apply and in `__check_auth`; D12; argument 0 pinned for `OWNER_FNS` | none | Partial: account powers, recovery, guardian approvals, and token-admin functions are refused on chain; unpinned functions, unverified verifiers, and listing grants rely on the wallet (L7, cases 1–3). |
| Grant-key thief exceeds an intended total | E | 2 | `cap` on `transfer` only | none | Accepted: argument bounds are per call; only a cap is cumulative. |
| Colluding guardians or a ZK-secret thief | S, E | 3 | D5, D6, D7 | none | Accepted: indistinguishable from the owner's factor; bounded by the delay, the uncapped `Loss` veto, and `Combined`. |
| Griefer: evidence-free attempts, stale evidence, replayed proofs or approvals | D | 4 | D2, D9, D10, D13 | none | Mitigated. |
| Verifier that accepts any signature | S, E | 5 | `is_verified_verifier`, `UnverifiedVerifier`, `Compiler_DocInvalid`; one signer per unverified verifier per rule | none | Partial: admin rules and recovery credentials use only verified, admin-free verifiers; grants may use unverified ones; the ML-DSA verifier's `fips204` dependency is unaudited. |
| Registry admin or manager approves a hostile verifier, replaces the registry's code, or fills an empty pinned address | T, E, D | 6 | §16 content addressing; no upgrade on deployed contracts; a resolved `verifier-name` must equal the signer's `verifier` | [contract-admin governance](./DEFERRED.md#contract-admin-governance-behind-a-multisig-and-timelock) | Open: one human-held key, changes take effect at once; the account checks verifiers' code but not its compiler's, interpreter's, or spending limit's; a broken or replaced `perch/verifiers` refuses every account document and recovery target that names a verifier until it is fixed. |
| Supply-chain attacker or wrong artifacts | T | 7 | §16 pinned hashes; `fetch-infra-wasm.sh`, `check-pins.sh`, `testnet_pins`, `verify-deployment.sh` | Packaging rule | Partial: pins are hash- and address-checked; the deployed builds are unreproduced, npm integrity is the consumer's, and five vendored crates carry Perch's ports. |
| External signature replayed on another account | S | 9 | §15 `addr_oz_v1` digest | none | Mitigated. |
| An `auth-root` contract issues the guarded call on a path the owner did not intend | E | 9 | the guarded rule's target, functions, arguments, signers, expiry, and cap; rule-core `authorize.exact-root` | none | Accepted: the condition names a contract and function, not its code or arguments; it is as narrow as the root contract's behaviour, including after that contract's own upgrades. |
| Signing request misdescribed: root conditions, stale or chosen snapshot, sibling entries, hidden grants, wrong bindings | S, T, E | 9, 10, L7 | `auth-root` enforced on chain | none | Partial: the chain decides; what the owner is shown depends on the wallet deriving contexts from the XDR, a live snapshot, listing grants, and reading `capabilities` first. |
| Indexer, relay, or RPC withholds data | D | 10 | §2 | none | Accepted: availability only; nothing they return is trusted without on-chain checks. |
| Storage expiry | D | 11 | §3.6 (archived, never reset) | none | Partial: `renew` does not extend rule records; restoring is the client's job. |
| Spending record reaches the entry-size limit | D | 11, L6 | rule-eval's history limit | none | Accepted: about 900 spends a window; further charges fail until spends age out. |
| A ZK proof reveals the secret | I | 12 | D14; `UltraKeccakZKFlavor` only | none | Mitigated, subject to the delta below. |
| Unsound ZK verifier delta | E | 12 | D14 | none | Open: the delta is unaudited until the audit audit-scope.md prepares. |
| Allowances granted before a freeze or grant wipe stay usable | E | L2 | D1 | none | Accepted: no account code can revoke them. |
| Replacing a capped rule resets its record | E | L3 | none | [persistent spending budgets](./DEFERRED.md#persistent-spending-budgets-across-replacements) | Accepted. |
| Ordinary and grant signatures are not revision-bound | T | L4 | `ContextRuleNotFound` on replaced rules | [revision-bound ordinary signatures](./DEFERRED.md#revision-bound-ordinary-signatures) | Accepted. |
| Leftover completion marker misclassifies an ordinary write | T | L5 | D8 (canonical target still bound) | [completion input-byte binding](./DEFERRED.md#completion-input-byte-binding) | Accepted until the exit criterion lands. |
| A credential any grant named before a recovery can never be named again, admin credentials and removed grants' keys included | D | 1, L10 | `WipedCredential`; the completion's target exempt | none | Accepted: deliberate, since the account cannot tell an owner's grant key from a thief's; wallets keep admin credentials out of grants. |
| Grant changes during a `Loss` authorized window | T | 1, L8 | completion wipes every grant | none | Accepted: grants are exempt from D3; the spec does not yet say so. |
| Upgrading a deployed account to this build locks it out | D | L9 | D11 delay | none | Accepted: no in-place migration; users of deployed accounts create a new account, funded with 5 XLM as before, rather than upgrade. |

No threat is listed under repudiation: every authorization is an on-chain
signature checked by the account, and every rule change is recorded by
`DocApplied` or `GrantApplied` with the applied document. The one off-chain
step, a guardian's out-of-band check of whose key a replacement is (§2),
leaves no record, and nothing in the protocol depends on proving it took
place. Information disclosure is limited to the ZK secret: documents,
rules, attempts, and approvals are public by design, and hiding which
accounts use ZK recovery is out of scope.

## Assets

| Asset | Where it lives | If compromised |
| --- | --- | --- |
| Funds | The `perch-account` | Theft. |
| Admin credentials (the account document's `self-admin` signers) | The owner's passkey, ed25519 or ML-DSA key, or a delegated G-account (CAP-0071) | Full owner authority under `Loss`; ordinary activity, including granting and spending, under `Protected` (adversary 1). |
| Grant credentials (session keys, CI keys, dApp keys) | Wherever the grantee keeps them: a browser, a CI secret, a server | Exactly what the grant's rules allow, within their caps and expiries, until the owner removes the grant or a recovery completion wipes it (adversary 2). |
| Recovery factors | Guardians' own accounts; the ZK secret in the owner's recovery kit | A guardian quorum or the secret is the owner as far as recovery can tell (§2; adversary 3). |
| Spending records and grant records | The account's own storage (`SpendRecords`, `Grants`, `GrantTags`, `RuleSet`) | A cap is only as good as its record: lost or reset history is unspent budget (L3, adversary 11). |
| `perch/constructorless` and `perch/verifiers` registry keys | The registries' admin and manager: one human-held key, backed up in 1Password ([DEFERRED](./DEFERRED.md#contract-admin-governance-behind-a-multisig-and-timelock)) | Which verifiers count as verified, which names resolve, the registry's own code, and, on a network where a pinned address is still empty, what lands there (adversary 6). |
| Build-time pins | `crates/*/wasm/*.sha256`, `registry.path`, `verifiers.path`, baked into the account and factory | Which compiler, verifier, and account bytes every account built from this source trusts (adversary 7). |
| rule-core | `bitswell/soroban-rule-core` at rev `a3c92ba`, a git dependency | The evaluator that decides every authorization but a recovery completion (adversary 8). |
| Release and npm publishing credentials | GitHub Actions (`release.yml`, `release-mainnet.yml`), npm | What gets published under Perch's names: contract wasm and the JS packages wallets sign with (adversary 7). |

## Adversaries

1. **Admin-key thief.** Holds an admin signer's credential.
   - `Loss`: the thief is the owner. They can change or remove recovery,
     veto attempts (T7), schedule an upgrade to any wasm (executable after
     120,960 ledgers, about seven days, D11), install grants, and drain
     funds. `Loss` assumes the key is lost, not stolen.
   - `Protected`: they can spend outside an authorized window, but cannot
     change recovery, upgrade the account, or block a recovery without the
     enrolled condition (D4, D5, D11). Once an attempt is authorized the
     account authorizes nothing but its completion, on every path,
     CAP-0071 delegation and grant rules included (D1, §9). Without an
     enrolled baseline, any account-document change the thief makes
     invalidates a collecting lost-key attempt (T4); compromise recovery from
     a baseline is the defence, and the baseline is optional (L1).
   - **Grants are ordinary activity.** `apply_grant` needs only owner
     authorization and calls no controller, so under `Protected` a thief can
     install a grant giving their own key spending rights. That adds nothing
     the stolen key could not already do, and it does not survive recovery:
     a completion advances `grant_generation`, which wipes every grant
     (`StaleGrant`), and afterwards no document may name a credential a
     wiped grant named (`WipedCredential`, `credential_generation`). A grant
     does not move `revision` or `doc_hash`, so it does not invalidate a
     collecting attempt either. Nor is it a policy change for D3: under
     `Loss`, which has no freeze, an authorized attempt blocks `apply_doc`
     (`AttemptAuthorized`) but not `apply_grant` or `remove_grant`
     (`grant_docs.rs`,
     `under_loss_the_owner_changes_grants_during_an_authorized_attempt`).
     Whatever grants exist when the attempt completes are wiped with the
     rest (L8).
   - **What the thief leaves behind survives.** A token allowance the thief
     approves, directly or through a grant rule, stays usable after the
     freeze and after a completion wipes the grant (L2).
2. **Grant-key thief (session key, CI key, dApp key).** Holds a credential a
   grant document names. It can do what the grant's rules allow and nothing
   else:
   - **Never the account's own powers.** `apply_grant` refuses
     (`GrantEscalation`) a `recovery` member, a `self-admin` rule, a rule
     scoped to the account itself, its recovery controller, or its ZK
     adapter or pool, and a rule naming a guardian approval or a token-admin
     function (`mint`, `clawback`, `set_admin`, `set_authorized`).
     `__check_auth` refuses the same calls again for any rule a grant
     installed, so a controller or pool adopted after the grant was applied
     is covered too. Grant rules must be contract-scoped.
   - **Own funds only, for the standard token functions.** A capped rule,
     and any grant rule for `transfer`, `transfer_from`, `approve`, `burn`,
     or `burn_from`, acts only when argument 0 is the account (matched by
     function name). Any other function, including a non-standard token's
     own spend function, matches as its argument predicates say;
     `selfPinWarnings` in perch-js lists the rules that pin no argument to
     the account, for the wallet to show (L7).
   - **Per-call bounds are per call.** An argument bound limits one
     invocation. Only a `cap` limits a total, and a cap applies only to
     `transfer` (README, "Stateless predicates and cumulative caps"). A
     grantee can call an uncapped rule as often as the rule allows.
   - **Expiry, revocation, recovery.** A rule's `not-after-ledger` ends it.
     `remove_grant` revokes a grant and every rule it installed. A
     completed recovery wipes all grants (adversary 1).
   - A signed, unsubmitted transaction outlives an in-place edit of its rule
     (L4).
3. **Colluding guardians or a ZK-secret thief.** Indistinguishable from the
   owner's own factor (§2). Under `Loss` the owner's veto is never capped
   (D5). `Combined` requires both factors. Every attempt waits out the delay
   before it can complete, which is the owner's window to notice. A
   completion's target is derived on chain from the source and the declared
   replacement set (D6), and replaced credentials are revoked permanently
   (D7).
4. **Griefer.** Opens attempts without evidence, submits stale evidence, or
   replays proofs or approvals. Opening an attempt is permissionless and
   blocks nothing until its condition is met (D2). Guardian approvals and
   proofs bind one statement: network, account, controller, epoch, action,
   and attempt (D13); epoch bumps kill older evidence (D10). Only a
   completion spends a nullifier, and nothing un-spends one (D9).
   `perch-relay` admits an approval only after an enforcing simulation of
   the whole controller call, so forged entries cannot displace a guardian's
   slot.
5. **A malicious or broken verifier.** An `External` signer is only as
   strong as its verifier's `verify`: one that accepts anything makes every
   rule holding its signers unguarded.
   - **Verified verifiers.** An account document, a recovery target, and
     the constructor's admin signers may name only a verifier
     `perch/verifiers` deployed: the account checks that the verifier sits
     at `deployer(perch/verifiers, sha256(its own code))`
     (`is_verified_verifier`, `UnverifiedVerifier`, `Compiler_DocInvalid`).
     A `verifier-name` binds name, version, and address into `doc_hash`;
     the account stores the address and authenticates against it, so a
     later re-pointing of the name changes no applied rule. Every compile
     resolves the name again, though (adversary 6).
   - **Unverified verifiers, in grants only.** A grant document may name a
     verifier by contract id alone, at most one signer per unverified
     verifier in a rule, so a verifier that accepts one signature for
     several keys cannot fill a threshold alone. `CompiledDoc::unverified`
     and perch-js's `unverifiedWarnings` exist for the wallet to warn; the
     contract enforces nothing more (L7).
   - **The shipped verifiers.** WebAuthn, ed25519, and ML-DSA-65 are
     constructorless and stateless, with no admin and no upgrade path. The
     ML-DSA verifier rests on the `fips204` crate, which is unaudited
     (`Cargo.toml`).
   - "Verified" means "the `perch/verifiers` registry deployed it", which is
     a statement about adversary 6, not about the verifier's code.
6. **Malicious or compromised registry admin or manager.** One human-held
   key administers `perch/constructorless` and `perch/verifiers`, and the
   registry's `upgrade`, `set_admin`, `set_manager`, and `remove_manager`
   take effect at once ([DEFERRED](./DEFERRED.md#contract-admin-governance-behind-a-multisig-and-timelock)).
   - **Already-deployed contracts are out of its reach.** Every pinned
     address is `deployer(registry, sha256(wasm))`, and every contract at
     one is constructorless with no upgrade entry point, so the key cannot
     change code an account already calls.
   - **New verifier names.** The manager approves each name in
     `perch/verifiers`. A compromised manager can publish a verifier that
     accepts anything and have it count as verified (adversary 5). It
     reaches an account only through a document that names it, which the
     owner approves, or through a phishing link that gets the owner to.
   - **Verifier names are a live dependency.** An account document may name
     a verifier only by `verifier-name`, and the doc compiler resolves each
     name with `perch/verifiers`' `fetch_hash` on every `compile_doc` and
     `derive_target`, so on every `apply_doc`, recovery target, and
     completion. The resolved address must equal the signer's `verifier`,
     so a hostile registry cannot swap in another verifier. But a registry
     whose code the key has replaced, or that no longer serves a published
     name and version, makes those calls fail (`DocInvalid`): document
     changes and recoveries that name a verifier stop until it is fixed.
     Applied rules keep authorizing, since they hold the address.
   - **Empty addresses.** "The account trusts whoever creates the chain on a
     network: until `perch/constructorless` exists there, the first creator
     of each link controls the infra it derives"
     ([wasm README](../crates/perch-smart-account/wasm/README.md)). The
     account checks a verifier's code against its address; it does not check
     the code at its pinned compiler, interpreter, or spending-limit address.
     So on a network where a pinned address is still empty, a registry whose
     code the key has replaced could place other bytes there.
     `perch/verifiers` is not deployed on testnet or mainnet yet.
     `verify-deployment.sh` must pass before a deployment is used (audit
     scope, "Outside the review units").
7. **Supply-chain attacker or wrong artifacts.** Swaps a dependency, a pin,
   a published wasm, or an npm package.
   - **Pins.** `fetch-infra-wasm.sh` refuses fetched wasm unless its
     SHA-256, and for a deployed contract its content address, match the
     manifest; `check-pins.sh` and `testnet_pins` check the committed and
     compiled pins; `verify-deployment.sh` checks the manifest against the
     chain.
   - **Builds.** `rust-toolchain.toml` pins rustc 1.99.1, the version the
     current testnet and mainnet deployments were built with (build commit
     `c135aca`, a clean tree). No reproduction of their hashes is recorded
     (audit scope, "Deployment provenance").
   - **Dependencies.** rule-core is a git dependency at a fixed rev; the
     OZ fork is a fork of a fork (bitswell-hq/theahaco__stellar-contracts-OZ
     `42089fc`), now linked only by the verifiers, interpreter, spending
     limit, and off-chain tools. This stack vendors and ports five crates to
     soroban-sdk 29 (`soroban-sdk-tools`, `soroban-poseidon`, `soroban-flux`,
     `registry-traits`, `admin-sep`); each port is Perch's change to
     third-party code, recorded in its NOTICE.
   - **npm.** Packages publish with `--provenance`; this repository records
     no integrity hashes. A consumer resolving a published version must show
     it equal to the reviewed source
     ([DEFERRED](./DEFERRED.md), "Packaging rule"). `perch-js` computes the
     digests wallets sign and the warnings they show, and
     `perch-review-core`'s npm wrapper computes the sign dialog's verdict, so
     a swapped package is a swapped signing screen.
8. **The evaluator.** Every authorization but a recovery completion is
   decided by `rule_eval::check_auth` from rule-core, after the account's
   own reserved-name, freeze, and grant-escalation checks. rule-core's
   evaluator is proven against its Lean model, but nothing checks that the
   compiled wasm matches the Lean translation (perch-review-core README,
   "Out of scope"). A recovery completion is checked by the account's
   record of the recovery rule and decided by the controller's
   `rcv_complete`, so recovery never depends on the evaluator.
9. **Malicious dApp or signing request.** Asks a wallet to sign an
   authorization entry, or to apply a grant.
   - **Cross-account replay.** An `External` signer signs
     `sha256(sha256(AUTH_ADDR_DOMAIN || account_id || signature_payload) ||
     xdr(rule_ids))` (`addr_oz_v1`), so a signature collected for one account
     does not authorize another that shares the key (§15).
   - **Exact roots.** An `auth-root` condition requires the account's
     current authorization entry to start at one exact contract and
     function. It checks neither the root's arguments nor ancestors, and
     does not prove that every context in a signed tree executed
     ([auth-root.md](./auth-root.md)). It trusts the root contract: any
     code at that contract, including after the contract's own upgrade,
     that makes the guarded call under that function satisfies the
     condition, within the guarded rule's other conditions and cap.
     Evidence: rule-core's `authorize.exact-root` (proven in its Lean
     model; `rust.exact-root` tested) and `auth_root.rs` (enforcing host
     auth: direct, wrong, fabricated, reordered, and cross-entry roots
     refused). `selectRules` screens roots from the
     contexts the caller passes; the wallet must derive them from the actual
     authorization XDR. An old low-level client skips the screening; the
     account still enforces the root.
   - **Off-chain verdicts.** `perch-review-core`'s verdict equals the
     account's `__check_auth` only for the ledger entries and ledger sequence
     given, assuming every signer not marked unverified authenticates. It
     does not compose two entries of one account that charge one cap, does
     not model network limits, and answers `controller` for a completion.
     Storage can change between review and inclusion.
   - **Hidden grants.** `configuration` and `installed_rules` cover the
     account document only; grant rules are listed by `grants` and `grant`.
     A wallet that reviews an account by `configuration` alone shows the
     owner none of the grants (L7).
   - **Bindings.** Generated clients decode structs by position. A client
     that decodes a snapshot-1 account with snapshot-3 bindings misreads
     its rules; read `capabilities` first ([AGENTS.md](../AGENTS.md),
     "Generated TypeScript bindings").
10. **Compromised indexer, relay, or RPC.** Availability only for
    recovery: a wrong pool witness makes a proof the pool refuses, and a
    relay can delay or drop approvals but never make the controller accept
    one (§2). Off-chain review is different: `perch-review-core` trusts the
    snapshot it is given, so an RPC that serves stale or chosen ledger
    entries can make the sign dialog's verdict and remaining budgets wrong.
    The chain still decides.
11. **Storage expiry and size.** The account's rule records, grant records,
    and spending records live in persistent storage: an archived entry is
    restored, never silently reset (§3.6). The account's `renew` does not
    extend its rule records, so an idle account may need a restore before
    its next transaction, which is the submitting client's job. A capped
    rule's spending record holds up to 1,000 spends per window in rule-eval,
    but the network's 64 KiB entry limit is reached at about 900; past that
    every charge fails until spends leave the window, so a grantee with many
    small transfers can exhaust its own rule (L6).
12. **The ZK verifier.** Proofs are Barretenberg's zero-knowledge flavor
    (`UltraKeccakZKFlavor`). The verifier is NethermindEth's audited
    UltraHonk verifier plus Perch's delta for that flavor. **No audit
    covered the delta before the one audit-scope.md prepares**, and the
    adapter still exports a raw `verify_proof` nothing in Perch calls.
    Until the delta is audited, recovery's ZK factor rests on unaudited
    code.

## Several account builds

Infra is resolved from build-time-pinned wasm hashes, never a runtime
address (§16; [AGENTS.md](../AGENTS.md), "Infra contracts are resolved from
a build-time-pinned wasm hash"). So:

- **This source reaches no deployed account by publication.** The deployed
  testnet and mainnet accounts decide with OZ's code and keep their pinned
  compiler, interpreter, and spending limit. They reach this behaviour only
  through their own delayed upgrade (§12) or by moving to a new account.
- **In-place upgrade from a deployed build is not a supported path.** This
  account reads only the snapshot-3 stored-rule layout and refuses the maps
  earlier builds stored; per `check_auth`'s documentation, an account with
  no stored rule set authorizes nothing but a recovery completion. An
  account whose storage an OZ-era build wrote has no such rule set. No test
  upgrades a deployed account to this build, and
  [account-interface.md](./account-interface.md#types) says testnet preview
  accounts are recreated, not migrated. Until a migration exists and is
  tested, a wallet must not offer this upgrade to an existing account; its
  users create a new account instead, funded with 5 XLM as before (L9).
- **Every document-schema change is a new compiler at a new address.**
  `auth-root`, grants, and named verifiers are options only accounts built
  from this source have. Generated clients for the new interface are marked
  undeployed; `legacyAccount` and `legacyDocCompiler` keep the deployed ABI.
- **Recovery generations are as before.** Each Perch redeploy puts the
  controller, pool, and adapter at new addresses; an account calls the
  controller its own document names and moves only by applying a document
  that names another, gated as a reconfiguration (§10, §16).

## Limits within the audited behaviour

These hold at this revision. Each names the adversary it widens, the spec
requirements that bound it, and, where the change is post-audit work, its
entry in [DEFERRED.md](./DEFERRED.md).

- **L1. `Protected` without a baseline does not protect against an admin-key
  thief.** Any account-document change invalidates a collecting lost-key
  attempt (T4); only compromise recovery from an enrolled baseline is immune
  (§2, §3.5). The protocol keeps `baseline` optional; wallets should require
  one. Adversary 1. Requirements: D4, D6.
- **L2. The freeze and grant wipes stop new authorizations, not permissions
  already given.** A token allowance, or an approval another contract
  stored, stays usable by its holder through an authorized window and after
  a completion wipes the grant that made it (§9, "What the freeze cannot
  reach"). Grant rules may call `approve` with any spender their predicates
  allow. Adversaries 1 and 2. Requirement: D1 (new authorizations only).
- **L3. Replacing a capped rule, or changing its cap, starts an empty
  spending record.** A cap is a per-window limit on the rule as installed,
  not a budget that persists across document changes. This holds for grant
  rules (a re-applied grant whose capped rule changes) and for compromise
  recovery restoring a baseline. Adversaries 1 and 2.
  Deferred: [persistent spending budgets](./DEFERRED.md#persistent-spending-budgets-across-replacements).
- **L4. Only `apply_doc` is bound to a revision.** An ordinary signature
  binds the invocation and the selected rule ids. A transaction signed
  before its rule was removed or replaced fails closed
  (`ContextRuleNotFound`); one whose rule was edited in place keeps the id
  and executes under the rule as it is at inclusion. `apply_grant` advances
  no revision at all, and a re-applied grant is reconciled against its own
  records, so a rule it edits in place keeps its id under every signature
  already collected for it. Whoever holds a signed,
  unsubmitted transaction can submit it after the owner narrows the rule.
  Adversary 2, 9. Deferred:
  [revision-bound ordinary signatures](./DEFERRED.md#revision-bound-ordinary-signatures).
- **L5. A leftover completion marker can misclassify an ordinary write.**
  Within the same ledger and authorized window, an owner-authorized
  `apply_doc` carrying a differently formatted spelling of the authorized
  canonical target can consume a leftover marker and run the completion's
  revocation, nullifier, and epoch effects. The installed document is still
  the authorized target. Adversary 1. Requirement: D8. Deferred:
  [completion input-byte binding](./DEFERRED.md#completion-input-byte-binding).
- **L6. Capped rules are bounded by entry size before rule-eval's history
  limit.** About 900 spends in a window fill a spending record's 64 KiB
  entry, and further charges fail until spends age out. A grant document's
  record is bounded at 49,152 bytes. Adversaries 2 and 11
  ([perch-review-core README](../crates/perch-review-core/README.md);
  [recovery/budgets.md](./recovery/budgets.md), "The stored bound").
- **L7. Three grant protections are wallet warnings, not contract
  checks.** The contract refuses every grant rule that reaches the
  account's own powers (adversary 2). Beyond that, a grant is as broad as
  its rules say, and three cases rely on the wallet showing the owner what
  they approve. A wallet that skips these asks the owner to approve rules
  whose reach they cannot see. Adversaries 2, 5, 9.
  1. **Rules on functions the account does not pin.** The account requires
     argument 0 to be itself only for `transfer`, `transfer_from`,
     `approve`, `burn`, and `burn_from`, matched by name. Any other
     function matches as the rule's argument predicates say. Example: a
     grant rule for a token's `increase_allowance(owner, spender, amount)`
     with no predicate on `spender` lets the grant's key give any spender
     an allowance over the account's balance, and that allowance survives
     `remove_grant` and a recovery completion (L2). The same holds for a
     non-standard token's own spend function. Guard: perch-js's
     `selfPinWarnings(doc)` lists every rule that pins no argument with
     `is-self`; the wallet shows it before the owner approves.
  2. **Unverified verifiers.** A grant signer may name a verifier by
     contract id alone, one `perch/verifiers` did not deploy. Its `verify`
     decides alone whether that signer signed. One that accepts any
     signature makes the rule usable by anyone, not only the intended key.
     The contract allows at most one signer per unverified verifier in a
     rule, so such a verifier cannot fill a threshold by itself, and
     nothing more. Guard: `CompiledDoc::unverified` and perch-js's
     `unverifiedWarnings`; the wallet warns before the owner approves.
  3. **Grants are not in `configuration`.** `configuration` and
     `installed_rules` cover the account document only. A wallet that
     reviews an account through them shows the owner none of its grants,
     including ones a thief installed (adversary 1). Guard: `grant_count`,
     `grants`, `grant`, and perch-js's `readGrantDoc`, which rebuilds each
     grant document and checks it against its stored `doc_hash`; the
     wallet lists grants beside the account document and offers
     `remove_grant`.
- **L8. Documentation lags the code.** At this revision
  [recovery/spec.md](./recovery/spec.md) §15 and §3.6 still describe OZ's
  `do_check_auth` and OZ storage; and
  [account-interface.md](./account-interface.md) and the account's source
  cite "spec §7.6" for grant documents and wiped credentials, which the
  spec does not contain. Until the spec specifies grants, their only
  normative description is account-interface.md and the code. The spec's
  D3 also reads wider than the code: it refuses "every policy change"
  during an authorized window, but grant changes are not refused (adversary
  1, "Grants are ordinary activity"). Under `Protected` the freeze stops
  them anyway; under `Loss` they succeed. §7.6, when written, should state
  this exemption.
- **L9. No migration from deployed accounts.** See
  [Several account builds](#several-account-builds). The plan for deployed
  accounts is a new account, funded with 5 XLM as at first creation, not an
  in-place upgrade.
- **L10. A credential a grant ever named is barred for good once a
  recovery completes.** The credential index (`grant_credentials`) records
  every credential a grant document names, under the grant generation it
  was named in, and is never cleared. After a completion, `apply_grant`
  and `apply_doc` refuse (`WipedCredential`) any document naming one of
  them; only the completion's own target is exempt, so a credential a
  thief once granted cannot block a later recovery. Two consequences for
  wallets:
  1. **An admin credential that was also in a grant must be rotated.** If
     a key names both an account-document signer and a grant signer (for
     example the owner's passkey reused for an app grant), the completion's
     target may keep it, but every later `apply_doc` that still names it is
     refused. The owner has to drop it from the account document before
     they can change anything else. Wallets should keep admin credentials
     out of grants.
  2. **Removing a grant does not clear its credentials.** `remove_grant`
     leaves the index alone, so a key from a grant the owner revoked
     before the recovery is barred too, as is one a re-applied grant
     stopped naming. Any key that appears in any grant document under a
     generation is single-generation.

  This is deliberate: after a recovery, the account cannot tell an owner's
  old grant key from one a thief installed. Adversaries 1 and 2.
  Requirement: none in the spec yet (L8).

## Trusted

- The Stellar network: consensus, RPC (for recovery reads; off-chain review
  trusts its snapshot, adversary 10), and the host's secp256r1, ed25519,
  SHA-256, BN254, and Poseidon2 functions.
- Soroban 29.0.1's CAP-0071 delegated-auth and invoker-auth behaviour, and
  its preorder of authorization contexts, as pinned by Perch's tests
  ([recovery/cap-0071.md](./recovery/cap-0071.md),
  [auth-root.md](./auth-root.md), `auth_root.rs`). `auth-root` takes the
  root from `contexts[0]` of the account's host-authenticated entry; a host
  that ordered contexts differently would make the condition test the wrong
  call without any error, so a host upgrade must rerun those tests.
- rule-core's `rule_eval` and `soroban-facade` at rev `a3c92ba` behave as
  its Lean model says (adversary 8).
- The OZ fork at `42089fc`, for the code that still links it: the
  verifiers' key handling (`webauthn::verify`), the legacy interpreter and
  spending-limit policies.
- Perch's controller, pool, adapter, doc compiler, verifiers, and factory
  behave as their source says. None has an admin or an upgrade entry point
  (§16; the factory is constructorless and storage-free), so this is trust
  in code at a content-addressed address, not in a party.
- The `perch/constructorless` and `perch/verifiers` registries' admin and
  manager, for what counts as a verified verifier, for empty addresses on a
  new network, and for serving the `verifier-name` lookups every account
  document and recovery target needs (adversary 6).
- Signers' devices keep private keys non-exportable; guardians check out of
  band that the replacement credentials they approve belong to the person
  recovering (§2).

## Out of scope

- Losing both the admin credentials and every recovery factor.
- A thief who holds an admin credential and every factor of the enrolled
  condition.
- Stellar consensus or host-function bugs; browser, OS, or device
  compromise.
- A consumer's wallet, factory, relayer, and hosting (Nido's own threat
  model).
- The deployed OZ-era accounts' behaviour (the audit of the build they run).
- Hiding which accounts use ZK recovery (§1).
