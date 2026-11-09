# The account's contract interface

The deployed account's doc comments are compiled into its wasm's contract
spec, which generated bindings and explorers show, and the account is close
to the network's 131,072-byte contract-size limit. So each entry point, type,
field, error and event carries a one- or two-line doc in the spec, and the
longer notes are here. The source links each section from a `//` comment.
[`recovery/spec.md`](recovery/spec.md) is normative for recovery, scoped
documents and upgrades; where this page and the spec disagree, the spec wins.

## Constructor

`__constructor(admin_signers)` installs rule 0, `admin`: a policy-free rule
scoped to the account itself, for `admin_signers`. A rule scoped to the
account authorizes every entry point that requires the account's own
authorization: `apply_doc`, `execute` (arbitrary calls as the account), the
upgrade entry points, and `cancel_recovery`. It is full owner authority, not
`apply_doc` alone.

The signers get the checks OZ's context-rule registry gave them, with its
error codes: at least one (3004), at most 15 (3010), external keys of at
most 256 bytes (3013), and no two that are one key (3007): two delegated
signers with one address, or external signers their verifier's
`batch_canonicalize_key` maps to the same bytes, each verifier asked once.
A rule a document installs gets the same limits; the compiler has already
refused a non-canonical key and a key declared twice, so applies ask no
verifier. The constructor emits `context_rule_added` for rule 0, as OZ's
registry announces a rule: its id, name, contract, no last ledger, its
signers' positions as their ids, and no policy.

## Applying documents

### `apply_doc`

`apply_doc(doc_json, approval_valid_until, expected_revision)` applies the
admin document: the account's own rules, its recovery member, and everything
a recovery restores. With the scoped-document entry points it is the only way
authorization changes. The doc compiler it calls is derived from build-time
pins (`crates/perch-smart-account/wasm/README.md`), never passed in. It brings
the installed rules to the document in one invocation, changing only the
rules that differ, and returns the canonical `doc_hash`.

- **Authorization.** The owner (any ordinary rule scoped to the account), or,
  for a recovery completion only, the zero-signer recovery rule, whose
  controller checks the exact target.
- **Recovery.** On an account with an adopted controller, the controller's
  `rcv_sync` classifies the call before any rule changes and refuses what the
  profile does not allow (spec §10). `approval_valid_until` is the freshness
  bound a `Protected` reconfiguration's recorded approvals were given for; it
  is ignored otherwise.
- **Wiped credentials.** It refuses (`WipedCredential`) a document naming a
  credential a scoped document named before the last completed recovery,
  except the completion's own target (spec §7.6).
- **Revision.** With `expected_revision`, it refuses with `StaleRevision`
  unless the account is still at that `revision`, so a document prepared
  against one configuration never overwrites a change made since. `None`
  applies over whatever revision is current. Every successful call advances
  the revision by one, a re-apply of the same document included.

### `apply_scope`

`apply_scope(scope, doc_json)` applies a scoped document under `scope`, an id
the owner chooses (one per app grant, say), and returns its `doc_hash`
(spec §7.6). Owner authorization.

- It refuses (`ScopeEscalation`) a `recovery` member, a `self-admin` rule, a
  rule scoped to the account, its recovery controller, or its ZK adapter or
  pool, or a rule whose `functions` names a guardian approval, so no scoped
  document reaches the admin document's rules, recovery, upgrades, or
  guardian approvals.
- It refuses (`NotNormalForm`) a document that is not in normal form. The
  compiler reports what the text shows (`CompiledDoc::normal_form`,
  `perch_ir::normal_form`): keys in lowercase hex, cap limits written as
  plain decimals, no cap token, no `threshold` asking every signer it names
  (write `all`), every capped rule's functions exactly `["transfer"]`, no
  `string-in` value over 256 bytes, and every declared signer named by a
  rule, the signers declared in the order the rules first name them. The
  account adds what only it can see: no `address-eq` naming the account
  (write `is-self`) and no rule whose `not-after-ledger` has already been
  reached, which is refused rather than dropped.
- It refuses (`WipedCredential`) a credential a scoped document named before
  the last completed recovery, and records every credential it names under
  the current scope generation.
- The document is compiled under the same caps as any document and reconciled
  against this scope's records only. Every rule it installs is tagged with
  the scope, and its stored rule carries the current scope generation, so
  applying over a wiped scope revives it with the new rules.
- It keeps the document's signer ids, not its text. Each normal-form
  document is the one document its stored rules lower from, so its records
  and signer ids give the text back ("Views", `scope_signer_ids`).
- It calls no controller, and leaves the applied `doc_hash` and the revision
  alone.

### Removing scopes

`remove_scope(scope)` revokes a grant: it removes the scoped document and
every rule it installed, with owner authorization. `gc_scope(scope)` removes a
scoped document a recovery completion wiped. It is permissionless, because
the wiped rules already authorize nothing, and it refuses a scope of the
current generation (`ScopeLive`).

## Calls as the account

`execute(target, target_fn, target_args)` calls `target_fn` on `target` as
this account: the account becomes the invoker, so `target`'s `require_auth`
of this account passes. It requires the account's authorization of this exact
call. It refuses the invoker-only hook names (`ReservedFunction`); otherwise
whoever can authorize `execute` could reach a controller, policy, or pool hook
as the account (spec §15).

## Views

- **`applied_doc`, `applied_doc_hash`, `document`.** The applied admin
  document's canonical bytes and `doc_hash`, `None` before the first
  `apply_doc`, when only the constructor's admin rule exists. Under CANON v1
  the hash is `sha256` of the bytes, so anyone can check installed ==
  reviewed. `document` returns the bytes with the revision they belong to.
- **`revision`.** 0 after the constructor, advanced by one in every successful
  `apply_doc` (whatever it changes, a re-apply of the same document included)
  and every executed upgrade. Freeze changes, recovery attempts, evidence, and
  cancellations do not advance it, and neither do scoped documents: a grant
  changing never makes an admin document prepared against this revision
  stale. It never decreases and never repeats, so unlike `doc_hash` it tells
  A → B → A apart.
- **`configuration`.** Everything rule selection and signing need for the
  admin document, read at one ledger, with the revision it belongs to.
  Scoped documents' rules are not in it; `scopes` and `scope` list them.
- **`capabilities`.** See `AccountCapabilities` below.
- **`installed_rules`, `rule_set`.** `installed_rules` is every context rule
  the admin document installed, with its id; `apply_doc` matches the
  document's rules against these. `rule_set` is aligned with it: entry `i` is
  the rule-eval rule installed rule `i` enforces, and what `__check_auth`
  evaluates. The account stores each rule once, as one record holding its
  id, name and policies and its rule-eval rule; a rule's scope, signers and
  last ledger in `installed_rules` are its rule-eval rule's.
- **`get_context_rules_count`, `get_context_rule`.** The account's rules in
  OZ's `ContextRule` shape, read from its records (the admin document's and
  every scope's). A rule keeps its id while it is edited in place and gets a
  new one when it is added or installed again; no id is given twice. A
  rule's `signer_ids` and `policy_ids` are its signers' and policies'
  positions in it. The count includes scoped documents' and expired
  rules.
- **`scope_generation`.** 0 until the first completed recovery, then advanced
  by one by each completed recovery and by nothing else: not by enrollment,
  reconfiguration, removal, a controller switch, or an executed upgrade, all
  of which advance `recovery_generation`. A scope whose record has another
  generation is wiped.
- **`credential_generation`.** The last scope generation a scoped document
  named this credential fingerprint under. Once `scope_generation` is past
  it, no document may name the credential (spec §7.6).
- **`scope`, `scope_rule_set`, `scope_signer_ids`.** A scoped document's
  record, its rule-eval rules (aligned with the record's rules, each
  carrying the scope generation it was applied under; empty for an unknown
  id), and its signer ids in declaration order. The account does not store
  the document's text: the three give it back, since the account applies a
  scoped document only in normal form. perch-js's `rebuildScopeDoc` (and
  `readScopeDoc`, which reads the three) rebuilds it and trusts it only once
  its `sha256` is the record's `doc_hash`. Rule names repeat across scopes,
  so a wallet selects a scoped rule by `(scope, name)`.
- **`scopes(start, count)`.** The scope ids at positions
  `start..start + count` of the index (fewer at its end), wiped ones
  included. Removing a scope moves the last id into its position, so a
  listing read across several calls can miss an id that moved in between;
  read `scope_count` again to tell.
- **`renew`.** Extends the account's instance, the applied document and its
  credential fingerprints, and the named revoked-set and enrolled-id entries
  to the network maximum. Permissionless; it changes no meaning.

## Recovery hooks

`rcv_gate(attempt_id, frozen_until)` is invoker-only: the adopted controller
sets (`frozen_until > 0`) or clears (`0`) the `Protected` freeze for
`attempt_id`. The account mirrors the freeze rather than asking the
controller from `__check_auth`, because an account approving as a guardian
through the same controller instance runs `__check_auth` while that
controller is on the call stack, and the host refuses re-entry.

`cancel_recovery(attempt_id)` is a `Loss` owner's cancellation of a recovery
attempt (spec T7). The controller refuses it under `Protected`.

## Upgrades

`schedule_upgrade(wasm_hash, approval_valid_until)` schedules an upgrade,
executable after `ACCOUNT_UPGRADE_DELAY_LEDGERS` (spec §12), and returns the
request id. Owner authorization; under `Protected` also the condition's
recorded approval of `Upgrade { request_id, wasm_hash }` fresh until
`approval_valid_until` (`next_upgrade_request_id` names the id to approve).
It is refused while a recovery attempt is authorized, and replaces any
earlier request.

`execute_upgrade(request_id)` executes the pending upgrade once its delay has
elapsed, with owner authorization.

- If the recovery generation moved since scheduling (any enrollment,
  reconfiguration, removal, controller switch, completed recovery, or
  executed upgrade), the request is stale and the call refuses with
  `StaleUpgrade`.
- The refusal leaves the request in place, since a failed invocation keeps
  none of its writes. It can never execute, because the generation never
  decreases, and it stays until `schedule_upgrade` replaces it,
  `cancel_upgrade` removes it, or a completion clears it.
- Otherwise the controller, if one is adopted, checks its epoch and bumps it
  (refusing during an authorized attempt), the generation advances, and the
  Wasm is replaced after this invocation.

### `UpgradeRequest` and the recovery generation

Staleness is judged against the account's own recovery generation, a `u64`
the account keeps in its own storage. It starts at 0 and is never reset. It
advances on every `rcv_sync` outcome other than `Unchanged`
(`controller::SyncOutcome::bumps_generation`) and on every executed upgrade.

The controller's epoch cannot play this role. It belongs to one controller
and does not exist while the account is unenrolled, so a request scheduled
unenrolled would survive enrolling recovery and removing it again: the final
state has no controller, just as at scheduling. `controller_epoch` is still
recorded when a controller is adopted, and passed back as
`UpgradeStep::Execute` so the controller can check it too.

## Types

- **`AccountConfiguration.gate`** is a `Vec` of zero or one `FreezeGate`
  because `#[contracttype]` has no conversion for `Option` of a custom
  struct. The freeze is in force while the ledger is below its `until`.
- **`AccountCapabilities`** holds the constants of the deployed wasm a wallet
  checks before it builds anything for the account.
  - `interface_version` is `INTERFACE_VERSION`. Version 2 adds scoped
    documents; since then `configuration` and `installed_rules` cover the
    admin document only.
  - `doc_identity` is `canon_v1`: the applied `doc_hash` is `sha256` of the
    CANON v1 canonical bytes.
  - `auth_digest` is `addr_oz_v1`: a signer signs OZ's
    `sha256(bound_payload || context_rule_ids.to_xdr())`, where
    `bound_payload = sha256(AUTH_ADDR_DOMAIN || account_id ||
    signature_payload)` binds the account's own address, so a signature
    cannot be replayed on another account. The earlier `oz_rule_ids` scheme
    omitted the account address; a client reads this symbol to tell which
    digest an account expects.
  - `apply_modes` lists `one_tx` (the admin document in one `apply_doc`
    transaction) and `scoped_v1` (scoped documents through `apply_scope`,
    `remove_scope`, and `gc_scope`, spec §7.6).
  - `snapshot_version` is `SNAPSHOT_VERSION`, the layout of
    `AccountConfiguration`.
- **`InstalledRule.recovery`** marks the zero-signer recovery rule. Document
  rules are matched by name and the recovery rule by this flag, so a document
  rule that happens to be named `recovery` is never confused with it.
- **`InstalledPolicy.params`** is `sha256` of the install parameters' XDR. A
  policy whose parameters change is uninstalled and installed again; one whose
  parameters are unchanged is left alone.
- **`ScopeRecord.gen`** is the scope generation the scoped document was
  applied under. Once `scope_generation` has moved past it, a recovery
  completion has wiped the scope: its rules authorize nothing
  (`StaleScope`, from rule-eval's generation check on their stored rules),
  and anyone may remove them with `gc_scope`.

## Events

Rule changes emit no event of their own, so `DocApplied` and
`ScopeApplied`, with the applied document (`applied_doc` serves the admin
document; a scope's records and signer ids rebuild a scoped one), are the
whole record of a change. The constructor emits
`context_rule_added` for its admin rule (see "Constructor"). `UpgradeDropped` is emitted when a scheduled upgrade is cancelled,
replaced by a newer request, found stale at execution, or cleared by a
recovery.

## Errors

The account's errors flatten the doc compiler's (`Compiler_*`) and the
recovery controller's (`Recovery_*`) in through `#[from_contract_client]`, so
their docs land in the account's spec too.

- **`AdminLockout`.** Applying a document that keeps no constraint-free,
  never-expiring self-admin rule with a signer could lock the admin out, so
  it is refused (anti-brick).
- **`ScopeEscalation`.** `apply_scope` was given a document a scoped document
  may not be: it has a `recovery` member, a `self-admin` rule, a rule scoped
  to the account itself, its recovery controller, or its ZK adapter or pool,
  or a rule whose `functions` names a guardian approval (spec §7.6).
  `__check_auth` also refuses a scoped rule selected for a guardian approval
  on any contract, with `PerchAuthError::ScopeEscalation`.
- **`ModelInvalid`.** The compiled document carries no model, more than one,
  a model soroban-facade cannot read, or one whose rules or recovery do not
  match the compiled rules one for one.
- **`UnguardedRule`.** A rule other than the recovery rule asks for no signer
  (INV-1), so an authorization with no signer at all would satisfy it.
- **`NotNormalForm`.** `apply_scope` was given a document outside normal form
  ("`apply_scope`"). Each refused form either has a normal spelling that
  stores the same rules (lowercase hex, a plain decimal limit, no token,
  `all`, `is-self`, the declarations reordered or the unnamed ones dropped)
  or is a rule that would authorize nothing: a capped rule on functions
  other than `transfer`, a `string-in` value no argument can match, a rule
  already expired.
- **`Compiler_KeyNotCanonicalizable`.** Either the verifier could not
  canonicalize the key at all, or the declared bytes differ from the
  canonical form it returns (for example a WebAuthn key carrying a
  credential-id suffix the verifier drops, or a non-canonical point
  encoding). The compiler refuses rather than canonicalizing silently, so the
  bytes the document hash and a recovery attempt's `replacements_hash` bind
  are exactly the bytes the installed credential uses, and two signers cannot
  hide one physical key under two spellings.
- **`Compiler_ReplacementRefused`.** The replacement set is not canonical, is
  empty for lost-key, names a signer id that is not replaceable or not
  declared in the source, or changes a credential's kind or verifier (spec
  §7.3 rules 1-3); or the action is not a recovery attempt.
- **`Recovery_EnrollmentIdReused`.** The controller checks the account's
  `is_enrolled_id` at T1; the pure `derive_target` cannot see the account's
  history.
