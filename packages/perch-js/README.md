# @stellar-registry/perch

TypeScript surface for [perch](https://github.com/stellar-registry/perch) policy
documents and accounts: the fail-closed PolicyDoc schema, canonical JSON +
`doc_hash` (byte-identical to the Rust model, parity-tested against shared
golden fixtures), a fluent builder producing validated documents, and the
consumer interface: revision-consistent account reads, rule selection,
authorization construction, limits, and the apply lifecycle.

Perch is a composable policy layer for Soroban smart accounts built on
OpenZeppelin stellar-accounts: policies are declarative canonical-JSON
documents, compiled onto the account's context rules.

## Install

```sh
npm install @stellar-registry/perch
```

ESM-only. Ships compiled JS + `.d.ts`; regular dependencies are `zod` and
`@noble/hashes`.

## Usage

```ts
import { policy, external, canonicalJson, docHash, ruleHash, configHash } from '@stellar-registry/perch';

const doc = policy()
  .network('Test SDF Network ; September 2015')
  .signer('admin', external(VERIFIER_ADDRESS, ADMIN_PUBKEY_HEX))
  .rule('admin', (r) => r.selfAdmin().signedBy('admin'))
  .build();

canonicalJson(doc); // the canonical wire form (what gets applied on-chain)
docHash(doc);       // sha256 of the canonical form, hex — the document identity
ruleHash(doc.rules[0]); // sha256("perch/rule" || rule bytes): a program's provenance
configHash(docWithRecovery); // sha256("perch/recovery/config" || recovery bytes)
```

`ruleHash` and `configHash` hash one fragment of the canonical form under its
own domain tag (`CANONICAL.md`, "Fragment hashes"), so callers never need to
spell the tags themselves; the tags are exported as `RULE_HASH_DOMAIN` and
`CONFIG_HASH_DOMAIN`.

Parsing/validating an existing document:

```ts
import { parsePolicyDocJson } from '@stellar-registry/perch';

const doc = parsePolicyDocJson(jsonText); // throws on any deviation — fail closed
```

## Guarantees

- `canonicalJson`, `docHash`, `ruleHash`, and `configHash` are byte-identical
  to the Rust implementation; all are pinned against committed golden vectors
  in CI.
- The schema rejects unknown fields, out-of-range values, and non-canonical
  encodings rather than normalizing them.

## Using a Perch account

Everything a wallet needs to read, select, sign for, and change a Perch
account, so it never computes a Perch hash, an authorization digest, or a
rule id itself (#108).

### Reads at one revision

Every account carries a configuration revision: 0 after deployment, one
more after every successful `apply_doc` (a re-apply of the same document
included) and every executed upgrade, and never anything else. Unlike
`doc_hash`, it tells A -> B -> A apart from A.

```ts
import { accountReader, readSnapshot } from '@stellar-registry/perch';
import { account, docCompiler } from '@stellar-registry/perch-contracts';

const reader = accountReader(accountId, new account.Client(opts(accountId)),
  new docCompiler.Client(opts(compilerId)));
const snapshot = await readSnapshot(reader); // configuration, limits, capabilities
snapshot.configuration.revision;             // what every value in it belongs to
```

`readSnapshot` reads `configuration()` (rules with their ids, the applied
`doc_hash`, recovery wiring, the freeze, the pinned infra), the compiler's
limits, the account's capabilities, and optionally `document()`, then the
revision again. `configuration()` and `document()` carry the revision they
belong to; the closing `revision()` read covers the limits and capabilities.
If any of these disagree, or an RPC answers from an older ledger than one
already seen (share a `LedgerClock` per endpoint), everything is read again.
Every answer's ledger counts, including those of an attempt that was thrown
away, so a retry never accepts an older one;
after three tries it throws `InconsistentRead`. The compiler client must be
the account's pinned `infra.docCompiler`, or `readSnapshot` throws
`CompilerMismatch`: the limits checked are then the ones the account's own
compiler enforces.

### Selecting rules by name and scope

```ts
import { selectRules, assertRevision, signingDigest, buildAuthPayload } from '@stellar-registry/perch';

const selection = selectRules(snapshot, { name: 'pay', scope: { type: 'contract', address: token } });
await assertRevision(reader, selection.revision);       // StaleRevision if it moved
const digest = signingDigest(signaturePayload, selection.ruleIds);
const signature = buildAuthPayload(selection, [{ signer, signature: await sign(digest) }]);
```

Rule ids are OZ context-rule ids. They survive an in-place edit and change
when a rule is replaced (a new scope, a rename, a removal and re-addition),
and OZ never reuses one, so select by name and scope at a revision and never
keep ids across revisions. `signingDigest` is what every signer signs: OZ's
`sha256(signature_payload || xdr(rule ids))`, where `signature_payload` is
the account auth entry's Soroban payload. `buildAuthPayload` is the `ScVal`
XDR of OZ's `AuthPayload` for that entry's `signature`.

The pre-sign check guarantees the selection was current when it was signed,
not when it executes. A transaction whose selected rule was removed or
replaced since fails closed on chain: the account's authentication fails
with `ContextRuleNotFound`, which `mapSubmissionError(err, { account, ... })`
turns into `StaleSelection`. One whose rule was edited in place executes
under the edited rule. `mapSubmissionError` reads the host's diagnostic
event log in the error and maps a code only when the account raised it
(its `apply_doc`, or its `__check_auth` through the host's "failed account
authentication" event), since the same number means something else in
another contract.

### Limits and capabilities

`snapshot.limits` holds the caps the account's compiler enforces;
`checkLimits(doc, snapshot.limits)` throws `OverLimits` for a document the
compiler would refuse. `readSnapshot` refuses with `UnsupportedCapability`
an account whose document identity, authorization digest, or snapshot
format this version does not implement, and a limits format it does not
know.

### Applying a document

```ts
import { applyDocument, oneTransactionBackend, StaleRevision } from '@stellar-registry/perch';

const op = applyDocument(doc, oneTransactionBackend(reader, transport), {
  sign: async (request) => [{ signer, signature: await sign(request.digest) }],
  onProgress: (event) => render(event),                     // prepare, authorize, submit, confirm
  onFeeEstimate: (step, fee) => confirmFee(fee),            // false aborts
  onError: (err) => (err instanceof StaleRevision ? 'retry' : 'abort'),
});
const { revision } = await op.result;
```

`applyDocument` reads a snapshot, refuses a frozen account (`AccountFrozen`)
or an over-limit document before anything is signed, selects the `admin`
rule, and runs the backend's steps. Just before each signature is asked
for, one `configuration()` read must show the snapshot's revision and no
freeze (`assertSignable`): a freeze does not move the revision, so the
revision alone would not show one set since the snapshot. The one
transaction `apply_doc` sends names that revision as `expected_revision`,
so it executes only at that revision: if another device's change lands
first, the account refuses it with `StaleRevision` and `onError` decides
whether to start again from a fresh read. Once the last step is
confirmed, the result's `revision` comes from a read at least as recent as
the confirmation ledger (`result.ledger`) and past the revision the apply
started from. A lagging RPC is read again, and one that keeps lagging is
`InconsistentRead`, without starting the apply again.

`transport` builds the transaction with the Stellar SDK. `prepareApplyDoc`
builds `apply_doc(doc_json, approval_valid_until, expected_revision)`, adds
the account's auth entry (address credentials, a fresh nonce, an
expiration), and returns that entry's signature payload with a fee
estimate. Its `submit(authPayload)` puts `authPayload` in the entry's
`signature`, simulates in enforcing mode (recording-mode simulation never
runs the account's `__check_auth`), and sends. The same caller code runs
against a backend that takes several transactions: a step that already
landed is skipped when an operation is retried or started again.

### Errors

| Error | When |
| --- | --- |
| `StaleRevision` | The account moved past the revision a selection or document was prepared at: before signing, or `apply_doc`'s `expected_revision` on chain |
| `StaleSelection` | A submitted transaction selected a rule id that no longer exists |
| `OverLimits` | A document over the compiler's caps |
| `AccountFrozen` | A `Protected` recovery attempt is authorized: before signing (with the attempt and its expiry), or the account refusing a submission |
| `InconsistentRead` | Reads kept disagreeing on the revision, or an RPC went backwards |
| `CompilerMismatch` | The reader's compiler is not the account's pinned one |
| `RuleNotFound`, `UnsupportedCapability`, `Aborted` | As named |

### Hashes and encodings

`docHash`, `ruleHash`, `configHash`, `statementDigest`, `replacementsHash`,
`credentialFingerprint`, `zkStatementFields`, `signingDigest`, and
`buildAuthPayload` are pinned against vectors the Rust suite writes from the
contracts' own code (`testdata/`).

Planned (tracked in the repo): `compile()` parity with the Rust compiler.

## License

Apache-2.0
