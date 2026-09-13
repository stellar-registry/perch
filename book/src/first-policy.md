# Your first policy: a release key

Imagine a maintainer who administers a smart account and a CI job that publishes releases. Giving both the same key would also give CI the maintainer's administrative power. Instead, give them different signers and separate rules.

The repository already contains a complete example. The following is included directly from `testdata/ci-publish-delegated.json`, so the book and fixture stay together. These are fixture identities and a historical ledger cutoff, not credentials or a deployment configuration to reuse.

```json
{{#include ../../testdata/ci-publish-delegated.json}}
```

Read the document from the outside in. `version` selects document format 1. `network` names the test network. `signers` gives local names to authentication methods. `rules` describes the authority granted to those names.

The `admin` rule applies to account administration and requires the `admin` signer. The `ci-publish` rule applies to one registry contract and requires `ci`. Its function allowlist contains `publish` and `publish_hash`. Its argument constraint requires argument **1**, the second argument, to equal the smart account's own address. Finally, it stops authorizing at ledger 55,000,000.

The argument index only makes sense with the target contract's interface. In this example it selects the publisher address. Perch does not infer argument meaning from a function name. If an interface changes, review the index again.

## Try predicting the decision

Assume the correct CI signer is authenticated, the registry is the one in the rule, the ledger is before the cutoff, and all other account requirements are met.

| Proposed call | Does this rule permit it? | Why? |
|---|---|---|
| `publish`, argument 1 is the smart account | Yes | All of this rule's conditions pass |
| `publish_hash`, argument 1 is someone else | No | `is-self` fails |
| `upgrade` on the registry | No | Function is outside the allowlist |
| `publish` with argument 1 missing | No | The argument cannot be checked |
| The valid call at ledger 55,000,000 | No | The cutoff is exclusive |

A passing policy check does not guarantee a successful transaction. The target may reject the call for its own reasons, and the host may enforce other authorization and resource requirements.

## Run a local check

From a repository checkout, install the Rust toolchain selected by `rust-toolchain.toml` using rustup, and install Z3 so `z3` is on your PATH. For example, Homebrew users can run `brew install z3`. No network transaction or private key is needed for this analysis:

```sh
cargo run -q -p perch-analyze -- only-calls \
  testdata/ci-publish-delegated.json \
  CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL \
  publish publish_hash
```

The command should report that only those functions can be authorized on that contract. It asks a question about the document's modeled possibilities; it does not check whether the historical fixture is usable on today's ledger. We will examine the analyzer's scope in [Checking a particular policy](analysis.md).

**Exercise:** Remove `functions` from the CI rule. What changes?

**Answer:** The function restriction disappears. The signer, argument, scope, and expiry checks remain, but any function in that scope satisfying them could qualify. An omitted allowlist does not mean “allow nothing.”
