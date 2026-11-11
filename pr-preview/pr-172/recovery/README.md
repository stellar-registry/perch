# Account recovery

Opt-in account recovery for perch smart accounts: restoring access after key
loss, or restoring an approved authorization baseline after suspected admin
compromise, without the account's own admin key. Recovery is guardian-based,
zero-knowledge-proof-based, or both combined, and is configured per account
in the same policy document that declares its signers and rules.

| Document | Contents |
| --- | --- |
| [`spec.md`](spec.md) | The normative specification: states and transitions, authorization per profile and mode, permitted document changes, revocation, nullifiers, account upgrades, the ZK adapter boundary, the membership pool, and storage. Where another document disagrees with it, it wins. |
| [`statement.md`](statement.md) | Byte layouts of the recovery statement, credential fingerprints, replacement sets, and the ZK projection, with cross-implementation vectors in `testdata/recovery/statement-v2.json`. |
| [`cap-0071.md`](cap-0071.md) | The delegated-auth and invoker-auth behaviour of the pinned OpenZeppelin fork and host that the spec relies on, each property pinned by an enforcing-auth test. |
| [`budgets.md`](budgets.md) | Measured resource budgets and the pool-depth rule. |
| [`implementation.md`](implementation.md) | Where each part of the spec is implemented and which tests pin it. |
| [`formal-verification-impact.md`](formal-verification-impact.md) | What the Lean model proves about recovery documents and `config_hash`, and what has no formal model. |

The ZK circuit, pool, and adapter are documented in [`../zk/`](../zk/README.md).
