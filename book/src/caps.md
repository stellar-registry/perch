# Per-call rules and cumulative caps

Suppose a signer is allowed to make a transfer of a particular amount. A rule that checks that amount can decide whether **this transfer** is acceptable. It cannot tell whether the signer already made a hundred identical transfers.

The interpreter is stateless: it has no operation that reads or updates a running spending total. Repeating an allowed call is still allowed by the same per-call predicates, subject to changing inputs such as the ledger sequence.

A cumulative cap therefore needs a component that remembers spending. Perch's `cap` field asks the compiler to attach a stateful spending-limit sibling policy to the same account rule. Both the interpreter and the sibling must pass.

## Express a cap

This fragment belongs inside a rule scoped to the token contract:

```json
"cap": {
  "limit": "10000000",
  "period-ledgers": 17280
}
```

The limit is a positive `i128` amount encoded as a decimal **string**, avoiding unsafe JSON numeric precision. Interpret it in the token's base units, not automatically as ten million whole tokens. The period is a nonzero number of ledgers. It is not a wall-clock day.

The token defaults to the rule's scope contract. If explicitly specified, it must equal that contract; caps on `self-admin` are invalid. The sibling meters the scoped token, so naming a different token would be misleading.

The document describes a rolling-window cap, while the exact accounting and reset behavior belongs to the deployed sibling implementation. Review that implementation and its supported token operations when designing a spending policy. The interpreter's stateless proof does not establish accounting correctness.

## Why this boundary exists

Imagine two histories that end with identical invocation inputs: one account has spent nothing, the other has exhausted its allowance. A stateless function sees the same input in both cases and must return the same result. Enforcing a different decision requires additional state.

This is the central intuition behind the repository's [enforceability discussion](https://github.com/stellar-registry/perch/blob/main/docs/verification/THEORY.md). It explains why adding more per-call comparisons would not create a cumulative limit.

**Exercise:** Would limiting the amount in each call enforce “at most 100 in total”?

<details>
<summary>Reveal the answer</summary>

No. Multiple individually permitted calls can exceed the total. Use cumulative accounting, and check every alternative route that could authorize spending.


</details>