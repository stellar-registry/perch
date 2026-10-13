# The language: who, where, what, and when

A policy document has a collection of signer declarations and a collection of named rules. Signer IDs and rule names must be unique within their respective collections. A rule refers to signers by their local IDs, making it possible to review authority separately from key material.

## Who: signers and principals

Authentication answers “which identities have authorized this call?” Authorization answers “are those identities allowed to make it?” A signer declaration specifies the first part; a rule's `principals` specifies the second.

An **external** signer declares a verifier contract and hex-encoded key material. The verifier interprets the key and checks signatures. Perch does not assume every external key is an ed25519 public key. A **delegated** signer declares an account or contract address; the Soroban host authenticates its delegation for the call tree through CAP-0071.

`all` means every listed signer must authorize. `threshold` means at least `m` of the listed signers must authorize. For example, this principals fragment expresses two of three declared signers:

```json
{"type":"threshold","m":2,"signers":["alice","bob","carol"]}
```

This is a fragment, not a complete policy. The IDs must also be declared. A zero threshold, a threshold greater than the list size, duplicate IDs, and references to undeclared signers are invalid.

There is also a schema form called `self-authenticating`, in which a separate policy takes responsibility for authentication. It requires the explicit acknowledgement `this-policy-authenticates-or-anyone-can-fire-this-rule`. **The current v1 compiler rejects this form as unsupported.** Schema acceptance alone is not evidence that a document can be installed.

## Where: scope

`contract` scopes a rule to a particular contract address. `self-admin` scopes it to administrative operations on the smart account. Allowing an ordinary contract call does not automatically grant account administration.

Rules grant alternatives: another applicable rule can grant authority even if a narrow rule does not. Restrictions attached to one rule do not create a global deny rule. Read the whole document when deciding what a signer can do.

## What: functions and arguments

Within a rule, constraints combine with **and**: the signer requirement and function restriction and each argument restriction must pass. The `functions` list is an allowlist; matching any one listed name satisfies that particular check.

Arguments use zero-based positions. `args` allows one predicate per listed index. The document language supports five predicates:

| Predicate | Question | Expected argument type |
|---|---|---|
| `is-self` | Is this the smart account's address? | Address |
| `address-eq` | Is this the specified address? | Address |
| `string-in` | Is this one of the specified strings? | String |
| `string-prefix` | Does this string begin with the specified prefix? | String |
| `u32-eq` | Is this the specified unsigned 32-bit integer? | U32 |

Types matter. A Soroban symbol is not a string, and the text `"7"` is not the integer `7`. A missing or incorrectly typed argument cannot satisfy a check by accident. The evaluator also bounds string inputs; see [Evaluation](evaluation.md).

The document language does not offer arbitrary expressions, loops, regular expressions, or general numeric inequalities. Some additional operations exist in the lower-level program format, but that does not make them document predicates.

## When: an exclusive ledger cutoff

`not-after-ledger: X` means the rule can authorize only while the current ledger sequence is less than X. A ledger sequence is a block-like counter, **not a Unix timestamp**. X must be nonzero. Omitting the field leaves the rule without this cutoff.

The compiler translates X to the account framework's inclusive `valid_until = X - 1`. This check happens outside the interpreter program, before attached policies run.

## Absence is a choice

Omitting `functions` means any function in scope; omitting `args` means no argument restrictions. Explicit empty lists for these fields are rejected, and JSON `null` is not a substitute for absence. Unknown fields and tags are rejected rather than ignored. These rules make misspelled restrictions visible as errors.

**Exercise:** Does `signedBy("alice", "bob")` mean Alice or Bob?

<details>
<summary>Reveal the answer</summary>

It means both. Use a one-of-two threshold when either signer should suffice.

</details>

<div class="perch-lab" data-perch-lab="quiz">
<h3>Check your understanding</h3>
<p class="lab-fallback">Two authenticated listed signers meet a two-of-three threshold. Meeting the signer requirement does not guarantee the transaction will succeed.</p>
<script type="application/json" data-quiz>
{
  "question": "A rule uses a two-of-three threshold. Alice and Carol authorize; Bob does not. What happens to the signer requirement?",
  "answers": [
    {
      "text": "It passes; two listed signers are authenticated.",
      "correct": true,
      "feedback": "Two is enough for this threshold. The other constraints still need to pass."
    },
    {
      "text": "It fails because Bob did not authorize.",
      "correct": false,
      "feedback": "That would be the all-signers form. A threshold needs only m of the listed signers."
    },
    {
      "text": "The entire transaction is guaranteed to succeed.",
      "correct": false,
      "feedback": "A signer check is only one condition. Other policy checks and the target contract can still reject the call."
    }
  ]
}
</script>
</div>
