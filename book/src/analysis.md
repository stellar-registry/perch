# Checking a particular policy

A correct evaluator can faithfully enforce a policy that is too permissive. `perch-analyze` helps compare a document with a question about your intent.

It encodes possible invocations as logical constraints and asks Z3, an SMT solver, for an answer. **Satisfiable** means the solver found an assignment meeting those constraints; the assignment can be a **witness**, an example call. **Unsatisfiable** means no assignment exists within the encoding. **Unknown** means the solver did not decide the question.

Whether satisfiable is good or bad depends on the question. A witness is welcome when asking “can this rule ever work?” and unwelcome when asking “can this rule authorize outside my allowlist?”

## Four questions

Run these from the repository root with Z3 on PATH:

```sh
cargo run -q -p perch-analyze -- dead-rules testdata/ci-publish-delegated.json
cargo run -q -p perch-analyze -- can-call testdata/ci-publish-delegated.json publish
cargo run -q -p perch-analyze -- only-calls \
  testdata/ci-publish-delegated.json \
  CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL \
  publish publish_hash
cargo run -q -p perch-analyze -- narrows \
  testdata/ci-publish-delegated.json testdata/ci-publish-delegated.json
```

`dead-rules` seeks an authorizing invocation for each rule. `can-call` seeks one for a named function on contract scopes. `only-calls` seeks a counterexample outside the function list on the **specified contract**; it is not a statement about every other contract or account administration. The last command compares a document with itself as a simple baseline.

For a real change, replace the second path to `narrows` with a proposed child policy. **Narrowing**, also called attenuation, means reducing authority. The implementation matches rule names, compares program semantics, and separately checks scope, expiry, and cap changes. It is a conservative tool with explicit structural conditions, not a complete equivalence checker over every possible rearrangement of a document.

## Interpret results carefully

The CLI uses exit 0 for a successful check, 1 for a failed check or relevant undecided result, and 2 for usage/input errors such as missing Z3. Read warnings and output, not just a “proved” line. Solver unknown is not a proof; for `can-call`, the absence of a reported witness should not be read as a universal impossibility theorem if any underlying result is undecided.

Two concrete assumptions deserve special attention. The encoding treats the smart account's own address as distinct from every literal address in the document. It also counts string characters, while the on-chain evaluator limits string bytes to 256. ASCII agrees across both representations; non-ASCII strings near the bound can diverge. Treat the corresponding warnings and your use of literal self-addresses as reasons to inspect whether a result applies.

The encoding abstracts invocation data and does not simulate live chain state or execute target contracts. Caps need separate structural comparisons; the analyzer does not prove the stateful sibling's accounting. The SMT encoding itself has not been proved sound and complete in Lean. See [its source](https://github.com/stellar-registry/perch/blob/main/crates/perch-analyze/src/lib.rs) for current abstractions and warnings.

**Exercise:** If `only-calls` succeeds for the registry, can the document still allow calls to a token contract?

<details>
<summary>Reveal the answer</summary>

Yes. The query is scoped to the supplied registry address. Review the other scopes or ask additional questions about them.


</details>