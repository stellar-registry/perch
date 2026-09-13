# The Perch Book

Perch describes what a smart account may authorize. You write a policy document: who may act, which contracts and functions they may call, and which conditions each call must satisfy. Perch turns that document into rules enforced on Soroban, Stellar's smart-contract platform.

This book is for developers, infrastructure engineers, security reviewers, and other technical readers. You should be comfortable reading configuration files and small code examples. You do **not** need a background in programming languages, theorem proving, Rust, or Lean. We introduce the specialist vocabulary when it becomes useful.

Our running example is a release pipeline. A CI key should publish software on behalf of an account, but should not become an administrator of that account. We will read its policy, follow a call through the evaluator, and then ask what evidence supports the implementation.

## How to read this book

Start with [your first policy](first-policy.md), then follow the language chapters in order. Each chapter adds to the same mental model. The second half explains the formalization: a precise, executable description of behavior and proofs about that description. You can read it without learning to write Lean.

For a review, keep the [language reference](reference.md) and [assurance boundaries](assurance.md) open beside the document. Exercises are short thought experiments with answers, and require no wallet or deployed account.

The book describes the code in this checkout. It is a guide, not a replacement for [CANONICAL.md](https://github.com/stellar-registry/perch/blob/main/CANONICAL.md), the normative canonical-format specification. Features can exist in the document schema before every compiler or proof supports them. We call out those differences explicitly.

## Four pieces of vocabulary

An **account** holds authorization rules. An **invocation** is a call, including its target, function, and arguments. A **signer** supplies evidence of authority. A **predicate** is a question with an answer, such as “is argument 1 the account's own address?”

Perch is a small declarative language. A document describes the calls it permits; it does not give a sequence of instructions for publishing a release. The caller still makes the call, and the target contract still implements the operation.
