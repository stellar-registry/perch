# A formal model you can read

Testing tries examples. A proof establishes a statement for every input described by its assumptions. Perch uses both, because each answers a different question.

A **formalization** makes behavior precise enough for a machine to reason about. Perch's Lean 4 model defines inputs, verdicts, operations, evaluation, and lowering as mathematical data and functions. It is executable: the same definitions used in proofs can also evaluate test cases.

Lean is a programming language and proof assistant. Its kernel checks that a proof follows from the definitions and assumptions. You do not have to trust the author's prose as the proof, but you still have to check whether the formal statement captures the behavior you care about.

## Read one theorem

The source in `formal/PerchFormal/Theorems.lean` contains this statement (the proof body is omitted here):

```text
theorem lowering_preserves (r : DocRule) (inp : Inputs)
    (hcap : (leafOps r).length ≤ MAX_STACK_DEPTH) :
    eval (buildProgram r) inp = docSemantics r inp
```

Read it as: take any modeled rule `r` and invocation inputs `inp`. Assume the generated checks fit the stack limit. Evaluating the compiled program gives the same verdict as interpreting the rule directly.

`DocRule` and `Inputs` name data types. `hcap` names an assumption. The colon introduces the proposition being proved. The equality compares two ways of computing a result. The checked proof following `:= by` explains to Lean why that equality holds.

The important separation is that `docSemantics` describes predicates directly, while `buildProgram` produces operations for a stack machine. A bug in the translation cannot simply redefine both sides unnoticed: the proof must connect them.

## Take the statement apart

Open the part you want to understand. The three parts work together: a domain of inputs, a condition, and a conclusion.

<details>
<summary>For which inputs? — r : DocRule and inp : Inputs</summary>

For every rule and invocation represented by these Lean types. The modeled rule is a slice of the full policy, so this is not a statement about arbitrary deployed accounts.

</details>

<details>
<summary>Under what condition? — hcap</summary>

The generated leaves must fit the stack bound. A proof with this assumption does not establish the conclusion for programs that exceed the bound. Rust revalidates generated programs separately.

</details>

<details>
<summary>What follows? — the equality</summary>

Two ways of computing a verdict agree: reading the modeled predicates directly and running the translated program. This rules out a mismatch inside that modeled translation. It does not establish that the policy expresses the author's intended permissions.

</details>

<div class="perch-lab" data-perch-lab="quiz">
<h3>Can you spot the proof boundary?</h3>
<p class="lab-fallback">The theorem establishes agreement within its model and stack bound. It does not prove business intent or cumulative accounting.</p>
<script type="application/json" data-quiz>
{
  "question": "Which claim is supported by lowering_preserves?",
  "answers": [
    {
      "text": "Within the model and stack bound, lowering preserves the rule verdict.",
      "correct": true,
      "feedback": "The equality connects the modeled rule meaning to the modeled generated program under hcap."
    },
    {
      "text": "Every deployed Perch account always enforces the right business policy.",
      "correct": false,
      "feedback": "Intent, deployment, authentication, and the model-to-Rust connection are outside this theorem."
    },
    {
      "text": "Cumulative spending caps can never be exceeded.",
      "correct": false,
      "feedback": "Cumulative accounting belongs to a stateful sibling, outside this stateless lowering statement."
    }
  ]
}
</script>
</div>

## What the statements establish

| Result | Plain-language meaning | Scope to remember |
|---|---|---|
| Verdict laws | AND/OR obey the specified algebra; negating U preserves U | Three-valued verdicts |
| Total evaluation | Evaluation terminates by structural recursion | The Lean function |
| `validate_sound` | Validated programs agree with an evaluation without defensive structural guards | Does not eliminate unknown leaf results |
| `zero_signers_denied` | Lowered modeled rules give F with zero signers | Assumes the checks fit the stack bound |
| `lowering_preserves` | Modeled lowering preserves the rule's verdict | The program-producing slice of a rule |
| `emitDoc_injective` | Different modeled documents cannot emit identical canonical representations | The canonical model's document domain |

The model represents already-decoded values with explicit failure cases. It does not execute Soroban's actual value decoder. Signer counts are inputs; the theorem does not prove a signature algorithm or the host's authentication process.

`DocRule` contains a signer count, optional function names, and argument predicates. Scope selection, expiry, cumulative accounting, and account installation are outside this lowering statement. It also does not model threshold signer selection end to end. Passing the right threshold count into a modeled program is not a proof of the Rust compiler's complete threshold path.

## Canonicalization: why an inverse proves uniqueness

Suppose an emitter turns documents into canonical text, and a parser can always recover the original modeled document from that text. Two distinct documents cannot then emit the same text: parsing it would have to recover two different originals. That is the idea behind `pDoc_rt` and `emitDoc_injective`.

This proves uniqueness of the modeled canonical representation, not that SHA-256 can never collide. It also requires attention to the model's domain. The current `CPrincipals` model includes `all` and `selfAuth`, **but not `threshold`**. The canonical model does include cap fields. Do not extend the injectivity theorem to threshold documents without extending the model and proof.

The [next chapter](assurance.md) explains how these mathematical results connect to the shipped implementation.

**Exercise:** Does `lowering_preserves` prove that the release pipeline has the right permissions?

<details>
<summary>Reveal the answer</summary>

No. It proves agreement between two modeled meanings under its assumptions. A faithfully compiled policy can still grant more authority than its author intended.


</details>