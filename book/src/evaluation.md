# How a call is evaluated

The compiler translates a policy into account rules and, when necessary, a small interpreter program. This translation is called **lowering**: representing the same intended checks in a form closer to the execution machinery.

The account framework selects the relevant context and matched signers. Scope and expiry are enforced through account rules. The interpreter checks the program's signer floor, function restrictions, and argument predicates. Stateful caps run in a sibling policy.

## Three answers instead of two

A predicate returns one of three verdicts:

| Verdict | Meaning | Allows at the root? |
|---|---|---|
| True (`T`) | The check succeeded | Yes |
| False (`F`) | The check definitely failed | No |
| Unknown (`U`) | The check could not be evaluated safely | No |

A wrong address gives F. A missing argument or the wrong argument type gives U. This distinction matters when checks are combined, especially with negation.

If a decode failure were treated as false, negating it would produce true. Perch instead defines `Not U = U`. A failure to understand input never becomes permission merely because someone negated a predicate.

<div class="perch-lab" data-perch-lab="logic">
<h3>Explore True, False, and Unknown</h3>
<p>Predict the result, then switch between AND, OR, and NOT. These are program-level combinations; the ordinary document constraints combine with AND.</p>
<p class="lab-fallback">NOT Unknown is Unknown and denies. True OR Unknown is True and allows. True AND Unknown is Unknown and denies. Enable JavaScript for the controls; the explanation and examples below also work without them.</p>
</div>

The complete combination table is small:

| A | B | A AND B | A OR B |
|---|---|---|---|
| T | T | T | T |
| T | U | U | T |
| T | F | F | T |
| U | U | U | U |
| U | F | F | U |
| F | F | F | F |

Swapping A and B gives the same answer. A definite true branch can win an OR even when another branch is unknown. “Fail closed” means only a definite true final verdict authorizes; it does not mean every unknown anywhere forces the whole expression to fail. The document compiler's ordinary constraints combine with AND.

## A tiny stack machine

The program uses reverse Polish notation (RPN): write checks first and a combining operation afterward. The machine keeps intermediate verdicts on a stack, a list where the most recent result is on top.

Here is the CI rule's program in explanatory notation, not its serialized wire encoding:

```text
MinSigners(1)
FnIn(["publish", "publish_hash"])
ArgAddrIsSelf(1)
All(3)
```

For a valid invocation the first three operations push T, T, T; `All(3)` replaces them with T. If the publisher argument is missing, they push T, T, U; the final result is U and authorization is denied. The contract address and ledger cutoff are not missing checks: the enclosing account rule handles them.

The frozen program format also has `Any`, `Not`, and further typed comparisons. Those are lower-level operations, not arbitrary JSON expressions available in `PolicyDoc`.

<div class="perch-lab" data-perch-lab="trace">
<h3>Watch the stack change</h3>
<p>Use Next step to see each check push a verdict, then watch All combine them. Change the input to start a new trace. This is an illustration of the fixed CI program, not the Rust or Lean evaluator.</p>
<p class="lab-fallback">For a missing publisher: MinSigners pushes T, FnIn pushes T, ArgAddrIsSelf pushes U, and All(3) leaves U. The root denies. Enable JavaScript for the controls; the explanation and examples below also work without them.</p>
<script type="application/json" data-policy-fixture>
{{#include ../../testdata/ci-publish-delegated.json}}
</script>
</div>

## Why validation comes first

A malformed program could try to combine three results when only two exist. Validation simulates stack sizes without needing an invocation. It checks version, program length, operator arity, stack bounds, and a single final result. The current limits are 256 operations and stack depth 128. Leaf decoding still has its own checks, including string-length bounds.

A structurally valid program can still return U for a missing or wrongly typed argument. Structural safety does not promise that every input is meaningful or authorized.

## Keeping the signer check

When an OpenZeppelin account rule has attached policies, those policies are responsible for signer sufficiency. The compiler therefore includes `MinSigners` in interpreter programs, including capped rules. For an `all` rule it requires the listed signers; for a threshold rule it requires the threshold over the matched subset.

A constraint-free `all` rule without a cap can remain policy-free and use the account framework's native signer check. This keeps a basic admin path independent of the interpreter. Threshold rules always need the interpreter. This design reduces one failure dependency; it is not a promise that an account can never become inaccessible.
