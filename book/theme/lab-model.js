/* Educational model for the book's fixed examples, not an authorization SDK.
 * The actual contracts remain authoritative. Keep this subset small and test
 * its leaves against the repository's hand-authored conformance vectors. */
(function (root) {
  'use strict';
  const and = (a, b) => a === 'F' || b === 'F' ? 'F' : a === 'U' || b === 'U' ? 'U' : 'T';
  const or = (a, b) => a === 'T' || b === 'T' ? 'T' : a === 'U' || b === 'U' ? 'U' : 'F';
  const not = a => a === 'U' ? 'U' : a === 'T' ? 'F' : 'T';
  const verdict = value => value ? 'T' : 'F';

  // Same typed invocation vocabulary as testdata/eval/eval-vectors.json.
  function leaf(op, invocation) {
    if (op.op === 'min-signers') return verdict(invocation.signer_count >= op.n);
    if (op.op === 'fn-in') {
      return invocation.context === 'contract' ? verdict(op.fns.includes(invocation.fn)) : 'U';
    }
    if (op.op === 'arg-addr-is-self') {
      if (invocation.context !== 'contract') return 'U';
      const arg = invocation.args[op.i];
      return arg?.type === 'address' ? verdict(arg.value === 'self') : 'U';
    }
    throw new Error(`Unsupported teaching operation: ${op.op}`);
  }

  function release(rule, input) {
    // Fail explicitly if the shared fixture moves beyond the lab's scope.
    if (rule.scope.type !== 'contract' || rule.principals.type !== 'all' ||
        rule.args.length !== 1 || rule.args[0].pred.type !== 'is-self' || rule.cap) {
      throw new Error('The teaching lab needs updating for this fixture.');
    }
    const ledgerText = String(input.ledger);
    if (!/^\d+$/.test(ledgerText) || Number(ledgerText) > 4294967295) {
      return { error: 'Enter a whole ledger sequence from 0 to 4,294,967,295.' };
    }
    const arg = input.argument === 'missing' ? undefined : input.argument === 'wrong-type'
      ? { type: 'string', value: 'self' }
      : { type: 'address', value: input.argument };
    const args = [];
    if (arg) args[rule.args[0].index] = arg;
    const invocation = {
      context: 'contract', fn: input.fn, args,
      signer_count: input.signed ? rule.principals.signers.length : 0,
    };
    const ops = [
      { op: 'min-signers', n: rule.principals.signers.length },
      ...(input.restrictFunctions ? [{ op: 'fn-in', fns: rule.functions }] : []),
      { op: 'arg-addr-is-self', i: rule.args[0].index },
    ];
    const leaves = ops.map(op => leaf(op, invocation));
    const program = leaves.reduce(and, 'T');
    const scope = verdict(input.target === 'registry');
    const expiry = verdict(Number(ledgerText) < rule['not-after-ledger']);
    const combined = and(and(scope, expiry), program);
    const labels = ops.map(op => op.op === 'min-signers' ? `MinSigners(${op.n})`
      : op.op === 'fn-in' ? `FnIn(${op.fns.join(', ')})` : `ArgAddrIsSelf(${op.i})`);
    const trace = [{ op: 'Before execution', stack: [], note: 'The stack starts empty.' }];
    leaves.forEach((v, i) => trace.push({ op: labels[i], stack: leaves.slice(0, i + 1),
      note: `${labels[i]} pushes ${v}. The top of the stack is on the right.` }));
    trace.push({ op: `All(${leaves.length})`, stack: [program],
      note: `Combine ${leaves.length} verdicts with AND. Only T allows at the program root.` });
    return { allowed: combined === 'T', combined, program, scope, expiry, trace,
      checks: [
        { label: 'Account rule: target contract', value: scope,
          reason: scope === 'T' ? 'The target is the registry in this rule.' : 'This rule does not apply to the other contract.' },
        { label: 'Account rule: expiry', value: expiry,
          reason: expiry === 'T' ? `Ledger ${ledgerText} is before ${rule['not-after-ledger']}.`
            : `At or after ledger ${rule['not-after-ledger']}, this rule has expired.` },
        ...ops.map((op, i) => ({ label: `Program: ${labels[i]}`, value: leaves[i],
          reason: op.op === 'min-signers' ? (input.signed ? 'The required CI signer is assumed authenticated.' : 'No CI signer is authenticated.')
            : op.op === 'fn-in' ? (leaves[i] === 'T' ? 'The function is in the allowlist.' : 'The function is outside the allowlist.')
            : leaves[i] === 'T' ? 'The publisher argument is the smart account address.'
            : leaves[i] === 'F' ? 'The publisher is a different address.'
            : 'The publisher argument is missing or has the wrong type; the result is Unknown.' })),
      ],
      rule: { ...rule, ...(input.restrictFunctions ? {} : { functions: undefined }) },
    };
  }
  const api = { and, or, not, leaf, release };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.PerchBookLab = api;
})(globalThis);
