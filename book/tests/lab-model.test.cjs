const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const model = require('../theme/lab-model.js');
const load = name => JSON.parse(readFileSync(resolve(__dirname, '../../testdata', name), 'utf8'));
const rule = load('ci-publish-delegated.json').rules.find(r => r.name === 'ci-publish');
const baseline = { target: 'registry', fn: 'publish', argument: 'self',
  ledger: String(rule['not-after-ledger'] - 1), signed: true, restrictFunctions: true };
const run = patch => model.release(rule, { ...baseline, ...patch });

test('complete three-valued truth tables, including unknown under negation', () => {
  const v = ['T', 'F', 'U'];
  const expectedAnd = [['T','F','U'], ['F','F','F'], ['U','F','U']];
  const expectedOr = [['T','T','T'], ['T','F','U'], ['T','U','U']];
  v.forEach((a, i) => v.forEach((b, j) => {
    assert.equal(model.and(a, b), expectedAnd[i][j]);
    assert.equal(model.or(a, b), expectedOr[i][j]);
  }));
  assert.deepEqual(v.map(model.not), ['F', 'T', 'U']);
});

test('all single-leaf conformance cases in the supported subset match the frozen expectations', () => {
  const cases = load('eval/eval-vectors.json').cases.filter(c => c.valid && c.program.ops.length === 1 &&
    ['min-signers', 'fn-in', 'arg-addr-is-self'].includes(c.program.ops[0].op));
  assert.ok(cases.length >= 9, 'The frozen supported cases must be present.');
  const names = { true: 'T', false: 'F', unknown: 'U' };
  for (const c of cases) assert.equal(model.leaf(c.program.ops[0], c.invocation), names[c.verdict], c.name);
});

test('the real CI fixture determines function names, argument position, and exclusive expiry', () => {
  for (const fn of rule.functions) assert.equal(run({ fn }).allowed, true);
  assert.equal(run({ ledger: String(rule['not-after-ledger']) }).allowed, false);
  assert.equal(run({ ledger: String(rule['not-after-ledger'] + 1) }).allowed, false);
  for (const patch of [{ target: 'other' }, { signed: false }, { fn: 'upgrade' }, { argument: 'other' }]) {
    assert.equal(run(patch).allowed, false, JSON.stringify(patch));
  }
});

test('missing and wrongly typed arguments remain Unknown through the conjunction', () => {
  for (const argument of ['missing', 'wrong-type']) {
    const result = run({ argument });
    assert.equal(result.program, 'U');
    assert.equal(result.allowed, false);
    assert.deepEqual(result.trace.map(step => step.stack), [[], ['T'], ['T', 'T'], ['T', 'T', 'U'], ['U']]);
  }
});

test('scope and expiry can deny even if the illustrative program trace allows', () => {
  for (const patch of [{ target: 'other' }, { ledger: String(rule['not-after-ledger']) }]) {
    const result = run(patch);
    assert.equal(result.program, 'T');
    assert.equal(result.allowed, false);
  }
});

test('removing the function restriction widens authority but keeps the signer and argument checks', () => {
  const result = run({ fn: 'upgrade', restrictFunctions: false });
  assert.equal(result.allowed, true);
  assert.equal(result.rule.functions, undefined);
  assert.equal(result.trace.at(-1).op, 'All(2)');
  assert.equal(run({ fn: 'upgrade', restrictFunctions: false, signed: false }).allowed, false);
  assert.equal(run({ fn: 'upgrade', restrictFunctions: false, argument: 'missing' }).allowed, false);
  assert.deepEqual(rule.functions, ['publish', 'publish_hash'], 'The source fixture is not mutated.');
});

test('invalid ledger inputs never produce an allowing result', () => {
  for (const ledger of ['', '-1', '0.5', 'Infinity', 'NaN', '1e3', '4294967296']) {
    const result = run({ ledger });
    assert.ok(result.error, ledger); assert.notEqual(result.allowed, true);
  }
  assert.equal(run({ ledger: '0' }).allowed, true);
  assert.equal(run({ ledger: '4294967295' }).allowed, false);
});

test('quizzes have exactly one correct answer and explanatory feedback for every choice', () => {
  const { readdirSync } = require('node:fs');
  const dir = resolve(__dirname, '../src');
  let count = 0;
  for (const name of readdirSync(dir).filter(n => n.endsWith('.md'))) {
    const text = readFileSync(resolve(dir, name), 'utf8');
    for (const match of text.matchAll(/<script type="application\/json" data-quiz>([\s\S]*?)<\/script>/g)) {
      const quiz = JSON.parse(match[1]); count++;
      assert.ok(quiz.question);
      assert.equal(quiz.answers.filter(a => a.correct).length, 1);
      for (const a of quiz.answers) assert.ok(a.text && a.feedback);
    }
  }
  assert.equal(count, 2);
});
