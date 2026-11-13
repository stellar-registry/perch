// The five builder scenarios must preserve the rule model's refusals and only
// commit tentative spending after authentication. No DOM dependencies.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const source = new URL('../source/', import.meta.url);
const context = vm.createContext({ console });
for (const file of ['figures.js', 'journey.js']) {
  vm.runInContext(readFileSync(new URL(`html/${file}`, source), 'utf8'), context);
}
const { evaluate } = context.PerchJourney;
const facts = JSON.parse(readFileSync(new URL('facts/example.json', source), 'utf8'));
const limit = Number(facts['shop-cap-xlm'].value);
const period = Number(facts['shop-period-ledgers'].value);
const allowed = evaluate('pay', limit, period);
assert.equal(allowed.ok, true);
assert.equal(allowed.total, 10);
assert.equal(allowed.states.join(','), 'pass,pass,pass,pass,pass');
for (const [name, failed] of [['over', 2], ['recipient', 1], ['signature', 3], ['recovery', 0]]) {
  const result = evaluate(name, limit, period);
  assert.equal(result.ok, false, name);
  assert.equal(result.failed, failed, `${name}: first refusing stage`);
  assert.equal(result.total, 6, `${name}: refused request cannot consume budget`);
  assert.equal(result.states[failed], 'fail');
  assert.ok(result.states.slice(failed + 1).every(s => s === 'unreached'));
}
assert.equal(evaluate('pay', limit, period).total, 10, 'scenarios start from the same saved history');
assert.throws(() => evaluate('unknown'));
console.log('Decision flow: five scenarios, refusal ordering and commit boundary passed.');
