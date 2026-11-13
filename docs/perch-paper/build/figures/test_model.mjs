// node docs/perch-paper/build/figures/test_model.mjs
//
// Checks PerchModel (source/html/figures.js) against what the paper prints and records:
//   1. Figure 3's events (fig-cap-window; facts cap-event-1..5);
//   2. the refusals of the attenuation table (tab-attenuation), and that every allowed step narrows;
//   3. the Perch window column of the recorded run (fig-sim.run.json), at the run's ledgers;
//   4. the verdicts the static explorable figures print (fig-attenuation, fig-auth-path),
//      which build/figures/perchmodel.py computed.
// Exits 1 on any mismatch. Node 18 or later; no dependencies.
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'source');
const ctx = { console };
ctx.globalThis = ctx;
vm.runInNewContext(readFileSync(join(SRC, 'html', 'figures.js'), 'utf8'), ctx);
const M = ctx.PerchModel;
if (!M) { console.error('figures.js did not define PerchModel'); process.exit(1); }

let n = 0;
const fails = [];
const check = (ok, what) => { n++; if (!ok) fails.push(what); };
const facts = {};
for (const f of readdirSync(join(SRC, 'facts')).filter((x) => x.endsWith('.json'))) {
  for (const [k, v] of Object.entries(JSON.parse(readFileSync(join(SRC, 'facts', f), 'utf8')))) facts[k] = typeof v === 'object' ? v.value : v;
}

// 1. Figure 3: ledgers t, t, t + 1, t + 99, t + 100 under the grant's cap.
{
  const limit = Number(facts['grant1-cap-xlm']);
  const period = Number(facts['grant1-period-ledgers']);
  const t = 1000;
  const events = [[t, 6], [t, 5], [t + 1, 4], [t + 99, 1], [t + 100, 5]];
  let rec = M.emptyRecord();
  events.forEach(([L, x], k) => {
    const text = facts[`cap-event-${k + 1}`];
    const c = M.charge(rec, limit, period, L, x);
    const want = /accepted/.test(text);
    check(c.ok === want, `Figure 3 event ${k + 1}: model ${c.ok ? 'accepts' : 'refuses'}, fact says "${text}"`);
    if (!c.ok && c.why === 'limit') check(text.includes(`${c.remaining} + ${x} = ${c.total} > ${limit}`) || text.includes(`holds ${c.remaining}`), `Figure 3 event ${k + 1}: arithmetic ${c.remaining} + ${x} = ${c.total} not in "${text}"`);
    if (c.ok) { rec = c.record; check(text.includes(String(c.total)), `Figure 3 event ${k + 1}: total ${c.total} not in "${text}"`); }
  });
}

// 2. The attenuation table: each refused move, and narrowing for each allowed step.
{
  const tab = JSON.parse(readFileSync(join(SRC, 'tables', 'tab-attenuation.json'), 'utf8'));
  const refusedCells = tab.rows.map((r) => r[2]).join('; ');
  const capped = () => [{ name: 'r', contract: 'XLM', functions: { only: ['transfer'] }, conds: [], signers: ['app', 'helper'], threshold: 1, cap: { limit: 10, period: 100, arg: 2 }, validUntil: 5000, generation: null },
    { name: 'u', contract: 'game', functions: { except: [] }, conds: [], signers: ['app'], threshold: 1, cap: null, validUntil: null, generation: null }];
  const moves = [
    ['raise_threshold', 0, 0, 'ThresholdLowered', 'a lower threshold'],
    ['add_cap', 0, { limit: 5, period: 100, arg: 2 }, 'CapPresent', 'a second cap'],
    ['add_cap', 1, { limit: 0, period: 100, arg: 2 }, 'InvalidCap', 'a non-positive limit'],
    ['add_cap', 1, { limit: 5, period: 0, arg: 2 }, 'InvalidCap', 'a zero period'],
    ['lower_cap_limit', 0, 20, 'LimitRaised', 'a higher limit'],
    ['lengthen_cap_period', 0, 50, 'PeriodShortened', 'a shorter period'],
    ['lower_valid_until', 0, 6000, 'ValidUntilRaised', 'a later expiry'],
  ];
  for (const [step, i, param, err, phrase] of moves) {
    const r = M.attenuate(capped(), step, i, param);
    check(!r.ok && r.error === err, `attenuation ${step}(${JSON.stringify(param)}): want ${err}, got ${r.ok ? 'ok' : r.error}`);
    check(refusedCells.includes(phrase), `tab-attenuation does not list the refusal "${phrase}"`);
  }
  check(!M.attenuate(capped(), 'change_target', 0).ok, 'no step changes a target');
  // Every allowed step from the table: the child accepts no probe the parent refuses.
  const allowed = [['drop_rule', 0], ['remove_functions', 0, ['transfer']], ['restrict_functions', 1, ['guess']],
    ['add_cond', 0, { op: 'eq', i: 1, v: 'shop' }], ['add_cond', 0, { op: 'atmost', i: 2, n: 3 }], ['remove_signers', 0, ['helper']],
    ['raise_threshold', 0, 2], ['add_cap', 1, { limit: 5, period: 100, arg: 2 }], ['lower_cap_limit', 0, 4],
    ['lengthen_cap_period', 0, 200], ['lower_valid_until', 0, 900]];
  check(new Set(allowed.map((a) => a[0])).size === 10 && allowed.every((a) => M.STEPS.includes(a[0])), 'the ten attenuation steps');
  for (const [step, i, param] of allowed) {
    const parent = capped();
    const r = M.attenuate(parent, step, i, param);
    check(r.ok, `attenuation ${step} refused`);
    if (!r.ok) continue;
    for (const [id, , ctx, auth] of M.E1.probes) {
      check(!M.accepts(r.rules, ctx, auth, 1000) || M.accepts(parent, ctx, auth, 1000), `after ${step}, the child accepts probe ${id} that the parent refuses`);
    }
  }
}

// 3. The recorded run: the Perch grant's window, at the run's ledgers.
{
  const run = JSON.parse(readFileSync(join(SRC, 'figures', 'fig-sim.run.json'), 'utf8'));
  const rules = [{ name: 'shop', contract: 'XLM', functions: { only: ['transfer'] }, conds: [{ op: 'eq', i: 1, v: 'shop' }], signers: ['app'], threshold: 1,
    cap: { limit: 10, period: 100, arg: 2 }, validUntil: null, generation: 0 }];
  let rec = M.emptyRecord();
  let ledger = null;
  let compared = 0;
  for (const st of run.steps) {
    const d = st.designs.perch;
    const q = st.request;
    if (q.op === 'pay') {
      const now = ledger;
      const auth = q.signer === 'unlisted' ? ['stranger'] : ['app'];
      const a = M.authorize(rules, [rec], [M.transfer(q.to === 'shop' ? 'shop' : 'mallory', q.amount_xlm)], [0], auth, now, 0);
      // a forged signer passes the decision; the verifier, outside the model, refuses
      const applied = a.ok && q.signer !== 'forged';
      check(applied === (d.status === 'applied'), `run command ${st.command}: model ${applied ? 'applies' : 'refuses'}, recorded ${d.status}`);
      if (q.signer === 'forged') check(a.ok, `run command ${st.command}: the forged signer should pass the decision`);
      if (applied) rec = a.records[0];
      const spends = rec.history.map((e) => ({ xlm: String(e.amount), ledger: e.ledger }));
      check(JSON.stringify(spends) === JSON.stringify(d.window.spends), `run command ${st.command}: model record ${JSON.stringify(spends)}, recorded ${JSON.stringify(d.window.spends)}`);
      check(String(M.windowTotal(rec.history, now, 100)) === d.window.stored_xlm || !applied, `run command ${st.command}: window total`);
      compared++;
    }
    if (d.ledger != null) ledger = d.ledger;
  }
  check(compared >= 10, `the recorded run has ${compared} payments`);
}

// 4. The static figures' verdicts.
const svg = (f) => readFileSync(join(SRC, 'figures', f), 'utf8');
{
  const parent = M.E1.parent();
  let child = parent;
  for (const [step, i, param] of M.E1.steps) child = M.attenuate(child, step, i, param).rules;
  check(!M.attenuate(child, ...M.E1.refused.slice(0, 3)).ok, 'fig-attenuation: the refused move');
  for (const [, id, p, c] of svg('fig-attenuation.svg').matchAll(/data-probe="([^"]+)" data-parent="([^"]+)" data-child="([^"]+)"/g)) {
    const [, , ctx, auth] = M.E1.probes.find((x) => x[0] === id);
    check((M.accepts(parent, ctx, auth, M.E1.ledger) ? 'accepts' : 'refuses') === p, `fig-attenuation probe ${id}: parent`);
    check((M.accepts(child, ctx, auth, M.E1.ledger) ? 'accepts' : 'refuses') === c, `fig-attenuation probe ${id}: child`);
  }
}
{
  const s = svg('fig-auth-path.svg');
  let seen = 0;
  for (const [, stage, body] of s.matchAll(/<g data-exits="([^"]+)">(.*?)<\/g><\/g>(?=<g data-stage|<path|<\/svg>|$)/gs)) {
    for (const [, sid] of body.matchAll(/data-exit="([^"]+)"/g)) {
      const r = M.E3.run(...sid.split(' '));
      check(r.stage === stage, `fig-auth-path ${sid}: model stops at ${r.stage}, figure at ${stage}`);
      seen++;
    }
  }
  check(seen >= 9, `fig-auth-path: ${seen} scenarios read`);
}

if (fails.length) {
  console.error(`model test: ${fails.length} of ${n} checks failed`);
  for (const f of fails) console.error('  ' + f);
  process.exit(1);
}
console.log(`model test: ${n} checks passed`);
