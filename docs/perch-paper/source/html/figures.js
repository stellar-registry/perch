// Interactive figures: progressive enhancement over the static SVG that the
// LaTeX edition also draws (build/svg2tikz.py). Without this script every
// step and scenario shows at once, which is the print and no-JavaScript form.
//
// Markup, on <figure data-interactive="stepper">:
//   <g data-step="N">              drawn as past / current / future
//   [data-scenario="a b"]          shown only under the listed scenarios
//   [data-unreached="a b"]         drawn as not reached under the listed scenarios
//   [data-print="no"]              hidden until this script runs; never printed
//   [data-cursor] on a step group  shown only while its step is current
//   [data-detail="text"]           shown below the figure when selected or stepped to
//   data-scenarios="id:Label|…"    on the figure: scenario picker, after "Every scenario"
//   <li data-step="N"> in the figure's text alternative: the step narrative; a nested
//   <li data-step="N" data-scenario="s"> adds the narrative for scenario s, or replaces it
//   with data-mode="replace".
// A figure may instead name a controller registered with PerchFigures.register(name, fn);
// fn(fig, helpers) runs once, after the page has loaded. Any element with
// data-explorable="<controller>" (for example a div around an unnumbered table) gets the
// same controller.
//
// Explorables (E1-E3) and theorem instances compute from PerchModel, a plain transcription
// of rule-core cbabe59 (definitions D2-D6), and say so with a MODEL chip; what comes from a
// recorded run says RECORDED; the embedded simulation says EXECUTED. A model panel never
// prints an account error code or describes OpenZeppelin behaviour. The static figure stays
// the print form. build/figures/test_model.mjs checks PerchModel against the static figures
// and the recorded run.

// ---------------------------------------------------------------- PerchModel
// Values: an address or symbol is a string, an i128 a number. Amounts are whole XLM and
// overflow is not modelled. Same model, in Python, in build/figures/perchmodel.py.
(() => {
  const sat = (a, b) => Math.max(0, a - b); // ledger subtraction stopping at 0 (u32 saturating_sub)
  const MAX_HISTORY = 1000;
  const clone = (x) => JSON.parse(JSON.stringify(x));

  const functionsMatch = (f, fn) => (f.only ? f.only.includes(fn) : !f.except.includes(fn));
  function condHolds(c, args) {
    if (c.i >= args.length) return false;
    const v = args[c.i];
    if (c.op === 'eq') return v === c.v;
    if (c.op === 'atmost') return typeof v === 'number' && v <= c.n;
    if (c.op === 'in') return c.vs.includes(v);
    if (c.op === 'prefix') return typeof v === 'string' && v.startsWith(c.s);
    throw new Error(`unknown condition ${c.op}`);
  }
  // Distinct listed signers that signed (signer.rs signed_count).
  const signedCount = (signers, auth) => [...new Set(signers)].filter((s) => auth.includes(s)).length;
  // rule_allows, check by check, in its order.
  function allowsChecks(r, ctx, auth) {
    if (ctx.create) return [['target', false]];
    return [
      ['target', ctx.contract === r.contract],
      ['function', functionsMatch(r.functions, ctx.fn)],
      ['arguments', r.conds.every((c) => condHolds(c, ctx.args))],
      ['threshold', r.threshold <= signedCount(r.signers, auth)],
    ];
  }
  const allows = (r, ctx, auth) => allowsChecks(r, ctx, auth).every(([, ok]) => ok);
  const emptyRecord = () => ({ history: [], total: 0 });
  const copyRecord = (r) => ({ history: r.history.map((e) => ({ ...e })), total: r.total });

  // cap.rs check_spend: the record after a spend, or why it is refused (D3 iii).
  function charge(rec, limit, period, now, amount) {
    if (typeof amount !== 'number') return { ok: false, why: 'amount' };
    if (amount < 0) return { ok: false, why: 'negative' };
    if (amount === 0) return { ok: true, record: copyRecord(rec), remaining: rec.total, amount, total: rec.total, limit };
    const h = rec.history;
    if (h.length && now < h[h.length - 1].ledger) return { ok: false, why: 'before-newest' };
    const cut = sat(now, period);
    let k = 0;
    let removed = 0;
    while (k < h.length && h[k].ledger <= cut) { removed += h[k].amount; k++; }
    const remaining = rec.total - removed;
    const total = remaining + amount;
    if (total > limit) return { ok: false, why: 'limit', remaining, amount, total, limit };
    if (h.length - k >= MAX_HISTORY) return { ok: false, why: 'full' };
    return { ok: true, record: { history: [...h.slice(k).map((e) => ({ ...e })), { ledger: now, amount }], total }, remaining, amount, total, limit };
  }

  // authorize.rs: three passes (D3). Returns the next records, or the first refusal; `trace`
  // lists every check made, in order.
  function authorize(rules, records, contexts, choices, auth, now, gen) {
    const trace = [];
    const no = (check, i, extra = {}) => ({ ok: false, check, i, trace, ...extra });
    if (choices.length !== contexts.length) return no('choices', null);
    if (records.length !== rules.length) return no('records', null);
    for (let i = 0; i < contexts.length; i++) {
      const r = rules[choices[i]];
      trace.push({ i, check: 'found', ok: !!r });
      if (!r) return no('found', i);
      const expired = r.validUntil != null && r.validUntil < now;
      trace.push({ i, check: 'unexpired', ok: !expired });
      if (expired) return no('unexpired', i);
      const stale = r.generation != null && r.generation !== gen;
      trace.push({ i, check: 'generation', ok: !stale });
      if (stale) return no('generation', i);
      for (const [check, ok] of allowsChecks(r, contexts[i], auth)) {
        trace.push({ i, check, ok });
        if (!ok) return no(check, i);
      }
    }
    const unused = auth.find((s) => !choices.some((j) => rules[j].signers.includes(s)));
    trace.push({ i: null, check: 'signers', ok: unused === undefined });
    if (unused !== undefined) return no('signers', null, { signer: unused });
    const out = records.map(copyRecord);
    const charges = [];
    for (let i = 0; i < contexts.length; i++) {
      const j = choices[i];
      const cap = rules[j].cap;
      if (!cap) continue;
      const amount = contexts[i].args[cap.arg];
      if (typeof amount !== 'number') { trace.push({ i, check: 'charge', ok: false }); return no('amount', i); }
      const c = charge(out[j], cap.limit, cap.period, now, amount);
      trace.push({ i, check: 'charge', ok: c.ok, charge: c });
      if (!c.ok) return no('charge', i, { charge: c });
      out[j] = c.record;
      charges.push({ i, j, charge: c });
    }
    return { ok: true, records: out, charges, trace };
  }
  // Whether some rule, named for the context, accepts it alone from empty records.
  const acceptingRule = (rules, ctx, auth, now, gen = 0) =>
    rules.findIndex((_, j) => authorize(rules, rules.map(emptyRecord), [ctx], [j], auth, now, gen).ok);
  const accepts = (...a) => acceptingRule(...a) >= 0;

  // attenuate.rs: the ten steps; a refusal names the table's reason.
  const REFUSAL = {
    NoSuchRule: 'no such rule', ThresholdLowered: 'a lower threshold', CapPresent: 'a second cap',
    NoCap: 'the rule has no cap', InvalidCap: 'a non-positive limit or a zero period', LimitRaised: 'a higher limit',
    PeriodShortened: 'a shorter period', ValidUntilRaised: 'a later expiry', NoStep: 'no step changes a target',
  };
  const STEPS = ['drop_rule', 'remove_functions', 'restrict_functions', 'add_cond', 'remove_signers', 'raise_threshold',
    'add_cap', 'lower_cap_limit', 'lengthen_cap_period', 'lower_valid_until'];
  function attenuate(rules, step, i, param) {
    if (step === 'change_target') return { ok: false, error: 'NoStep' };
    if (!(i >= 0 && i < rules.length)) return { ok: false, error: 'NoSuchRule' };
    const out = clone(rules);
    const r = out[i];
    const fail = (error) => ({ ok: false, error });
    switch (step) {
      case 'drop_rule': out.splice(i, 1); break;
      case 'add_cond': r.conds.push(clone(param)); break;
      case 'remove_functions':
        r.functions = r.functions.only ? { only: r.functions.only.filter((f) => !param.includes(f)) }
          : { except: [...r.functions.except, ...param.filter((f) => !r.functions.except.includes(f))] };
        break;
      case 'restrict_functions':
        r.functions = r.functions.only ? { only: r.functions.only.filter((f) => param.includes(f)) }
          : { only: param.filter((f) => !r.functions.except.includes(f)) };
        break;
      case 'remove_signers': r.signers = r.signers.filter((s) => !param.includes(s)); break;
      case 'raise_threshold': if (param < r.threshold) return fail('ThresholdLowered'); r.threshold = param; break;
      case 'add_cap':
        if (r.cap) return fail('CapPresent');
        if (!(param.limit > 0 && param.period > 0)) return fail('InvalidCap');
        r.cap = { ...param };
        break;
      case 'lower_cap_limit':
        if (!r.cap) return fail('NoCap');
        if (param > r.cap.limit) return fail('LimitRaised');
        if (param <= 0) return fail('InvalidCap');
        r.cap.limit = param;
        break;
      case 'lengthen_cap_period':
        if (!r.cap) return fail('NoCap');
        if (param < r.cap.period) return fail('PeriodShortened');
        r.cap.period = param;
        break;
      case 'lower_valid_until':
        if (r.validUntil != null && param > r.validUntil) return fail('ValidUntilRaised');
        r.validUntil = param;
        break;
      default: throw new Error(`unknown step ${step}`);
    }
    return { ok: true, rules: out };
  }

  // scoped.rs lower_scoped (D6): refuse a recovery configuration or any rule on the account or
  // the excluded set; otherwise stamp every rule with the generation.
  function lowerScoped(doc, account, excluded, gen) {
    if (doc.recovery) return { ok: false, error: 'RecoveryConfigured' };
    const bad = doc.rules.find((r) => r.self || r.contract === account || excluded.includes(r.contract));
    if (bad) return { ok: false, error: 'ExcludedScope', rule: bad.name };
    return { ok: true, rules: doc.rules.map((r) => ({ ...clone(r), generation: gen })) };
  }

  // D4: the charges at t with L - P < t <= L.
  const inWindow = (t, L, P) => sat(L, P) < t && t <= L;
  const windowTotal = (list, L, P) => list.filter((e) => inWindow(e.ledger, L, P)).reduce((a, e) => a + e.amount, 0);

  // ---- the explorables' scenarios (perchmodel.py has the same)
  const ACCOUNT = 'account', GAME = 'game', XLM = 'XLM', SHOP = 'shop', ELSEWHERE = 'another recipient';
  const rule = (name, contract, functions, { conds = [], signers = ['app'], threshold = 1, cap = null, validUntil = null, generation = null } = {}) =>
    ({ name, contract, functions, conds, signers, threshold, cap, validUntil, generation });
  const transfer = (to, amount) => ({ contract: XLM, fn: 'transfer', args: [ACCOUNT, to, amount] });
  const PIN_SHOP = { op: 'eq', i: 1, v: SHOP };
  const PIN_GAME = { op: 'eq', i: 1, v: GAME };

  // E1: the shop grant's rule plus a game rule; signers app or helper, threshold 1.
  const E1 = {
    ledger: 1000,
    parent: () => [
      rule('play', GAME, { except: [] }, { signers: ['app', 'helper'], validUntil: 5000 }),
      rule('shop', XLM, { only: ['transfer'] }, { conds: [PIN_SHOP], signers: ['app', 'helper'], cap: { limit: 10, period: 100, arg: 2 } }),
    ],
    probes: [
      ['guess', 'the game’s `guess`', { contract: GAME, fn: 'guess', args: [ACCOUNT, 7] }, ['app']],
      ['t1', 'transfer 1 to the shop', transfer(SHOP, 1), ['app']],
      ['t5', 'transfer 5 to the shop', transfer(SHOP, 5), ['app']],
      ['else', 'transfer 1 elsewhere', transfer(ELSEWHERE, 1), ['app']],
      ['approve', '`approve` on XLM', { contract: XLM, fn: 'approve', args: [ACCOUNT, SHOP, 5, 2000] }, ['app']],
      ['account', 'a call to the account', { contract: ACCOUNT, fn: 'apply_scope', args: ['grant'] }, ['app']],
      ['helper', 'a transfer signed by `helper` alone', transfer(SHOP, 1), ['helper']],
    ],
    steps: [['restrict_functions', 0, ['guess'], 'restrict `play` to `guess`'],
      ['lower_cap_limit', 1, 4, 'lower the cap limit to 4'],
      ['remove_signers', 1, ['helper'], 'remove the signer `helper` from `shop`']],
    refused: ['lower_cap_limit', 1, 20, 'raise the cap limit to 20'],
  };
  // T5's replay: a guess then five transfers of 1, one ledger apart, through the child; its
  // accepted requests through the parent from empty records, choices renumbered by `origin`.
  function replay(parent, child, origin) {
    const run = [[E1.probes[0][2], ['app']], ...Array(5).fill([transfer(SHOP, 1), ['app']])];
    let rec = child.map(emptyRecord);
    const childRun = [];
    run.forEach(([ctx, auth], k) => {
      const now = E1.ledger + k;
      let done = null;
      for (let j = 0; j < child.length && !done; j++) {
        const d = authorize(child, rec, [ctx], [j], auth, now, 0);
        if (d.ok) { rec = d.records; done = { ctx, auth, now, j, ok: true }; }
      }
      if (!done) {
        const j = acceptingRule(child, ctx, auth, now);
        const d = authorize(child, rec, [ctx], [j >= 0 ? j : 0], auth, now, 0);
        done = { ctx, auth, now, j, ok: false, d };
      }
      childRun.push(done);
    });
    let prec = parent.map(emptyRecord);
    const parentRun = childRun.filter((x) => x.ok).map((x) => {
      const d = authorize(parent, prec, [x.ctx], [origin[x.j]], x.auth, x.now, 0);
      if (d.ok) prec = d.records;
      return { ...x, pj: origin[x.j], ok: d.ok };
    });
    return { childRun, parentRun };
  }

  // E3: the shop rule and the game grant's two rules, issued at generation 0; the shop rule's
  // record holds 6 from ledger t, and each request comes at ledger t + 1.
  const E3 = {
    t: 1000,
    grant(g) {
      const validUntil = g === 'expired' ? this.t : null;
      const rules = [
        rule('shop', XLM, { only: ['transfer'] }, { conds: [PIN_SHOP], cap: { limit: 10, period: 100, arg: 2 }, validUntil, generation: 0 }),
        rule('guess', GAME, { only: ['guess'] }, { validUntil, generation: 0 }),
        rule('spend', XLM, { only: ['transfer'] }, { cap: { limit: 2, period: 100, arg: 2 }, validUntil, generation: 0 }),
      ];
      return { rules, records: [{ history: [{ ledger: this.t, amount: 6 }], total: 6 }, emptyRecord(), emptyRecord()], gen: g === 'stale' ? 1 : 0 };
    },
    request(req, named) {
      const right = named === 'right';
      if (req === 'guess') return { contexts: [{ contract: GAME, fn: 'guess', args: [ACCOUNT, 7] }, transfer(GAME, 1)], choices: right ? [1, 2] : [0, 2] };
      if (req === 'within' || req === 'over') return { contexts: [transfer(SHOP, req === 'within' ? 4 : 5)], choices: right ? [0] : [2] };
      if (req === 'account') return { contexts: [{ contract: ACCOUNT, fn: 'apply_scope', args: ['grant'] }], choices: right ? [0] : [1] };
      throw new Error(`unknown request ${req}`);
    },
    run(req, signer, grant, named) {
      const { rules, records, gen } = this.grant(grant);
      const { contexts, choices } = this.request(req, named);
      const auth = signer === 'unlisted' ? ['stranger'] : ['app'];
      const d = authorize(rules, records, contexts, choices, auth, this.t + 1, gen);
      const stage = !d.ok ? 'decide' : signer === 'forged' ? 'authenticate' : 'store';
      return { stage, decision: d, verifier: d.ok, rules, contexts, choices, auth, gen };
    },
  };

  globalThis.PerchModel = {
    sat, allows, allowsChecks, charge, authorize, accepts, acceptingRule, attenuate, lowerScoped, inWindow, windowTotal,
    emptyRecord, REFUSAL, STEPS, E1, E3, replay, transfer, consts: { ACCOUNT, GAME, XLM, SHOP, ELSEWHERE, PIN_SHOP, PIN_GAME },
  };
})();

// ---------------------------------------------------------------- the page
(() => {
  if (typeof document === 'undefined') return;
  const M = globalThis.PerchModel;
  const CONTROLLERS = {};
  const el = (tag, attrs = {}, text) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) if (v != null && v !== false) e.setAttribute(k, v === true ? '' : v);
    if (text != null) e.textContent = text;
    return e;
  };
  // An element with children: strings (with `code` spans), nodes, or arrays of them.
  const h = (tag, attrs, ...kids) => {
    const e = el(tag, attrs || {});
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false) continue;
      e.append(k instanceof Node ? k : md(String(k)));
    }
    return e;
  };
  const md = (s) => {
    const f = document.createDocumentFragment();
    s.split('`').forEach((part, i) => { if (part) f.append(i % 2 ? el('code', {}, part) : document.createTextNode(part)); });
    return f;
  };
  const plain = (s) => s.replace(/`/g, '');
  let uidN = 0;
  const uid = (p) => `${p}-${++uidN}`;
  const squash = (s) => s.replace(/\s+/g, ' ').trim();
  // An item's own text, without the nested scenario items.
  const ownText = (li) => {
    const c = li.cloneNode(true);
    for (const n of c.querySelectorAll('ul, ol')) n.remove();
    return squash(c.textContent);
  };
  // The sticky head: the controls, then the narration, so both stay in view while stepping.
  const head = (fig, where) => {
    const hd = el('div', { class: 'fig-head' });
    const bar = el('div', { class: 'fig-bar', role: 'group', 'aria-label': 'Figure controls' });
    const live = el('p', { class: 'fig-live', 'aria-live': 'polite' });
    hd.append(bar, live);
    (where || fig).prepend(hd);
    return { head: hd, bar, live };
  };
  // A button that cannot act is aria-disabled, not disabled, so it keeps keyboard focus.
  const button = (label, attrs = {}) => el('button', { type: 'button', ...attrs }, label);
  const setOff = (btn, off) => btn.setAttribute('aria-disabled', String(off));
  const isOff = (btn) => btn.getAttribute('aria-disabled') === 'true';
  const reduced = () => window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const chip = (kind) => el('span', { class: 'xp-chip', 'data-kind': kind.toLowerCase() }, kind);
  const banner = (kind, text) => h('p', { class: 'xp-banner' }, chip(kind), ' ', text);
  const yes = (text = 'allows') => h('span', { class: 'xp-yes' }, el('span', { class: 'xp-mark', 'aria-hidden': 'true' }, '✓'), ` ${text}`);
  const no = (text = 'refuses') => h('span', { class: 'xp-no' }, el('span', { class: 'xp-mark', 'aria-hidden': 'true' }, '✕'), ` ${text}`);
  const labelled = (text, control) => h('label', { class: 'xp-field' }, h('span', {}, text), control);
  const select = (name, options, value) => {
    const s = el('select', { name });
    for (const [v, label] of options) s.append(el('option', { value: v }, label));
    if (value != null) s.value = value;
    return s;
  };
  const number = (name, value, min, max) => el('input', { type: 'number', name, value, min, max, step: 1, inputmode: 'numeric' });
  // Where an explorable mounts: a panel before the figure's caption (or at the end of a
  // container); the static form stays the print form and is hidden on screen.
  function mount(host, cls) {
    const panel = el('div', { class: `xp ${cls}` });
    const cap = host.querySelector(':scope > figcaption');
    if (cap) cap.before(panel); else host.append(panel);
    host.classList.add('xp-on');
    for (const n of host.querySelectorAll(':scope > svg, :scope > .table-wrap, :scope > table')) n.classList.add('xp-static');
    return panel;
  }
  const xOfLedger = (base) => (v) => (base === 0 ? String(v) : v === base ? 't' : v > base ? `t + ${v - base}` : `t − ${base - v}`);

  // Scroll the drawn nodes into view below the sticky head.
  function follow(hd, nodes) {
    const rects = nodes.map((n) => n.getBoundingClientRect()).filter((r) => r.width || r.height);
    if (!rects.length) return;
    const top = Math.min(...rects.map((r) => r.top));
    const bottom = Math.max(...rects.map((r) => r.bottom));
    const minTop = hd.offsetHeight + 8;
    let dy = 0;
    if (top < minTop) dy = top - minTop;
    else if (bottom > window.innerHeight - 8) dy = Math.min(bottom - window.innerHeight + 8, top - minTop);
    if (dy) window.scrollBy({ top: dy, behavior: reduced() ? 'auto' : 'smooth' });
  }

  // [data-detail] nodes: the text shows below the figure when a node is selected.
  function details(fig) {
    const nodes = [...fig.querySelectorAll('[data-detail]')];
    if (!nodes.length) return null;
    const out = el('p', { class: 'fig-detail', 'aria-live': 'polite' });
    fig.querySelector('figcaption').before(out);
    out.textContent = fig.dataset.detailHint || 'Source lines for a box appear here when you select it or step to it.';
    const show = (list, mark = true) => {
      out.textContent = list.map((n) => n.dataset.detail).join(' | ');
      for (const m of nodes) m.classList.toggle('hot', mark && list.includes(m));
    };
    for (const n of nodes) {
      n.addEventListener('mouseenter', () => show([n]));
      n.addEventListener('click', () => show([n]));
    }
    return { nodes, show };
  }

  function stepper(fig, { detail } = {}) {
    const groups = [...fig.querySelectorAll('svg [data-step]')];
    const steps = [...new Set(groups.map((g) => Number(g.dataset.step)))].sort((a, b) => a - b);
    const items = [...fig.querySelectorAll('.fig-text li[data-step]')];
    const general = new Map(items.filter((li) => !li.dataset.scenario).map((li) => [Number(li.dataset.step), ownText(li)]));
    const scenarios = (fig.dataset.scenarios || '').split('|').filter(Boolean).map((s) => s.split(':'));
    const { head: hd, bar, live } = head(fig);
    let pick = null;
    if (scenarios.length) {
      pick = el('select', { 'aria-label': 'Scenario', name: `${fig.id}-scenario` });
      pick.append(el('option', { value: '' }, 'Every scenario (as printed)'));
      for (const [id, label] of scenarios) pick.append(el('option', { value: id }, label));
      bar.append(pick);
    }
    const prev = button('Previous');
    const next = button('Next');
    const all = button('Show all');
    const count = el('span', { class: 'fig-count' });
    bar.append(prev, next, all, count);
    let i = -1;
    function draw(move) {
      const s = pick && pick.value ? pick.value : null;
      for (const n of fig.querySelectorAll('svg [data-scenario]')) {
        n.classList.toggle('off', s != null && !n.dataset.scenario.split(' ').includes(s));
      }
      for (const n of fig.querySelectorAll('[data-unreached]')) {
        n.classList.toggle('unreached', s != null && n.dataset.unreached.split(' ').includes(s));
      }
      const cur = steps[i];
      for (const g of groups) {
        const n = Number(g.dataset.step);
        g.dataset.state = i < 0 ? '' : n < cur ? 'past' : n === cur ? 'current' : 'future';
      }
      setOff(prev, i <= 0);
      setOff(next, i >= steps.length - 1);
      count.textContent = i < 0 ? `${steps.length} steps` : `Step ${i + 1} of ${steps.length}`;
      if (i < 0) {
        live.textContent = '';
      } else {
        const extra = s && items.find((li) => Number(li.dataset.step) === cur && (li.dataset.scenario || '').split(' ').includes(s));
        const parts = extra && extra.dataset.mode === 'replace' ? [] : [general.get(cur) || ''];
        live.textContent = [...parts, extra ? squash(extra.textContent) : ''].filter(Boolean).join(' ');
      }
      if (detail) {
        const here = i < 0 ? [] : detail.nodes.filter((n) => {
          const g = n.closest('[data-step]');
          return g && Number(g.dataset.step) === cur && !n.closest('.off') && n.getBoundingClientRect().width > 0;
        });
        if (here.length) detail.show(here, false);
      }
      if (move && i >= 0) follow(hd, groups.filter((g) => Number(g.dataset.step) === cur && !g.hasAttribute('data-cursor')));
      fig.dispatchEvent(new CustomEvent('figstep', { detail: { step: cur, scenario: s } }));
    }
    const go = (k) => { i = Math.min(steps.length - 1, Math.max(0, k)); draw(true); };
    prev.onclick = () => { if (!isOff(prev)) go(i - 1); };
    next.onclick = () => { if (!isOff(next)) go(i + 1); };
    all.onclick = () => { i = -1; draw(false); };
    if (pick) pick.onchange = () => draw(false);
    bar.addEventListener('keydown', (e) => {
      if (e.target === pick && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) return;
      if (e.target.tagName === 'INPUT') return;
      const k = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
      if (k) { go(i + k); e.preventDefault(); }
      if (e.key === 'Home') { go(0); e.preventDefault(); }
      if (e.key === 'End') { go(steps.length - 1); e.preventDefault(); }
    });
    draw(false);
    return { head: hd, bar, live };
  }

  // ---------------------------------------------------------------- E2: the cap window
  // fig-cap-window. The model opens on the figure's own events; the reader sends, advances, changes
  // the cap, checks each call alone, starts at ledger 0 or replaces the rule. The plot shows
  // the window total of the transfers that moved; refusals change nothing.
  CONTROLLERS['cap-window'] = (fig) => {
    const BASE = 1000;
    const FIG3 = [['send', 6], ['send', 5], ['advance', 1], ['send', 4], ['advance', 98], ['send', 1], ['advance', 1], ['send', 5]];
    const fig3 = () => FIG3.map(([op, v]) => (op === 'send' ? { op, amount: v } : { op, n: v }));
    const st = { lambda: 10, period: 100, percall: false, zero: false, actions: fig3(), inspect: BASE + 100, touched: false };
    const panel = mount(fig, 'xp-cap');
    const { bar, live } = head(fig, panel);
    const form = el('form', { class: 'xp-inline', 'aria-label': 'Send a transfer' });
    const amount = number(`${fig.id}-amount`, 5, 0, 100);
    amount.setAttribute('aria-label', 'Amount in XLM');
    const send = el('button', { type: 'submit', class: 'primary' }, 'Send');
    form.append(labelled('Amount', amount), send);
    const adv1 = button('+1 ledger');
    const adv10 = button('+10');
    const advP = button('+P');
    const undo = button('Undo');
    bar.append(form, adv1, adv10, advP, undo);
    panel.append(banner('MODEL', 'Computed in the page from the definitions of the charge and the window in What Perch proves: a transfer is charged only if the window total plus its amount stays within the limit, and a refusal changes nothing. Ledgers are illustrative; t is any ledger.'));
    const params = h('details', { class: 'xp-params' }, el('summary'));
    const lam = el('input', { type: 'range', min: 1, max: 20, step: 1, value: 10, name: `${fig.id}-limit` });
    const per = el('input', { type: 'range', min: 10, max: 200, step: 10, value: 100, name: `${fig.id}-period` });
    params.append(h('div', { class: 'xp-row' }, labelled('Limit λ (XLM)', lam), labelled('Period P (ledgers)', per)));
    const percall = el('input', { type: 'checkbox', name: `${fig.id}-percall` });
    const zero = el('input', { type: 'checkbox', name: `${fig.id}-zero` });
    const replace = button('Replace the rule');
    const reset = button('Reset to the figure’s events');
    const clear = button('Clear');
    const toggles = h('div', { class: 'xp-row' },
      h('label', { class: 'xp-check' }, percall, ' Check each call alone'),
      h('label', { class: 'xp-check' }, zero, ' Allow ledger 0 (no Stellar ledger has sequence 0; the theorem\u2019s bound over any P consecutive ledgers assumes ledger 1 or later)'),
      replace, reset, clear);
    const plot = el('div', { class: 'xp-plot-wrap' });
    const inspect = el('input', { type: 'range', step: 1, name: `${fig.id}-inspect` });
    const inspectOut = el('output', { class: 'xp-out' });
    const fullest = el('p', { class: 'xp-result' });
    const history = el('ol', { class: 'xp-log', 'aria-label': 'Transfers, in order' });
    panel.append(params, toggles, plot,
      h('div', { class: 'xp-row' }, h('label', { class: 'xp-field xp-grow' }, h('span', {}, 'Inspect the window at ledger L'), inspect)),
      inspectOut, fullest, h('p', { class: 'xp-sub' }, 'In the plot, as in the figure: a charge inside the inspected window is amber, one outside it is plain; a refused transfer is dashed red with a bar end and changes nothing.'), h('p', { class: 'xp-sub' }, 'Every transfer, in order:'), history);

    function run() {
      const base = st.zero ? 0 : BASE;
      let now = base;
      let rec = M.emptyRecord();
      const attempts = [];
      const moved = [];
      const replaced = [];
      for (const a of st.actions) {
        if (a.op === 'advance') { now += a.n; continue; }
        if (a.op === 'replace') { rec = M.emptyRecord(); replaced.push(now); attempts.push({ replace: true, ledger: now }); continue; }
        const before = M.windowTotal(moved, now, st.period);
        let r;
        if (st.percall) r = { ok: a.amount >= 0 && a.amount <= st.lambda, why: 'percall' };
        else r = M.charge(rec, st.lambda, st.period, now, a.amount);
        if (r.ok && !st.percall) rec = r.record;
        if (r.ok && a.amount > 0) moved.push({ ledger: now, amount: a.amount });
        attempts.push({ ledger: now, amount: a.amount, ok: r.ok, r, before, after: M.windowTotal(moved, now, st.period) });
      }
      return { base, now, rec, attempts, moved, replaced };
    }
    const sentence = (a, lab) => {
      if (a.replace) return `ledger ${lab(a.ledger)}: the rule is replaced; its window starts empty`;
      const at = `ledger ${lab(a.ledger)}: +${a.amount}`;
      if (a.ok && a.amount === 0) return `${at}: nothing to charge; the window holds ${a.after}`;
      if (st.percall) {
        return a.ok ? `${at} accepted (${a.amount} ≤ ${st.lambda} for one call); ${a.after} moved in the window`
          : `${at} refused (${a.amount} > ${st.lambda} for one call); nothing changes`;
      }
      const r = a.r;
      if (a.ok) return `${at} accepted; ${r.remaining} + ${a.amount} = ${r.total} ≤ ${st.lambda}`;
      if (r.why === 'limit') return `${at} refused; ${r.remaining} + ${a.amount} = ${r.total} > ${st.lambda}; record unchanged`;
      if (r.why === 'negative') return `${at} refused: a negative amount; record unchanged`;
      return `${at} refused; record unchanged`;
    };
    // Window totals over the ledgers where they change; the fullest window.
    function totals(moved, lo, hi) {
      const P = st.period;
      const pts = [...new Set([lo, ...moved.flatMap((e) => [e.ledger, e.ledger + P])])].filter((v) => v >= lo && v <= hi).sort((a, b) => a - b);
      const segs = pts.map((p, k) => ({ a: p, b: k + 1 < pts.length ? pts[k + 1] - 1 : hi, w: M.windowTotal(moved, p, P) }));
      const max = Math.max(0, ...segs.map((s) => s.w));
      return { segs, max, at: segs.find((s) => s.w === max) };
    }
    // Any P consecutive ledgers from s: s <= t < s + P (T6's second form).
    const periodMax = (moved) => Math.max(0, ...moved.map((e) => moved.filter((x) => x.ledger >= e.ledger && x.ledger < e.ledger + st.period).reduce((a, x) => a + x.amount, 0)));

    function draw(say) {
      const R = run();
      const lab = xOfLedger(R.base);
      const ledgers = R.attempts.map((a) => a.ledger);
      const lo = Math.max(0, Math.min(R.now, ...ledgers) - 1);
      const hi = Math.max(R.now, ...ledgers, ...R.moved.map((e) => Math.min(e.ledger + st.period, Math.max(R.now, ...ledgers) + st.period))) + 1;
      inspect.min = lo;
      inspect.max = hi;
      if (!st.touched) st.inspect = R.now;
      st.inspect = Math.min(hi, Math.max(lo, st.inspect));
      inspect.value = st.inspect;
      const L = st.inspect;
      const W = M.windowTotal(R.moved, L, st.period);
      const text = `Ledger ${lab(L)}; window (${lab(M.sat(L, st.period))}, ${lab(L)}]; ${W} of ${st.lambda} XLM`;
      inspect.setAttribute('aria-valuetext', text);
      inspectOut.textContent = `${text}.`;
      params.querySelector('summary').textContent = `Cap: ${st.lambda} XLM per ${st.period} ledgers (change)`;
      advP.textContent = `+${st.period}`;
      advP.setAttribute('aria-label', `Advance ${st.period} ledgers`);
      adv10.setAttribute('aria-label', 'Advance 10 ledgers');
      setOff(undo, !st.actions.length);
      const T = totals(R.moved, lo, hi);
      const over = T.max > st.lambda;
      let why = '';
      if (over && st.percall) why = ' Each call was checked alone, so nothing kept a running total.';
      else if (over && R.replaced.length) why = ' Over the limit only because the rule was replaced: each rule’s own record stayed within it.';
      let line = T.at ? `Largest window total: ${T.max} (L = ${lab(T.at.a)}${T.at.b > T.at.a ? ` to ${lab(T.at.b)}` : ''}); limit ${st.lambda}.${why}` : 'No transfer has moved yet.';
      const pm = periodMax(R.moved);
      if (st.zero && pm > st.lambda) {
        line += ` Every window (L − P, L] holds at most ${st.lambda}, but ledgers 0 to ${st.period - 1} hold ${pm}: the bound over any ${st.period} consecutive ledgers needs every transfer at ledger 1 or later.`;
      }
      fullest.textContent = line;
      fullest.classList.toggle('xp-over', over);
      history.replaceChildren(...R.attempts.map((a) => h('li', { class: a.replace ? 'xp-event' : a.ok ? 'xp-ok' : 'xp-refused' },
        a.replace ? null : a.ok ? el('span', { class: 'xp-mark', 'aria-hidden': 'true' }, '✓') : el('span', { class: 'xp-mark', 'aria-hidden': 'true' }, '✕'),
        ` ${sentence(a, lab)}`)));
      plot.innerHTML = svgPlot(R, T, lo, hi, L, lab);
      if (say !== undefined) live.textContent = say === true ? (R.attempts.length ? `${sentence(R.attempts[R.attempts.length - 1], lab)}.` : '') : say;
    }

    function svgPlot(R, T, lo, hi, L, lab) {
      const narrow = panel.clientWidth < 660;
      const Wd = narrow ? 340 : 760;
      const x0 = narrow ? 34 : 48;
      const x1 = Wd - 12;
      const top = 22;
      const ph = narrow ? 130 : 160;
      const y0 = top + ph;
      const refusedTop = R.attempts.filter((a) => !a.replace && !a.ok).map((a) => (a.r.remaining ?? a.before) + a.amount);
      const ymax = Math.max(st.lambda, T.max, ...refusedTop, 1) * 1.12;
      const yv = (v) => y0 - (v / ymax) * ph;
      // a compressed axis: gaps of more than 3 ledgers get a fixed width and a break mark
      const pts = [...new Set([lo, hi, R.now, ...R.attempts.map((a) => a.ledger), ...R.moved.map((e) => e.ledger + st.period)])]
        .filter((v) => v >= lo && v <= hi).sort((a, b) => a - b);
      const segs = [];
      let wsum = 0;
      for (let k = 0; k + 1 < pts.length; k++) {
        const gap = pts[k + 1] - pts[k];
        const w = gap > 3 ? 1.7 : 1 + 0.3 * (gap - 1);
        segs.push({ a: pts[k], b: pts[k + 1], w, brk: gap > 3 });
        wsum += w;
      }
      let xc = x0;
      for (const s of segs) { s.xa = xc; xc += (s.w / (wsum || 1)) * (x1 - x0); s.xb = xc; }
      const xv = (v) => {
        if (v <= pts[0]) return x0;
        for (const s of segs) if (v <= s.b) return s.xa + ((v - s.a) / (s.b - s.a)) * (s.xb - s.xa);
        return x1;
      };
      const n = (v) => Math.round(v * 10) / 10;
      const out = [];
      const t = (x, y, s, cls = 'm', anchor) => out.push(`<text x="${n(x)}" y="${n(y)}" class="${cls}" font-size="14"${anchor ? ` text-anchor="${anchor}"` : ''}>${s}</text>`);
      out.push(`<path class="fl-m" d="M${x0} ${top - 6}V${y0}H${x1}"/>`);
      t(x0 - 6, yv(0) + 5, '0', 'm', 'end');
      t(x0 - 6, yv(st.lambda) + 5, String(st.lambda), 'm', 'end');
      out.push(`<line class="fl-d dash" x1="${x0}" y1="${n(yv(st.lambda))}" x2="${x1}" y2="${n(yv(st.lambda))}"/>`);
      t(x1, yv(st.lambda) - 6, `limit ${st.lambda}`, 'd', 'end');
      for (const s of segs) if (s.brk) out.push(`<path class="fl-m" d="M${n((s.xa + s.xb) / 2 - 6)} ${y0 + 6}l5-12M${n((s.xa + s.xb) / 2)} ${y0 + 6}l5-12"/>`);
      // the window total of what moved
      let d = `M${x0} ${n(yv(T.segs.length ? T.segs[0].w : 0))}`;
      T.segs.forEach((s, k) => {
        if (k) d += `V${n(yv(s.w))}`;
        d += `H${n(k + 1 < T.segs.length ? xv(T.segs[k + 1].a) : x1)}`;
      });
      out.push(`<path class="fl" d="${d}"/>`);
      // refused transfers: a dashed bar above the total they would have made, ending in a cross
      for (const a of R.attempts) {
        if (a.replace || a.ok) continue;
        const from = st.percall ? 0 : (a.r.remaining ?? a.before);
        const xb = xv(a.ledger) + 3;
        out.push(`<rect class="bx-no dash" x="${n(xb)}" y="${n(yv(from + a.amount))}" width="10" height="${n(Math.max(2, yv(from) - yv(from + a.amount)))}" rx="0"/>`);
        out.push(`<path class="gl-d" d="M${n(xb)} ${n(yv(from + a.amount) - 15)}l10 10M${n(xb + 10)} ${n(yv(from + a.amount) - 15)}l-10 10"/>`);
      }
      for (const v of R.replaced) {
        out.push(`<line class="fl-k" x1="${n(xv(v))}" y1="${top - 6}" x2="${n(xv(v))}" y2="${y0}"/>`);
        t(Math.min(xv(v) + 4, x1 - 70), top + 8, 'replaced', 'k');
      }
      // the inspected window
      const a = M.sat(L, st.period);
      const xa = a >= lo ? xv(a) : x0;
      const xb = xv(L);
      out.push(`<line class="fl-k dash" x1="${n(xb)}" y1="${top - 6}" x2="${n(xb)}" y2="${y0}"/>`);
      // ledger labels, skipping any that would collide
      let right = -1e9;
      let ty = y0 + 20;
      for (const p of pts) {
        const s = lab(p);
        const w = s.length * 7.4;
        const x = Math.min(Math.max(xv(p), x0 + w / 2), x1 - w / 2);
        if (x - w / 2 < right + 8) continue;
        t(x, ty, s, 'm', 'middle');
        right = x + w / 2;
      }
      // charges as chips, in lanes so none overlap, drawn as the figure draws them: amber inside the
      // inspected window, plain outside it; a refused transfer dashed red with a bar end
      const lanes = [];
      const cy0 = y0 + 34;
      for (const at of R.attempts) {
        if (at.replace) continue;
        const s = `+${at.amount}`;
        const w = s.length * 8.6 + 14;
        const x = Math.min(Math.max(xv(at.ledger) - w / 2, 2), Wd - w - 2);
        let lane = lanes.findIndex((r) => x >= r + 4);
        if (lane < 0) { lanes.push(-1e9); lane = lanes.length - 1; }
        lanes[lane] = x + w;
        const y = cy0 + lane * 30;
        const inside = at.ok && M.inWindow(at.ledger, L, st.period);
        const cls = at.ok ? (inside ? 'bx bx-hi' : 'bx') : 'bx-no dash';
        out.push(`<rect class="${cls}" x="${n(x)}" y="${y}" width="${n(w)}" height="24" rx="4"/>`);
        if (!at.ok) out.push(`<path class="fl-d" d="M${n(x + w)} ${y - 3}V${y + 27}"/>`);
        t(x + w / 2, y + 17, s, at.ok ? (inside ? 'x' : 'm') : 'd', 'middle');
      }
      const wy = cy0 + Math.max(1, lanes.length) * 30 + 12;
      let extra = 0;
      const pm = periodMax(R.moved);
      if (st.zero && pm > st.lambda) {
        // T6's second form fails from ledger 0: the P ledgers from 0 hold more than the limit
        const za = xv(0);
        const zb = xv(st.period - 1);
        const zy = wy + 52;
        out.push(`<path class="fl-d" d="M${n(za)} ${zy - 8}V${zy + 8}M${n(za)} ${zy}H${n(zb)}M${n(zb)} ${zy - 8}V${zy + 8}"/>`);
        t(Math.min(za + 4, Wd - 200), zy + 24, `ledgers 0 to ${st.period - 1}: ${pm} > ${st.lambda}`, 'd');
        extra = 52;
      }
      out.push(`<path class="fl-k" d="M${n(xa)} ${wy}H${n(xb)}"/>`);
      if (a >= lo) out.push(`<path class="fl-k" d="M${n(xa + 6)} ${wy - 9}L${n(xa + 2)} ${wy - 5}L${n(xa + 1)} ${wy - 1}V${wy + 1}L${n(xa + 2)} ${wy + 5}L${n(xa + 6)} ${wy + 9}"/>`);
      out.push(`<path class="fl-k" d="M${n(xb - 5)} ${wy - 8}H${n(xb)}V${wy + 8}H${n(xb - 5)}"/>`);
      const W = M.windowTotal(R.moved, L, st.period);
      const wl = `window at ${lab(L)}: ${W} of ${st.lambda}`;
      const wx = Math.min(Math.max(xa, 2), Wd - wl.length * 7.4 - 2);
      t(wx, wy + 26, wl, 'k');
      t(2, 14, st.percall ? 'XLM moved in the window (each call checked alone)' : 'XLM in the window', 'm');
      const H = wy + 34 + extra;
      return `<svg class="xp-plot" viewBox="0 0 ${Wd} ${H}" aria-hidden="true" focusable="false">${out.join('')}</svg>`;
    }

    const act = (a) => { st.actions.push(a); draw(true); };
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const v = Math.round(Number(amount.value));
      if (!Number.isFinite(v) || v < 0 || v > 100) { live.textContent = 'Enter a whole amount from 0 to 100.'; return; }
      st.touched = false;
      act({ op: 'send', amount: v });
    });
    const advance = (k) => {
      st.touched = false;
      st.actions.push({ op: 'advance', n: k });
      const R = run();
      draw(`Now at ledger ${xOfLedger(R.base)(R.now)}; the window holds ${M.windowTotal(R.moved, R.now, st.period)} of ${st.lambda}.`);
    };
    adv1.onclick = () => advance(1);
    adv10.onclick = () => advance(10);
    advP.onclick = () => advance(st.period);
    undo.onclick = () => { if (isOff(undo)) return; st.actions.pop(); st.touched = false; draw('Undone.'); };
    replace.onclick = () => { st.touched = false; act({ op: 'replace' }); };
    clear.onclick = () => { st.actions = []; st.touched = false; draw('Cleared: no transfers yet, at ledger t.'); };
    reset.onclick = () => {
      Object.assign(st, { lambda: 10, period: 100, percall: false, zero: false, actions: fig3(), inspect: BASE + 100, touched: true });
      lam.value = 10; per.value = 100; percall.checked = false; zero.checked = false;
      draw('Back to the figure’s events.');
    };
    lam.addEventListener('input', () => { st.lambda = Number(lam.value); draw(`Limit ${st.lambda} XLM: the same transfers, judged again.`); });
    per.addEventListener('input', () => { st.period = Number(per.value); draw(`Period ${st.period} ledgers: the same transfers, judged again.`); });
    percall.addEventListener('change', () => {
      st.percall = percall.checked;
      draw(st.percall ? `Each call checked alone: any transfer up to ${st.lambda} is accepted, and nothing keeps a running total.` : 'Back to the window: each transfer is charged against the window total.');
    });
    zero.addEventListener('change', () => {
      st.zero = zero.checked;
      st.touched = true;
      if (st.zero) { st.actions = [{ op: 'send', amount: st.lambda }, { op: 'send', amount: st.lambda }]; st.inspect = 0; }
      else { st.actions = fig3(); st.inspect = BASE + 100; }
      draw(st.zero ? `Two transfers of ${st.lambda} at ledger 0: both accepted.` : 'Back to the figure’s events.');
    });
    inspect.addEventListener('input', () => { st.inspect = Number(inspect.value); st.touched = true; draw(); });
    st.touched = true;
    draw();
    if ('ResizeObserver' in window) {
      let w = panel.clientWidth;
      new ResizeObserver(() => { if (Math.abs(panel.clientWidth - w) > 20) { w = panel.clientWidth; draw(); } }).observe(panel);
    }
  };

  // ---------------------------------------------------------------- E1: attenuation
  // fig-attenuation, or [data-explorable="attenuation"] around tab-attenuate-instance.
  const RULE_PARTS = (r) => {
    const f = r.functions;
    const fns = f.only ? (f.only.map((x) => `\`${x}\``).join(', ') || 'no function') : `any function${f.except.length ? ` but ${f.except.join(', ')}` : ''}`;
    const conds = r.conds.map((c) => (c.op === 'eq' && c.i === 1 ? `recipient is the ${c.v}` : c.op === 'atmost' ? `amount at most ${c.n}` : 'a condition on an argument'));
    const out = [['target', `${r.contract === 'game' ? 'the game' : r.contract}, ${fns}`]];
    if (conds.length) out.push(['conds', conds.join('; ')]);
    out.push(['signers', `${r.signers.map((s) => `\`${s}\``).join(' or ') || 'no signer'}, threshold ${r.threshold}`]);
    if (r.cap) out.push(['cap', `cap ${r.cap.limit} per ${r.cap.period} ledgers`]);
    if (r.validUntil != null) out.push(['expiry', `last ledger ${r.validUntil}`]);
    return out;
  };
  function grantCard(title, rules, base) {
    const card = h('section', { class: 'xp-card' }, h('h4', {}, title));
    for (const r of rules) {
      const b = base && base.find((q) => q.name === r.name);
      const bp = b ? new Map(RULE_PARTS(b)) : null;
      card.append(h('p', { class: 'xp-rule' }, h('strong', {}, `rule \`${r.name}\``)),
        h('ul', {}, RULE_PARTS(r).map(([k, t]) => {
          const narrowed = bp && bp.get(k) !== t;
          return h('li', narrowed ? { class: 'xp-narrowed' } : {}, t, narrowed ? h('span', { class: 'xp-tag' }, 'narrowed') : null);
        })));
    }
    if (!rules.length) card.append(h('p', {}, 'No rules: the child allows nothing.'));
    return card;
  }
  // Why a rule set refuses a probe alone: the rule that gets furthest, and its failing check.
  function whyRefused(rules, ctx, auth) {
    let best = null;
    rules.forEach((r, j) => {
      const d = M.authorize(rules, rules.map(M.emptyRecord), [ctx], [j], auth, M.E1.ledger, 0);
      if (!d.ok && (!best || d.trace.length > best.d.trace.length)) best = { d, r };
    });
    if (!best) return 'no rule';
    const { d, r } = best;
    const name = `\`${r.name}\``;
    switch (d.check) {
      case 'target': return rules.some((q) => q.contract === ctx.contract) ? `target of ${name}` : `no rule for ${ctx.contract === 'account' ? 'the account' : ctx.contract === 'game' ? 'the game' : ctx.contract}`;
      case 'function': return `\`${ctx.fn}\` is not a function of ${name}`;
      case 'arguments': return `${name}\u2019s argument condition`;
      case 'threshold': return `${auth.map((s) => `\`${s}\``).join(', ')} is not a signer of ${name}`;
      case 'unexpired': return `${name} has expired`;
      case 'amount': return `${name} has a cap, and \`${ctx.fn}\` has no amount to charge`;
      case 'charge': return `${d.charge.remaining} + ${d.charge.amount} = ${d.charge.total} > ${d.charge.limit}, the cap of ${name}`;
      case 'signers': return 'a signer on no chosen rule';
      default: return d.check;
    }
  }
  function probeTable(parent, child) {
    const rows = M.E1.probes.map(([id, label, ctx, auth]) => [id, label, M.accepts(parent, ctx, auth, M.E1.ledger), M.accepts(child, ctx, auth, M.E1.ledger), ctx, auth]);
    const why = ([, , p, c, ctx, auth]) => {
      if (c) return '\u2014';
      const wc = whyRefused(child, ctx, auth);
      if (p) return `child: ${wc}`;
      const wp = whyRefused(parent, ctx, auth);
      return wp === wc ? `both: ${wc}` : `parent: ${wp}; child: ${wc}`;
    };
    const table = h('table', { class: 'xp-probes' },
      h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Probe'), h('th', { scope: 'col' }, 'Parent'), h('th', { scope: 'col' }, 'Child'), h('th', { scope: 'col' }, 'Why refused'))),
      h('tbody', {}, rows.map((r) => h('tr', { 'data-probe': r[0] }, h('th', { scope: 'row' }, r[1]), h('td', {}, r[2] ? yes('accepts') : no()), h('td', {}, r[3] ? yes('accepts') : no()), h('td', { class: 'xp-why' }, why(r))))));
    const nc = rows.filter((r) => r[3]).length;
    const np = rows.filter((r) => r[2]).length;
    const each = rows.every((r) => !r[3] || r[2]);
    return { table, rows, summary: `Child accepts ${nc} of ${rows.length}; ${each ? 'the parent accepts each' : 'the parent does not accept each'}. The parent accepts ${np}.` };
  }
  function replayList(parent, child, origin) {
    const { childRun, parentRun } = M.replay(parent, child, origin);
    const ok = childRun.filter((x) => x.ok).length;
    const lines = childRun.map((x, k) => {
      const what = x.ctx.fn === 'guess' ? 'guess' : `transfer ${x.ctx.args[2]} to the shop`;
      if (x.ok) return h('li', { class: 'xp-ok' }, el('span', { class: 'xp-mark', 'aria-hidden': 'true' }, '✓'), ` ${k + 1}. ${what}: the child accepts with rule \`${child[x.j].name}\` (number ${x.j})`);
      const c = x.d && x.d.charge;
      return h('li', { class: 'xp-refused' }, el('span', { class: 'xp-mark', 'aria-hidden': 'true' }, '✕'), ` ${k + 1}. ${what}: the child refuses${c && c.why === 'limit' ? ` (${c.remaining} + ${c.amount} = ${c.total} > ${c.limit})` : ''}`);
    });
    const pok = parentRun.filter((x) => x.ok).length;
    const renum = parentRun.some((x) => x.pj !== x.j) ? ' Rule numbers are renumbered to the parent’s, past the dropped rule.' : '';
    return { list: h('ol', { class: 'xp-log' }, lines), line: `The child accepted ${ok} of ${childRun.length}. Replayed through the parent from empty records: ${pok} of ${parentRun.length} accepted.${renum}`, all: pok === parentRun.length };
  }
  const MOVES = [
    ['drop_rule', 'Drop a rule (drop_rule)'], ['remove_functions', 'Remove functions (remove_functions)'],
    ['restrict_functions', 'Restrict to functions (restrict_functions)'], ['add_cond', 'Add an argument condition (add_cond)'],
    ['remove_signers', 'Remove signers (remove_signers)'], ['raise_threshold', 'Raise the threshold (raise_threshold)'],
    ['add_cap', 'Add a cap (add_cap)'], ['lower_cap_limit', 'Lower the cap limit (lower_cap_limit)'],
    ['lengthen_cap_period', 'Lengthen the cap period (lengthen_cap_period)'],
    ['lower_valid_until', 'Add or move an expiry earlier (lower_valid_until)'],
  ];
  const WIDEN = [['raise_limit', 'Raise the cap limit'], ['shorten_period', 'Shorten the cap period'], ['later_expiry', 'Move the expiry later'],
    ['lower_threshold', 'Lower the threshold'], ['change_target', 'Change the target']];
  CONTROLLERS.attenuation = (host) => {
    const panel = mount(host, 'xp-att');
    const parent = M.E1.parent();
    const st = { stack: [] }; // [{label, rules, origin}]
    const current = () => (st.stack.length ? st.stack[st.stack.length - 1] : { rules: parent, origin: parent.map((_, i) => i) });
    panel.append(banner('MODEL', 'Model result; the account cannot install an attenuated grant at the pinned build (proposed). Probes run alone from empty records.'));
    const cards = el('div', { class: 'xp-cards' });
    const stepSel = el('select', { name: uid('att-step') });
    const g1 = el('optgroup', { label: 'Attenuation steps' });
    for (const [v, l] of MOVES) g1.append(el('option', { value: v }, l));
    const g2 = el('optgroup', { label: 'Moves no step allows' });
    for (const [v, l] of WIDEN) g2.append(el('option', { value: v }, l));
    stepSel.append(g1, g2);
    stepSel.value = 'lower_cap_limit';
    const ruleSel = el('select', { name: uid('att-rule') });
    const valBox = el('span', { class: 'xp-val' });
    const apply = button('Apply', { class: 'primary' });
    const undo = button('Undo');
    const reset = button('Reset');
    const { bar, live } = head(host, panel);
    bar.setAttribute('aria-label', 'Attenuation controls');
    bar.append(labelled('Step', stepSel), labelled('Rule', ruleSel), valBox, apply, undo, reset);
    const applied = el('ol', { class: 'xp-steps', 'aria-label': 'Steps applied' });
    const grid = el('div', { class: 'xp-grid' });
    const summary = el('p', { class: 'xp-result', tabindex: '-1' });
    const replayBtn = button('Replay through the parent');
    const replayOut = el('div', { class: 'xp-replay', 'aria-live': 'polite' });
    panel.append(cards, h('p', { class: 'xp-sub' }, 'Steps applied to the parent:'), applied, grid, summary, h('div', { class: 'xp-row' }, replayBtn), replayOut);
    // The static table hides on screen; keep its caption with the explorable.
    const staticCap = host.querySelector('.xp-static caption');
    if (staticCap) {
      const cap = el('p', { class: 'xp-caption' });
      for (const n of staticCap.childNodes) cap.append(n.cloneNode(true));
      panel.append(cap);
    }
    let val = null;
    function valueControl() {
      const step = stepSel.value;
      const r = current().rules[Number(ruleSel.value)] || current().rules[0];
      const opts = {
        remove_functions: [['guess', '`guess`'], ['transfer', '`transfer`'], ['approve', '`approve`']],
        restrict_functions: [['guess', 'only `guess`'], ['transfer', 'only `transfer`']],
        add_cond: [['shop', 'recipient is the shop'], ['game', 'recipient is the game'], ['at3', 'amount at most 3']],
        remove_signers: [['helper', '`helper`'], ['app', '`app`']],
        change_target: [['account', 'the account'], ['other', 'another contract']],
      }[step];
      const nums = {
        raise_threshold: ['New threshold', (r ? r.threshold : 1) + 1], add_cap: ['Limit (per 100 ledgers)', 5],
        lower_cap_limit: ['New limit', r && r.cap ? Math.max(1, r.cap.limit - 6) : 4], lengthen_cap_period: ['New period', r && r.cap ? r.cap.period * 2 : 200],
        lower_valid_until: ['Last ledger', r && r.validUntil != null ? r.validUntil - 1000 : 4000],
        raise_limit: ['New limit', r && r.cap ? r.cap.limit + 10 : 20], shorten_period: ['New period', r && r.cap ? Math.max(1, r.cap.period - 50) : 50],
        later_expiry: ['Last ledger', r && r.validUntil != null ? r.validUntil + 1000 : 6000], lower_threshold: ['New threshold', r ? r.threshold - 1 : 0],
      }[step];
      valBox.replaceChildren();
      val = null;
      if (opts) { val = select(uid('att-val'), opts.map(([v, l]) => [v, plain(l)])); valBox.append(labelled('Value', val)); }
      else if (nums) { val = number(uid('att-val'), nums[1], -1, 100000); valBox.append(labelled(nums[0], val)); }
    }
    function describeMove() {
      const step = stepSel.value;
      const r = current().rules[Number(ruleSel.value)];
      const name = r ? `\`${r.name}\`` : 'the rule';
      const v = val ? (val.tagName === 'SELECT' ? val.selectedOptions[0].textContent : val.value) : '';
      const map = {
        drop_rule: `drop ${name}`, remove_functions: `remove ${v} from ${name}`, restrict_functions: `restrict ${name} to ${v.replace('only ', '')}`,
        add_cond: `add to ${name}: ${v}`, remove_signers: `remove the signer ${v} from ${name}`, raise_threshold: `set ${name}’s threshold to ${v}`,
        add_cap: `add a cap of ${v} per 100 ledgers to ${name}`, lower_cap_limit: `set ${name}’s cap limit to ${v}`,
        lengthen_cap_period: `set ${name}’s cap period to ${v}`, lower_valid_until: `set ${name}’s last ledger to ${v}`,
        raise_limit: `raise ${name}’s cap limit to ${v}`, shorten_period: `shorten ${name}’s cap period to ${v}`,
        later_expiry: `move ${name}’s last ledger to ${v}`, lower_threshold: `lower ${name}’s threshold to ${v}`,
        change_target: `change ${name}’s target to ${v}`,
      };
      return map[step];
    }
    function toModel() {
      const step = stepSel.value;
      const v = val ? (val.tagName === 'SELECT' ? val.value : Math.round(Number(val.value))) : null;
      const conds = { shop: M.consts.PIN_SHOP, game: M.consts.PIN_GAME, at3: { op: 'atmost', i: 2, n: 3 } };
      const s = {
        remove_functions: ['remove_functions', [v]], restrict_functions: ['restrict_functions', [v]], add_cond: ['add_cond', conds[v]],
        remove_signers: ['remove_signers', [v]], add_cap: ['add_cap', { limit: v, period: 100, arg: 2 }],
        raise_limit: ['lower_cap_limit', v], shorten_period: ['lengthen_cap_period', v], later_expiry: ['lower_valid_until', v],
        lower_threshold: ['raise_threshold', v], change_target: ['change_target', v],
      }[step] || [step, v];
      return s;
    }
    function draw() {
      const cur = current();
      const keep = ruleSel.value;
      ruleSel.replaceChildren(...cur.rules.map((r, i) => el('option', { value: i }, plain(r.name))));
      if (!cur.rules.length) ruleSel.append(el('option', { value: 0 }, '(none)'));
      if (keep && Number(keep) < cur.rules.length) ruleSel.value = keep;
      cards.replaceChildren(grantCard('Parent grant', parent, null), grantCard('Child grant', cur.rules, parent));
      applied.replaceChildren(...(st.stack.length ? st.stack.map((s) => h('li', {}, s.label)) : [h('li', { class: 'xp-none' }, 'none yet: the child equals the parent')]));
      const p = probeTable(parent, cur.rules);
      grid.replaceChildren(p.table);
      summary.textContent = p.summary;
      setOff(undo, !st.stack.length);
      replayOut.replaceChildren();
    }
    apply.onclick = () => {
      const cur = current();
      const [step, param] = toModel();
      const i = Number(ruleSel.value) || 0;
      const label = describeMove();
      const r = M.attenuate(cur.rules, step, i, param);
      if (!r.ok) {
        live.textContent = `${plain(label)}: refused (${M.REFUSAL[r.error]}); nothing changes.`;
        return;
      }
      const origin = cur.origin.slice();
      if (step === 'drop_rule') origin.splice(i, 1);
      st.stack.push({ label, rules: r.rules, origin });
      draw();
      live.textContent = `Applied: ${plain(label)}. ${summary.textContent}`;
      summary.focus({ preventScroll: false });
    };
    undo.onclick = () => { if (isOff(undo)) return; st.stack.pop(); draw(); live.textContent = `Undone. ${summary.textContent}`; };
    reset.onclick = () => { st.stack = []; draw(); live.textContent = 'Reset: the child equals the parent.'; };
    stepSel.onchange = valueControl;
    ruleSel.onchange = valueControl;
    replayBtn.onclick = () => {
      const cur = current();
      const r = replayList(parent, cur.rules, cur.origin);
      replayOut.replaceChildren(r.list, h('p', { class: 'xp-result' }, r.line));
    };
    // open on the three steps of the static form
    let rules = parent;
    for (const [step, i, param, label] of M.E1.steps) {
      rules = M.attenuate(rules, step, i, param).rules;
      st.stack.push({ label, rules, origin: [0, 1] });
    }
    draw();
    ruleSel.value = String(Math.max(0, current().rules.findIndex((r) => r.cap)));
    valueControl();
  };

  // ---------------------------------------------------------------- E3: the authorization path
  // fig-auth-path: four choices; the stepper lights each stage and the decision's checks.
  const STAGES = ['host', 'guards', 'select', 'decide', 'authenticate', 'store'];
  const STAGE_NAME = { host: 'Host call', guards: 'Guards', select: 'Select rules', decide: 'Decide', authenticate: 'Authenticate', store: 'Store' };
  const CHECKS = ['found', 'unexpired', 'generation', 'target', 'function', 'arguments', 'threshold', 'signers', 'charge'];
  const CHECK_NAME = { found: 'rule found', unexpired: 'unexpired', generation: 'current generation', target: 'target', function: 'function', arguments: 'arguments', threshold: 'threshold', signers: 'every signer used', charge: 'charge', amount: 'charge' };
  const E3_GROUPS = [
    ['req', 'Request', [['within', 'pay the shop 4 (within the cap)'], ['over', 'pay the shop 5 (over the cap)'], ['guess', 'a lost guess'], ['account', 'a call to the account']]],
    ['signer', 'Signer', [['app', 'the app’s key'], ['forged', 'another key signing as the app'], ['unlisted', 'a key on no rule']]],
    ['grant', 'Grant', [['current', 'current'], ['expired', 'expired'], ['stale', 'issued before a completed recovery']]],
    ['named', 'Rule named', [['right', 'the right rule'], ['wrong', 'the wrong rule']]],
  ];
  const ctxName = (c) => (c.fn === 'guess' ? 'the game’s `guess`' : c.fn === 'transfer' ? `transfer ${c.args[2]} to ${c.args[1] === 'shop' ? 'the shop' : c.args[1] === 'game' ? 'the game' : c.args[1]}` : 'a call to the account');
  function refusalWhy(run) {
    const d = run.decision;
    const c = d.check;
    const r = d.i != null ? run.rules[run.choices[d.i]] : null;
    const ctx = d.i != null ? ctxName(run.contexts[d.i]) : '';
    if (c === 'charge') return `charge: ${d.charge.remaining} + ${d.charge.amount} = ${d.charge.total} > ${d.charge.limit}, the limit of \`${r.name}\``;
    if (c === 'threshold') return `threshold: 0 of the ${r.threshold} listed signer${r.threshold === 1 ? '' : 's'} of \`${r.name}\` signed`;
    if (c === 'target' && run.contexts[d.i].contract === 'account') return `target: no grant rule may name the account itself (Theorem 8); \`${r.name}\` is for ${r.contract === 'game' ? 'the game' : r.contract}`;
    if (c === 'target') return `target: \`${r.name}\` is for ${r.contract === 'game' ? 'the game' : r.contract}, not for ${ctx}`;
    if (c === 'arguments') return `arguments: \`${r.name}\` requires another recipient than ${ctx}`;
    if (c === 'unexpired') return `unexpired: \`${r.name}\`’s last ledger has passed`;
    if (c === 'generation') return `current generation: \`${r.name}\` was issued at generation ${r.generation}; the account is at ${run.gen}`;
    if (c === 'signers') return 'every signer used: a claimed signer is on no chosen rule';
    return CHECK_NAME[c] || c;
  }
  function witness(run) {
    return h('div', { class: 'xp-card xp-witness' }, h('h4', {}, 'Witness: the rule that allows each context'),
      h('ul', {}, run.contexts.map((c, i) => {
        const r = run.rules[run.choices[i]];
        const ch = run.decision.charges.find((x) => x.i === i);
        return h('li', {}, `${ctxName(c)} ← rule \`${r.name}\`: target, function, arguments and threshold (1 of \`app\`) hold`,
          ch ? `; charge ${ch.charge.remaining} + ${ch.charge.amount} = ${ch.charge.total} ≤ ${ch.charge.limit}` : '');
      })));
  }
  function e3Choices(prefix, onchange, compact) {
    const wrap = el('div', { class: 'xp-choices' });
    const get = {};
    for (const [key, legend, opts] of E3_GROUPS) {
      const name = uid(`${prefix}-${key}`);
      const fs = h('fieldset', { class: 'xp-fs' }, h('legend', {}, legend));
      const sel = select(`${name}-s`, opts, opts[0][0]);
      sel.setAttribute('aria-label', legend);
      sel.className = 'xp-fs-select';
      const radios = [];
      opts.forEach(([v, label], k) => {
        const r = el('input', { type: 'radio', name, value: v, checked: k === 0 });
        radios.push(r);
        fs.append(h('label', { class: 'xp-radio' }, r, ` ${label}`));
        r.addEventListener('change', () => { sel.value = v; onchange(); });
      });
      sel.addEventListener('change', () => { for (const r of radios) r.checked = r.value === sel.value; onchange(); });
      fs.append(sel);
      if (compact && key !== 'req' && key !== 'signer') continue;
      wrap.append(fs);
      get[key] = () => sel.value;
    }
    return { wrap, get };
  }
  CONTROLLERS['auth-path'] = (fig) => {
    const svgs = [...fig.querySelectorAll('svg')];
    const root = svgs[0];
    const trap = root && root.dataset.recordedTrap;
    const cmd = root && root.dataset.recordedCommand;
    const panel = el('div', { class: 'xp xp-auth' });
    svgs[0].before(panel);
    fig.classList.add('xp-on');
    const { bar, live } = head(fig, panel);
    bar.setAttribute('aria-label', 'Stepper');
    const every = button('Every scenario (as printed)', { 'aria-pressed': 'true' });
    const prev = button('Previous');
    const next = button('Next');
    const end = button('Run to the end');
    const count = el('span', { class: 'fig-count' });
    bar.append(every, prev, next, end, count);
    const sim = document.getElementById('sim-embed');
    panel.append(banner('MODEL', h('span', {}, 'Computed in the page from the decision function’s definition (D3). The account itself runs in the simulation', sim ? h('span', {}, ' (', h('a', { href: '#sim-embed' }, 'run both accounts'), ').') : '.')));
    const choices = e3Choices(fig.id, () => play());
    panel.append(choices.wrap);
    // the stepper follows the choices in the tab order
    choices.wrap.after(bar.parentElement);
    const result = el('div', { class: 'xp-result-box' });
    const after = el('div', { class: 'xp xp-auth-out' });
    svgs[svgs.length - 1].after(after);
    after.append(result);
    let run = null;
    let k = -1;
    const stopAt = () => STAGES.indexOf(run.stage);
    function checkStates() {
      // per check: pass if evaluated and passed for every context, stop at the failing one, else unreached
      const s = {};
      for (const t of run.decision.trace) {
        const key = t.check === 'amount' ? 'charge' : t.check;
        if (!t.ok) s[key] = 'stop';
        else if (s[key] !== 'stop') s[key] = 'pass';
      }
      return s;
    }
    function mark(g, state) {
      g.dataset.xstate = state;
      for (const m of g.querySelectorAll(':scope > [data-mark]')) m.classList.toggle('off', !((state === 'pass' && m.dataset.mark === 'pass') || (state === 'stop' && m.dataset.mark === 'stop')));
    }
    function paint() {
      const exitsOff = run != null;
      for (const g of fig.querySelectorAll('[data-exits]')) g.classList.toggle('off', exitsOff);
      every.setAttribute('aria-pressed', String(!exitsOff));
      for (const svg of svgs) {
        for (const g of svg.querySelectorAll('[data-stage]')) {
          const idx = STAGES.indexOf(g.dataset.stage);
          let state = '';
          if (run) {
            const stop = stopAt();
            const refusedHere = idx === stop && run.stage !== 'store';
            if (idx < k || (idx === k && !refusedHere && k === stop && run.stage === 'store')) state = 'pass';
            if (idx === k && refusedHere) state = 'stop';
            if (idx > stop && k >= stop) state = 'unreached';
            g.dataset.state = idx === k ? 'current' : idx > k && idx <= stop ? 'future' : '';
          } else g.dataset.state = '';
          mark(g, state);
        }
        const cs = run && k >= 3 ? checkStates() : {};
        for (const g of svg.querySelectorAll('[data-check]')) {
          const s = run && k >= 3 ? (cs[g.dataset.check] || 'unreached') : '';
          mark(g, s);
        }
      }
      setOff(prev, !run || k <= 0);
      setOff(next, !run || k >= stopAt());
      setOff(end, !run || k >= stopAt());
      count.textContent = run ? `Stage ${k + 1} of ${stopAt() + 1}` : '6 stages';
    }
    function narrate(quiet) {
      const stage = STAGES[k];
      const d = run.decision;
      const names = run.choices.map((j) => `\`${run.rules[j].name}\``).join(' and ');
      const what = run.contexts.map(ctxName).join(', then ');
      const signer = { app: 'the app’s key', forged: 'the app, signed with another key', unlisted: 'a key on no rule' }[choices.get.signer()];
      const t = {
        host: `Host call: ${what}; the app names ${names}; claimed signer: ${signer}.`,
        guards: 'Guards: no reserved hook name, the account is not frozen, and no grant rule is on a recovery contract. Passed.',
        select: `Select rules: ${names} found, with ${run.choices.length > 1 ? 'their' : 'its'} spending record${run.choices.length > 1 ? 's' : ''}. The account does not search.`,
        decide: d.ok ? `Decide: every check passes${(d.charges || []).length ? `; ${(d.charges || []).map((c) => `charge ${c.charge.remaining} + ${c.charge.amount} = ${c.charge.total} ≤ ${c.charge.limit}`).join('; ')}` : ''}.`
          : `Decide: refused at ${refusalWhy(run)}. Nothing written; verifier called: no.`,
        authenticate: run.stage === 'authenticate' ? `Authenticate: the signature is not the app’s key; the verifier traps${trap ? ` (recorded run, command ${cmd}: ${trap})` : ''}. Nothing written.`
          : 'Authenticate: the app’s verifier checks the signature over the digest. Passed.',
        store: `Store: ${(d.charges || []).map((c) => `\`${run.rules[c.j].name}\`’s record now holds ${c.charge.total}`).join('; ') || 'no record changes'}. Accepted.`,
      }[stage];
      if (!quiet) live.textContent = plain(t);
      if (k >= stopAt()) showResult(); else result.replaceChildren();
    }
    function showResult() {
      const d = run.decision;
      if (run.stage === 'store') {
        result.replaceChildren(h('p', { class: 'xp-verdict xp-ok' }, el('span', { class: 'xp-mark', 'aria-hidden': 'true' }, '✓'), ' Accepted. Verifier called: yes.'), witness(run));
      } else if (run.stage === 'decide') {
        result.replaceChildren(h('p', { class: 'xp-verdict xp-refused' }, el('span', { class: 'xp-mark', 'aria-hidden': 'true' }, '✕'), ` Refused at the decision: ${refusalWhy(run)}. Nothing written. Verifier called: no.`));
      } else {
        result.replaceChildren(h('p', { class: 'xp-verdict xp-refused' }, el('span', { class: 'xp-mark', 'aria-hidden': 'true' }, '✕'), ' The decision accepts; authentication fails. Nothing written.'),
          ...(trap ? [h('p', { class: 'xp-banner' }, chip('RECORDED'), ` In the reference run (command ${cmd}), the Ed25519 verifier trapped with ${trap} and the host reverted the call.`)] : []));
      }
    }
    let timer = null;
    const halt = () => { if (timer) { clearInterval(timer); timer = null; } };
    function start(fromChoice) {
      halt();
      run = M.E3.run(choices.get.req(), choices.get.signer(), choices.get.grant(), choices.get.named());
      k = fromChoice ? stopAt() : 0;
      paint();
      narrate();
    }
    // A new choice walks the stages from the host call, one every 400 ms; with reduced motion
    // it shows where the request stops at once. Either way the stepper can walk it again.
    function play() {
      if (reduced()) { start(true); return; }
      halt();
      run = M.E3.run(choices.get.req(), choices.get.signer(), choices.get.grant(), choices.get.named());
      k = 0;
      paint();
      narrate(true);
      timer = setInterval(() => {
        k += 1;
        const last = k >= stopAt();
        paint();
        narrate(!last);
        if (last) halt();
      }, 400);
    }
    const go = (j) => { halt(); if (!run) start(false); k = Math.max(0, Math.min(stopAt(), j)); paint(); narrate(); };
    every.onclick = () => { halt(); run = null; k = -1; paint(); result.replaceChildren(); live.textContent = 'Every scenario, as printed: the right column gives where each one stops.'; };
    prev.onclick = () => { if (!isOff(prev)) go(k - 1); };
    next.onclick = () => { if (!run) { start(false); return; } if (!isOff(next)) go(k + 1); };
    end.onclick = () => { if (!isOff(end)) go(stopAt()); };
    setOff(next, false);
    bar.addEventListener('keydown', (e) => {
      const d = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
      if (d) { if (!run) start(false); else go(k + d); e.preventDefault(); }
      if (e.key === 'Home') { go(0); e.preventDefault(); }
      if (e.key === 'End') { go(run ? stopAt() : 5); e.preventDefault(); }
    });
    paint();
    setOff(next, false);
    setOff(end, true);
  };

  // ---------------------------------------------------------------- the dual simulation
  // fig-sim is the poster: a stepper over the recorded run. Inside .sim-embed (sim-panel.html)
  // it also gets "Start the simulation here", which loads the page into a frame; "Try these"
  // links carry ?scenario= for the full page and load the same commands into the frame.
  CONTROLLERS['sim-poster'] = (fig, helpers) => {
    stepper(fig, helpers);
    const embed = fig.closest('.sim-embed');
    if (embed) simEmbed(embed);
  };
  const b64url = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  function simEmbed(embed) {
    if (embed.dataset.ready) return;
    embed.dataset.ready = '1';
    const src = embed.dataset.src;
    const full = embed.dataset.full;
    const mb = embed.dataset.mb;
    const fig = embed.querySelector('figure.fig');
    const tries = embed.querySelector('.sim-try');
    // Start, and the full page (the frame links its reference and hash tables).
    const actions = h('div', { class: 'sim-actions' });
    const startBtn = button(`Start the simulation here (${mb ? `${mb} MB, ` : ''}runs offline in this tab)`, { class: 'primary' });
    actions.append(el('span', { class: 'xp-chip', 'data-kind': 'executed' }, 'RUNS THE REAL CONTRACTS'), startBtn, el('a', { href: full }, 'Open the full page'));
    const open = embed.querySelector(':scope > .sim-open');
    if (open) open.replaceWith(actions); else embed.prepend(actions);
    const frameBox = el('div', { class: 'sim-frame' });
    if (tries) tries.after(frameBox); else actions.after(frameBox);
    const note = tries && tries.querySelector('.sim-note');
    if (note) note.textContent = 'Each link runs its scenario here, starting the simulation if it is not running; Ctrl- or Cmd-click opens it on the full page instead. Both accounts run every request, from a fresh ledger with the rule installed.';
    let fold = null;
    if (fig) {
      if (!fig.querySelector('.xp-chip')) {
        const cap = fig.querySelector('figcaption');
        if (cap) cap.prepend(chip('RECORDED'), ' ');
      }
      // Once the simulation runs, the recorded figure folds away (on screen only) behind a toggle.
      fold = button('Show the recorded run', { class: 'sim-fold', 'aria-expanded': 'true', 'aria-controls': fig.id, hidden: '' });
      fig.before(fold);
      fold.onclick = () => {
        const shown = embed.classList.toggle('sim-folded') === false;
        fold.setAttribute('aria-expanded', String(shown));
        fold.textContent = shown ? 'Hide the recorded run' : 'Show the recorded run';
      };
    }
    let frame = null;
    let ready = false;
    let pending = null;
    const theme = () => document.documentElement.dataset.theme;
    // Focus the frame's first request control (same origin), else the frame itself.
    function focusFrame() {
      try {
        const first = frame.contentDocument && frame.contentDocument.getElementById('sim-amount');
        if (first) { first.focus(); return; }
      } catch { /* another origin, such as file:// */ }
      frame.focus();
    }
    // autostart=1 sets up both ledgers and installs the rule; a scenario does that, then runs it.
    function start(commands) {
      if (frame) return;
      let url = src;
      if (theme()) url += `${url.includes('?') ? '&' : '?'}theme=${theme()}`;
      url += `${url.includes('?') ? '&' : '?'}${commands ? `scenario=${b64url(JSON.stringify(commands))}` : 'autostart=1'}`;
      frame = el('iframe', { src: url, title: 'OpenZeppelin and Perch accounts in soroban-sim', loading: 'eager' });
      frame.addEventListener('load', () => {
        ready = true;
        if (pending) { post(pending); pending = null; }
        focusFrame();
      });
      frameBox.append(frame);
      startBtn.hidden = true;
      embed.classList.add('sim-started', 'sim-folded');
      if (fold) { fold.hidden = false; fold.setAttribute('aria-expanded', 'false'); fold.textContent = 'Show the recorded run'; }
      frame.focus();
    }
    function post(commands) { frame.contentWindow.postMessage({ type: 'perch-sim:load', commands }, '*'); }
    window.addEventListener('message', (e) => {
      if (!frame || e.source !== frame.contentWindow) return;
      const d = e.data;
      if (!d || typeof d !== 'object' || d.type !== 'perch-sim:height') return;
      const hgt = Number(d.height ?? d.h);
      // the frame takes its content's height, so the page scrolls, not the frame
      if (Number.isFinite(hgt) && hgt > 0) frame.style.height = `${Math.min(Math.max(hgt, 240), 40000)}px`;
    });
    startBtn.onclick = () => start(null);
    for (const a of embed.querySelectorAll('a[data-commands]')) {
      a.addEventListener('click', (e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button) return;
        let commands;
        try { commands = JSON.parse(a.dataset.commands); } catch { return; }
        e.preventDefault();
        if (!frame) start(commands);
        else if (ready) { post(commands); focusFrame(); } else pending = commands;
        frameBox.scrollIntoView({ block: 'start', behavior: reduced() ? 'auto' : 'smooth' });
      });
    }
  }

  // ---------------------------------------------------------------- theorem instances
  // <div class="thm-instance" data-instance="<id>"> inside a statement card: a model
  // instance of the statement's formula, behind "Try an instance".
  const INSTANCES = {};
  const ALIAS = { 'cap-window-bound': 'inst-cap-window', acceptance: 'inst-auth-witness', 'attenuation-narrows': 'inst-attenuate-probes',
    containment: 'inst-lower-scoped', 'recovery-stale': 'inst-recovery-generation', 'trace-inclusion': 'inst-trace-replay' };

  INSTANCES['inst-cap-window'] = (box) => {
    const st = { lambda: 10, period: 100, rows: [[100, 6], [100, 5], [101, 4], [199, 1], [200, 5], ['', '']] };
    const lam = el('input', { type: 'range', min: 1, max: 20, value: 10, step: 1, name: uid('i6-l') });
    const per = el('input', { type: 'range', min: 10, max: 200, value: 100, step: 10, name: uid('i6-p') });
    const lamOut = el('output');
    const perOut = el('output');
    const zero = el('input', { type: 'checkbox', name: uid('i6-z') });
    const table = el('table', { class: 'xp-rows' });
    const out = el('p', { class: 'xp-result', 'aria-live': 'polite' });
    const out2 = el('p', { class: 'xp-sub' });
    box.append(h('div', { class: 'xp-row' }, h('label', { class: 'xp-field' }, h('span', {}, 'λ = ', lamOut), lam), h('label', { class: 'xp-field' }, h('span', {}, 'P = ', perOut), per)),
      h('p', { class: 'xp-sub' }, 'Up to six charge attempts to one capped rule, from an empty record, in order:'), table,
      h('label', { class: 'xp-check' }, zero, ' Start at ledger 0 (no Stellar ledger has sequence 0)'), out, out2);
    const inputs = [];
    table.append(h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Ledger'), h('th', { scope: 'col' }, 'Amount'), h('th', { scope: 'col' }, 'Verdict'))));
    const tbody = el('tbody');
    table.append(tbody);
    st.rows.forEach((r, k) => {
      const l = number(uid('i6-led'), r[0], 0, 100000);
      const a = number(uid('i6-amt'), r[1], 0, 1000);
      l.setAttribute('aria-label', `Attempt ${k + 1}: ledger`);
      a.setAttribute('aria-label', `Attempt ${k + 1}: amount`);
      const v = el('td');
      inputs.push([l, a, v]);
      tbody.append(h('tr', {}, h('td', {}, l), h('td', {}, a), v));
      l.addEventListener('input', draw);
      a.addEventListener('input', draw);
    });
    function draw() {
      st.lambda = Number(lam.value);
      st.period = Number(per.value);
      lamOut.textContent = st.lambda;
      perOut.textContent = st.period;
      let rec = M.emptyRecord();
      const moved = [];
      for (const [l, a, v] of inputs) {
        if (l.value === '' || a.value === '') { v.replaceChildren(h('span', { class: 'xp-none' }, '—')); continue; }
        const L = Math.round(Number(l.value));
        const x = Math.round(Number(a.value));
        const c = M.charge(rec, st.lambda, st.period, L, x);
        if (c.ok) { rec = c.record; if (x > 0) moved.push({ ledger: L, amount: x }); v.replaceChildren(yes(`accepted (${c.remaining} + ${x} = ${c.total})`)); }
        else v.replaceChildren(no(c.why === 'limit' ? `refused (${c.remaining} + ${x} = ${c.total} > ${st.lambda})` : c.why === 'before-newest' ? 'refused (before the newest charge)' : 'refused'));
      }
      const pts = [...new Set(moved.flatMap((e) => [e.ledger, e.ledger + st.period - 1]))];
      let best = -1;
      let bestL = null;
      for (const L of pts) { const w = M.windowTotal(moved, L, st.period); if (w > best) { best = w; bestL = L; } }
      const none = moved.length && best === 0 ? ' The charges at ledger 0 are in no window (L − P, L].' : '';
      out.textContent = bestL == null ? 'Nothing accepted yet.' : `Σ over the fullest window (${M.sat(bestL, st.period)}, ${bestL}] = ${best} ${best <= st.lambda ? '≤' : '>'} λ = ${st.lambda}; refused charges are not in the sum.${none}`;
      const firstLedger = Math.min(...moved.map((e) => e.ledger));
      let pm = 0;
      for (const e of moved) pm = Math.max(pm, moved.filter((x) => x.ledger >= e.ledger && x.ledger < e.ledger + st.period).reduce((s, x) => s + x.amount, 0));
      out2.textContent = !moved.length ? '' : firstLedger >= 1
        ? `Any ${st.period} consecutive ledgers hold at most ${pm} ${pm <= st.lambda ? '≤' : '>'} λ: the second form holds, since every charge is at ledger 1 or later.`
        : `Any ${st.period} consecutive ledgers: up to ${pm}${pm > st.lambda ? ` > λ; the second form needs every authorization at ledger 1 or later, and a charge is at ledger 0` : ''}.`;
    }
    lam.addEventListener('input', draw);
    per.addEventListener('input', draw);
    zero.addEventListener('change', () => {
      const rows = zero.checked ? [[0, st.lambda], [0, st.lambda], ['', ''], ['', ''], ['', ''], ['', '']] : st.rows;
      inputs.forEach(([l, a], k) => { l.value = rows[k][0]; a.value = rows[k][1]; });
      draw();
    });
    draw();
  };

  INSTANCES['inst-auth-witness'] = (box) => {
    const presets = [['within app current right', 'pay the shop 4 (within the cap)'], ['guess app current right', 'a lost guess'],
      ['over app current right', 'pay the shop 5 (over the cap)'], ['within unlisted current right', 'a key on no rule'], ['account app current right', 'a call to the account']];
    const pick = select(uid('i2'), presets);
    const out = el('div', { 'aria-live': 'polite' });
    box.append(h('p', { class: 'xp-sub' }, 'The shop rule and the game grant’s two rules; the app names one rule per context.'), labelled('Request', pick), out);
    const draw = () => {
      const run = M.E3.run(...pick.value.split(' '));
      if (run.decision.ok) out.replaceChildren(witness(run), h('p', { class: 'xp-result' }, 'Accepted, and every context is allowed by the rule chosen for it, under the signers given.'));
      else out.replaceChildren(h('p', { class: 'xp-result' }, no('refused'), ` at ${plain(refusalWhy(run))}. The statement is about accepted requests, so it holds with nothing to show.`));
    };
    pick.onchange = draw;
    draw();
  };

  function attenuateBox(box, withReplay) {
    const parent = M.E1.parent();
    const checks = M.E1.steps.map(([step, i, param, label]) => [el('input', { type: 'checkbox', checked: true, name: uid('i4') }), step, i, param, label]);
    const drop = el('input', { type: 'checkbox', name: uid('i5') });
    const out = el('div');
    const line = el('p', { class: 'xp-result', 'aria-live': 'polite' });
    box.append(h('div', { class: 'xp-row' }, checks.map(([c, , , , label]) => h('label', { class: 'xp-check' }, c, ' ', label)),
      withReplay ? h('label', { class: 'xp-check' }, drop, ' first drop rule `play`') : null), out, line);
    const draw = () => {
      let rules = parent;
      let origin = [0, 1];
      if (withReplay && drop.checked) { rules = M.attenuate(rules, 'drop_rule', 0).rules; origin = [1]; }
      for (const [c, step, i, param] of checks) {
        if (!c.checked) continue;
        const j = rules.findIndex((r) => r.name === parent[i].name);
        if (j < 0) continue;
        rules = M.attenuate(rules, step, j, param).rules;
      }
      if (withReplay) {
        const r = replayList(parent, rules, origin);
        out.replaceChildren(r.list);
        line.textContent = r.line;
      } else {
        const p = probeTable(parent, rules);
        out.replaceChildren(p.table);
        line.textContent = p.summary;
      }
    };
    for (const [c] of checks) c.addEventListener('change', draw);
    drop.addEventListener('change', draw);
    draw();
  }
  INSTANCES['inst-attenuate-probes'] = (box) => attenuateBox(box, false);
  INSTANCES['inst-trace-replay'] = (box) => attenuateBox(box, true);

  INSTANCES['inst-lower-scoped'] = (box) => {
    const A = 'account';
    const X = ['controller', 'zk'];
    const targets = [['game', 'the game'], ['XLM', 'the XLM contract'], [A, 'the account'], ['controller', 'its adopted recovery controller'], ['zk', 'its zero-knowledge adapter or pool']];
    const pick = select(uid('i8'), targets);
    const derive = button('Derive');
    const out = el('div', { 'aria-live': 'polite' });
    box.append(h('p', { class: 'xp-sub' }, 'A grant document with one rule on the chosen target, lowered on account A, with the excluded set X (the adopted recovery controller, and the zero-knowledge adapter and pool) and generation 0.'),
      h('div', { class: 'xp-row' }, labelled('Rule target', pick), derive), out);
    let derived = 0;
    const probes = [[A, 'a call to the account'], ['controller', 'a call to the recovery controller'], ['zk', 'a call to the adapter or pool']];
    const draw = () => {
      const doc = { recovery: false, rules: [{ name: 'r', contract: pick.value, functions: { except: [] }, conds: [], signers: ['app'], threshold: 1, cap: null, validUntil: null }] };
      const low = M.lowerScoped(doc, A, X, 0);
      if (!low.ok) { out.replaceChildren(h('p', { class: 'xp-result' }, no('target excluded'), `: lowering refuses the document, since ${targets.find((t) => t[0] === pick.value)[1]} is the account or in X. Nothing is installed.`)); return; }
      let rules = low.rules;
      const steps = [];
      for (let k = 0; k < derived; k++) {
        const s = [['restrict_functions', 0, ['transfer', 'guess'], 'restrict its functions'], ['lower_valid_until', 0, 4000, 'add an expiry'], ['add_cond', 0, M.consts.PIN_SHOP, 'add a condition']][k % 3];
        rules = M.attenuate(rules, s[0], s[1], s[2]).rules;
        steps.push(s[3]);
      }
      out.replaceChildren(h('p', {}, yes('lowered'), `: one rule on ${targets.find((t) => t[0] === pick.value)[1]}, generation 0${steps.length ? `; derived by: ${steps.join(', ')}` : ''}.`),
        h('ul', {}, probes.map(([c, label]) => h('li', {}, `${label}: `, rules.some((r) => M.allows(r, { contract: c, fn: 'any', args: [] }, ['app'])) ? yes() : no('no rule allows it')))));
    };
    pick.onchange = () => { derived = 0; draw(); };
    derive.onclick = () => { derived++; draw(); };
    draw();
  };

  INSTANCES['inst-recovery-generation'] = (box) => {
    let gen = 0;
    let grants = [];
    const fresh = () => { gen = 0; grants = [['grant 1 (shop)', 0], ['grant 2 (game)', 0]]; };
    fresh();
    const complete = button('Complete a recovery');
    const issue = button('Issue a new grant');
    const reset = button('Reset');
    const out = el('div', { 'aria-live': 'polite' });
    box.append(h('div', { class: 'xp-row' }, complete, issue, reset), out);
    const draw = (say) => {
      out.replaceChildren(h('p', {}, `Account generation: ${gen}.`), h('ul', {}, grants.map(([name, g]) => {
        const rule = { name, contract: 'XLM', functions: { only: ['transfer'] }, conds: [], signers: ['app'], threshold: 1, cap: null, validUntil: null, generation: g };
        const d = M.authorize([rule], [M.emptyRecord()], [M.transfer('shop', 1)], [0], ['app'], 1000, gen);
        return h('li', {}, `${name}, issued at generation ${g}: `, d.ok ? yes('accepts a transfer') : no(`refuses every nonempty batch (issued at ${g}, current ${gen}); stored until collected`));
      })), ...(say ? [h('p', { class: 'xp-sub' }, say)] : []));
    };
    complete.onclick = () => { gen++; draw(`A completed recovery moved the generation to ${gen}.`); };
    issue.onclick = () => { grants.push([`grant ${grants.length + 1}`, gen]); draw(`Issued at generation ${gen}.`); };
    reset.onclick = () => { fresh(); draw('Reset: generation 0, two grants.'); };
    draw();
  };

  function instance(div) {
    if (div.dataset.ready) return;
    const id = ALIAS[div.dataset.instance] || div.dataset.instance;
    const fn = INSTANCES[id];
    if (!fn) return;
    div.dataset.ready = '1';
    const body = el('div', { class: 'xp xp-inst' });
    const note = banner('MODEL', 'An instance of the statement, computed in the page.');
    // The build wraps the instance in "Try an instance"; a bare one gets its own.
    if (div.closest('details.thm-try')) div.append(note, body);
    else div.append(h('details', { class: 'thm-try' }, h('summary', {}, 'Try an instance'), note, body));
    fn(body);
  }

  // ---------------------------------------------------------------- the other figures
  // fig-proof-paths: pick a statement; the boxes for the objects it is about and the
  // trusted parts it assumes are marked. Reads the statement list's data-objects and
  // data-assumes (li#stmt-<id>), so the figure and the statements cannot disagree.
  CONTROLLERS['proof-paths'] = (fig) => {
    const stmts = [...document.querySelectorAll('[id^="stmt-"][data-objects]')];
    const nodes = [...fig.querySelectorAll('svg [data-node]')];
    if (!stmts.length || !nodes.length) return;
    const name = (id) => (nodes.find((n) => n.dataset.node === id) || {}).dataset?.label || id;
    const list = (ids) => ids.map(name).join(', ');
    const { bar, live } = head(fig);
    const pick = el('select', { 'aria-label': 'Statement', name: `${fig.id}-statement` });
    pick.append(el('option', { value: '' }, 'Every statement'));
    const groups = new Map();
    for (const li of stmts) {
      const key = li.dataset.objects;
      if (!groups.has(key)) {
        groups.set(key, el('optgroup', { label: `About ${list(key.split(' '))}` }));
        pick.append(groups.get(key));
      }
      const strong = li.querySelector('strong');
      groups.get(key).append(el('option', { value: li.id }, squash(strong ? strong.textContent : li.id)));
    }
    bar.append(pick);
    bar.append(el('span', { class: 'fig-key' }, 'Thick amber border: what it is about. Thick blue border: what it assumes.'));
    const link = el('a', { hidden: '' }, 'Read the statement');
    bar.append(link);
    pick.onchange = () => {
      const li = pick.value && document.getElementById(pick.value);
      const objs = li ? li.dataset.objects.split(' ') : [];
      const ass = li ? (li.dataset.assumes || '').split(' ').filter(Boolean) : [];
      for (const n of nodes) {
        n.classList.toggle('sel-obj', objs.includes(n.dataset.node));
        n.classList.toggle('sel-tr', ass.includes(n.dataset.node));
      }
      link.hidden = !li;
      if (li) link.href = `#${li.id}`;
      live.textContent = li ? `${squash(pick.selectedOptions[0].textContent)} About: ${list(objs)}. Assumes: ${list(ass)}.` : '';
    };
  };

  // fig-same-task: a stepper over the recorded requests, plus recorded repeated sends
  // ("Send again" shows the next recorded send of a lane; it decides nothing) and a
  // switch between the recorded contracts per payment and what is documented but not run.
  CONTROLLERS['same-task'] = (fig, helpers) => {
    stepper(fig, helpers);
    const svgs = [...fig.querySelectorAll('svg')];
    const bar = el('div', { class: 'fig-bar fig-bar2', role: 'group', 'aria-label': 'Repeated payments and contracts' });
    const live = el('p', { class: 'fig-live', 'aria-live': 'polite' });
    svgs[svgs.length - 1].after(bar, live);
    const lanes = new Map();
    for (const g of fig.querySelectorAll('svg [data-lane]')) {
      lanes.set(g.dataset.lane, Math.max(lanes.get(g.dataset.lane) || 0, Number(g.dataset.send)));
    }
    const names = { percall: 'Send again: per-call bound', window: 'Send again: window' };
    for (const [lane, n] of lanes) {
      let pos = 0;
      const btn = button(names[lane] || `Send again: ${lane}`);
      btn.onclick = () => {
        pos = pos >= n ? 1 : pos + 1;
        let say = '';
        for (const g of fig.querySelectorAll(`svg [data-lane="${lane}"]`)) {
          const k = Number(g.dataset.send);
          g.classList.toggle('off', k > pos);
          g.dataset.state = k === pos ? 'current' : 'past';
          if (k === pos) say = g.dataset.say;
        }
        live.textContent = pos === n ? `${say} That was the last recorded send; press again to start over.` : say;
      };
      bar.append(btn);
    }
    const toggle = el('span', { class: 'fig-events', role: 'group', 'aria-label': 'Contracts per payment' });
    const views = [['recorded', 'Recorded per payment'], ['documented', 'Documented, not run']];
    const btns = views.map(([v, label]) => {
      const b = button(label, { 'aria-pressed': String(v === 'recorded') });
      b.onclick = () => {
        for (const g of fig.querySelectorAll('svg [data-view]')) g.classList.toggle('off', g.dataset.view !== v);
        for (const [w, x] of btns) x.setAttribute('aria-pressed', String(w === v));
        const shown = svgs.find((s) => s.getBoundingClientRect().width > 0) || svgs[0];
        live.textContent = [...shown.querySelectorAll(`[data-view="${v}"]`)].map((g) => g.dataset.say).join(' ');
      };
      toggle.append(b);
      return [v, b];
    });
    bar.append(toggle);
  };

  // ---------------------------------------------------------------- reading paths
  // <nav class="reading-paths"> holding anchors with data-reading (or data-path-choice)="5|20|all"
  // (the no-JS form) becomes a radio group. Blocks carry data-path="5", "20" or "5 20"; the
  // 5-minute path keeps blocks tagged 5, the 20-minute path those tagged 5 or 20. A section with
  // anything left out keeps its heading and lede and gets an Expand button. A link or a URL hash
  // into a shortened section expands it and lands on the target. Print shows everything.
  const RP_KEY = 'perch-reading-path';
  let rpReveal = () => {};
  function readingPaths(nav) {
    if (nav.dataset.ready || !document.querySelector('[data-path]')) return;
    nav.dataset.ready = '1';
    const choices = [...nav.querySelectorAll('[data-reading], [data-path-choice]')].map((a) => [a.dataset.reading ?? a.dataset.pathChoice, squash(a.textContent)]);
    if (!choices.length) return;
    const name = uid('path');
    const live = el('p', { class: 'rp-live', 'aria-live': 'polite' });
    const fs = h('fieldset', { class: 'rp' }, h('legend', {}, 'Reading path'));
    const sections = [...document.querySelectorAll('main section[id]')];
    const keepAlways = (c) => c.matches('h2, .lede, .alias, .rp-expand');
    const wanted = (v) => (e) => (e.dataset.path || '').split(' ').some((p) => p === '5' || (v === '20' && p === '20'));
    function expand(s, focus) {
      for (const c of s.children) c.classList.remove('rp-hide');
      for (const b of s.querySelectorAll(':scope > .rp-expand')) b.remove();
      if (focus) {
        const h2 = s.querySelector(':scope > h2');
        if (h2) { h2.setAttribute('tabindex', '-1'); h2.focus({ preventScroll: true }); }
      }
    }
    function apply(v, say) {
      let collapsed = 0;
      for (const s of sections) {
        expand(s, false);
        if (v === 'all') continue;
        const want = wanted(v);
        let hidden = 0;
        for (const c of [...s.children]) {
          if (keepAlways(c) || want(c) || [...c.querySelectorAll('[data-path]')].some(want)) continue;
          c.classList.add('rp-hide');
          hidden++;
        }
        if (!hidden) continue;
        collapsed++;
        const more = button('Expand this section', { class: 'rp-expand' });
        more.onclick = () => { expand(s, true); live.textContent = `${squash((s.querySelector(':scope > h2') || s).textContent)}: expanded.`; };
        const after = s.querySelector(':scope > .lede') || s.querySelector(':scope > h2');
        if (after) after.after(more); else s.prepend(more);
      }
      if (say) live.textContent = v === 'all' ? 'Whole paper: every section shown.' : `${v}-minute path: ${collapsed} sections shortened; each keeps its heading, its summary and an Expand button. Links into a shortened section expand it.`;
      try { sessionStorage.setItem(RP_KEY, v); } catch { /* storage unavailable */ }
    }
    // Expand the shortened section (and any closed <details>) holding `target`.
    rpReveal = (target) => {
      if (!target) return false;
      const s = target.closest('main section[id]');
      let changed = false;
      if (s && target.closest('.rp-hide')) { expand(s, false); changed = true; }
      for (let d = target.closest('details:not([open])'); d; d = d.parentElement && d.parentElement.closest('details:not([open])')) { d.open = true; changed = true; }
      return changed;
    };
    let start = 'all';
    try { start = sessionStorage.getItem(RP_KEY) || 'all'; } catch { /* storage unavailable */ }
    if (!choices.some(([v]) => v === start)) start = 'all';
    for (const [v, label] of choices) {
      const r = el('input', { type: 'radio', name, value: v, checked: v === start });
      r.addEventListener('change', () => apply(v, true));
      fs.append(h('label', { class: 'xp-radio' }, r, ` ${label}`));
    }
    nav.replaceChildren(fs, live);
    apply(start, false);
  }
  // Theorem and definition cards: the head is a heading for assistive technology (one level
  // below the section's last heading), and the plain reading describes the <math> itself.
  function theoremCards() {
    for (const head of document.querySelectorAll('.thm-head')) {
      if (/^H[1-6]$/.test(head.tagName)) continue;
      const sec = head.closest('section');
      let level = 3;
      if (sec) {
        const hs = [...sec.querySelectorAll('h2, h3, h4')].filter((x) => x.compareDocumentPosition(head) & Node.DOCUMENT_POSITION_FOLLOWING);
        if (hs.length) level = Math.min(6, Number(hs[hs.length - 1].tagName[1]) + 1);
      }
      head.setAttribute('role', 'heading');
      head.setAttribute('aria-level', String(level));
    }
    for (const box of document.querySelectorAll('.thm-math[aria-describedby]')) {
      const m = box.querySelector('math');
      if (m && !m.hasAttribute('aria-describedby')) m.setAttribute('aria-describedby', box.getAttribute('aria-describedby'));
      box.removeAttribute('aria-describedby');
    }
    // A formula wider than its column scrolls sideways; make that region reachable by keyboard.
    const boxes = [...document.querySelectorAll('.thm-math')];
    const mark = () => {
      for (const box of boxes) {
        const wide = box.scrollWidth > box.clientWidth + 1;
        if (wide) { box.setAttribute('tabindex', '0'); box.setAttribute('aria-label', 'Formula; scroll sideways for the rest'); } else { box.removeAttribute('tabindex'); box.removeAttribute('aria-label'); }
      }
    };
    mark();
    if (boxes.length && 'ResizeObserver' in window) {
      let w = document.documentElement.clientWidth;
      new ResizeObserver(() => { if (document.documentElement.clientWidth !== w) { w = document.documentElement.clientWidth; mark(); } }).observe(document.documentElement);
    }
  }
  const hashTarget = (hash) => {
    if (!hash || hash.length < 2) return null;
    try { return document.getElementById(decodeURIComponent(hash.slice(1))); } catch { return null; }
  };
  // A link into this page: reveal the target before the browser scrolls to it.
  document.addEventListener('click', (e) => {
    const a = e.target.closest && e.target.closest('a[href*="#"]');
    if (!a || a.origin !== location.origin || a.pathname !== location.pathname) return;
    rpReveal(hashTarget(a.hash));
  }, true);
  window.addEventListener('hashchange', () => {
    const t = hashTarget(location.hash);
    if (rpReveal(t)) t.scrollIntoView({ behavior: 'instant' });
  });

  function init() {
    for (const nav of document.querySelectorAll('.reading-paths')) {
      try { readingPaths(nav); } catch (err) { console.error('reading paths:', err); }
    }
    const helpers = (fig, detail) => ({ el, head, button, detail, stepper });
    for (const fig of document.querySelectorAll('figure.fig')) {
      const kind = fig.dataset.interactive;
      fig.classList.add('js');
      try {
        const detail = details(fig);
        if (kind === 'stepper') stepper(fig, { detail });
        else if (kind && CONTROLLERS[kind]) CONTROLLERS[kind](fig, helpers(fig, detail));
      } catch (err) {
        console.error(`figure ${fig.id}:`, err);
        fig.classList.remove('js', 'xp-on');
      }
    }
    for (const host of document.querySelectorAll('[data-explorable]:not(figure)')) {
      try { if (CONTROLLERS[host.dataset.explorable]) CONTROLLERS[host.dataset.explorable](host, helpers(host, null)); } catch (err) {
        console.error(`explorable ${host.id || host.dataset.explorable}:`, err);
        host.classList.remove('xp-on');
      }
    }
    for (const embed of document.querySelectorAll('.sim-embed')) {
      try { simEmbed(embed); } catch (err) { console.error('simulation embed:', err); }
    }
    for (const div of document.querySelectorAll('.thm-instance[data-instance]')) {
      try { instance(div); } catch (err) { console.error(`instance ${div.dataset.instance}:`, err); }
    }
    theoremCards();
    // Arrived with a hash: everything is mounted now, so reveal the target and land on it.
    const t = hashTarget(location.hash);
    if (t) { rpReveal(t); requestAnimationFrame(() => t.scrollIntoView({ behavior: 'instant' })); }
  }
  window.PerchFigures = { register: (name, fn) => { CONTROLLERS[name] = fn; }, instances: INSTANCES };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else queueMicrotask(init);
})();
