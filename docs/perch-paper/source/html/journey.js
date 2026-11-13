// A small, illustrative shell around the existing paper model. This is not
// contract execution; signature outcomes are scenario inputs, not crypto.
(() => {
  const SCENARIOS = {
    pay: { amount: 4, to: 'shop', signature: true, generation: 0 },
    over: { amount: 5, to: 'shop', signature: true, generation: 0 },
    recipient: { amount: 1, to: 'elsewhere', signature: true, generation: 0 },
    signature: { amount: 1, to: 'shop', signature: false, generation: 0 },
    recovery: { amount: 1, to: 'shop', signature: true, generation: 1 },
  };
  function evaluate(name, limit = 10, period = 100) {
    const s = SCENARIOS[name];
    if (!s) throw new Error('Unknown decision scenario');
    const rule = { contract: 'XLM', functions: { only: ['transfer'] },
      conds: [{ i: 0, op: 'eq', v: 'account' }, { i: 1, op: 'eq', v: 'shop' }],
      signers: ['app'], threshold: 1, validUntil: null, generation: 0,
      cap: { arg: 2, limit, period } };
    const record = { history: [{ ledger: 1000, amount: 6 }], total: 6 };
    const request = { contract: 'XLM', fn: 'transfer', args: ['account', s.to, s.amount] };
    const model = globalThis.PerchModel.checkAuth([rule], [record], [request], [0], ['app'], 1001, s.generation);
    const failed = !model.ok ? (model.check === 'generation' ? 0 : model.check === 'charge' ? 2 : 1)
      : !s.signature ? 3 : null;
    const ok = failed === null;
    return { ok, failed, amount: s.amount, to: s.to, total: ok ? model.records[0].total : record.total,
      limit, spent: record.total, states: [0, 1, 2, 3, 4].map(i => failed === null || i < failed ? 'pass' : i === failed ? 'fail' : 'unreached') };
  }
  globalThis.PerchJourney = { evaluate };
  if (typeof document === 'undefined') return;
  function mount(host) {
    const limit = Number(host.dataset.limit.replaceAll(',', ''));
    const period = Number(host.dataset.period.replaceAll(',', ''));
    let result;
    const descriptions = () => [
      result.failed === 0 ? 'Recovery advanced the account generation. This earlier grant is stale, so the request stops here.' : 'The account finds the selected grant. It belongs to the current generation and has not expired.',
      result.to === 'shop' ? 'The target is XLM, the function is transfer, the sender is this account, and the recipient is the shop.' : 'The grant names the shop. A different recipient fails its argument predicate.',
      `${result.spent} already spent + ${result.amount} requested ${result.spent + result.amount <= result.limit ? '≤' : '>'} ${result.limit} XLM. Any new record is tentative until authentication succeeds.`,
      result.failed === 3 ? 'The supplied signature is invalid. The account refuses without committing the tentative budget update.' : 'The account authenticates the supplied app signature. In this model the signature outcome is a preset; the real contract verifies it.',
      result.ok ? `All checks passed. The account commits ${result.total} XLM charged to the window; the host can continue the authorized call. A later transaction failure rolls this back.` : 'A prior check failed. No spending record is committed and this request cannot proceed.',
    ];
    const inspect = (index) => {
      host.querySelectorAll('[data-flow-inspect]').forEach(b => b.setAttribute('aria-pressed', String(Number(b.dataset.flowInspect) === index)));
      host.querySelectorAll('[data-flow-stage]').forEach(n => n.classList.toggle('selected', Number(n.dataset.flowStage) === index));
      const skipped = result.states[index] === 'unreached';
      host.querySelector('[data-flow-detail]').textContent = `${skipped ? 'Not reached. ' : ''}${descriptions()[index]}`;
    };
    const choose = (name) => {
      result = evaluate(name, limit, period);
      host.querySelectorAll('[data-flow-preset]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.flowPreset === name)));
      host.querySelectorAll('[data-flow-stage]').forEach(n => n.dataset.state = result.states[Number(n.dataset.flowStage)]);
      host.querySelector('[data-flow-verdict]').textContent = result.ok ? '✓ Allowed' : '× Refused';
      host.querySelector('.journey-result').dataset.verdict = result.ok ? 'allow' : 'refuse';
      host.querySelector('[data-flow-explanation]').textContent = result.ok ? `${result.spent} + ${result.amount} = ${result.total} ≤ ${limit} XLM.`
        : ['Earlier grant invalidated by recovery.', 'Recipient outside the grant.', `${result.spent} + ${result.amount} > ${limit} XLM.`, 'Signature verification failed.'][result.failed];
      host.querySelector('[data-flow-budget]').textContent = `${limit - result.total} XLM left${result.ok ? '' : ' · budget unchanged'}`;
      inspect(result.failed ?? 4);
    };
    host.querySelectorAll('[data-flow-preset]').forEach(b => b.addEventListener('click', () => choose(b.dataset.flowPreset)));
    host.querySelectorAll('[data-flow-inspect]').forEach(b => b.addEventListener('click', () => inspect(Number(b.dataset.flowInspect))));
    choose('pay');
    host.querySelectorAll('[hidden]').forEach(e => { e.hidden = false; });
    host.classList.add('journey-ready');
  }
  function init() { document.querySelectorAll('.paper-journey').forEach(mount); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
