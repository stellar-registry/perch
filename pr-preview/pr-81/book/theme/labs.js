/* Local-only progressive enhancement. No eval, network requests, or persistence. */
(function () {
  'use strict';
  const model = globalThis.PerchBookLab;
  let sequence = 0;
  const words = { T: 'True', F: 'False', U: 'Unknown' };
  function el(tag, text, attrs = {}) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    return node;
  }
  function select(label, entries, value, parent) {
    const id = `perch-control-${++sequence}`;
    const wrap = el('label', label, { for: id });
    const control = el('select', undefined, { id });
    entries.forEach(([key, text]) => control.append(el('option', text, { value: key })));
    control.value = value;
    wrap.append(control); parent.append(wrap);
    return control;
  }
  function checkbox(label, checked, parent) {
    const wrap = el('label', undefined, { class: 'lab-checkbox' });
    const control = el('input', undefined, { type: 'checkbox' });
    control.checked = checked;
    wrap.append(control, document.createTextNode(label)); parent.append(wrap);
    return control;
  }
  function button(label, run, parent) {
    const b = el('button', label, { type: 'button' });
    b.addEventListener('click', run); parent.append(b); return b;
  }
  function status(parent) {
    const node = el('p', '', { role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true', class: 'lab-result' });
    parent.append(node); return node;
  }
  function releaseLab(host, body) {
    const rule = JSON.parse(host.querySelector('[data-policy-fixture]').textContent).rules.find(r => r.name === 'ci-publish');
    const fields = el('fieldset'); fields.append(el('legend', 'Change the proposed call'));
    const grid = el('div', undefined, { class: 'lab-grid' }); fields.append(grid); body.append(fields);
    const target = select('Target contract', [['registry', 'The registry in this rule'], ['other', 'A different contract']], 'registry', grid);
    const fn = select('Function', [...rule.functions.map(n => [n, n]), ['upgrade', 'upgrade']], rule.functions[0], grid);
    const argument = select(`Publisher argument (index ${rule.args[0].index})`, [
      ['self', 'Smart account address'], ['other', 'A different address'],
      ['missing', 'Missing argument'], ['wrong-type', 'String instead of address'],
    ], 'self', grid);
    const ledgerLabel = el('label', 'Ledger sequence');
    const ledger = el('input', undefined, { type: 'number', min: '0', max: '4294967295', step: '1' });
    ledger.value = rule['not-after-ledger'] - 1;
    ledgerLabel.append(ledger); grid.append(ledgerLabel);
    const signed = checkbox('CI signer authenticated (assumed for this example)', true, fields);
    const policyFields = el('fieldset'); policyFields.append(el('legend', 'Change the policy'));
    const restrict = checkbox('Keep the function allowlist', true, policyFields); body.append(policyFields);
    const presets = el('div', undefined, { class: 'lab-buttons', 'aria-label': 'Example calls' }); body.append(presets);
    const result = status(body);
    const checks = el('ul', undefined, { class: 'lab-checks' }); body.append(checks);
    const changed = el('details'); changed.append(el('summary', 'See the rule being evaluated'));
    const json = el('pre'); const code = el('code', '', { class: 'language-json' }); json.append(code); changed.append(json); body.append(changed);
    const stepper = el('details', undefined, { class: 'lab-stepper' });
    stepper.open = host.dataset.perchLab === 'trace';
    stepper.append(el('summary', 'Step through the interpreter program'));
    stepper.append(el('p', 'This trace explores the program separately. On-chain, a wrong target or expired rule stops authorization before the interpreter runs.'));
    const trace = el('p', '', { class: 'lab-stack' }); stepper.append(trace);
    const actions = el('div', undefined, { class: 'lab-buttons' }); stepper.append(actions);
    let current = 0, evaluated;
    const back = button('Previous step', () => { current--; showStep(); }, actions);
    const next = button('Next step', () => { current++; showStep(); }, actions);
    const stepStatus = status(stepper);
    body.append(stepper);
    function showStep() {
      const step = evaluated.trace[current];
      trace.textContent = `${step.op} → stack [${step.stack.join(', ')}]`;
      stepStatus.textContent = `Step ${current} of ${evaluated.trace.length - 1}. ${step.note}`;
      back.disabled = current === 0; next.disabled = current === evaluated.trace.length - 1;
    }
    function update() {
      evaluated = model.release(rule, { target: target.value, fn: fn.value, argument: argument.value,
        ledger: ledger.value, signed: signed.checked, restrictFunctions: restrict.checked });
      current = 0; checks.replaceChildren();
      stepper.hidden = Boolean(evaluated.error); changed.hidden = Boolean(evaluated.error);
      if (evaluated.error) {
        result.textContent = evaluated.error; result.dataset.verdict = 'U'; return;
      }
      result.textContent = `${evaluated.allowed ? 'This rule allows' : 'This rule does not allow'} this call. Combined teaching result: ${words[evaluated.combined]}.`;
      result.dataset.verdict = evaluated.combined;
      for (const check of evaluated.checks) {
        const item = el('li'); item.append(el('strong', `${words[check.value]} — ${check.label}. `), document.createTextNode(check.reason)); checks.append(item);
      }
      code.textContent = JSON.stringify(evaluated.rule, null, 2);
      showStep();
    }
    function reset() {
      target.value = 'registry'; fn.value = rule.functions[0]; argument.value = 'self';
      ledger.value = rule['not-after-ledger'] - 1; signed.checked = true; restrict.checked = true;
    }
    button('Reset to allowed call', () => { reset(); update(); }, presets);
    button('Try a missing argument', () => { reset(); argument.value = 'missing'; update(); }, presets);
    button('Try the expiry boundary', () => { reset(); ledger.value = rule['not-after-ledger']; update(); }, presets);
    button('Try a wider policy', () => { reset(); fn.value = 'upgrade'; restrict.checked = false; update(); }, presets);
    fields.addEventListener('input', update); fields.addEventListener('change', update);
    policyFields.addEventListener('change', update);
    update();
  }
  function logicLab(host, body) {
    const fields = el('fieldset'); fields.append(el('legend', 'Combine verdicts'));
    const grid = el('div', undefined, { class: 'lab-grid' }); fields.append(grid); body.append(fields);
    const entries = Object.entries(words);
    const a = select('Verdict A', entries, 'U', grid);
    const operation = select('Operation', [['and', 'A AND B'], ['or', 'A OR B'], ['not', 'NOT A']], 'not', grid);
    const b = select('Verdict B', entries, 'T', grid);
    const result = status(body);
    function update() {
      b.disabled = operation.value === 'not';
      const v = model[operation.value](a.value, b.value);
      const expression = operation.value === 'not' ? `NOT ${words[a.value]}` : `${words[a.value]} ${operation.value.toUpperCase()} ${words[b.value]}`;
      result.textContent = `${expression} = ${words[v]}. ${v === 'T' ? 'This final verdict allows.' : 'This final verdict denies.'} ${v === 'U' ? 'Not enough information is still not permission.' : operation.value === 'or' && (a.value === 'U' || b.value === 'U') ? 'A definite True branch wins OR.' : ''}`;
      result.dataset.verdict = v;
    }
    fields.addEventListener('change', update);
    button('Reset verdicts', () => { a.value = 'U'; b.value = 'T'; operation.value = 'not'; update(); }, body);
    update();
  }
  function quiz(host, body) {
    const data = JSON.parse(host.querySelector('[data-quiz]').textContent);
    const fields = el('fieldset'); fields.append(el('legend', data.question));
    const name = `perch-quiz-${++sequence}`;
    const choices = data.answers.map((answer, i) => {
      const label = el('label', undefined, { class: 'lab-choice' });
      const input = el('input', undefined, { type: 'radio', name, value: String(i) });
      label.append(input, document.createTextNode(answer.text)); fields.append(label); return input;
    });
    body.append(fields);
    const actions = el('div', undefined, { class: 'lab-buttons' }); body.append(actions);
    const feedback = status(body);
    button('Check my answer', () => {
      const index = choices.findIndex(choice => choice.checked);
      if (index < 0) { feedback.textContent = 'Choose an answer first.'; return; }
      const answer = data.answers[index];
      feedback.textContent = `${answer.correct ? 'Correct.' : 'Try again.'} ${answer.feedback}`;
      feedback.dataset.verdict = answer.correct ? 'T' : 'F';
    }, actions);
    button('Reset question', () => { choices.forEach(c => { c.checked = false; }); feedback.textContent = ''; delete feedback.dataset.verdict; }, actions);
    fields.addEventListener('change', () => { feedback.textContent = ''; delete feedback.dataset.verdict; });
  }
  // Native details stay collapsed when printed in some engines. Expand them
  // for print, then restore each reader's disclosure state afterward.
  let closedForPrint = [];
  window.addEventListener('beforeprint', () => {
    if (closedForPrint.length) return;
    closedForPrint = Array.from(document.querySelectorAll('details:not([open])'));
    closedForPrint.forEach(detail => { detail.open = true; });
  });
  window.addEventListener('afterprint', () => {
    closedForPrint.forEach(detail => { detail.open = false; });
    closedForPrint = [];
  });
  document.querySelectorAll('[data-perch-lab]').forEach(host => {
    const body = el('div', undefined, { class: 'lab-interactive' });
    try {
      if (host.dataset.perchLab === 'logic') logicLab(host, body);
      else if (host.dataset.perchLab === 'quiz') quiz(host, body);
      else releaseLab(host, body);
      host.append(body); host.dataset.ready = 'true';
    } catch (error) {
      // Leave the static explanation visible if assets or fixture shapes change.
      console.error('Perch Book interactive example unavailable:', error);
    }
  });
})();
