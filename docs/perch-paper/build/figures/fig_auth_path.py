"""fig-auth-path: one authorization in six stages (explorable E3; static form).

Writes the wide and narrow SVG and fig-auth-path.steps.json (the algorithm figure's text,
which the LaTeX edition prints as a table). The stages and their exits restate
fig-check-auth's nine steps; error numbers come from the facts. The right column,
"where each scenario stops", is computed with perchmodel.py (rule-core's check_auth), and
the forged-signer exit quotes the recorded run (fig-sim.run.json). The <g data-stage>,
<g data-check> and <g data-exit> groups are the controller's hooks; marks carry
data-print="no".
"""
import html
import json
import re
from figlib import SVG, FIGDIR, fact, num, wrap, arrow_down
import perchmodel as M

FID = 'fig-auth-path'
RUN = json.loads((FIGDIR / 'fig-sim.run.json').read_text())

# (key, title, steps.json text, short text for the SVG, exits, assurance)
STAGES = [
    ('host', 'Host call',
     'The Soroban host calls `__check_auth(signature_payload, auth payload, contexts)`; the auth payload names one '
     'rule per context (`context_rule_ids`) and the claimed signers.',
     'The host calls `__check_auth`: the contexts, one named rule per context, the claimed signers.',
     [], 'trusted (host)'),
    ('guards', 'Guards',
     'Refuse a context calling a reserved hook name ({{fact:reserved-hook-names}}), an account frozen during a '
     'recovery (the vision paper), and a selected grant rule on the account\u2019s adopted recovery contracts. '
     'A recovery completion leaves here.',
     'Reserved hook names, an account frozen during a recovery, a grant rule on the account\u2019s adopted recovery contracts.',
     ['`ReservedFunction` ({{fact:auth-error-reserved-function}})', '`AccountFrozen` ({{fact:auth-error-account-frozen}})',
      '`GrantEscalation` ({{fact:auth-error-grant-escalation}})', 'a completion: decided by the recovery controller'],
     'tested'),
    ('select', 'Select rules',
     'Resolve each named rule ID to a stored rule and its spending record; the account does not search.',
     'Look up each named rule and its spending record; no search.',
     ['`ContextRuleNotFound` ({{fact:oz-error-context-rule-not-found}})'], 'tested'),
    ('decide', 'Decide',
     '`rule_eval::check_auth` maps the rules, records, contexts, choices, claimed signers, ledger and generation to the '
     'next records or a refusal. It reads no storage and checks no signature.',
     '`rule_eval::check_auth`: no storage read, no signature checked.',
     ['stale grant: `StaleGrant` ({{fact:auth-error-stale-grant}})',
      'otherwise `RuleEvalRefused` ({{fact:auth-error-rule-eval-refused}})'], 'proved'),
    ('authenticate', 'Authenticate',
     'Hash the payload, the account and the rule IDs into a digest; each external signer’s verifier contract '
     'checks it (trusted); a delegated signer authorizes through the host.',
     'External signers: verifier checks the digest. Delegated signers: host checks approval.',
     ['bad signature: the verifier traps ({{fact:verifier-trap-error}} for Ed25519)',
      '`ExternalVerificationFailed` ({{fact:oz-error-external-verification-failed}})'], 'tested; verifier trusted'),
    ('store', 'Store', 'Store each changed spending record. Authorized.', 'Write each changed spending record. Authorized.',
     [], 'tested'),
]
BOX = {'host': 'trusted', 'decide': 'proved', 'authenticate': 'trusted'}
CHECKS = [('found', 'rule found'), ('unexpired', 'unexpired'), ('generation', 'current generation'),
          ('target', 'target'), ('function', 'function'), ('arguments', 'arguments'),
          ('threshold', 'threshold'), ('signers', 'every signer used'), ('charge', 'charge')]
CHECK_LABEL = dict(CHECKS)

# The printed scenarios: (request, signer, grant, rule named, label).
SCENARIOS = [
    ('within', 'app', 'current', 'right', 'pay the shop 4, within the cap'),
    ('guess', 'app', 'current', 'right', 'a lost guess'),
    ('over', 'app', 'current', 'right', 'pay the shop 5, over the cap'),
    ('account', 'app', 'current', 'right', 'a call to the account'),
    ('within', 'unlisted', 'current', 'right', 'a key on no rule'),
    ('within', 'app', 'expired', 'right', 'an expired grant'),
    ('within', 'app', 'stale', 'right', 'a grant from before a recovery'),
    ('within', 'app', 'current', 'wrong', 'the wrong rule named'),
    ('within', 'forged', 'current', 'right', 'another key signing as the app'),
]
SETUP = ('MODEL. Rules: `shop` (XLM to the shop, 10 per 100 ledgers; its window holds 6), and the game grant’s '
         '`guess` and `spend` (XLM, 2 per 100). Signed by the app’s key unless noted.')


def expand(s):
    """Facts resolved, for the SVG."""
    return re.sub(r'\{\{fact:([^}]+)\}\}', lambda m: fact(m.group(1)).replace('`', ''), s)


def recorded_trap():
    """The verifier's error when another key signs in the app's name, from the recorded run."""
    for st in RUN['steps']:
        if st['request'].get('signer') == 'forged':
            errs = [h for h in st['designs']['perch']['hops'] if 'error' in h and h['contract'] == 'Ed25519 verifier']
            inner = errs[0]['error'][len('Error('):-1]
            kind, _, rest = inner.partition('(')
            return f'Error({kind}, {rest.rstrip(")")})', st['command']
    raise SystemExit('fig-sim.run.json has no forged-signer step')


def why(run):
    """The model's reason a run stopped, or what it charged."""
    d = run['decision']
    if not d['ok']:
        c = d['check']
        if c == 'charge':
            ch = d['charge']
            return f'charge: {ch["remaining"]} + {ch["amount"]} = {ch["total"]} > {ch["limit"]}'
        if c == 'threshold':
            return 'threshold: 0 of 1 listed signers'
        return CHECK_LABEL[c]
    i, ch = d['charges'][-1]
    r = run['rules'][run['choices'][i]]
    return f'accepted; `{r["name"]}` window {ch["remaining"]} + {ch["total"] - ch["remaining"]} = {ch["total"]} of {r["cap"]["limit"]}'


def exits():
    trap, cmd = recorded_trap()
    out = {k: [] for k, *_ in STAGES}
    for req, signer, grant, named, label in SCENARIOS:
        run = M.e3_run(req, signer, grant, named)
        if run['stage'] == 'authenticate':
            text = f'{label}: the decision accepts; the verifier traps (recorded run, command {cmd}: {trap})'
        else:
            text = f'{label}: {why(run)}'
        out[run['stage']].append((f'{req} {signer} {grant} {named}', text, run['stage'] == 'store'))
    return out


def marks(s, x, y):
    """Pass and stop marks, shown by the controller only."""
    s.add('<g data-mark="pass" data-print="no" class="off">')
    s.check(x, y)
    s.close()
    s.add('<g data-mark="stop" data-print="no" class="off">')
    s.cross(x + 6, y + 6, 5)
    s.path(f'M{num(x + 15)} {num(y - 1)}V{num(y + 13)}', 'fl-d')
    s.close()


def exit_mark(s, x, y, ok):
    """Accepted: a check. Stopped: a cross and a bar end."""
    if ok:
        s.check(x, y - 11, 'gl')
    else:
        s.cross(x + 5, y - 5, 4)
        s.path(f'M{num(x + 13)} {num(y - 12)}V{num(y + 1)}', 'fl-d')


def check_rows(s, x, y, w, cols, draw=True):
    """The decision's checks as small boxes, `cols` per row; returns height."""
    cw = (w - (cols - 1) * 6) / cols
    if draw:
        for k, (key, label) in enumerate(CHECKS):
            cx = x + (k % cols) * (cw + 6)
            cy = y + (k // cols) * 30
            s.open(data_check=key)
            s.box(cx, cy, cw, 26, 'tested', 4)
            s.text(cx + 8, cy + 18, label, 'x', 14)
            marks(s, cx + cw - 24, cy + 7)
            s.close()
    return (len(CHECKS) + cols - 1) // cols * 30


def stage(s, x, y, w, n, st, size, h=None):
    """A stage box: title, text, the account's exits, and for the decision its checks. Returns height."""
    key, title, _, short, ex, _ = st
    kind = BOX.get(key, 'tested')
    left = x + 12 + (14 if kind == 'trusted' else 0)
    tw = x + w - 12 - left
    rows = wrap(short, tw - 26, size)
    erows = wrap('exits: ' + '; '.join(expand(e) for e in ex), tw, 14) if ex else []
    ch = check_rows(s, 0, 0, w - 24, 2, False) + 12 if key == 'decide' else 0
    natural = 44 + (len(rows) - 1) * 18 + (len(erows) * 17 + 4 if erows else 0) + ch + 12
    if h is None:
        return natural
    s.open(data_stage=key)
    s.box(x, y, w, h, kind, 6)
    s.text(left, y + 24, f'{n}  {title}', 't', size)
    yy = s.lines(left, y + 44, rows, 'x', size, lh=18)
    if erows:
        yy = s.lines(left, yy + 21, erows, 'm', 14, lh=17)
    if key == 'decide':
        check_rows(s, x + 12, yy + 10, w - 24, 2)
    marks(s, x + w - 26, y + 12)
    s.close()
    return h


def draw(narrow):
    W = 340 if narrow else 760
    size = 14 if narrow else 15
    s = SVG(FID, W, narrow=narrow)
    trap, cmd = recorded_trap()
    s.root_attrs['data-recorded-trap'] = trap
    s.root_attrs['data-recorded-command'] = str(cmd)
    ex = exits()
    s.text(2, 16, 'THE ACCOUNT’S STAGES AND EXITS', 't tag', 14)
    if not narrow:
        s.text(368, 16, 'WHERE EACH SCENARIO STOPS', 't tag', 14)
        s.lines(368, 36, wrap(SETUP, 388, 14), 'm', 14, lh=17)
        y = 30
    else:
        y = s.lines(2, 36, wrap(SETUP, 334, 14), 'm', 14, lh=17) + 14
    sx, sw = 2, (W - 4 if narrow else 352)
    for n, st in enumerate(STAGES, 1):
        key = st[0]
        h = stage(s, sx, y, sw, n, st, size)
        if not narrow:
            ey = max(y + 20, 130)
            s.open(data_exits=key)
            for sid, line, ok in ex[key]:
                rows = wrap(line, 368, 14)
                s.add(f'<g data-exit="{html.escape(sid)}">')
                exit_mark(s, 368, ey, ok)
                s.lines(388, ey, rows, 'x', 14, lh=17)
                s.close()
                ey += len(rows) * 17 + 6
            if key == 'decide':
                s.lines(388, ey + 4, ['Every refusal here: nothing written,', 'no verifier called.'], 'm', 14, lh=17)
                ey += 44
            s.close()
            h = max(h, ey - y - 4)
        stage(s, sx, y, sw, n, st, size, h)
        y += h
        if narrow and ex[key]:
            y += 8
            s.open(data_exits=key)
            for sid, line, ok in ex[key]:
                rows = wrap(line, 304, 14)
                s.add(f'<g data-exit="{html.escape(sid)}">')
                exit_mark(s, 6, y + 17, ok)
                s.lines(28, y + 17, rows, 'x', 14, lh=17)
                s.close()
                y += len(rows) * 17 + 6
            if key == 'decide':
                y = s.lines(28, y + 17, wrap('Every refusal here: nothing written, no verifier called.', 304, 14), 'm', 14, lh=17) + 6
            s.close()
        if n < len(STAGES):
            arrow_down(s, sx + 40, y + 2, y + 20, 'fl-m', 'perch-ah-m')
            y += 24
    s.h = y + 4
    return s


def steps():
    st = {
        'intro': 'One authorization through `__check_auth` at the pinned build, in six stages.',
        'steps': [{'n': str(n), 'text': f'**{title}.** {text}', 'exits': ex, 'assurance': assurance}
                  for n, (_, title, text, _, ex, assurance) in enumerate(STAGES, 1)],
        'outro': 'No exit writes anything; the verifier runs only after the decision accepts.',
    }
    (FIGDIR / f'{FID}.steps.json').write_text(json.dumps(st, indent=1, ensure_ascii=False) + '\n', encoding='utf-8')


if __name__ == '__main__':
    print(draw(False).write(), draw(True).write())
    steps()
    t = FIGDIR / f'{FID}.text.html'
    if t.exists():
        t.unlink()
