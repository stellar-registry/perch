"""fig-same-task: one task in both designs, replayed from the recorded walkthrough run.

Reads source/figures/fig-same-task.run.json (recorded output only) and writes the wide
and narrow SVG and the text alternative. Every verdict, code and call comes from that
file; nothing here decides a payment.
"""
import html
import json
from figlib import SVG, FIGDIR, fact, num, width, wrap

FID = 'fig-same-task'
RUN = json.loads((FIGDIR / f'{FID}.run.json').read_text())
STEPS = RUN['steps']
PER_CALL = RUN['per_call_only']
DESIGNS = (('oz', 'OpenZeppelin account + oz-policy-builder'), ('perch', 'Perch account'))
CHIP = {'OpenZeppelin account': 'account', 'Perch account': 'account', 'spending_limit': 'spending_limit',
        'policy-interpreter': 'interpreter', 'Ed25519 verifier': 'verifier', 'document compiler': 'compiler',
        'XLM contract': 'XLM'}
CODE_NAMES = {
    int(fact('oz-spending-limit-exceeded')): 'SpendingLimitExceeded',
    int(fact('opb-error-arg-mismatch')): fact('opb-error-arg-mismatch-name'),
    int(fact('oz-error-unauthorized-signer')): 'UnauthorizedSigner',
    int(fact('auth-error-rule-eval-refused')): 'RuleEvalRefused',
}
LANE_PER_CALL = 'percall'
LANE_WINDOW = 'window'


def err_text(e):
    """Error(Crypto(InvalidInput)) -> Error(Crypto, InvalidInput)."""
    inner = e[len('Error('):-1]
    kind, _, rest = inner.partition('(')
    return f'Error({kind}, {rest.rstrip(")")})'


def analyse(d):
    """Ordered calls (merged per contract run), the refusing contract and its error."""
    calls, refusal = [], None
    for h in d['hops']:
        if 'error' in h:
            if refusal is None:
                refusal = (h['contract'], h['error'])
            continue
        if h['depth'] == 0 and h['contract'] == 'XLM contract':
            continue
        if calls and calls[-1][0] == h['contract']:
            calls[-1][1].append(h['fn'])
        else:
            calls.append((h['contract'], [h['fn']]))
    if refusal and (not calls or calls[-1][0] != refusal[0]):
        calls.append((refusal[0], []))
    return calls, refusal


def code_label(d, refusal):
    if d['code'] is not None:
        assert refusal and refusal[1] == f'Error(Contract({d["code"]}))', (d, refusal)
        return f'{d["code"]} · {CODE_NAMES[d["code"]]}'
    return err_text(refusal[1])


def cell_items(d, part=None):
    calls, refusal = analyse(d)
    items = []
    for i, (contract, _fns) in enumerate(calls):
        if i:
            items.append(('arrow',))
        refused_here = refusal is not None and i == len(calls) - 1 and contract == refusal[0]
        kind = 'deny' if refused_here else ('key' if CHIP[contract] == 'account' else
                                            'trusted' if CHIP[contract] == 'verifier' else 'tested')
        items.append(('chip', CHIP[contract], kind))
    if part == 'chain':
        return items
    if part == 'result':
        items = []
    if d['status'] == 'applied':
        items += [('check',), ('text', 'applied', 'x')]
    else:
        items += [('cross',), ('pill', code_label(d, refusal))]
    return items


def item_w(it, size):
    k = it[0]
    if k == 'chip':
        return width(it[1], size) + (20 if it[2] == 'trusted' else 10)
    if k == 'arrow':
        return 12
    if k == 'pill':
        return width(it[1], size) + 20
    if k == 'check':
        return 16
    if k == 'cross':
        return 14
    return width(it[1], size) + 2


def flow(s, x, y, w, items, size=14, lh=30, draw=True):
    """Lay items left to right, wrapping before an item that would overflow; returns height."""
    cx, cy = x, y
    for n, it in enumerate(items):
        iw = item_w(it, size)
        # keep an arrow with the chip it points to
        need = iw + (item_w(items[n + 1], size) + 3 if it[0] == 'arrow' and n + 1 < len(items) else 0)
        if cx > x and cx + need > x + w:
            cx, cy = x, cy + lh
        if draw:
            k = it[0]
            if k == 'chip':
                s.box(cx, cy, iw, 24, it[2], 4)
                s.text(cx + (15 if it[2] == 'trusted' else 5), cy + 17, it[1], 'd' if it[2] == 'deny' else 'x', size)
            elif k == 'arrow':
                s.path(f'M{num(cx)} {num(cy + 12)}H{num(cx + 11)}', 'fl-m', marker_end='url(#perch-ah-m)')
            elif k == 'pill':
                s.pill(cx, cy - 1, it[1], 'd', size, h=26)
            elif k == 'check':
                s.check(cx + 1, cy + 6, 'gl')
            elif k == 'cross':
                s.cross(cx + 6, cy + 12, 5)
            else:
                s.text(cx, cy + 17, it[1], it[2], size)
        cx += iw + 3
    return cy - y + 24


def detail(d):
    calls = ' → '.join(f'{h["contract"]}.{h["fn"]}' for h in d['hops'] if 'fn' in h)
    n = d['entries']
    # Instruction counts are left out: the paper reports no cross-design cost.
    parts = [calls, f'{n} authorization {"entry" if n == 1 else "entries"}']
    return ' · '.join(parts)


def step_label(st):
    return st['label']


def lanes():
    """The recorded sends of both lanes, with what each shows; nothing is decided here."""
    moved = 0
    pc = []
    for i, snd in enumerate(PER_CALL['sends'], 1):
        ok = snd['result'] == 'applied'
        if ok:
            moved += int(snd['xlm'])
        mark = '✓' if ok else f'✕ {snd["code"]}'
        amount = snd['xlm'].replace(' + ', ' XLM + ') if 'stroop' in snd['xlm'] else f'{snd["xlm"]} XLM'
        pc.append({'i': i, 'amount': amount, 'ok': ok, 'code': snd.get('code'),
                   'sub': f'moved so far: {moved} XLM',
                   'say': (f'Per-call bound only, send {i}: {amount}, '
                           + ('applied' if ok else f'refused with {snd["code"]} ({CODE_NAMES[snd["code"]]})')
                           + f'; {moved} XLM moved so far.')})
    assert str(moved) == PER_CALL['moved_xlm'], (moved, PER_CALL['moved_xlm'])
    win = []
    pick = [STEPS[1], STEPS[2], STEPS[6]]
    subs = ['window total: 6 XLM', 'window total: 6 XLM', '100 ledgers on: window 5 XLM']
    for i, (st, sub) in enumerate(zip(pick, subs), 1):
        tot = sub.split()[-2]
        oz, pe = st['designs']['oz'], st['designs']['perch']
        assert oz['status'] == pe['status']
        ok = oz['status'] == 'applied'
        amt = st['request']['amount_xlm']
        pre = '100 ledgers later, ' if i == 3 else ''
        win.append({'i': i, 'amount': f'{amt} XLM', 'ok': ok, 'code': None if ok else (oz['code'], pe['code']),
                    'sub': sub,
                    'say': (f'Window, send {i}: {pre}{amt} XLM, '
                            + ('applied by both' if ok else
                               f'refused: OpenZeppelin {oz["code"]} ({CODE_NAMES[oz["code"]]}), Perch {pe["code"]} '
                               f'({CODE_NAMES[pe["code"]]})')
                            + f'; the window holds {tot} XLM.')})
    return pc, win


def send_box(s, x, y, w, snd, size, lane):
    s.open(data_lane=lane, data_send=str(snd['i']), data_say=snd['say'])
    s.box(x, y, w, 46, 'tested' if snd['ok'] else 'deny', 6)
    s.text(x + 10, y + 18, snd['amount'], 't', size)
    mx = x + 10 + width(snd['amount'], size, True) + 8
    if snd['ok']:
        s.check(mx, y + 7, 'gl')
    else:
        s.cross(mx + 6, y + 13, 5)
        code = (f'OZ {snd["code"][0]} · Perch {snd["code"][1]}' if isinstance(snd['code'], tuple) else str(snd['code']))
        s.text(mx + 16, y + 18, code, 'd', size)
    s.text(x + 10, y + 37, snd['sub'], 'm', size)
    s.close()


CONTRACTS = {
    'oz': [('account', 'key'), ('spending_limit', 'tested'), ('interpreter', 'tested')],
    'perch': [('account', 'key'), ('verifier', 'trusted')],
}
STATE = {
    'oz': '3 contracts called; state in 3: rules (account), history (`spending_limit`), predicate (interpreter).',
    'perch': '2 contracts called; state in 1: rules, grants and spending records (account).',
}
DOCUMENTED = {
    'oz': ('Documented, not run: a threshold policy for multi-signer rules (policy-synth README, "Threshold"); an '
           'execution adapter to bind calls across a batch (oz-policy-builder docs/stellar.md:191-195).'),
    'perch': ('Documented, not run: the threshold is part of the rule, with no other contract. A rule may '
              'require its entry\'s root call (exact roots); this grant does not.'),
}


def recorded_contracts():
    """Check the per-payment contract lists against the trace of command 2."""
    st = STEPS[1]
    for key, _ in DESIGNS:
        seen = []
        for h in st['designs'][key]['hops']:
            c = CHIP[h['contract']]
            if c != 'XLM' and c not in seen:
                seen.append(c)
        assert seen == [c for c, _ in CONTRACTS[key]], (key, seen)


def cell(s, x, y, w, d, size, draw=True):
    """A design's cell: the ordered calls, then the result and the entries; returns height."""
    ch = flow(s, x + 8, y + 7, w - 16, cell_items(d, 'chain'), size, draw=draw)
    rh = flow(s, x + 8, y + 7 + ch + 5, w - 16, cell_items(d, 'result'), size, draw=draw)
    return 7 + ch + 5 + rh + 7


def contracts_cell(s, x, y, w, key, size):
    items = []
    for j, (c, k) in enumerate(CONTRACTS[key]):
        if j:
            items.append(('arrow',))
        items.append(('chip', c, k))
    who = 'OpenZeppelin' if key == 'oz' else 'Perch'
    s.open(data_view='recorded', data_say=f'{who}: ' + STATE[key].replace('`', ''))
    ch = flow(s, x + 8, y + 7, w - 16, items, size)
    rows = wrap(STATE[key], w - 16, size)
    s.lines(x + 8, y + 7 + ch + 18, rows, 'x', size, lh=17)
    s.close()
    drows = wrap(DOCUMENTED[key], w - 16, size)
    say = html.escape(f'{who}: ' + DOCUMENTED[key].replace('`', ''))
    s.add(f'<g data-view="documented" data-print="no" class="off" data-say="{say}">')
    s.lines(x + 8, y + 20, drows, 'x', size, lh=17)
    s.close()
    return max(7 + ch + 6 + len(rows) * 17, 8 + len(drows) * 17) + 8


def entries_label(key):
    ns = {st['designs'][key]['entries'] for st in STEPS}
    assert len(ns) == 1, ns
    n = ns.pop()
    return f'{n} authorization {"entry" if n == 1 else "entries"} a request'


def wide():
    s = SVG(FID, 760)
    size = 14
    LX, LW = 2, 136
    COLS = {'oz': (146, 314), 'perch': (468, 290)}
    s.text(LX, 16, 'RECORDED RUN', 'm tag', 14)
    s.text(LX, 34, 'one request a row', 'm', 14)
    for key, title in DESIGNS:
        x, w = COLS[key]
        s.text(x, 16, title, 't', 15)
        s.text(x, 34, entries_label(key), 'm', 14)
    y = 46
    for i, st in enumerate(STEPS, 1):
        probe = SVG(FID, 760)
        lab = wrap(step_label(st), LW - 28, size, True)
        h = max(max(cell(probe, COLS[k][0], 0, COLS[k][1], st['designs'][k], size, False) for k, _ in DESIGNS),
                len(lab) * 17 + 12)
        s.open(data_step=str(i), data_command=str(st['command']))
        s.numdot(LX + 11, y + 17, i, r=11, size=14)
        s.lines(LX + 28, y + 22, lab, 't', size, lh=17)
        for key, _ in DESIGNS:
            x, w = COLS[key]
            d = st['designs'][key]
            s.open(data_detail=detail(d))
            s.box(x, y, w, h, 'tested', 6)
            cell(s, x, y, w, d, size)
            s.close()
        s.close()
        y += h + 5
    # send again: a per-call bound alone against a window
    pc, win = lanes()
    y += 22
    s.text(LX, y, 'REPEATED PAYMENTS', 't tag', 14)
    s.text(LX + 196, y, 'in-rule payments, sent again; recorded', 'm', 14)
    for lane, title, sends in (
            (LANE_PER_CALL, f'Per-call bound only: the interpreter alone, at most {PER_CALL["cap_per_call_xlm"]} XLM per call '
                            '(a local network, outside the walkthrough)', pc),
            (LANE_WINDOW, 'Window: 10 XLM per 100 ledgers, in `spending_limit` and in the Perch grant (the walkthrough)', win)):
        y += 21
        s.text(LX, y, title, 'x', size)
        y += 7
        bw = (756 - 8 * (len(sends) - 1)) / len(sends)
        for j, snd in enumerate(sends):
            send_box(s, LX + j * (bw + 8), y, bw, snd, size, lane)
        y += 46
        if lane == LANE_PER_CALL:
            y += 19
            s.text(LX, y, f'{PER_CALL["moved_xlm"]} XLM moved under a {PER_CALL["cap_per_call_xlm"]} XLM per-call bound: '
                   'the interpreter keeps no running total.', 'm', size)
    # contracts per payment
    y += 26
    s.lines(LX, y, ['CONTRACTS', 'PER PAYMENT'], 't tag', 14, lh=17)
    s.text(LX, y + 34, 'from the trace', 'm', 14)
    y -= 12
    probe = SVG(FID, 760)
    h = max(contracts_cell(probe, COLS[k][0], y, COLS[k][1], k, size) for k, _ in DESIGNS)
    for key, _ in DESIGNS:
        x, w = COLS[key]
        s.box(x, y, w, h, 'tested', 6)
        contracts_cell(s, x, y, w, key, size)
    s.h = y + h + 2
    return s


def narrow():
    s = SVG(FID, 340, narrow=True)
    size = 14
    s.text(2, 16, 'RECORDED RUN', 'm tag', 14)
    y = 30
    for i, st in enumerate(STEPS, 1):
        s.open(data_step=str(i), data_command=str(st['command']))
        s.numdot(13, y + 12, i, r=11, size=14)
        lab = wrap(step_label(st), 300, 15, True)
        s.lines(32, y + 17, lab, 't', 15, lh=19)
        y += 10 + len(lab) * 19
        for key, tag in (('oz', 'OPENZEPPELIN + OZ-PB'), ('perch', 'PERCH')):
            tag = f'{tag} · {entries_label(key).replace(" authorization", "").replace(" a request", "").upper()}'
            d = st['designs'][key]
            probe = SVG(FID, 340)
            h = 20 + cell(probe, 2, 0, 336, d, size, False)
            s.open(data_detail=detail(d))
            s.box(2, y, 336, h, 'tested', 6)
            s.text(10, y + 19, tag, 'm tag', 14)
            cell(s, 2, y + 20, 336, d, size)
            s.close()
            y += h + 6
        s.close()
        y += 10
    pc, win = lanes()
    y += 14
    s.text(2, y, 'REPEATED PAYMENTS', 't tag', 14)
    for lane, title, sends in (
            (LANE_PER_CALL, f'Per-call bound only: the interpreter alone, at most {PER_CALL["cap_per_call_xlm"]} XLM per call '
                            '(a local network, outside the walkthrough)', pc),
            (LANE_WINDOW, 'Window: 10 XLM per 100 ledgers, in `spending_limit` and in the Perch grant (the walkthrough)', win)):
        rows = wrap(title, 336, size)
        s.lines(2, y + 22, rows, 'x', size, lh=17)
        y += 22 + (len(rows) - 1) * 17 + 8
        for snd in sends:
            send_box(s, 2, y, 336, snd, size, lane)
            y += 52
        if lane == LANE_PER_CALL:
            rows = wrap(f'{PER_CALL["moved_xlm"]} XLM moved under a {PER_CALL["cap_per_call_xlm"]} XLM per-call bound: '
                        'the interpreter keeps no running total.', 336, size)
            s.lines(2, y + 12, rows, 'm', size, lh=17)
            y += 12 + len(rows) * 17
    y += 26
    s.text(2, y, 'CONTRACTS PER PAYMENT', 't tag', 14)
    y += 8
    for key, tag in (('oz', 'OPENZEPPELIN + OZ-PB'), ('perch', 'PERCH')):
        probe = SVG(FID, 340)
        h = 20 + contracts_cell(probe, 2, 0, 336, key, size)
        s.box(2, y, 336, h, 'tested', 6)
        s.text(10, y + 19, tag, 'm tag', 14)
        contracts_cell(s, 2, y + 20, 336, key, size)
        y += h + 8
    s.h = y - 6
    return s


def md(t):
    parts = t.split('`')
    return ''.join(f'<code>{html.escape(p, quote=False)}</code>' if i % 2 else html.escape(p, quote=False)
                   for i, p in enumerate(parts))


def text_alt():
    names = dict(DESIGNS)
    out = [f'<p>Recorded from the native reference run of the walkthrough. The task: {html.escape(RUN["task"])} '
           'Each item gives, for each design, the contracts called while the account authorized the request, in '
           'order, and where it was refused.</p><ol>']
    for i, st in enumerate(STEPS, 1):
        parts = []
        for key, _ in DESIGNS:
            d = st['designs'][key]
            calls, refusal = analyse(d)
            chain = ' → '.join(f'{c} ({", ".join(f) if f else "refuses"})' for c, f in calls)
            res = 'applied' if d['status'] == 'applied' else f'refused: {code_label(d, refusal)}'
            n = d['entries']
            parts.append(f'{"OpenZeppelin" if key == "oz" else "Perch"}, {n} authorization '
                         f'{"entry" if n == 1 else "entries"}: {html.escape(chain)}; {html.escape(res)}.')
        extra = ''
        out.append(f'<li data-step="{i}"><strong>{html.escape(st["label"])}</strong> (command {st["command"]}). '
                   + ' '.join(parts) + extra + '</li>')
    out.append('</ol>')
    pc, win = lanes()
    out.append('<p>Send again, per-call bound only. ' + html.escape(PER_CALL['_source']) + '</p><ul>')
    out += [f'<li>{html.escape(x["say"])}</li>' for x in pc]
    out.append('</ul><p>Send again, window (from the walkthrough):</p><ul>')
    out += [f'<li>{html.escape(x["say"])}</li>' for x in win]
    out.append('</ul><p>Contracts per payment, from the trace of command 2. OpenZeppelin: '
               + md(STATE['oz']) + ' Perch: ' + md(STATE['perch']) + '</p>')
    out.append('<p>' + md(DOCUMENTED['oz']) + ' Perch: ' + md(DOCUMENTED['perch'].replace('Documented, not run: ', '')) + '</p>')
    return ''.join(out)


if __name__ == '__main__':
    recorded_contracts()
    print(wide().write(), narrow().write())
    (FIGDIR / f'{FID}.text.html').write_text(text_alt() + '\n', encoding='utf-8')
