"""fig-sim: the dual simulation's recorded reference run, for print, the PDF and no-JS readers.

Reads source/figures/fig-sim.run.json (the native reference run of sim/index.html; recorded
output only) and writes the wide and narrow SVG and the text alternative. Per command:
each design's verdict and code, the contracts its account called (compactly), and its
window; consecutive commands with the same request and the same replies share a row.
Nothing here decides a payment. It also checks that sim-panel.html states the page's
size as the simulation page has it.
"""
import html
import json
import re
from figlib import SVG, FIGDIR, PAPER, fact, num, width, wrap
import perchmodel as M

FID = 'fig-sim'
RUN = json.loads((FIGDIR / f'{FID}.run.json').read_text())
STEPS = RUN['steps']
DESIGNS = (('oz', 'OpenZeppelin account + oz-policy-builder', 'OPENZEPPELIN + OZ-PB'), ('perch', 'Perch account', 'PERCH'))
CHIP = {'OpenZeppelin account': 'account', 'Perch account': 'account', 'spending_limit': 'spending_limit',
        'policy-interpreter': 'interpreter', 'Ed25519 verifier': 'verifier', 'document compiler': 'compiler',
        'XLM contract': 'XLM'}
CODE_NAMES = {
    int(fact('oz-spending-limit-exceeded')): 'SpendingLimitExceeded',
    int(fact('opb-error-arg-mismatch')): fact('opb-error-arg-mismatch-name'),
    int(fact('oz-error-unauthorized-signer')): 'UnauthorizedSigner',
    int(fact('auth-error-rule-eval-refused')): 'RuleEvalRefused',
}


def err_text(e):
    """Error(Crypto(InvalidInput)) -> Error(Crypto, InvalidInput)."""
    inner = e[len('Error('):-1]
    kind, _, rest = inner.partition('(')
    return f'Error({kind}, {rest.rstrip(")")})'


def analyse(d):
    """Contracts called, merged per run of one contract, and the refusing contract and error."""
    calls, refusal = [], None
    for h in d.get('hops', []):
        if 'error' in h:
            if refusal is None:
                refusal = (h['contract'], h['error'])
            continue
        if h['depth'] == 0 and h['contract'] == 'XLM contract':
            continue
        c = CHIP[h['contract']]
        if not calls or calls[-1] != c:
            calls.append(c)
    if refusal and (not calls or calls[-1] != CHIP[refusal[0]]):
        calls.append(CHIP[refusal[0]])
    return calls, refusal


def verdict(d):
    """(ok, text) for a design's reply; None when the design did nothing at this command."""
    if 'status' not in d:
        return None
    if d['status'] == 'applied':
        return True, 'applied'
    if d.get('code') is not None:
        return False, f'{d["code"]} {CODE_NAMES[d["code"]]}'
    _, refusal = analyse(d)
    return False, err_text(d.get('host_error') or refusal[1])


def window(d):
    w = d.get('window')
    return 'off' if w is None else f'{w["stored_xlm"]}/{w["limit_xlm"]}'


def record_note(d):
    """After closing ledgers: the stored record, and whether its spends are still in the window."""
    w = d.get('window')
    if w is None:
        return 'no window'
    cut = max(0, d['ledger'] - w['period_ledgers'])
    inside = sum(int(s['xlm']) for s in w['spends'] if s['ledger'] > cut)
    stored = int(w['stored_xlm'])
    if inside < stored:
        return f'window {inside} of {w["limit_xlm"]} (record lists {stored} XLM)'
    return f'window {stored} of {w["limit_xlm"]}'


def owner_text(st):
    """What an owner's policy change did, in place of "applied"."""
    return 'removed' if st['request']['spending_limit'] == 'off' else 're-attached'


def perch_reasons():
    """The model's reason for each Perch refusal in the run: rule-core's authorize (perchmodel) on
    the grant's rule, replayed at the run's ledgers and checked against every recorded verdict. The
    account itself returns code 5 for any refusal, so the reason is the model's, and is labelled so."""
    rule = M.rule('shop', M.XLM, {'only': ['transfer']}, [M.PIN_SHOP], ('app',), cap={'limit': 10, 'period': 100, 'arg': 2})
    rec, ledger, out = M.empty_record(), None, {}
    for st in STEPS:
        d, q = st['designs']['perch'], st['request']
        if q['op'] == 'pay':
            auth = ['stranger'] if q.get('signer') == 'unlisted' else ['app']
            to = M.SHOP if q.get('to', 'shop') == 'shop' else M.ELSEWHERE
            a = M.authorize([rule], [rec], [M.transfer(to, q['amount_xlm'])], [0], auth, ledger, 0)
            applied = a['ok'] and q.get('signer') != 'forged'
            assert applied == (d['status'] == 'applied'), (st['command'], a, d['status'])
            if applied:
                rec = a['records'][0]
            elif not a['ok']:
                c = a['check']
                if c == 'charge':
                    ch = a['charge']
                    out[st['command']] = f'window {ch["remaining"]} + {ch["amount"]} > {ch["limit"]}'
                else:
                    out[st['command']] = {'arguments': 'not the shop',
                                          'threshold': 'signer not on the rule'}.get(c, c)
        if d.get('ledger') is not None:
            ledger = d['ledger']
    return out


REASONS = perch_reasons()


def row_info(sts, key):
    """For a row of identical commands: how many, and how much the design sent across them."""
    before = None
    for st in STEPS:
        if st['command'] == sts[0]['command']:
            break
        before = st['designs'][key].get('balance_xlm', before)
    after = sts[-1]['designs'][key].get('balance_xlm')
    sent = int(before) - int(after) if before is not None and after is not None else 0
    return {'n': len(sts), 'sent': sent, 'why': REASONS.get(sts[0]['command']) if key == 'perch' else None}


def short_label(st, n=1):
    """A short label for the request, from the command itself."""
    q = st['request']
    if q['op'] == 'reset':
        return 'set up'
    if q['op'] == 'install':
        return 'install the rule'
    if q['op'] == 'advance':
        return f'close {q["ledgers"]} ledgers'
    if q['op'] == 'oz_policy':
        return f'`spending_limit` {q["spending_limit"]}'
    to = '' if q['to'] == 'shop' else ' elsewhere'
    who = {'forged': ', another key as the app', 'unlisted': ', key not on the rule'}.get(q.get('signer', 'app'), '')
    times = {1: '', 2: ', twice', 3: ', three times'}.get(n, f', {n} times')
    return f'pay {q["amount_xlm"]} XLM{to}{who}{times}'


def rows():
    """Consecutive payments with the same request and the same replies share a row."""
    out = []
    for st in STEPS:
        sig = (json.dumps(st['request'], sort_keys=True),
               tuple((verdict(st['designs'][k]), tuple(analyse(st['designs'][k])[0]), window(st['designs'][k]))
                     for k, *_ in DESIGNS))
        if out and out[-1][0] == sig and st['request']['op'] == 'pay':
            out[-1][1].append(st)
        else:
            out.append((sig, [st]))
    return [sts for _, sts in out]


def chips(d):
    """The contracts the account called; the account itself only when it refused or nothing else ran."""
    calls, refusal = analyse(d)
    inner = [c for c in calls if c != 'account'] or ['account']
    out = []
    for i, c in enumerate(inner):
        if i:
            out.append(('arrow',))
        refused_here = refusal is not None and i == len(inner) - 1 and c == CHIP[refusal[0]]
        out.append(('chip', c, 'deny' if refused_here else 'trusted' if c == 'verifier' else
                    'key' if c == 'account' else 'tested'))
    return out


def chip_w(it, size):
    if it[0] == 'arrow':
        return 12
    if it[0] == 'note':
        return width(it[1], size) + 6
    return width(it[1], size) + (20 if it[2] == 'trusted' else 10)


def draw_chips(s, x, y, w, items, size, draw=True):
    """Chips left to right, wrapping; a refusing chip ends in a bar. Returns height."""
    cx, cy = x, y
    for n, it in enumerate(items):
        iw = chip_w(it, size)
        need = iw + (chip_w(items[n + 1], size) + 3 if it[0] == 'arrow' and n + 1 < len(items) else 0)
        if cx > x and cx + need > x + w:
            cx, cy = x, cy + 28
        if draw:
            if it[0] == 'arrow':
                s.path(f'M{num(cx)} {num(cy + 12)}H{num(cx + 11)}', 'fl-m', marker_end='url(#perch-ah-m)')
            elif it[0] == 'note':
                s.text(cx + 6, cy + 17, it[1], 'm', size)
            else:
                s.box(cx, cy, iw, 24, it[2], 4)
                s.text(cx + (15 if it[2] == 'trusted' else 5), cy + 17, it[1], 'd' if it[2] == 'deny' else 'x', size)
                if it[2] == 'deny':
                    s.path(f'M{num(cx + iw)} {num(cy - 3)}V{num(cy + 27)}', 'fl-d')
        cx += iw + 3
    return cy - y + 24


def cell(s, x, y, w, d, st, size, draw=True, info=None):
    """A design's cell: the contracts called, then the verdict and the window; returns height."""
    info = info or {'n': 1, 'sent': 0, 'why': None}
    v = verdict(d)
    op = st['request']['op']
    if v is None:
        text = (f'set up; {d["balance_xlm"]} XLM' if op == 'reset' else
                record_note(d) if op == 'advance' else
                'not run: no Perch counterpart')
        rows = wrap(text, w - 20, size)
        hh = 14 + len(rows) * 18
        if draw:
            s.box(x, y, w, hh, 'none' if op == 'oz_policy' else 'tested', 6)
            s.lines(x + 10, y + 21, rows, 'm', size, lh=18)
        return hh
    if draw:
        s.box(x, y, w, cell(s, x, y, w, d, st, size, False, info), 'tested', 6)
    items = chips(d) + ([('note', f'(model: {info["why"]})')] if info['why'] else [])
    h = 6 + draw_chips(s, x + 8, y + 6, w - 16, items, size, draw) + 4
    ok, text = v
    if op == 'oz_policy' and ok:
        text = owner_text(st)
    times = f' \u00d7{info["n"]}' if info['n'] > 1 else ''
    if op == 'pay' and ok and info['n'] > 1:
        line = f'applied{times} \u00b7 {info["sent"]} XLM sent' + ('' if d.get('window') else ' \u00b7 no window')
    else:
        line = text + times + (f' \u00b7 {window(d)}' if op == 'pay' else '')
    lines = wrap(line, w - 36, size)
    if draw:
        if ok:
            s.check(x + 9, y + h + 3, 'gl')
        else:
            s.cross(x + 15, y + h + 9, 5)
        s.lines(x + 30, y + h + 15, lines, 'x' if ok else 'd', size, lh=18)
    return h + len(lines) * 18 + 8


def detail(d):
    return ' → '.join(f'{h["contract"]}.{h["fn"]}' for h in d.get('hops', []) if 'fn' in h)


def provenance():
    p = RUN['pins']
    return (f'Window: XLM in it / limit. Perch returns code 5 for any refusal; a "model" reason replays rule-core\u2019s '
            f'authorize at the run\u2019s ledgers. Page SHA-256 {RUN["page_sha256"][:12]}\u2026, run '
            f'{RUN["golden_sha256"][:12]}\u2026; soroban-sim {p["soroban_sim"][:7]}, OpenZeppelin '
            f'{p["openzeppelin_stellar_contracts"].split()[-1].strip("()")}, oz-policy-builder {p["oz_policy_builder"][:7]}, '
            f'Perch {p["perch"][:7]}, rule-core {p["rule_core"][:7]}.')


def entries(key):
    n = {st['designs'][key].get('entries') for st in STEPS} - {None}
    assert len(n) == 1, n
    n = n.pop()
    return f'{n} authorization {"entry" if n == 1 else "entries"} a request'


def row_attrs(sts):
    return {'data_step': str(sts[0]['command'] + 1), 'data_command': ' '.join(str(x['command']) for x in sts)}


def num_label(sts):
    a, b = sts[0]['command'], sts[-1]['command']
    return str(a) if a == b else f'{a}–{b}'


def label(s, x, y, sts, w, size, lh):
    """The command number (a dot, or a range) and the short label; returns the label's line count."""
    nl = num_label(sts)
    if len(nl) > 2:
        s.text(x, y + 17, nl, 't', size)
        lab = wrap(short_label(sts[0], len(sts)), w - 40, size, True)
        s.lines(x + 40, y + 17, lab, 't', size, lh=lh)
    else:
        s.numdot(x + 11, y + 12, nl, r=11, size=14)
        lab = wrap(short_label(sts[0], len(sts)), w - 30, size, True)
        s.lines(x + 30, y + 17, lab, 't', size, lh=lh)
    return len(lab)


def wide():
    s = SVG(FID, 760)
    size = 14
    LX, LW = 2, 150
    COLS = {'oz': (156, 300), 'perch': (460, 298)}
    s.text(LX, 16, 'RECORDED RUN', 'm tag', 14)
    s.text(LX, 34, 'pay: to the shop', 'm', 14)
    for key, title, _ in DESIGNS:
        x, w = COLS[key]
        s.text(x, 16, title, 't', 14)
        s.text(x, 34, entries(key), 'm', 14)
    y = 46
    for sts in rows():
        st = sts[0]
        probe = SVG(FID, 760)
        nlab = label(probe, LX, 0, sts, LW, size, 17)
        h = max(max(cell(probe, COLS[k][0], 0, COLS[k][1], st['designs'][k], st, size, False, row_info(sts, k)) for k, *_ in DESIGNS),
                nlab * 17 + 10)
        s.open(**row_attrs(sts))
        label(s, LX, y + 4, sts, LW, size, 17)
        for key, *_ in DESIGNS:
            x, w = COLS[key]
            d = st['designs'][key]
            s.open(data_detail=detail(d) or short_label(st))
            cell(s, x, y, w, d, st, size, info=row_info(sts, key))
            s.close()
        s.close()
        y += h + 3
    y += 16
    y = s.lines(LX, y, wrap(provenance(), 740, 14), 'm', 14, lh=17)
    s.h = y + 8
    return s


def narrow():
    s = SVG(FID, 340, narrow=True)
    size = 14
    s.text(2, 16, 'RECORDED RUN', 'm tag', 14)
    y = s.lines(2, 36, wrap('Payments go to the shop unless noted.', 330, 14),
                'm', 14, lh=17) + 10
    for sts in rows():
        st = sts[0]
        s.open(**row_attrs(sts))
        y += label(s, 2, y, sts, 336, 15, 19) * 19 + 10
        for key, _, tag in DESIGNS:
            d = st['designs'][key]
            s.open(data_detail=detail(d) or short_label(st))
            s.text(4, y + 14, tag, 'm tag', 14)
            h = cell(s, 2, y + 20, 336, d, st, size, info=row_info(sts, key))
            s.close()
            y += h + 26
        s.close()
        y += 6
    y = s.lines(2, y + 12, wrap(provenance(), 320, 14), 'm', 14, lh=17)
    s.h = y + 8
    return s


def text_alt():
    out = [f'<p>{html.escape(RUN["_source"])} The task: {html.escape(RUN["task"])}</p><ol>']
    for sts in rows():
        items = []
        for st in sts:
            parts = []
            for key, title, _ in DESIGNS:
                d = st['designs'][key]
                v = verdict(d)
                who = 'OpenZeppelin' if key == 'oz' else 'Perch'
                if v is None:
                    parts.append(f'{who}: {"not run" if st["request"]["op"] == "oz_policy" else "no request"}; '
                                 f'ledger {d["ledger"]}, {d["balance_xlm"]} XLM.')
                    continue
                calls, _ = analyse(d)
                n = d['entries']
                w = d.get('window')
                win = 'no window' if w is None else f'window {w["stored_xlm"]} of {w["limit_xlm"]} XLM'
                arrow = ' → '
                vt = owner_text(st) if st['request']['op'] == 'oz_policy' and v[0] else v[1]
                if key == 'perch' and st['command'] in REASONS:
                    vt += f' (the model\u2019s reason: {REASONS[st["command"]]})'
                parts.append(f'{who}: {html.escape(vt)}; called {arrow.join(calls)}; {n} authorization '
                             f'{"entry" if n == 1 else "entries"}; {win}'
                             + ('; state unchanged' if d.get('state_unchanged') else '') + '.')
            items.append(f'<strong>{html.escape(st["label"])}</strong> (command {st["command"]}). ' + ' '.join(parts))
        out.append(f'<li data-step="{sts[0]["command"] + 1}">' + ' '.join(items) + '</li>')
    out.append(f'</ol><p>{html.escape(provenance())}</p>')
    return ''.join(out)


def table():
    """tab-sim, generated: one row per command, each design's verdict, where it was refused, and its window.
    Written as source/figures/tab-sim.table.json (the table data for source/tables/tab-sim.json)."""
    where = {'account': 'the account', 'spending_limit': '`spending_limit`', 'interpreter': 'the interpreter',
             'verifier': 'the verifier'}

    def win(d):
        w = d.get('window')
        return 'no window' if w is None else f'window {w["stored_xlm"]} of {w["limit_xlm"]}'

    def cell(st, key):
        d = st['designs'][key]
        op = st['request']['op']
        v = verdict(d)
        if v is None:
            if op == 'reset':
                return f'set up; {d["balance_xlm"]} XLM'
            if op == 'advance':
                return f'{st["request"]["ledgers"]} ledgers closed \u00b7 {record_note(d)}'
            return '\u2014'
        ok, text = v
        if ok:
            return owner_text(st) if op == 'oz_policy' else 'applied' + (f' \u00b7 {win(d)}' if op == 'pay' else '')
        calls, refusal = analyse(d)
        code = str(d['code']) if d.get('code') is not None else text
        return f'refused, {code} in {where[CHIP[refusal[0]]]} \u00b7 {win(d)}'

    rows = [[str(st['command']), short_label(st).replace('`', '`'), cell(st, 'oz'), cell(st, 'perch')] for st in STEPS]
    n_oz = {st['designs']['oz'].get('entries') for st in STEPS} - {None}
    n_pe = {st['designs']['perch'].get('entries') for st in STEPS} - {None}
    return {
        'columns': ['Step', 'Request', 'OpenZeppelin account', 'Perch account'],
        'rows': rows,
        'title': 'The recorded run, one command a row.',
        'caption': (f'Recorded by soroban-sim\u2019s native run of the simulation page. OpenZeppelin requests carried '
                    f'{n_oz.pop()} authorization entries, Perch requests {n_pe.pop()}. The window is the Perch grant\u2019s '
                    'record, or `spending_limit`\u2019s history (none while it is removed). Every refusal was an enforcing '
                    'simulation that left the ledger unchanged. Payments go to the shop unless noted. The window column is '
                    'the stored record; spends 100 or more ledgers old leave it at the next charge.'),
        'latex_size': 'scriptsize',
        'latex_colspec': '@{}r>{\\raggedright\\arraybackslash}p{0.17\\linewidth}LL@{}',
    }


def check_panel():
    """sim-panel.html states the simulation page's size; it must match sim/index.html."""
    page = PAPER / 'sim' / 'index.html'
    panel = PAPER / 'source' / 'html' / 'sim-panel.html'
    if not (page.exists() and panel.exists()):
        return
    mb = f'{page.stat().st_size / 1e6:.1f}'
    text = panel.read_text()
    m = re.search(r'data-mb="([^"]+)"', text)
    if m and not m.group(1).startswith('{{') and m.group(1) != mb:
        raise SystemExit(f'sim-panel.html says {m.group(1)} MB; sim/index.html is {mb} MB')
    # each "Try these" link: its ?scenario= decodes to its data-commands
    import base64
    for b64, cmds in re.findall(r'scenario=([A-Za-z0-9_-]+)" data-commands=\'([^\']+)\'', text):
        if json.loads(base64.urlsafe_b64decode(b64 + '=' * (-len(b64) % 4))) != json.loads(cmds):
            raise SystemExit(f'sim-panel.html: a scenario link disagrees with its data-commands: {cmds}')


if __name__ == '__main__':
    check_panel()
    print(wide().write(), narrow().write())
    (FIGDIR / f'{FID}.text.html').write_text(text_alt() + '\n', encoding='utf-8')
    (FIGDIR / 'tab-sim.table.json').write_text(json.dumps(table(), indent=1, ensure_ascii=False) + '\n', encoding='utf-8')
