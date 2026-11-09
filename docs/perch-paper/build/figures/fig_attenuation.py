"""fig-attenuation: hand part of a grant to a helper (explorable E1; static form).

Three attenuation steps from the parent grant, one move the table refuses, and seven
probes run against parent and child. Every verdict comes from perchmodel.py, the
transcription of rule-core's attenuate and authorize; the page's controller recomputes
the same with figures.js. The <g data-probe> groups carry the verdicts for the model test.
"""
import html
import json
from figlib import SVG, FIGDIR, num, width, wrap
import perchmodel as M

FID = 'fig-attenuation'


def model():
    parent = M.parent_grant()
    child = parent
    steps = []
    for step, i, param, label in M.E1_STEPS:
        r = M.attenuate(child, step, i, param)
        assert r['ok'], (step, r)
        child = r['rules']
        steps.append((label, True, None))
    step, i, param, label = M.E1_REFUSED
    r = M.attenuate(child, step, i, param)
    assert not r['ok']
    steps.append((label, False, M.REFUSAL[r['error']]))
    probes = []
    for pid, label, ctx, auth in M.PROBES:
        p = M.accepts(parent, ctx, auth, M.LEDGER)
        c = M.accepts(child, ctx, auth, M.LEDGER)
        assert p or not c, pid   # T4 on this probe
        probes.append((pid, label, p, c))
    return parent, child, steps, probes, replay(parent, child)


def replay(parent, child):
    """T5: the child's run of a guess then five transfers of 1, one ledger apart, then its
    accepted requests replayed through the parent from empty records."""
    run = [(M.PROBES[0][2], ['app'])] + [(M.transfer(M.SHOP, 1), ['app'])] * 5
    rec = [M.empty_record() for _ in child]
    accepted, refused = [], []
    for k, (ctx, auth) in enumerate(run):
        now = M.LEDGER + k
        for j in range(len(child)):
            d = M.authorize(child, rec, [ctx], [j], auth, now, 0)
            if d['ok']:
                rec = d['records']
                accepted.append((ctx, auth, now, j))
                break
        else:
            refused.append(k)
    prec = [M.empty_record() for _ in parent]
    ok = 0
    for ctx, auth, now, j in accepted:
        d = M.authorize(parent, prec, [ctx], [j], auth, now, 0)   # no rule dropped: same index
        if d['ok']:
            prec = d['records']
            ok += 1
    assert ok == len(accepted)
    return len(run), len(accepted), ok


def parts(r):
    """A rule's parts as (key, text): target and functions, conditions, signers, cap."""
    f = r['functions']
    if 'only' in f:
        fns = ', '.join(f'`{x}`' for x in f['only']) or 'no function'
    else:
        fns = 'any function' + (' but ' + ', '.join(f['except']) if f['except'] else '')
    conds = []
    for c in r['conds']:
        if c['op'] == 'eq' and c['i'] == 1:
            conds.append(f'recipient is the {c["v"]}')
        elif c['op'] == 'atmost':
            conds.append(f'amount at most {c["n"]}')
        else:
            conds.append('a condition on an argument')
    target = 'the game' if r['contract'] == M.GAME else r['contract']
    out = [('target', f'{target}, {fns}')]
    if conds:
        out.append(('conds', '; '.join(conds)))
    out.append(('signers', f'{" or ".join(f"`{s}`" for s in r["signers"]) or "no signer"}, threshold {r["threshold"]}'))
    if r.get('cap'):
        out.append(('cap', f'cap {r["cap"]["limit"]} per {r["cap"]["period"]} ledgers'))
    if r.get('valid_until') is not None:
        out.append(('expiry', f'last ledger {r["valid_until"]}'))
    return out


def describe(r, base=None):
    """(text, narrowed) per part; a part differing from `base`'s is narrowed."""
    bp = dict(parts(base)) if base else None
    return [(t, bp is not None and bp.get(k) != t) for k, t in parts(r)]


def card(s, x, y, w, title, rules, base, size, draw=True):
    """A grant card; returns its height. Narrowed lines carry a key-coloured bar."""
    lh = 18
    if draw:
        s.box(x, y, w, card(s, x, y, w, title, rules, base, size, False), 'tested', 6)
    ty = y + 22
    if draw:
        s.text(x + 12, ty, title, 't tag', 14)
    ty += lh + 4
    for r in rules:
        b = next((q for q in base if q['name'] == r['name']), None) if base else None
        if draw:
            s.text(x + 12, ty, f'rule {r["name"]}', 't', size)
        ty += lh
        for text, narrowed in describe(r, b):
            rows = wrap(text, w - 40, size)
            if draw:
                if narrowed:
                    s.rect(x + 14, ty - 13, 5, len(rows) * lh - 2, 'bx bx-k', 0)
                s.lines(x + 26, ty, rows, 'x', size, lh=lh)
            ty += len(rows) * lh
        ty += 4
    return ty - y - 4


def mark(s, x, y, ok, size, word=True):
    """Allows: a check. Refuses: a cross and a bar end. The word repeats the shape."""
    if ok:
        s.check(x, y - 11, 'gl')
    else:
        s.cross(x + 6, y - 5, 5)
        s.path(f'M{num(x + 15)} {num(y - 12)}V{num(y + 2)}', 'fl-d')
    if word:
        s.text(x + 22, y, 'accepts' if ok else 'refuses', 'x' if ok else 'd', size)


def draw(narrow):
    parent, child, steps, probes, (n_run, n_child, n_parent) = model()
    W = 340 if narrow else 760
    size = 14 if narrow else 15
    s = SVG(FID, W, narrow=narrow)
    s.text(2, 16, 'MODEL', 'm tag', 14)
    s.text(60, 16, 'computed from the attenuation steps; not run on chain' if not narrow else 'computed; not run on chain', 'm', 14)
    y = 30
    if narrow:
        cols = [(2, 336)]
    else:
        cols = [(2, 246), (257, 246), (512, 246)]
    # parent | steps | child (stacked when narrow)
    probe = SVG(FID, W)
    hp = card(probe, 0, 0, cols[0][1], 'PARENT GRANT', parent, None, size, False)
    hc = card(probe, 0, 0, cols[-1][1], 'CHILD GRANT', child, parent, size, False)
    sx, sw = cols[1] if not narrow else cols[0]
    srows = []
    for k, (label, ok, why) in enumerate(steps):
        text = label if ok else f'{label}: refused ({why}); nothing changes'
        srows.append((k, ok, wrap(text, sw - 40, size)))
    hs = 26 + sum(len(r) * 18 + 8 for _, _, r in srows)
    if narrow:
        card(s, 2, y, 336, 'PARENT GRANT', parent, None, size)
        y += hp + 10
        sy = y
    else:
        h = max(hp, hc, hs)
        card(s, 2, y, 246, 'PARENT GRANT', parent, None, size)
        card(s, 512, y, 246, 'CHILD GRANT', child, parent, size)
        sy = y
    s.text(sx + 4, sy + 22, 'STEPS', 't tag', 14)
    ty = sy + 44
    for k, ok, rows in srows:
        s.open(data_step_result='applied' if ok else 'refused')
        if ok:
            s.numdot(sx + 15, ty - 5, k + 1, r=11, size=14)
        else:
            s.cross(sx + 15, ty - 5, 5)
        s.lines(sx + 34, ty, rows, 'x' if ok else 'd', size, lh=18)
        s.close()
        ty += len(rows) * 18 + 8
    if not narrow:
        y += h + 24
        s.text(2, y, 'A bar at the left of a line marks a part of the child the steps narrowed.', 'm', 14)
        y += 30
    else:
        y = ty + 6
        card(s, 2, y, 336, 'CHILD GRANT', child, parent, size)
        y += hc + 24
        y = s.lines(2, y, wrap('A bar marks a narrowed part. P: parent, C: child.', 336, 14), 'm', 14, lh=18) + 30
    # probe grid
    lw = 220 if narrow else 430
    px, cx = (236, 290) if narrow else (470, 620)
    s.text(2, y, 'PROBE', 't tag', 14)
    s.text(px, y, 'PARENT' if not narrow else 'P', 't tag', 14)
    s.text(cx, y, 'CHILD' if not narrow else 'C', 't tag', 14)
    y += 8
    for pid, label, p, c in probes:
        rows = wrap(label, lw, size)
        h = len(rows) * 18 + 10
        s.open(data_probe=pid, data_parent='accepts' if p else 'refuses', data_child='accepts' if c else 'refuses')
        s.line(2, y, W - 2, y, 'rule')
        s.lines(2, y + 22, rows, 'x', size, lh=18)
        mark(s, px, y + 22, p, size, not narrow)
        mark(s, cx, y + 22, c, size, not narrow)
        s.close()
        y += h
    s.line(2, y, W - 2, y, 'rule')
    n_c = sum(1 for *_, c in probes if c)
    n_p = sum(1 for _, _, p, _ in probes if p)
    y += 24
    summary = (f'The child accepts {n_c} of {len(probes)} probes, and the parent accepts each of them; '
               f'the parent accepts {n_p}.')
    y = s.lines(2, y, wrap(summary, W - 4, size), 't', size, lh=18) + 24
    rep = (f'Replay: the child accepts {n_child} of {n_run} requests (a guess, then five transfers of 1, '
           f'one ledger apart; the fifth would make 5 > 4). From empty records the parent accepts all {n_parent}.')
    y = s.lines(2, y, wrap(rep, W - 4, size), 'x', size, lh=18)
    s.h = y + 8
    return s


def text_alt():
    parent, child, steps, probes, (n_run, n_child, n_parent) = model()

    def md(t):
        parts = t.split('`')
        return ''.join(f'<code>{html.escape(p)}</code>' if i % 2 else html.escape(p) for i, p in enumerate(parts))
    out = ['<p>A model, computed from the attenuation steps of rule-core; not run on chain. The parent grant: ']
    out.append('; '.join(f'rule {r["name"]}: ' + ', '.join(md(t) for t, _ in describe(r)) for r in parent) + '.</p><ol>')
    for label, ok, why in steps:
        out.append(f'<li>{md(label)}: ' + ('applied' if ok else f'refused ({html.escape(why)}); nothing changes') + '</li>')
    out.append('</ol><p>The child grant: ' + '; '.join(
        f'rule {r["name"]}: ' + ', '.join(md(t) + (' (narrowed)' if n else '') for t, n in describe(r, next(q for q in parent if q['name'] == r['name'])))
        for r in child) + '.</p>')
    out.append('<table><thead><tr><th>Probe</th><th>Parent</th><th>Child</th></tr></thead><tbody>')
    for pid, label, p, c in probes:
        out.append(f'<tr><td>{md(label)}</td><td>{"accepts" if p else "refuses"}</td><td>{"accepts" if c else "refuses"}</td></tr>')
    out.append('</tbody></table>')
    n_c = sum(1 for *_, c in probes if c)
    out.append(f'<p>The child accepts {n_c} of {len(probes)}; the parent accepts each of them. Replay: the child accepts '
               f'{n_child} of {n_run} requests, and the parent accepts all {n_parent} from empty records.</p>')
    return ''.join(out)


def table():
    """tab-attenuate-instance (HTML only, unnumbered): the static form of the attenuation explorable.
    Written as source/figures/tab-attenuate-instance.table.json."""
    parent, child, steps, probes, (n_run, n_child, n_parent) = model()
    done = '; '.join(f'{k}. {label}' for k, (label, ok, _) in enumerate(steps, 1) if ok)
    refused = next(f'{label} ({why})' for label, ok, why in steps if not ok)
    n_c = sum(1 for *_, c in probes if c)
    return {
        'columns': ['Probe', 'Parent', 'Child'],
        'rows': [[label, 'accepts' if p else 'refuses', 'accepts' if c else 'refuses'] for _, label, p, c in probes],
        'title': 'Attenuation, modelled: three steps narrow a grant, and one widening move is refused.',
        'caption': (f'MODEL; the account cannot install an attenuated grant at the pinned build (proposed). Parent: '
                    + '; '.join(f'rule `{r["name"]}`: ' + ', '.join(t for t, _ in describe(r)) for r in parent)
                    + f'. Steps: {done}. Refused: {refused}; nothing changes. Each probe runs alone from empty records. '
                    f'The child accepts {n_c} of {len(probes)}, and the parent accepts each of them.'),
        'editions': ['html'],
    }


if __name__ == '__main__':
    print(draw(False).write(), draw(True).write())
    (FIGDIR / f'{FID}.text.html').write_text(text_alt() + '\n', encoding='utf-8')
    (FIGDIR / 'tab-attenuate-instance.table.json').write_text(json.dumps(table(), indent=1, ensure_ascii=False) + '\n', encoding='utf-8')
