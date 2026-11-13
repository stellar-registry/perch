"""fig-two-paths: generated from source/figures/fig-two-paths.phases.json (SVG, narrow SVG, text alternative)."""
import html
import json
import re
from figlib import SVG, FIGDIR, fact, num, wrap

FID = 'fig-two-paths'
DATA = json.loads((FIGDIR / f'{FID}.phases.json').read_text())
SIDES = ('perch', 'oz')


def detail(cell):
    srcs = '; '.join(f'{DATA["repos"][r]}{p}' for r, p in cell['src'])
    return f'{srcs} · {cell["io"]}'


def cell_height(cell, w, size, lh):
    inner = w - 24
    a = len(wrap(cell['text'], inner, size))
    b = len(wrap(cell.get('direct', ''), inner, size)) if cell.get('direct') else 0
    rows = max(a, b)
    h = 12 + rows * lh + 8
    if cell.get('refusal'):
        h += 34
    return h


def draw_cell(s, x, y, w, h, cell, size, lh, tag=None):
    a = {'data_detail': detail(cell)}
    if cell.get('unreached'):
        a['data_unreached'] = ' '.join(cell['unreached'])
    s.open(**a)
    s.box(x, y, w, h, 'none' if cell.get('none') else 'tested', 6)
    ty = y + 12 + round(size * 0.8)
    cls = 'm' if cell.get('none') else 'x'
    if tag:
        s.text(x + 12, ty, tag, 'm tag', 14)
        ty += lh
    if cell.get('direct'):
        s.open(data_scenario='lost overcap')
        s.lines(x + 12, ty, wrap(cell['text'], w - 24, size), cls, size, lh=lh)
        s.close()
        s.open(data_scenario='direct', data_print='no')
        s.lines(x + 12, ty, wrap(cell['direct'], w - 24, size), cls, size, lh=lh)
        s.close()
    else:
        s.lines(x + 12, ty, wrap(cell['text'], w - 24, size), cls, size, lh=lh)
    r = cell.get('refusal')
    if r:
        py = y + h - 34
        s.open(data_scenario=r['scenario'])
        s.path(f'M{num(x + 12)} {num(py + 13)}H{num(x + 26)}', 'fl-d', marker_end='url(#perch-bar)')
        s.cross(x + 40, py + 13, 5)
        s.pill(x + 52, py, f'{r["code"]} · {fact(r["fact"])}', 'd', 14)
        s.close()
    s.close()


def wide():
    s = SVG(FID, 760)
    s.root_attrs['data-walk'] = 'phases'
    LX, PX, OX, CW = 2, 150, 460, 298
    size, lh = 14, 18
    for x, side in ((PX, 'perch'), (OX, 'oz')):
        c = DATA['columns'][side]
        s.text(x, 18, c['title'], 't', 16)
        s.text(x, 38, c['sub'], 'm', 14)
    y = 52
    for ph in DATA['phases']:
        h = max(cell_height(ph[sd], CW, size, lh) for sd in SIDES)
        s.open(data_step=str(ph['n']), data_phase=ph['id'])
        s.numdot(LX + 12, y + 20, ph['n'], r=11, size=14)
        s.lines(LX + 30, y + 25, wrap(ph['name'], 110, 15, True), 't', 15, lh=19)
        for x, side in ((PX, 'perch'), (OX, 'oz')):
            draw_cell(s, x, y, CW, h, ph[side], size, lh)
        s.close()
        y += h + 10
    s.text(2, y + 14, 'Cross and bar: where a guess over the cap is refused. Dashed: no such phase, or not reached in this scenario.', 'm', 14)
    s.h = y + 22
    return s


def narrow():
    s = SVG(FID, 340, narrow=True)
    s.root_attrs['data-walk'] = 'phases'
    size, lh = 14, 18
    y = 0
    for ph in DATA['phases']:
        s.open(data_step=str(ph['n']), data_phase=ph['id'])
        s.numdot(13, y + 16, ph['n'], r=11, size=14)
        s.text(32, y + 21, ph['name'], 't', 15)
        y += 34
        for side, tag in (('perch', 'PERCH'), ('oz', 'OPENZEPPELIN')):
            h = cell_height(ph[side], 336, size, lh) + lh
            draw_cell(s, 2, y, 336, h, ph[side], size, lh, tag)
            y += h + 8
        s.close()
        y += 10
    lines = wrap('Cross and bar: where a guess over the cap is refused. Dashed: no such phase, or not reached in this scenario.', 336, 14)
    s.lines(2, y + 6, lines, 'm', 14, lh=18)
    s.h = y + 6 + 18 * len(lines) - 6
    return s


def md(t):
    """Inline `code` to HTML."""
    parts = t.split('`')
    return ''.join(f'<code>{html.escape(p, quote=False)}</code>' if i % 2 else html.escape(p, quote=False) for i, p in enumerate(parts))


def text_alt():
    sc = DATA['scenarios']
    out = ['<p>Rows are the phases of one <code>__check_auth</code> for a lost guess under the game grant spelled out in the next figure: '
           'the <code>guess</code> and the 1-XLM transfer it makes. Each phase gives Perch, then the OpenZeppelin account '
           'whose rules carry the <code>policy-interpreter</code> and <code>spending_limit</code>, with the source lines '
           'read. Notes give the other two scenarios where they differ. Nothing here is measured.</p><ol>']
    for ph in DATA['phases']:
        p, o = ph['perch'], ph['oz']
        out.append(f'<li data-step="{ph["n"]}"><strong>{html.escape(ph["name"])}.</strong> '
                   f'Perch: {md(p["text"])} OpenZeppelin: {md(o["text"])}<ul>')
        out.append('<li>Source lines: ' + html.escape(detail(p)) + '. ' + html.escape(detail(o)) + '.</li>')
        notes = {'overcap': [], 'direct': []}
        for side, who, short in (('perch', 'Perch', 'Perch'), ('oz', 'The OpenZeppelin account', 'OpenZeppelin')):
            c = ph[side]
            r = c.get('refusal')
            if r:
                notes['overcap'].append(f'{md(r["note"])} Code: <code>{r["code"]}</code> ({fact(r["fact"])}).')
            if 'overcap' in c.get('unreached', []) and not c.get('none'):
                notes['overcap'].append(f'{who} does not reach this phase.')
        if p.get('direct') or o.get('direct'):
            notes['direct'] = [f'{html.escape(ph["name"])}. Perch: {md(p.get("direct", p["text"]))} '
                               f'OpenZeppelin: {md(o.get("direct", o["text"]))}']
        for k, v in notes.items():
            if v:
                mode = ' data-mode="replace"' if k == 'direct' else ''
                out.append(f'<li data-step="{ph["n"]}" data-scenario="{k}"{mode}>{html.escape(sc[k])}: {" ".join(v)}</li>')
        out.append('</ul></li>')
    out.append('</ol>')
    return ''.join(out)


if __name__ == '__main__':
    print(wide().write(), narrow().write())
    (FIGDIR / f'{FID}.text.html').write_text(text_alt() + '\n', encoding='utf-8')
