"""fig-cap-window: the shop grant's cap on illustrative ledgers, with hooks for the cap-window controller."""
import json
import re
from figlib import SVG, FIGDIR, fact, num, wrap

FID = 'fig-cap-window'
LIMIT = 10
CHARGES = [(0, 6), (1, 4), (100, 5)]        # ledger offset from t, XLM
REFUSED = [(0, 6, 5, 2), (99, 10, 1, 4)]    # ledger, total before, amount, event number
EVENTS = [(1, 0), (2, 0), (3, 1), (4, 99), (5, 100)]   # event, ledger
STATIC_L = 100


def lab(v):
    return 't' if v == 0 else (f't + {v}' if v > 0 else f't − {-v}')


def make(narrow):
    if narrow:
        W, X = 340, {-1: 52, 0: 100, 1: 148, 2: 164, 98: 188, 99: 206, 100: 256, 101: 306}
        x0, x1, y0, k, size, ax_r = 40, 334, 196, 12.5, 14, 336
    else:
        W, X = 760, {-1: 120, 0: 210, 1: 300, 2: 330, 98: 490, 99: 520, 100: 610, 101: 700}
        x0, x1, y0, k, size, ax_r = 96, 742, 220, 15, 15, 742

    def xl(v):
        if v in X:
            return X[v]
        return X[2] + (v - 2) / 96 * (X[98] - X[2])

    def yv(a):
        return y0 - a * k

    s = SVG(FID, W, narrow=narrow)
    s.root_attrs['data-limit'] = str(LIMIT)
    s.root_attrs['data-period'] = '100'
    s.root_attrs['data-ledger-x'] = ' '.join(f'{v}:{num(x)}' for v, x in sorted(X.items()))
    s.root_attrs['data-static'] = str(STATIC_L)
    # axes
    s.text(x0 - 8 if narrow else 2, 16, 'XLM in the window', 'm', size, None if not narrow else None)
    s.line(x0, yv(11.6), x0, y0, 'fl-m')
    s.line(x0, y0, ax_r, y0, 'fl-m')
    for a in (0, 5, 10):
        s.text(x0 - 8, yv(a) + 5, str(a), 'm', size, 'end')
    s.line(x0, yv(LIMIT), ax_r, yv(LIMIT), 'fl-d dash')
    s.text(xl(1) + 8, yv(LIMIT) + 18, f'limit {LIMIT}' + ('' if narrow else ' XLM'), 'd', size)
    bx = (X[2] + X[98]) / 2
    s.path(f'M{num(bx - 7)} {num(y0 + 6)}l6-12M{num(bx + 1)} {num(y0 + 6)}l6-12', 'fl-m')
    for v in (-1, 0, 1, 99, 100, 101):
        s.line(xl(v), y0, xl(v), y0 + 6, 'fl-m')
        s.text(xl(v), y0 + 22, lab(v).replace(' ', '') if narrow else lab(v), 'm', size, 'middle')
    # window total after each ledger: the step line
    d = (f'M{num(x0)} {num(y0)}H{num(xl(0))}V{num(yv(6))}H{num(xl(1))}V{num(yv(10))}H{num(xl(100) - 4)}')
    s.path(d, 'fl')
    s.path(f'M{num(xl(100) - 4)} {num(yv(10))}V{num(yv(4))}', 'fl-m dash')
    s.path(f'M{num(xl(100) - 4)} {num(yv(4))}H{num(xl(100) + 4)}V{num(yv(9))}H{num(xl(101))}', 'fl')
    s.path(f'M{num(xl(101))} {num(yv(9))}V{num(yv(5))}', 'fl-m dash')
    s.path(f'M{num(xl(101))} {num(yv(5))}H{num(ax_r)}', 'fl')
    # refused attempts: a dashed bar above the total that would cross the limit, with a cross
    bw = 10 if narrow else 14
    for v, before, amt, ev in REFUSED:
        bxl = xl(v) + 6
        s.open(data_event=str(ev), data_at=str(v))
        s.rect(bxl, yv(before + amt), bw, amt * k, 'bx-no dash', 0)
        s.cross(bxl + bw / 2, yv(before + amt) - 10, 5)
        s.close()
    # event numbers
    if narrow:
        pos = {1: (xl(0) - 16, yv(3)), 2: (xl(0) - 16, yv(9.2)), 3: (xl(1) - 16, yv(8)),
               4: (xl(99) + 30, yv(8.4)), 5: (xl(100) + 18, yv(6.8))}
    else:
        pos = {1: (xl(0) - 20, yv(3)), 2: (xl(0) - 20, yv(9.2)), 3: (xl(1) - 20, yv(8)),
               4: (xl(99) + 40, yv(8.4)), 5: (xl(100) + 22, yv(6.8))}
    for ev, at in EVENTS:
        s.open(data_event=str(ev), data_at=str(at))
        s.numdot(*pos[ev], ev, r=11, size=14)
        s.close()
    # charges: amber when inside the window at the static ledger, plain when outside
    cy = y0 + 34
    if not narrow:
        s.text(x0 - 8, cy + 17, 'charges', 'm', size, 'end')
    cw = 34 if narrow else 40
    for v, amt in CHARGES:
        inside = STATIC_L - 100 < v <= STATIC_L
        s.open(data_ledger=str(v), data_amount=str(amt))
        # inside the window: amber; outside: plain. Dashed is kept for refused transfers.
        s.rect(xl(v) - cw / 2, cy, cw, 24, 'bx bx-hi' if inside else 'bx', 4)
        s.text(xl(v), cy + 17, f'+{amt}', 'x' if inside else 'm', size, 'middle')
        s.close()
    # windows at t + 99 and t + 100 (static form; the controller replaces them with one live window)
    wy = cy + 50
    s.open(data_static='window')
    for L, held in ((99, '6 + 4 = 10'), (100, '4 + 5 = 9')):
        a, b = xl(L - 100), xl(L)
        label = f'window at {lab(L)}: ({lab(L - 100)}, {lab(L)}] holds {held}'
        if narrow:
            label = f'at {lab(L)}: ({lab(L - 100)}, {lab(L)}], {held.split(" = ")[1]}'
        s.text(a, wy, label, 'k', size)
        bracket(s, a, b, wy + 12)
        wy += 40
    s.close()
    # live window and cursor, drawn by the controller only
    s.add(f'<g data-print="no" data-live="window"><text x="{num(xl(0))}" y="{num(cy + 50)}" class="k" font-size="{size}"></text>'
          f'<path class="fl-k" d=""/><path class="fl-k" d=""/><path class="fl-k" d=""/></g>')
    s.add(f'<g data-print="no" data-live="cursor" data-left="{num(x0)}"><line x1="{num(xl(STATIC_L))}" y1="{num(yv(11.6))}" x2="{num(xl(STATIC_L))}" '
          f'y2="{num(y0)}" class="fl-k dash"/></g>')
    # event list
    ey = wy + 6
    for ev, at in EVENTS:
        txt = fact(f'cap-event-{ev}')
        if narrow:
            txt = re.sub(r'(\S) ([+−=>≤]) (\S)', '\\1\u00a0\\2\u00a0\\3', txt)
        lines = wrap(txt, W - 40, size)
        s.open(data_event=str(ev), data_at=str(at))
        s.numdot(13, ey - 5, ev, r=11, size=14)
        s.lines(32, ey, lines, 'x', size, lh=size + 4)
        s.close()
        ey += (len(lines) - 1) * (size + 4) + 28
    s.h = ey - 14
    return s


def bracket(s, a, b, y):
    """The interval (a, b]: an open end drawn as a chevron, a closed end as a square bracket."""
    s.path(f'M{num(a)} {num(y)}H{num(b)}', 'fl-k')
    s.path(f'M{num(a + 6)} {num(y - 9)}L{num(a + 2)} {num(y - 5)}L{num(a + 1)} {num(y - 1)}V{num(y + 1)}'
           f'L{num(a + 2)} {num(y + 5)}L{num(a + 6)} {num(y + 9)}', 'fl-k')
    s.path(f'M{num(b - 5)} {num(y - 8)}H{num(b)}V{num(y + 8)}H{num(b - 5)}', 'fl-k')


def steps():
    st = {
        'intro': ('The shop grant caps transfers at {{fact:grant1-cap-xlm}} XLM per {{fact:grant1-period-ledgers}} ledgers; '
                  '*t* is an illustrative ledger. At ledger *L* the window holds the charges made after *L* − 100 and '
                  'through *L*.'),
        'steps': [{'n': str(ev), 'text': '{{fact:cap-event-%d}}' % ev} for ev, _ in EVENTS],
        'outro': ('The charge of 6 made at *t* stops counting at *t* + 100, and the charge of 4 made at *t* + 1 stops '
                  'counting at *t* + 101, when the window holds only the 5.'),
    }
    (FIGDIR / f'{FID}.steps.json').write_text(json.dumps(st, indent=1, ensure_ascii=False) + '\n', encoding='utf-8')


if __name__ == '__main__':
    print(make(False).write(), make(True).write())
    steps()
    t = FIGDIR / f'{FID}.text.html'
    if t.exists():
        t.unlink()
