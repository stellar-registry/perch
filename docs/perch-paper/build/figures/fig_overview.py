"""fig-overview: who does what (HTML only). The owner installs a grant; the app signs its own calls;
the host asks the account, whose one decision function checks the grant and its window; a
verifier contract checks the signature; then the record is stored. Every box is plain: the HTML
edition states what Perch does, and the PDF and the verification paper carry the evidence levels."""
from figlib import SVG, num, wrap, arrow_down, arrow_right

FID = 'fig-overview'


def label(s, x, y, text, w, size=14, cls='x', anchor=None):
    return s.lines(x, y, wrap(text, w, size), cls, size, lh=17, anchor=anchor)


def wide():
    s = SVG(FID, 760)
    s.text(2, 16, 'WHO DOES WHAT', 't tag', 14)
    s.textbox(2, 44, 170, [('Owner', 't'), ('the account\u2019s administrator', 'm')], 'tested', size=15, minh=62)
    s.textbox(2, 196, 170, [('App or agent', 't'), ('holds its own key', 'm')], 'tested', size=15, minh=62)
    s.textbox(256, 196, 190, [('Soroban host', 't'), ('runs the call; asks each account', 'm')], 'tested', size=15, minh=62)
    # the account: the installed grant, the decision function, the store
    probe = SVG(FID, 760)
    hg = probe.textbox(546, 0, 198, [('Installed grant', 't'), ('rules and spending records', 'm')], 'tested', size=14)
    hd = probe.textbox(546, 0, 198, [('Decision function', 't'), ('`rule_eval::check_auth` checks the rules and the window', 'x')], 'tested', size=14)
    hs = probe.textbox(546, 0, 198, [('Store', 't'), ('the new window record', 'm')], 'tested', size=14)
    yg = 46
    yd = yg + hg + 14
    ys = yd + hd + 26
    bottom = ys + hs + 12
    s.box(532, 10, 226, bottom - 10, 'key', 8)
    s.text(546, 34, 'Perch account', 't', 15)
    s.textbox(546, yg, 198, [('Installed grant', 't'), ('rules and spending records', 'm')], 'tested', size=14)
    s.textbox(546, yd, 198, [('Decision function', 't'), ('`rule_eval::check_auth` checks the rules and the window', 'x')], 'tested', size=14)
    s.textbox(546, ys, 198, [('Store', 't'), ('the new window record', 'm')], 'tested', size=14)
    yv = bottom + 30
    hv = s.textbox(532, yv, 226, [('Verifier contract', 't'), ('checks the app\u2019s signature', 'm')], 'tested', size=14)
    # 1 install, 2 sign, 3 ask, 4 verify then store
    arrow_right(s, 174, 542, yg + hg / 2, 'fl', 'perch-ah')
    label(s, 190, yg + hg / 2 - 10, '1  installs a grant (`apply_grant`)', 340)
    arrow_right(s, 174, 252, 226, 'fl', 'perch-ah')
    label(s, 182, 216, '2  signs', 70)
    s.path(f'M{num(446)} {num(226)}H{num(496)}V{num(yd + hd / 2)}H{num(542)}', 'fl', marker_end='url(#perch-ah)')
    label(s, 488, yd + hd / 2 - 46, '3  asks the account', 160, anchor='end')
    label(s, 488, yd + hd / 2 - 29, '(`__check_auth`)', 160, anchor='end')
    s.path(f'M{num(750)} {num(yd + hd / 2)}H{num(766 - 10)}V{num(yv - 4)}', 'fl-m dash', marker_end='url(#perch-ah-m)')
    arrow_down(s, 600, yd + hd + 2, ys - 4, 'fl', 'perch-ah')
    label(s, 256, yv + 14, '4  only after the decision accepts: the verifier checks the signature, then the record is stored', 260)
    s.h = yv + hv + 4
    return s


def narrow():
    s = SVG(FID, 340, narrow=True)
    s.text(2, 16, 'WHO DOES WHAT', 't tag', 14)
    y = 28
    steps = [
        ([('Owner', 't'), ('installs a grant (`apply_grant`)', 'x')], 'tested'),
        ([('App or agent', 't'), ('signs its own call', 'x')], 'tested'),
        ([('Soroban host', 't'), ('asks the account (`__check_auth`)', 'x')], 'tested'),
        ([('Decision function', 't'), ('`rule_eval::check_auth` checks the installed grant’s rules and window', 'x')], 'tested'),
        ([('Verifier contract', 't'), ('checks the signature, only after the decision accepts', 'x')], 'tested'),
        ([('Store', 't'), ('the new window record', 'x')], 'tested'),
    ]
    for k, (items, kind) in enumerate(steps):
        h = s.textbox(2, y, 336, items, kind, size=14, minh=50)
        y += h
        if k + 1 < len(steps):
            arrow_down(s, 40, y + 2, y + 18, 'fl', 'perch-ah')
            y += 22
    s.h = y + 8
    return s


if __name__ == '__main__':
    print(wide().write(), narrow().write())
