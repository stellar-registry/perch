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
    s.textbox(214, 196, 190, [('Soroban host', 't'), ('runs the call; asks each account', 'm')], 'tested', size=15, minh=62)
    # The verifier is outside the account. The only path into Store comes back
    # from that verifier, so the geometry shows the same ordering as the prose.
    probe = SVG(FID, 760)
    hg = probe.textbox(442, 0, 302, [('Installed grant', 't'), ('rules and spending records', 'm')], 'tested', size=14)
    hd = probe.textbox(442, 0, 302, [('Decision function', 't'), ('`rule_eval::check_auth` checks the rules and the window', 'x')], 'tested', size=14)
    hs = probe.textbox(442, 0, 302, [('Store after both checks pass', 't'), ('the new window record', 'm')], 'tested', size=14)
    yg = 46
    yd = yg + hg + 18
    ys = max(300, yd + hd + 90)
    bottom = ys + hs + 12
    s.box(428, 10, 330, bottom - 10, 'key', 8)
    s.text(442, 34, 'Perch account', 't', 15)
    s.textbox(442, yg, 302, [('Installed grant', 't'), ('rules and spending records', 'm')], 'tested', size=14)
    s.textbox(442, yd, 302, [('Decision function', 't'), ('`rule_eval::check_auth` checks the rules and the window', 'x')], 'tested', size=14)
    s.textbox(442, ys, 302, [('Store after both checks pass', 't'), ('the new window record', 'm')], 'tested', size=14)
    yv = ys
    hv = s.textbox(214, yv, 190, [('Verifier contract', 't'), ('checks the app\u2019s signature', 'm')], 'tested', size=14)
    # 1 install, 2 sign, 3 ask, 4 verify then store
    arrow_right(s, 174, 438, yg + hg / 2, 'fl', 'perch-ah')
    label(s, 190, yg + hg / 2 - 28, '1  installs a grant (`apply_grant`)', 230)
    arrow_right(s, 174, 210, 226, 'fl', 'perch-ah')
    label(s, 174, 179, '2 signs', 60)
    s.path(f'M404 226H416V{num(yd + hd / 2)}H438', 'fl', marker_end='url(#perch-ah)')
    label(s, 398, yd + hd / 2 - 30, '3 asks the account', 190, anchor='end')
    label(s, 398, yd + hd / 2 - 13, '(`__check_auth`)', 190, anchor='end')
    s.path(f'M593 {num(yd + hd + 2)}V{num(yv - 11)}H309V{num(yv - 4)}', 'fl', marker_end='url(#perch-ah)')
    label(s, 446, yv - 25, '4 decision accepts', 230)
    arrow_right(s, 406, 438, ys + hs / 2, 'fl', 'perch-ah')
    label(s, 442, bottom + 22, '5 valid signature → commit record', 302)
    label(s, 2, bottom + 22, 'Any refusal leaves the record unchanged.', 400)
    s.h = max(bottom + 30, yv + hv + 4)
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
        ([('Store after both checks pass', 't'), ('the new window record', 'x')], 'tested'),
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
