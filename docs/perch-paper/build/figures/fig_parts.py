"""fig-parts: the parts of a Perch account and the calls out of it."""
from figlib import SVG, FIGDIR, arrow_down, num

FID = 'fig-parts'

ACTORS = [
    ('key', [('Owner, passkey wallet', 't'), ('Signs account documents and grant installs.', 'x')]),
    ('key', [('App (Guess the Number)', 't'), ('Signs its calls with its grant key.', 'x')]),
    ('key', [('Soroban host', 't'), ('Calls `__check_auth` for each authorization entry.', 'x')]),
]
INNER = [
    ('tested', [('`__check_auth`', 't'), ('Account shell: guards, digest, signers', 'x'), ('TESTED', 'm tag', 14)]),
    ('proved', [('`rule_eval`, a linked library', 't'), ('`authorize`, `lower`, `lower_scoped`', 'x', 14), ('PROVED', 'g tag', 14)]),
    ('tested', [('Storage', 't'), ('Rules, grants, spending records, grant generation, credential index', 'x')]),
]
TARGETS = [
    (176, 'trusted', [('Every authorization', 'a', 14), ('Verifier contracts', 't', 14), ('Ed25519, WebAuthn', 'x', 14), ('TRUSTED', 'm tag', 14)]),
    (176, 'tested', [('Every install', 'a', 14), ('Document compiler', 't', 14), ('Resolves names in `perch/verifiers`', 'x', 14), ('TESTED', 'm tag', 14)]),
    (202, 'tested', [('Account-document writes, upgrades, cancellations, completions', 'a', 14), ('Recovery controller', 't', 14), ('TESTED', 'm tag', 14)]),
    (92, 'tested', [('Enrollment', 'a', 14), ('ZK pool', 't', 14), ('TESTED', 'm tag', 14)]),
]
IW = [200, 292, 216]


def wide():
    s = SVG(FID, 760, narrow=False)
    xs, w = [2, 258, 514], 244
    probe = SVG(FID, 760)
    h = max(probe.textbox(x, 2, w, items, kind, size=15) for (kind, items), x in zip(ACTORS, xs))
    for (kind, items), x in zip(ACTORS, xs):
        s.textbox(x, 2, w, items, kind, size=15, minh=h)
    ya = 2 + h
    s.path(f'M502 {num(2 + h / 2)}H512', 'fl-k', marker_end='url(#perch-ah-k)')
    s.path(f'M123 {num(ya)}V{num(ya + 14)}H590V{num(ya + 2)}', 'fl-k', marker_end='url(#perch-ah-k)')
    acc_y = ya + 30
    arrow_down(s, 690, ya, acc_y - 2)
    s.text(682, ya + 26, '`__check_auth`', 'm', 14, 'end')
    inner_y = acc_y + 32
    xs = [14, 14 + IW[0] + 12, 14 + IW[0] + IW[1] + 24]
    probe = SVG(FID, 760)
    ih = max(probe.textbox(x, inner_y, w_, it, k, size=15) for (k, it), x, w_ in zip(INNER, xs, IW))
    acc_h = inner_y - acc_y + ih + 12
    s.rect(2, acc_y, 756, acc_h, 'bx', 8)
    s.text(14, acc_y + 23, 'Perch account, `perch_account.wasm`', 't', 16)
    for (k, it), x, w_ in zip(INNER, xs, IW):
        s.textbox(x, inner_y, w_, it, k, size=15, minh=ih)
    s.path(f'M{xs[1] - 12} {num(inner_y + ih / 2)}H{xs[1] - 2}', 'fl-m', marker_end='url(#perch-ah-m)')
    yb = acc_y + acc_h
    ty = yb + 26
    x = 2
    probe = SVG(FID, 760)
    th = max(probe.textbox(0, ty, w_, it, k, size=14, lh=18) for w_, k, it in TARGETS)
    for w_, k, it in TARGETS:
        arrow_down(s, x + 30, yb, ty - 2)
        s.textbox(x, ty, w_, it, k, size=14, lh=18, minh=th)
        x += w_ + 10
    arrow_down(s, x + 30, yb, ty - 2)
    s.text(x + 4, ty + 22, 'Owner', 'a', 14)
    s.text(x + 4, ty + 40, '`execute`', 'a', 14)
    s.text(x + 4, ty + 62, 'Any', 't', 14)
    s.text(x + 4, ty + 80, 'contract', 't', 14)
    s.h = ty + th + 2
    return s


def narrow():
    s = SVG(FID, 340, narrow=True)
    y = 2
    hs = []
    for kind, items in ACTORS:
        h = s.textbox(18, y, 320, items, kind, size=14)
        hs.append((y, h))
        y += h + 12
    # owner, app -> host along the left rail
    host_y, host_h = hs[2]
    s.path(f'M18 {num(hs[0][0] + 22)}H8V{num(host_y + 22)}H16', 'fl-k', marker_end='url(#perch-ah-k)')
    s.path(f'M18 {num(hs[1][0] + 22)}H8', 'fl-k')
    yb = host_y + host_h
    acc_y = yb + 28
    arrow_down(s, 60, yb, acc_y - 2)
    s.text(68, yb + 19, '`__check_auth`', 'm', 14)
    # draw account frame first, then inner boxes
    probe = SVG(FID, 340, narrow=True)
    heights = [probe.textbox(14, 0, 312, it, k, size=14) for k, it in INNER]
    acc_h = 32 + sum(heights) + 10 * (len(heights) - 1) + 12
    s.rect(2, acc_y, 336, acc_h, 'bx', 8)
    s.text(14, acc_y + 22, 'Perch account', 't', 15)
    iy = acc_y + 32
    for (k, it), h in zip(INNER, heights):
        s.textbox(14, iy, 312, it, k, size=14)
        iy += h + 10
    yb = acc_y + acc_h
    y = yb + 24
    rail = []
    for w_, k, it in TARGETS:
        h = s.textbox(24, y, 314, it, k, size=14)
        rail.append(y + 20)
        y += h + 10
    rail.append(y + 20)
    s.text(36, y + 18, 'Owner `execute`', 'a', 14)
    s.text(36, y + 38, 'Any contract', 't', 14)
    s.path(f'M12 {num(yb)}V{num(rail[-1])}', 'fl')
    for ry in rail:
        s.path(f'M12 {num(ry)}H22', 'fl', marker_end='url(#perch-ah)')
    s.h = y + 46
    return s


if __name__ == '__main__':
    print(wide().write(), narrow().write())
