"""fig-proof-paths: one source, a proof path and a shipping path; data-node hooks for the proof-paths controller."""
from figlib import SVG, FIGDIR, fact, num, wrap

FID = 'fig-proof-paths'
LABELS = {
    'rustc-nightly': 'nightly rustc', 'model': 'the evaluator model', 'translation': 'the Lean translation', 'account-model': 'the account event model',
    'host-model': 'the host model', 'canon': "Perch's canon package", 'kernel': "Lean's kernel", 'charon': 'Charon',
    'aeneas': 'Aeneas', 'aeneas-lib': "Aeneas's Lean library", 'denotations': 'the denotations',
    'doc-allows': 'the document meaning Doc.allows', 'host-models': 'the host models matching the host',
    'canon-emitter': "the Lean emitter matching Perch's canon.rs",
}


def node(s, nid, x, y, w, items, kind, size=14, minh=0, lh=17, pad=10):
    s.open(data_node=nid, data_label=LABELS[nid]) if nid else s.open()
    h = s.textbox(x, y, w, items, kind, size=size, minh=minh, lh=lh, pad=pad)
    s.close()
    return h


def wide():
    s = SVG(FID, 760)
    C = [(124, 150), (288, 124), (426, 174), (614, 144)]
    s.text(124, 14, 'PROOF PATH', 't tag', 14)
    r1, h1 = 22, 72
    node(s, 'rustc-nightly', C[0][0], r1, C[0][1], [('nightly rustc → MIR', 't'), (f'`{fact("rustc-mir-nightly").replace("nightly-", "")}`', 'x')], 'trusted', minh=h1)
    node(s, 'charon', C[1][0], r1, C[1][1], [('Charon → LLBC', 't'), (f'`{fact("charon-rev")}`', 'x')], 'trusted', minh=h1)
    node(s, 'aeneas', C[2][0], r1, C[2][1], [('Aeneas → Lean', 't'), (f'`{fact("aeneas-rev")}`', 'x')], 'trusted', minh=h1)
    node(s, 'aeneas-lib', C[3][0], r1, C[3][1], [("Aeneas's Lean library", 't')], 'trusted', minh=h1)
    for (x, w), (x2, _) in zip(C[:2], C[1:3]):
        s.path(f'M{x + w} {r1 + 36}H{x2 - 2}', 'fl', marker_end='url(#perch-ah)')
    # the Lean region: proved statements about these objects
    ry = r1 + h1 + 12
    rb = ry + 150
    s.box(116, ry, 492, rb - ry, 'proved', 8)
    s.text(130, ry + 22, 'PROVED IN LEAN', 'g tag', 14)
    s.path(f'M{C[2][0] + 40} {r1 + h1}V{ry + 34}', 'fl', marker_end='url(#perch-ah)')
    ya = ry + 36
    node(s, 'model', C[0][0], ya, C[0][1], [('Evaluator model', 't'), ('readable Lean', 'm')], 'proved', pad=10)
    node(s, 'translation', C[2][0], ya, C[2][1], [('Lean translation', 't'),
                                                (f'{fact("extracted-lean-lines")} lines', 'm')], 'proved', pad=10)
    ey = ya + 25
    s.path(f'M{C[0][0] + C[0][1]} {ey}H{C[2][0] - 2}', 'fl-g', marker_start='url(#perch-ah-g)', marker_end='url(#perch-ah-g)')
    s.text((C[0][0] + C[0][1] + C[2][0]) / 2, ey - 8, 'equivalence', 'g', 14, 'middle')
    yb = ya + 58
    node(s, 'account-model', C[0][0], yb, C[0][1], [('Account event model', 't')], 'proved', pad=10, minh=50)
    node(s, 'host-model', C[1][0], yb, C[1][1], [('Soroban host model', 't')], 'proved', pad=10, minh=50)
    s.text(C[2][0] + 4, yb + 20, f'{fact("exported-theorems")} exported theorems,', 'g', 14)
    s.text(C[2][0] + 4, yb + 38, 'standard axioms only', 'g', 14)
    # trusted specification under the region
    ys = rb + 8
    node(s, 'denotations', C[0][0], ys, C[0][1], [('Denotations', 'x')], 'trusted', minh=32, pad=7)
    node(s, 'doc-allows', C[1][0], ys, C[1][1], [('`Doc.allows`', 'x')], 'trusted', minh=32, pad=7)
    node(s, 'host-models', C[2][0], ys, C[2][1], [('Host models, tested', 'x')], 'trusted', minh=32, pad=7)
    # kernel and the canon package
    kx, kw = C[3]
    node(s, 'kernel', kx, ry, kw, [('Lean kernel', 't'), (f'`{fact("lean-rule-core")}`', 'x')], 'trusted', minh=54, pad=8)
    s.path(f'M{kx} {ry + 27}H610', 'fl-m', marker_end='url(#perch-ah-m)')
    cy = ry + 64
    node(s, 'canon', kx, cy, kw, [('Perch canon', 't'), (f'Lean `{fact("lean-perch-canon")}`', 'm'),
                                  ('CANON v1 injective', 'm')], 'proved', minh=rb - cy, pad=8)
    node(s, 'canon-emitter', kx, ys, kw, [('Canon emitter', 'x')], 'trusted', minh=32, pad=7)
    # the gap, and the tests that bridge the two paths
    gy = ys + 40
    s.open()
    s.rect(C[2][0], gy, 758 - C[2][0], 44, 'bx-no dash', 6)
    s.cross(C[2][0] + 16, gy + 22, 5)
    s.lines(C[2][0] + 30, gy + 18, ['Nothing checks this Wasm against', 'the translation.'], 'x', 14, lh=17)
    s.close()
    sy = gy + 64
    # The bridging tests run a natively built account, not the shipped Wasm.
    node(s, None, C[0][0], gy, 412 - C[0][0], [('Natively built account, in tests:', 't'),
                                              (f'{fact("lean-doc-traces")} Lean traces; rule-core vectors', 'm')], 'tested', minh=44, pad=6)
    s.path(f'M281 {rb}V{gy - 2}', 'fl-m dash', marker_end='url(#perch-ah-m)')
    s.path(f'M419 {rb}V{gy + 22}H414', 'fl-m dash', marker_end='url(#perch-ah-m)')
    # shipping path
    s.text(124, sy - 7, 'SHIPPING PATH', 't tag', 14)
    hs = 66
    node(s, None, C[0][0], sy, 134, [(f'rustc `{fact("rustc-perch")}` → Wasm', 't')], 'trusted', minh=hs, pad=8)
    node(s, None, 270, sy, 600 - 270, [('`perch_account.wasm`: the shell around linked `authorize`, `lower`, '
                                        '`lower_scoped`', 'x'), ('TESTED', 'm tag')], 'tested', minh=hs, pad=8)
    node(s, None, kx, sy, kw, [('Simulator and testnet runs', 'x'), ('TESTED', 'm tag')], 'tested', minh=hs, pad=8)
    s.path(f'M258 {sy + 33}H268', 'fl', marker_end='url(#perch-ah)')
    s.path(f'M600 {sy + 33}H{kx - 2}', 'fl', marker_end='url(#perch-ah)')
    # one source feeding both paths
    srcy = ry + 24
    h = node(s, None, 2, srcy, 104, [('One source', 't'), ('`crates/`', 'x'), ('`rule-eval`', 'x'),
                                     (f'about {fact("rule-eval-lines")} lines', 'm')], 'tested', pad=8)
    s.path(f'M40 {srcy}V{r1 + 36}H{C[0][0] - 2}', 'fl', marker_end='url(#perch-ah)')
    s.path(f'M40 {srcy + h}V{sy + 33}H{C[0][0] - 2}', 'fl', marker_end='url(#perch-ah)')
    s.h = sy + hs + 2
    return s


def narrow():
    s = SVG(FID, 340, narrow=True)
    y = 2
    h = node(s, None, 2, y, 336, [('One source: `crates/rule-eval`', 't'), (f'about {fact("rule-eval-lines")} lines of Rust', 'm')], 'tested')
    y += h + 26
    s.text(40, y - 8, 'PROOF PATH', 't tag', 14)
    s.path(f'M30 {y - 26}V{y - 2}', 'fl', marker_end='url(#perch-ah)')
    for nid, items in (('rustc-nightly', [('nightly rustc → MIR', 't'), (f'`{fact("rustc-mir-nightly")}`', 'x')]),
                       ('charon', [('Charon → LLBC', 't'), (f'`{fact("charon-rev")}`', 'x')]),
                       ('aeneas', [('Aeneas → Lean', 't'), (f'`{fact("aeneas-rev")}`', 'x')]),
                       ('aeneas-lib', [("Aeneas's Lean library", 't')])):
        h = node(s, nid, 20, y, 318, items, 'trusted')
        y += h + 8
    y += 4
    top = y
    ix, iw = 14, 312
    y += 32
    for nid, items, kind in (('translation', [('Lean translation', 't'), (f'{fact("extracted-lean-lines")} lines; CI regenerates', 'm')], 'proved'),
                             (None, [('equivalence', 'g')], None),
                             ('model', [('Evaluator model (readable Lean)', 't')], 'proved'),
                             ('account-model', [('Account event model', 't')], 'proved'),
                             ('host-model', [('Soroban host model', 't')], 'proved'),
                             (None, [(f'{fact("exported-theorems")} exported theorems, standard axioms only', 'g')], None),
                             ('denotations', [('Denotations', 'x')], 'trusted'),
                             ('doc-allows', [('`Doc.allows`', 'x')], 'trusted'),
                             ('host-models', [('Host models, tested against the host', 'x')], 'trusted')):
        if kind is None:
            if items[0][0] == 'equivalence':
                s.path(f'M60 {y - 6}V{y + 18}', 'fl-g', marker_start='url(#perch-ah-g)', marker_end='url(#perch-ah-g)')
                s.text(72, y + 11, 'equivalence', 'g', 14)
                y += 26
            else:
                s.text(ix + 6, y + 12, items[0][0], 'g', 14)
                y += 24
            continue
        h = node(s, nid, ix + 6, y, iw - 12, items, kind, minh=0, pad=8)
        y += h + 6
    s.box(2, top, 336, y - top + 6, 'proved', 8)
    # the region box must sit under its contents: move it to the front of this block
    region = s.parts.pop()
    region_inner = s.parts.pop()
    idx = next(i for i, p in enumerate(s.parts) if 'data-node="translation"' in p)
    s.parts[idx:idx] = [region_inner, region]
    s.text(14, top + 22, 'PROVED IN LEAN', 'g tag', 14)
    region_bottom = y + 6
    y += 18
    h = node(s, 'kernel', 20, y, 318, [(f'Lean kernel `{fact("lean-rule-core")}` checks the theorems', 't')], 'trusted')
    y += h + 10
    ch = 0
    s.open(data_node='canon', data_label=LABELS['canon'])
    probe_h = 92
    s.box(20, y, 318, probe_h, 'proved', 8)
    s.text(32, y + 24, f'Perch canon package, Lean `{fact("lean-perch-canon")}`', 't', 14)
    s.close()
    node(s, 'canon-emitter', 32, y + 36, 294, [("Lean emitter matches `canon.rs`", 'x')], 'trusted', minh=40)
    y += probe_h + 14
    s.open()
    s.rect(20, y, 318, 44, 'bx-no dash', 6)
    s.cross(36, y + 22, 5)
    s.lines(50, y + 18, ['Nothing checks this Wasm', 'against the translation.'], 'x', 14, lh=17)
    s.close()
    y += 54
    h = node(s, None, 20, y, 318, [('Natively built account, in tests:', 't'),
                                   (f'{fact("lean-doc-traces")} Lean traces; rule-core vectors', 'm')], 'tested')
    s.path(f'M10 {region_bottom}V{y + 22}H18', 'fl-m dash', marker_end='url(#perch-ah-m)')
    y += h + 14
    s.text(20, y + 12, 'SHIPPING PATH', 't tag', 14)
    y += 24
    rustc_y = y
    for items, kind in (([(f'rustc `{fact("rustc-perch")}` → `wasm32v1-none`', 't'), ('from the same source', 'm')], 'trusted'),
                        ([('`perch_account.wasm`: the shell around linked `authorize`, `lower`, `lower_scoped`', 'x'),
                          ('TESTED', 'm tag')], 'tested'),
                        ([('Simulator and testnet runs', 'x'), ('TESTED', 'm tag')], 'tested')):
        h = node(s, None, 20, y, 318, items, kind)
        y += h + 8
    s.h = y - 6
    return s


if __name__ == '__main__':
    print(wide().write(), narrow().write())
