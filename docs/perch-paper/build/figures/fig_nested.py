"""fig-nested: one grant covers a game's guess and the stake transfer inside it (HTML only).

The scenario is auth_root.rs (integration tests) and docs/nido-sim/: rule `game` scopes the game contract;
rule `pay-game` allows the XLM token's `transfer` only from the account (argument 0), only when the
entry's root call is exactly `game.guess`, within a cap. The account checks every call of the
signed tree against the rule the payload names for it (rule-core authorize.rs:105-136)."""
import html
import re

from figlib import FIGDIR, SVG, fact, num, arrow_down

FID = 'fig-nested'
STAKE, CAP, PERIOD = fact('nested-stake-xlm'), fact('nested-cap-xlm'), fact('nested-period-ledgers')

GRANT_A = [('Rule `game`', 't'), ('any function of the game contract, signed by the app’s key', 'm')]
GRANT_B = [('Rule `pay-game`', 't'), ('the XLM token’s `transfer` only', 'x'),
           ('argument 0 is the account itself', 'x'),
           ('argument 1 is the game', 'x'),
           ('only when the entry’s root call is exactly `game.guess`', 'x'),
           (f'at most {CAP} XLM in any {PERIOD} ledgers', 'x')]
NODE_1 = [('1  root call', 'm'), ('`game.guess(3, account)`', 'x'),
          ('✓ rule `game`: a call to the game contract', 'g')]
NODE_2 = [('2  call inside it, on a loss', 'm'), (f'`XLM.transfer(account, game, {STAKE} XLM)`', 'x'),
          ('✓ rule `pay-game`: from the account, to the game', 'g'),
          ('✓ the entry’s root is exactly `game.guess`', 'g'),
          (f'✓ {STAKE} of {CAP} XLM in the window', 'g')]
REFUSED = [('Refused, with nothing written', 'd'),
           ('✕ the same transfer signed as its own entry: its root is `XLM.transfer`', 'x'),
           ('✕ the transfer under `game.other`, or under another game’s `guess`', 'x'),
           ('✕ the stake sent to anyone but the game', 'x'),
           (f'✕ a third loss within {PERIOD} ledgers: over the cap', 'x')]


def heights(w, items_list, size=14):
    probe = SVG(FID, 760)
    return [probe.textbox(0, 0, w, items, 'tested', size=size) for items in items_list]


def wide():
    s = SVG(FID, 760)
    s.text(2, 16, 'ONE GRANT, THE CALL AND THE PAYMENT INSIDE IT', 't tag', 14)
    # left: the grant, two rules
    gx, gw = 2, 262
    ha, hb = heights(gw - 28, [GRANT_A, GRANT_B])
    s.box(gx, 30, gw, 44 + ha + 12 + hb + 14, 'key', 8)
    s.text(gx + 14, 54, 'The app’s grant', 't', 15)
    ya = 66
    s.textbox(gx + 14, ya, gw - 28, GRANT_A, 'tested', size=14)
    yb = ya + ha + 12
    s.textbox(gx + 14, yb, gw - 28, GRANT_B, 'tested', size=14)
    # right: the signed tree
    tx = 300
    s.text(tx, 54, 'The entry the app signs', 't', 15)
    h1, h2 = heights(458, [NODE_1]) + heights(430, [NODE_2])
    y1 = 66
    s.textbox(tx, y1, 458, NODE_1, 'tested', size=14)
    y2 = y1 + h1 + 22
    s.textbox(tx + 28, y2, 430, NODE_2, 'tested', size=14)
    s.path(f'M{num(tx + 12)} {num(y1 + h1)}V{num(y2 + 24)}H{num(tx + 24)}', 'fl', marker_end='url(#perch-ah)')
    # each node is checked against the rule the payload names for it
    s.path(f'M{num(gx + gw - 14)} {num(ya + ha / 2)}H{num(282)}V{num(y1 + 24)}H{num(tx - 4)}', 'fl-k dash',
           marker_end='url(#perch-ah-k)')
    s.path(f'M{num(gx + gw - 14)} {num(yb + hb / 2)}H{num(282)}V{num(y2 + h2 / 2)}H{num(tx + 24)}', 'fl-k dash',
           marker_end='url(#perch-ah-k)')
    yr = max(y2 + h2, 30 + 44 + ha + 12 + hb + 14) + 24
    hr = s.textbox(2, yr, 756, REFUSED, 'deny', size=14)
    s.h = yr + hr + 4
    return s


def narrow():
    s = SVG(FID, 340, narrow=True)
    s.text(2, 16, 'ONE GRANT, THE CALL INSIDE IT', 't tag', 14)
    y = 30
    s.text(2, y + 14, 'The app’s grant', 't', 15)
    y += 26
    y += s.textbox(2, y, 336, GRANT_A, 'key', size=14) + 8
    y += s.textbox(2, y, 336, GRANT_B, 'key', size=14) + 22
    s.text(2, y + 14, 'The entry the app signs', 't', 15)
    y += 26
    h1 = s.textbox(2, y, 336, NODE_1, 'tested', size=14)
    y += h1
    arrow_down(s, 20, y + 2, y + 18, 'fl', 'perch-ah')
    y += 22
    y += s.textbox(18, y, 320, NODE_2, 'tested', size=14) + 18
    y += s.textbox(2, y, 336, REFUSED, 'deny', size=14)
    s.h = y + 4
    return s


def text_alt():
    def code(s):
        return re.sub(r'`([^`]+)`', r'<code>\1</code>', html.escape(s, quote=False))

    def items(rows):
        return ''.join(f'<li>{code(t.lstrip(chr(0x2713) + chr(0x2715) + " "))}</li>' for t, _ in rows)
    return (f'<p>The app’s grant has two rules.</p><ul>'
            f'<li>{code(GRANT_A[0][0])}: {code(GRANT_A[1][0])}.</li>'
            f'<li>{code(GRANT_B[0][0])}: ' + '; '.join(code(t) for t, _ in GRANT_B[1:]) + '.</li></ul>'
            f'<p>The entry the app signs holds a tree of two calls, and the account checks each against its rule.</p>'
            f'<ol><li>{code(NODE_1[1][0])}, the root call: rule <code>game</code> accepts a call to the game contract.</li>'
            f'<li>{code(NODE_2[1][0])}, made by the game on a loss: rule <code>pay-game</code> accepts it because it '
            f'is from the account to the game, the entry’s root is exactly <code>game.guess</code>, and it brings the window '
            f'to {STAKE} of {CAP} XLM.</li></ol>'
            f'<p>{code(REFUSED[0][0])}:</p><ul>{items(REFUSED[1:])}</ul>')


if __name__ == '__main__':
    print(wide().write(), narrow().write())
    (FIGDIR / f'{FID}.text.html').write_text(text_alt() + '\n', encoding='utf-8')
