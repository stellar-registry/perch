#!/usr/bin/env python3
"""Perch deck thumbnail (16:9): the deck's title dial and its guilloche seals, in the deck's dark palette.

Ports buildSeal() and B.title from index.html with the same digests and geometry;
writes the SVG named on the command line (1280 x 720 user units):

    python3 thumbnail.py thumbnail.svg
"""
import math
import sys

OUT = sys.argv[1]
W, H = 1280, 720
PAPER, INK, INK2, RULE, NOW, SEAL = '#0D1628', '#E6EAF1', '#98A5BB', 'rgba(230,234,241,.17)', '#6EC4EF', '#E2C068'
DISPLAY = '"Didot", "Bodoni 72", "Bodoni MT", "Big Caslon", "Hoefler Text", Georgia, serif'
TEXT = '"Optima", "Candara", "Segoe UI", "Avenir Next", system-ui, sans-serif'
DIGESTS = {  # the deck's illustrative bytes, not real digests
    'A': '5f0e9a3cd41b7728e6a9c0f3b58d2e7164af90c3e25b7d18aa3f6c0954e2b8d7',
    'P': 'c93a07e15b2d48f6a1e07c3d95b2f84e16a0d7c39e5b2f8401a6d3c7e95b20f4',
}


def f2(n):
    return f'{round(n * 100) / 100:g}'


def seal_symbol(sid, hexs, dense):
    b = [int(hexs[i * 2:i * 2 + 2], 16) for i in range(32)]
    out = [f'<symbol id="{sid}" viewBox="-100 -100 200 200" overflow="visible">']
    d = ''
    for i in range(32):
        a = i / 32 * math.pi * 2 - math.pi / 2
        r1, r2 = 86, 90 + 10 * b[i] / 255
        d += f'M{f2(r1 * math.cos(a))} {f2(r1 * math.sin(a))}L{f2(r2 * math.cos(a))} {f2(r2 * math.sin(a))}'
    out.append(f'<path d="{d}" class="s-tick"/>')
    out.append('<circle r="83" class="s-ring"/><circle r="6" class="s-ring"/>')
    bands = [(30, 0), (50, 10), (68, 20)] if dense else [(38, 0), (64, 12)]
    copies, n = (11, 520) if dense else (6, 300)
    for r0, o in bands:
        amp = 4.5 + 9 * b[o] / 255
        k = 3 + (b[o + 1] % 9) + round(r0 / 22)
        m = 1 + (b[o + 2] % 5)
        mod = .1 + .6 * b[o + 3] / 255
        ph = b[o + 4] / 255 * math.pi * 2
        for c in range(copies):
            sh = c / copies * math.pi * 2
            p = []
            for i in range(n + 1):
                t = i / n * math.pi * 2
                r = r0 + amp * math.sin(k * t + sh) * (1 + mod * math.sin(m * t + ph))
                p.append(('L' if i else 'M') + f2(r * math.cos(t)) + ' ' + f2(r * math.sin(t)))
            out.append(f'<path d="{"".join(p)}Z" class="s-wave"/>')
    out.append('</symbol>')
    return ''.join(out)


ICONS = {
    'key': ['<circle cx="-14" cy="0" r="9"/>', '<path d="M-5 0H26M18 0V8M24 0V6"/>'],
    'person': ['<circle cx="0" cy="-10" r="9"/>', '<path d="M-18 22C-18 5 18 5 18 22"/>'],
    'agent': ['<rect x="-17" y="-20" width="34" height="26" rx="8"/>', '<path d="M0 -20V-26M-21 26V22C-21 15 21 15 21 22V26M-8 -1H8"/>',
              '<circle cx="-7" cy="-10" r="2.6" class="dot"/>', '<circle cx="7" cy="-10" r="2.6" class="dot"/>', '<circle cx="0" cy="-28" r="2.4" class="dot"/>'],
}


def dial(sw=2.4):
    """B.title in its own 800 x 800 frame."""
    cx = cy = 400
    deg = math.pi / 180

    def pol(r, a):
        return cx + r * math.cos(a * deg), cy + r * math.sin(a * deg)

    def P(r, a):
        x, y = pol(r, a)
        return f'{f2(x)} {f2(y)}'

    g = [f'<circle cx="{cx}" cy="{cy}" r="362" stroke="{RULE}" stroke-width="{f2(.6 * sw)}"/>']
    d = ''.join(f'M{P(274, i * 2 - 90)}L{P(283 if i % 10 else 293, i * 2 - 90)}' for i in range(180))
    g.append(f'<path d="{d}" stroke="{INK2}" stroke-width="{f2(.3 * sw)}"/>')
    g.append(f'<circle cx="{cx}" cy="{cy}" r="184" stroke="{NOW}" stroke-width="{f2(1.2 * sw)}"/>')
    g.append(f'<circle cx="{cx}" cy="{cy}" r="170" stroke="{NOW}" stroke-width="{f2(.4 * sw)}"/>')
    g.append(f'<g transform="translate({cx} {cy})" color="{SEAL}"><use href="#seal-P" x="-130" y="-130" width="260" height="260"/></g>')
    for a, x, inside in [(-206, 3, 0), (-188, 5, 0), (-154, 6, 0), (-146, 4, 1), (-52, 5, 1)]:
        x1, y1 = pol(196, a)
        x2, y2 = pol(196 + x * 11, a)
        st = f'stroke="{NOW}" stroke-width="{f2(3.4 * sw)}"' if inside else f'stroke="{INK2}" stroke-width="{f2(2.2 * sw)}" opacity=".45"'
        g.append(f'<line x1="{f2(x1)}" y1="{f2(y1)}" x2="{f2(x2)}" y2="{f2(y2)}" {st}/>')
    a0, a1 = -150, -48
    sector = f'M{P(190, a0)}L{P(304, a0)}A304 304 0 0 1 {P(304, a1)}L{P(190, a1)}A190 190 0 0 0 {P(190, a0)}Z'
    g.append(f'<path d="{sector}" stroke="{NOW}" stroke-width="{f2(.5 * sw)}" fill="url(#hatch-now)"/>')
    for a in (a0, a1):
        x1, y1 = pol(186, a)
        x2, y2 = pol(312, a)
        g.append(f'<line x1="{f2(x1)}" y1="{f2(y1)}" x2="{f2(x2)}" y2="{f2(y2)}" stroke="{NOW}" stroke-width="{f2(1.5 * sw)}"/>')

    def icon(name, x, y, s, col):
        sc = s / 60
        body = ''.join(ICONS[name]).replace('class="dot"', f'fill="{col}"')
        return (f'<g transform="translate({x} {y}) scale({f2(sc)})" stroke="{col}" stroke-width="{f2(sw / sc)}" class="icon">'
                f'{body}</g>')

    def lk(x, y, a, r):
        tx, ty = pol(r, a)
        L = math.hypot(tx - x, ty - y)
        return (f'<line x1="{f2(x + (tx - x) / L * 52)}" y1="{f2(y + (ty - y) / L * 52)}" x2="{f2(tx)}" y2="{f2(ty)}" '
                f'stroke="{INK2}" stroke-width="{f2(.5 * sw)}"/>')

    g += [icon('key', 108, 118, 74, NOW), lk(108, 118, -126, 314), icon('agent', 692, 118, 74, NOW), lk(692, 118, -62, 314),
          icon('person', 108, 690, 74, INK), lk(108, 690, 135, 190)]
    return ''.join(g)


def main():
    s = .86
    ox, oy = 930 - 400 * s, 360 - 400 * s
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="t">
<title id="t">Perch: bounded grants for apps and agents on Stellar</title>
<defs>
<style>
.s-wave {{ fill: none; stroke: currentColor; stroke-width: .7; vector-effect: non-scaling-stroke; opacity: .9; }}
.s-tick {{ fill: none; stroke: currentColor; stroke-width: 1.6; vector-effect: non-scaling-stroke; stroke-linecap: round; }}
.s-ring {{ fill: none; stroke: currentColor; stroke-width: 1; vector-effect: non-scaling-stroke; }}
.dial * {{ stroke-linecap: round; stroke-linejoin: round; }}
.dial :not([fill]) {{ fill: none; }}
</style>
<pattern id="hatch-now" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><line x1="0" y1="0" x2="0" y2="8" stroke="{NOW}" stroke-width="1.2" opacity=".55"/></pattern>
{seal_symbol('seal-P', DIGESTS['P'], True)}
{seal_symbol('seal-A-mini', DIGESTS['A'], False)}
</defs>
<rect width="{W}" height="{H}" fill="{PAPER}"/>
<rect x="10.5" y="10.5" width="{W - 21}" height="{H - 21}" fill="none" stroke="{RULE}"/>
<rect x="15.5" y="15.5" width="{W - 31}" height="{H - 31}" fill="none" stroke="{RULE}" stroke-width=".6"/>
<g class="dial" transform="translate({f2(ox)} {f2(oy)}) scale({s})">{dial()}</g>
<text x="76" y="352" fill="{INK}" font-family='{DISPLAY}' font-size="188" letter-spacing="-2">Perch</text>
<text fill="{INK}" font-family='{TEXT}' font-size="34"><tspan x="80" y="438">Bounded grants for apps</tspan><tspan x="80" y="482">and agents on Stellar</tspan></text>
<g transform="translate(118 590)" color="{SEAL}"><use href="#seal-A-mini" x="-38" y="-38" width="76" height="76"/></g>
</svg>
'''
    open(OUT, 'w', encoding='utf-8').write(svg)


main()
