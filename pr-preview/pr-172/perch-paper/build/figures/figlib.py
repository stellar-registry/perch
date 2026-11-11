"""Helpers that write the paper's figure SVG subset (see build/svg2tikz.py).

Shapes encode assurance: proved = double border, tested = single border,
trusted = hatched strip, refusal = bar end and cross, not called = dashed.
Text sizes stay within 14-17 u. No style= and no opacity.
"""
import html
import json
import re
from pathlib import Path

import os

PAPER = Path(__file__).resolve().parents[2]
REPO = PAPER.parent.parent
# make.py --check points FIGDIR at a scratch directory and compares.
FIGDIR = Path(os.environ.get('PERCH_FIG_OUT') or PAPER / 'source/figures')
FACTS = {}
for _fp in sorted((REPO / 'docs/perch-paper/source/facts').glob('*.json')):
    for _k, _v in json.loads(_fp.read_text()).items():
        FACTS[_k] = _v['value'] if isinstance(_v, dict) else _v


def fact(k):
    return FACTS[k]


# Helvetica advance widths (1/1000 em); the page's system sans is a little wider.
_HELV = {
    ' ': 278, '!': 278, '"': 355, '#': 556, '$': 556, '%': 889, '&': 667, "'": 191, '(': 333, ')': 333,
    '*': 389, '+': 584, ',': 278, '-': 333, '.': 278, '/': 278, ':': 278, ';': 278, '<': 584, '=': 584,
    '>': 584, '?': 556, '@': 1015, '[': 278, '\\': 278, ']': 278, '^': 469, '_': 556, '`': 333, '{': 334,
    '|': 260, '}': 334, '~': 584,
    'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778, 'H': 722, 'I': 278, 'J': 500,
    'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778, 'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611,
    'U': 722, 'V': 667, 'W': 944, 'X': 667, 'Y': 667, 'Z': 611,
    'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556, 'h': 556, 'i': 222, 'j': 222,
    'k': 500, 'l': 222, 'm': 833, 'n': 556, 'o': 556, 'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278,
    'u': 556, 'v': 500, 'w': 722, 'x': 500, 'y': 500, 'z': 500,
    '→': 1000, '←': 1000, '⇄': 1000, '↔': 1000, '−': 584, '·': 278, '‖': 400, '≤': 584, '≥': 584,
    '…': 1000, '’': 222, '—': 1000, '–': 556, '×': 584, '∪': 700, '✓': 800, '✕': 800, '§': 556,
}
SANS_K = 1.05   # Chromium system sans versus Helvetica (calibrated)
BOLD_K = 1.12
MONO_EM = 0.6


def _seg_width(s, size, mono=False, bold=False):
    if mono:
        return len(s) * MONO_EM * size
    k = BOLD_K if bold else SANS_K
    return sum(_HELV.get(ch, 600 if not ch.isdigit() else 556) for ch in s) / 1000 * size * k


def segments(content):
    """Split `code` spans: [(text, mono)]."""
    out = []
    for i, part in enumerate(content.split('`')):
        if part:
            out.append((part, i % 2 == 1))
    return out


def width(content, size=15, bold=False):
    return sum(_seg_width(t, size, m, bold) for t, m in segments(content))


def _words(content):
    """Words as lists of (text, mono) runs; spaces inside code spans also break."""
    words, cur = [], []
    for text, mono in segments(content):
        parts = text.split(' ')
        for j, part in enumerate(parts):
            if j > 0:
                words.append(cur)
                cur = []
            if part:
                cur.append((part, mono))
    words.append(cur)
    return [w for w in words if w]


def _join(words):
    runs = []
    for i, w in enumerate(words):
        for j, (t, m) in enumerate(w):
            if j == 0 and i > 0:
                prev_m = runs[-1][1]
                # the space takes the style of the run it continues
                if prev_m and m:
                    runs[-1] = (runs[-1][0] + ' ' + t, True)
                    continue
                runs.append((' ', False))
            if runs and runs[-1][1] == m and not (j == 0 and i > 0 and runs[-1][0] == ' '):
                runs[-1] = (runs[-1][0] + t, m)
            else:
                runs.append((t, m))
    return ''.join(f'`{t}`' if m else t for t, m in runs)


def wrap(content, maxw, size=15, bold=False):
    """Greedy wrap on spaces, including spaces inside code spans; a newline forces a break."""
    if '\n' in content:
        out = []
        parts = content.split('\n')
        opened = False
        for part in parts:
            if opened:
                part = '`' + part
            opened = part.count('`') % 2 == 1
            if opened:
                part += '`'
            out += wrap(part, maxw, size, bold)
        return out
    lines, line = [], []
    for w in _words(content):
        cand = line + [w]
        if not line or width(_join(cand), size, bold) <= maxw:
            line = cand
        else:
            lines.append(_join(line))
            line = [w]
    if line:
        lines.append(_join(line))
    return lines


def esc(s):
    return html.escape(s, quote=False)


def num(v):
    return f'{float(v):.2f}'.rstrip('0').rstrip('.')


def attrs(d):
    out = []
    for k, v in d.items():
        if v is None or v is False:
            continue
        k = k.rstrip('_').replace('_', '-')
        out.append(f'{k}="{html.escape(str(v))}"')
    return (' ' + ' '.join(out)) if out else ''


class SVG:
    def __init__(self, fid, w, h=None, narrow=False):
        self.fid, self.w, self.h, self.narrow = fid, w, h, narrow
        self.parts = []
        self.root_attrs = {}

    # raw ------------------------------------------------------------
    def add(self, s):
        self.parts.append(s)

    def open(self, **a):
        self.parts.append(f'<g{attrs(a)}>')

    def close(self):
        self.parts.append('</g>')

    # shapes ---------------------------------------------------------
    def rect(self, x, y, w, h, cls, rx=6, **a):
        self.add(f'<rect x="{num(x)}" y="{num(y)}" width="{num(w)}" height="{num(h)}" rx="{num(rx)}" class="{cls}"{attrs(a)}/>')

    def line(self, x1, y1, x2, y2, cls, **a):
        self.add(f'<line x1="{num(x1)}" y1="{num(y1)}" x2="{num(x2)}" y2="{num(y2)}" class="{cls}"{attrs(a)}/>')

    def path(self, d, cls, **a):
        self.add(f'<path d="{d}" class="{cls}"{attrs(a)}/>')

    def circle(self, cx, cy, r, cls, **a):
        self.add(f'<circle cx="{num(cx)}" cy="{num(cy)}" r="{num(r)}" class="{cls}"{attrs(a)}/>')

    def text(self, x, y, content, cls='x', size=15, anchor=None, **a):
        body = ''.join(f'<tspan class="mono">{esc(t)}</tspan>' if m else esc(t) for t, m in segments(content))
        an = f' text-anchor="{anchor}"' if anchor and anchor != 'start' else ''
        self.add(f'<text x="{num(x)}" y="{num(y)}" class="{cls}" font-size="{num(size)}"{an}{attrs(a)}>{body}</text>')

    def lines(self, x, y, lines, cls='x', size=15, lh=None, anchor=None):
        lh = lh or round(size * 1.33)
        for i, ln in enumerate(lines):
            self.text(x, y + i * lh, ln, cls, size, anchor)
        return y + (len(lines) - 1) * lh

    # composite marks -------------------------------------------------
    def check(self, x, y, cls='gl'):
        """A check mark whose box is x..x+12, y..y+12."""
        self.path(f'M{num(x)} {num(y + 6)}l4 5l8-10', cls)

    def cross(self, cx, cy, r=5, cls='gl-d'):
        self.path(f'M{num(cx - r)} {num(cy - r)}l{num(2 * r)} {num(2 * r)}M{num(cx + r)} {num(cy - r)}l{num(-2 * r)} {num(2 * r)}', cls)

    def numdot(self, cx, cy, n, r=11, size=14, cls='bx'):
        self.circle(cx, cy, r, cls)
        self.text(cx, cy + size * 0.35, str(n), 't', size, 'middle')

    def pill(self, x, y, label, kind='d', size=14, h=26):
        w = width(label, size) + 22
        cls = {'d': 'pill pill-d', 'g': 'pill pill-g', 'k': 'pill pill-k', 'm': 'pill pill-m'}[kind]
        self.rect(x, y, w, h, cls, rx=h / 2)
        self.text(x + 11, y + h / 2 + size * 0.36, label, {'d': 'd', 'g': 'g', 'k': 'k', 'm': 'm'}[kind], size)
        return w

    def box(self, x, y, w, h, kind='tested', rx=6, **a):
        """Draw a box whose border shape encodes its assurance."""
        if kind == 'proved':
            self.rect(x, y, w, h, 'bx bx-pr', rx, **a)
            self.rect(x + 4, y + 4, w - 8, h - 8, 'fl-g', max(rx - 4, 0))
        elif kind == 'trusted':
            self.rect(x, y, w, h, 'bx', rx, **a)
            self.rect(x + 3, y + 3, 11, h - 6, 'tr', 0)
        elif kind == 'none':
            self.rect(x, y, w, h, 'bx dash', rx, **a)
        else:
            cls = {'tested': 'bx', 'key': 'bx bx-k', 'hi': 'bx bx-hi', 'deny': 'bx bx-no'}[kind]
            self.rect(x, y, w, h, cls, rx, **a)

    def textbox(self, x, y, w, items, kind='tested', size=15, lh=None, pad=12, minh=0, rx=6, **a):
        """A box holding text items [(content, cls)] wrapped to its width; returns height.

        `items` entries: (content, cls) or (content, cls, size)."""
        lh = lh or round(size * 1.33)
        left = x + pad + (14 if kind == 'trusted' else 0)
        maxw = x + w - pad - left
        rows = []
        for it in items:
            content, cls = it[0], it[1]
            sz = it[2] if len(it) > 2 else size
            bold = 't' in cls.split() or 'tag' in cls.split()
            for ln in wrap(content, maxw, sz, bold):
                rows.append((ln, cls, sz))
        h = max(minh, pad + 4 + len(rows) * lh + pad - 4)
        self.box(x, y, w, h, kind, rx, **a)
        ty = y + pad + 4 + round(0.78 * size)
        for ln, cls, sz in rows:
            self.text(left, ty, ln, cls, sz)
            ty += lh
        return h

    def render(self, extra=None):
        cls = 'narrow' if self.narrow else 'wide'
        ra = {'class': cls, 'viewBox': f'0 0 {num(self.w)} {num(self.h)}', 'role': 'img',
              'aria-labelledby': f'{self.fid}-title', 'aria-describedby': f'{self.fid}-text'}
        ra.update(self.root_attrs)
        a = ' '.join(f'{k}="{html.escape(str(v))}"' for k, v in ra.items())
        return f'<svg {a}>' + ''.join(self.parts) + '</svg>\n'

    def write(self, name=None):
        name = name or (f'{self.fid}.narrow.svg' if self.narrow else f'{self.fid}.svg')
        (FIGDIR / name).write_text(self.render(), encoding='utf-8')
        return FIGDIR / name


def arrow_down(svg, x, y1, y2, cls='fl', marker='perch-ah'):
    svg.path(f'M{num(x)} {num(y1)}V{num(y2)}', cls, marker_end=f'url(#{marker})')


def arrow_right(svg, x1, x2, y, cls='fl', marker='perch-ah'):
    svg.path(f'M{num(x1)} {num(y)}H{num(x2)}', cls, marker_end=f'url(#{marker})')
