"""Convert the paper's figure SVG subset to a TikZ picture.

The HTML paper styles its figures with CSS classes bound to theme tokens. The
LaTeX paper draws the same SVG with the light theme's colors, so a figure has
one source. Only the subset the figures use is accepted: svg, g (opacity),
rect, line, circle, path (M L H V l h v z), text with tspan, the arrow markers
and the hatch pattern. Elements marked data-print="no" (interactive-only) are
skipped; other data-* attributes are ignored. Anything else raises, so a new figure cannot silently
lose an element in print.

Coordinates stay in SVG user units (1 unit = 1pt, y flipped); the caller wraps
the picture in \\resizebox so text and geometry scale together as in the page.
"""
import re
import xml.etree.ElementTree as ET

# Light-theme tokens (docs/perch-paper/source/html/style.css, light block).
TOKENS = {
    'text': '14191D', 'muted': '4F5D66', 'amber': '8A5A00', 'deny': 'A8382A',
    'key': '1F5D7A', 'green': '1F6B52', 'line': 'D9DCD6', 'tint': 'EBEDE7',
    'fig-stroke': '7D8A91', 'fig-fill': 'F1F2EE', 'fig-proved': 'E6F1EA',
    'fig-deny': 'F8E6E2', 'bg': 'FFFFFF',
}

# Class -> style properties, mirroring the page's `.fig .<class>` rules.
CLASSES = {
    'bx': {'fill': 'fig-fill', 'stroke': 'fig-stroke', 'width': 1.5},
    'bx-hi': {'stroke': 'amber', 'width': 2},
    'bx-k': {'stroke': 'key', 'width': 2},
    'bx-no': {'stroke': 'deny', 'width': 2, 'fill': 'fig-deny'},
    'bx-pr': {'stroke': 'green', 'width': 2.5, 'fill': 'fig-proved'},
    'dash': {'dash': (6, 4)},
    'tr': {'pattern': True},
    'band': {'fill': 'tint', 'stroke': None},
    'rule': {'stroke': 'line', 'width': 1},
    'pill': {'fill': None, 'width': 1.5},
    'pill-d': {'stroke': 'deny', 'fill': 'fig-deny'},
    'pill-g': {'stroke': 'green', 'fill': 'fig-proved'},
    'pill-k': {'stroke': 'key', 'fill': 'fig-fill'},
    'pill-m': {'stroke': 'fig-stroke', 'fill': 'fig-fill'},
    'fl': {'fill': None, 'stroke': 'amber', 'width': 2},
    'fl-d': {'fill': None, 'stroke': 'deny', 'width': 2},
    'fl-k': {'fill': None, 'stroke': 'key', 'width': 2},
    'fl-g': {'fill': None, 'stroke': 'green', 'width': 2},
    'fl-m': {'fill': None, 'stroke': 'fig-stroke', 'width': 1.5},
    'gl': {'fill': None, 'stroke': 'text', 'width': 2.2},
    'gl-d': {'fill': None, 'stroke': 'deny', 'width': 2.2},
    'gl-a': {'fill': None, 'stroke': 'amber', 'width': 2.2},
    'gl-g': {'fill': None, 'stroke': 'green', 'width': 2.2},
    # Interactive-figure hooks carry no print style.
    'step': {}, 'hot': {}, 'layer': {},
}
TEXT_CLASSES = {
    't': ('text', True), 'x': ('text', False), 'm': ('muted', False),
    'a': ('amber', False), 'd': ('deny', False), 'k': ('key', False),
    'g': ('green', False), 'tag': (None, True), 'mono': (None, False),
}
MARKERS = {
    'perch-ah': ('amber', 'arrow'), 'perch-ah-d': ('deny', 'arrow'),
    'perch-ah-k': ('key', 'arrow'), 'perch-ah-g': ('green', 'arrow'),
    'perch-ah-m': ('fig-stroke', 'arrow'), 'perch-bar': ('deny', 'bar'),
}
NS = '{http://www.w3.org/2000/svg}'
UNICODE = {
    '→': r'\ensuremath{\rightarrow}', '←': r'\ensuremath{\leftarrow}',
    '↔': r'\ensuremath{\leftrightarrow}', '≤': r'\ensuremath{\le}',
    '≥': r'\ensuremath{\ge}', '−': r'\ensuremath{-}', '×': r'\ensuremath{\times}',
    '·': r'\ensuremath{\cdot}', '…': r'\ldots{}', '∪': r'\ensuremath{\cup}',
    '‖': r'\ensuremath{\|}', '└': r'\textbar\_', '≠': r'\ensuremath{\neq}',
    '∈': r'\ensuremath{\in}', '✓': r'\checkmark{}', '—': '---', '–': '--',
    '“': '``', '”': "''", '‘': '`', '’': "'", '§': r'\S{}', '•': r'\textbullet{}',
}


def tex_escape(s):
    out = []
    for ch in s:
        if ch in '&%$#_{}':
            out.append('\\' + ch)
        elif ch == '~':
            out.append(r'\textasciitilde{}')
        elif ch == '^':
            out.append(r'\textasciicircum{}')
        elif ch == '\\':
            out.append(r'\textbackslash{}')
        elif ch == '<':
            out.append(r'\textless{}')
        elif ch == '>':
            out.append(r'\textgreater{}')
        elif ch in UNICODE:
            out.append(UNICODE[ch])
        else:
            out.append(ch)
    return ''.join(out)


def num(v):
    return f'{float(v):.2f}'.rstrip('0').rstrip('.')


def _style(el, inherited_opacity=None):
    props = {}
    for c in (el.get('class') or '').split():
        if c not in CLASSES and c not in TEXT_CLASSES:
            raise ValueError(f'unknown figure class {c!r} on <{el.tag}>')
        props.update(CLASSES.get(c, {}))
    if el.get('fill') == 'none':
        props['fill'] = None
    if el.get('stroke-dasharray'):
        a, b = el.get('stroke-dasharray').split()
        props['dash'] = (float(a), float(b))
    st = el.get('style')
    if st:
        for decl in filter(None, st.split(';')):
            k, v = [p.strip() for p in decl.split(':', 1)]
            m = re.fullmatch(r'var\(--([a-z0-9-]+)\)', v)
            if k in ('fill', 'stroke') and m:
                props[k] = m.group(1)
            elif k == 'stroke-width':
                props['width'] = float(v)
            else:
                raise ValueError(f'unsupported style {decl!r}')
    opts = []
    if props.get('fill'):
        opts.append(f'fill=c{props["fill"]}')
    if props.get('pattern'):
        opts.append('pattern=north east lines, pattern color=cfig-stroke')
    if props.get('stroke'):
        opts.append(f'draw=c{props["stroke"]}')
        opts.append(f'line width={num(props.get("width", 1))}pt')
    if 'dash' in props and props.get('stroke'):
        a, b = props['dash']
        opts.append(f'dash pattern=on {num(a)}pt off {num(b)}pt')
    if inherited_opacity:
        opts.append(f'opacity={inherited_opacity}')
    return opts


def _tips(el):
    def tip(ref):
        m = re.fullmatch(r'url\(#([a-z-]+)\)', ref or '')
        if not m:
            return ''
        color, kind = MARKERS[m.group(1)]
        if kind == 'bar':
            return f'Bar[width=14pt,line width=3pt,color=c{color}]'
        return f'Triangle[length=8pt,width=8pt,color=c{color},fill=c{color},line width=0pt]'
    s, e = tip(el.get('marker-start')), tip(el.get('marker-end'))
    if not (s or e):
        return []
    return ['{' + s + '}-{' + e + '}']


def _path_points(d):
    toks = re.findall(r'[MLHVZmlhvz]|-?\d*\.?\d+(?:e-?\d+)?', d)
    subpaths, cur, x, y, i, cmd = [], [], 0.0, 0.0, 0, None
    while i < len(toks):
        t = toks[i]
        if re.fullmatch(r'[A-Za-z]', t):
            cmd = t
            i += 1
            if cmd in 'Zz':
                cur.append('cycle')
                continue
            continue
        if cmd in 'Mm':
            nx, ny = float(toks[i]), float(toks[i + 1])
            i += 2
            if cmd == 'm':
                nx, ny = x + nx, y + ny
            if cur:
                subpaths.append(cur)
            cur = [(nx, ny)]
            x, y = nx, ny
            cmd = 'L' if cmd == 'M' else 'l'
        elif cmd in 'Ll':
            nx, ny = float(toks[i]), float(toks[i + 1])
            i += 2
            if cmd == 'l':
                nx, ny = x + nx, y + ny
            x, y = nx, ny
            cur.append((x, y))
        elif cmd in 'Hh':
            v = float(toks[i]); i += 1
            x = v if cmd == 'H' else x + v
            cur.append((x, y))
        elif cmd in 'Vv':
            v = float(toks[i]); i += 1
            y = v if cmd == 'V' else y + v
            cur.append((x, y))
        else:
            raise ValueError(f'unsupported path command {cmd!r} in {d!r}')
    if cur:
        subpaths.append(cur)
    return subpaths


def _text(el, opacity):
    color, bold = 'text', False
    for c in (el.get('class') or '').split():
        if c not in TEXT_CLASSES:
            raise ValueError(f'unknown text class {c!r}')
        tc, tb = TEXT_CLASSES[c]
        color = tc or color
        bold = bold or tb
    if el.get('font-weight') and int(el.get('font-weight')) >= 600:
        bold = True
    size = float(el.get('font-size', 15))
    anchor = {'start': 'base west', 'middle': 'base', 'end': 'base east'}[el.get('text-anchor', 'start')]
    parts = [tex_escape(el.text or '')]
    for ts in el:
        if ts.tag != NS + 'tspan':
            raise ValueError('only tspan may nest in text')
        cls = (ts.get('class') or '').split()
        inner = tex_escape(ts.text or '')
        if 'mono' in cls:
            inner = r'{\ttfamily ' + inner + '}'
        for c in cls:
            if c != 'mono' and TEXT_CLASSES.get(c, (None,))[0]:
                inner = r'\textcolor{c' + TEXT_CLASSES[c][0] + '}{' + inner + '}'
        parts.append(inner)
        parts.append(tex_escape(ts.tail or ''))
    body = ''.join(parts)
    font = r'\fontsize{' + num(size) + '}{' + num(size * 1.2) + r'}\selectfont\sffamily'
    if bold:
        font += r'\bfseries'
    op = f', opacity={opacity}' if opacity else ''
    return (f'\\node[anchor={anchor}, inner sep=0, text=c{color}{op}, font={font}] '
            f'at ({num(el.get("x"))},{num(el.get("y"))}) {{{body}}};')


def _walk(el, out, opacity=None):
    tag = el.tag.replace(NS, '')
    if el.get('data-print') == 'no':
        return
    if tag == 'g':
        op = el.get('opacity') or opacity
        for c in (el.get('class') or '').split():
            if c not in CLASSES:
                raise ValueError(f'unknown group class {c!r}')
        for ch in el:
            _walk(ch, out, op)
        return
    if tag in ('title', 'desc'):
        return
    if tag == 'rect':
        opts = _style(el, opacity)
        r = el.get('rx')
        if r and float(r) > 0:
            opts.append(f'rounded corners={num(min(float(r), float(el.get("height")) / 2, float(el.get("width")) / 2))}pt')
        x, y, w, h = (float(el.get(k)) for k in ('x', 'y', 'width', 'height'))
        if opts:
            out.append(f'\\path[{", ".join(opts)}] ({num(x)},{num(y)}) rectangle ({num(x + w)},{num(y + h)});')
    elif tag == 'line':
        opts = _style(el, opacity) + _tips(el)
        out.append(f'\\path[{", ".join(opts)}] ({num(el.get("x1"))},{num(el.get("y1"))}) -- ({num(el.get("x2"))},{num(el.get("y2"))});')
    elif tag == 'circle':
        opts = _style(el, opacity)
        out.append(f'\\path[{", ".join(opts)}] ({num(el.get("cx"))},{num(el.get("cy"))}) circle[radius={num(el.get("r"))}pt];')
    elif tag == 'path':
        opts = _style(el, opacity) + _tips(el)
        for sp in _path_points(el.get('d')):
            pts = ' -- '.join(p if p == 'cycle' else f'({num(p[0])},{num(p[1])})' for p in sp)
            out.append(f'\\path[{", ".join(opts)}] {pts};')
    elif tag == 'text':
        out.append(_text(el, opacity))
    else:
        raise ValueError(f'unsupported SVG element <{tag}>')


def convert(svg_text):
    """Return (tikz_source, width, height) for one figure SVG."""
    root = ET.fromstring(svg_text if 'xmlns=' in svg_text else svg_text.replace('<svg ', '<svg xmlns="http://www.w3.org/2000/svg" ', 1))
    _, _, w, h = (float(v) for v in root.get('viewBox').split())
    out = []
    for ch in root:
        _walk(ch, out)
    body = '\n'.join(out)
    return (f'\\begin{{tikzpicture}}[x=1pt,y=-1pt,line join=round,line cap=round]\n'
            f'\\useasboundingbox (0,0) rectangle ({num(w)},{num(h)});\n{body}\n\\end{{tikzpicture}}'), w, h


def color_definitions():
    return '\n'.join(f'\\definecolor{{c{k}}}{{HTML}}{{{v}}}' for k, v in TOKENS.items())
