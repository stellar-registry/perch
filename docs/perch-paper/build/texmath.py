"""Translate the LaTeX math the paper's statements use into MathML.

The academic edition typesets theorems from LaTeX math; the HTML edition shows
the same source as MathML, generated here at build time, so no script, font or
CDN is needed and both editions print one formula. Only the subset the paper
uses is accepted; anything else raises, so a formula never degrades silently.
"""
import html
import re

SYMBOLS = {
    # relations and arrows
    'le': ('mo', '≤'), 'leq': ('mo', '≤'), 'ge': ('mo', '≥'), 'geq': ('mo', '≥'), 'neq': ('mo', '≠'),
    'lt': ('mo', '<'), 'gt': ('mo', '>'),
    'in': ('mo', '∈'), 'notin': ('mo', '∉'), 'subseteq': ('mo', '⊆'), 'subset': ('mo', '⊂'),
    'supseteq': ('mo', '⊇'), 'to': ('mo', '→'), 'mapsto': ('mo', '↦'), 'rightarrow': ('mo', '→'),
    'Rightarrow': ('mo', '⇒'), 'implies': ('mo', '⟹'), 'iff': ('mo', '⟺'), 'Leftrightarrow': ('mo', '⇔'),
    'equiv': ('mo', '≡'), 'approx': ('mo', '≈'), 'models': ('mo', '⊨'), 'vdash': ('mo', '⊢'),
    'sqsubseteq': ('mo', '⊑'), 'preceq': ('mo', '⪯'),
    # operators
    'land': ('mo', '∧'), 'wedge': ('mo', '∧'), 'lor': ('mo', '∨'), 'vee': ('mo', '∨'), 'lnot': ('mo', '¬'),
    'neg': ('mo', '¬'), 'forall': ('mo', '∀'), 'exists': ('mo', '∃'), 'cup': ('mo', '∪'), 'cap': ('mo', '∩'),
    'setminus': ('mo', '∖'), 'cdot': ('mo', '⋅'), 'times': ('mo', '×'), 'circ': ('mo', '∘'), 'mid': ('mo', '∣'),
    'oplus': ('mo', '⊕'), 'Vert': ('mo', '‖'), 'parallel': ('mo', '∥'),
    'langle': ('mo', '⟨'), 'rangle': ('mo', '⟩'), 'lbrace': ('mo', '{'), 'rbrace': ('mo', '}'),
    'llbracket': ('mo', '⟦'), 'rrbracket': ('mo', '⟧'), 'lvert': ('mo', '|'), 'rvert': ('mo', '|'),
    'ldots': ('mo', '…'), 'cdots': ('mo', '⋯'), 'dots': ('mo', '…'),
    # constants
    'emptyset': ('mi', '∅'), 'varnothing': ('mi', '∅'), 'infty': ('mi', '∞'), 'bot': ('mi', '⊥'),
    'top': ('mi', '⊤'), 'ell': ('mi', 'ℓ'),
}
GREEK = {g: c for g, c in zip(
    'alpha beta gamma delta epsilon varepsilon zeta eta theta iota kappa lambda mu nu xi pi rho sigma tau '
    'upsilon phi varphi chi psi omega Gamma Delta Theta Lambda Xi Pi Sigma Phi Psi Omega'.split(),
    'αβγδϵεζηθικλμνξπρστυϕφχψωΓΔΘΛΞΠΣΦΨΩ')}
BIG = {'sum': '∑', 'prod': '∏', 'bigcup': '⋃', 'bigcap': '⋂', 'bigwedge': '⋀', 'bigvee': '⋁'}
FUNCS = {'max', 'min', 'dom', 'len', 'sup', 'inf', 'log'}
FONTS = {'mathrm': 'normal', 'mathit': 'italic', 'mathsf': 'sans-serif', 'mathtt': 'monospace',
         'mathbf': 'bold', 'mathcal': 'script', 'operatorname': 'normal'}
SPACES = {',': '0.17em', ':': '0.22em', ';': '0.28em', 'quad': '1em', 'qquad': '2em', ' ': '0.25em', '!': '0'}
TOKEN = re.compile(r'\x00(\d+)\x00|\\([A-Za-z]+|.)|([A-Za-z])|(\d+(?:\.\d+)?)|(\s+)|(.)', re.S)
# Text-style arguments keep their spaces, so they are cut out before tokenizing.
TEXTLIKE = re.compile(r'\\(text|textrm|textsf|texttt|textit|mathrm|mathit|mathsf|mathtt|mathbf|mathcal|operatorname)\{([^{}]*)\}')
TEXT_VARIANT = {'texttt': ' mathvariant="monospace"', 'textsf': ' mathvariant="sans-serif"', 'textit': ' mathvariant="italic"'}


class TexError(ValueError):
    pass


def _textlike(m, store):
    cmd, text = m.group(1), re.sub(r'\\(.)', r'\1', m.group(2))
    if cmd.startswith('text'):
        out = f'<mtext{TEXT_VARIANT.get(cmd, "")}>{html.escape(text)}</mtext>'
    else:
        out = f'<mi mathvariant="{FONTS[cmd]}">{html.escape(text)}</mi>'
        if cmd == 'operatorname':
            out += '<mo>&#x2061;</mo>'
    store.append(out)
    return f'\x00{len(store) - 1}\x00'


def _tokens(s, store):
    s = TEXTLIKE.sub(lambda m: _textlike(m, store), s)
    out = []
    for m in TOKEN.finditer(s):
        pre, cmd, letter, number, space, other = m.groups()
        if space:
            continue
        out.append(('pre', int(pre)) if pre is not None else ('cmd', cmd) if cmd is not None else
                   ('id', letter) if letter else ('num', number) if number else ('ch', other))
    return out


class _Parser:
    def __init__(self, tokens, store):
        self.t, self.i, self.store = tokens, 0, store

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def group(self):
        """One argument: {…} or a single token."""
        tok = self.peek()
        if tok == ('ch', '{'):
            self.take()
            out = self.seq('}')
            self.close()
            return _row(out)
        return self.atom()

    def close(self):
        if self.take() != ('ch', '}'):
            raise TexError('unclosed {')

    def raw_group(self):
        tok = self.take()
        if tok != ('ch', '{'):
            raise TexError('expected {')
        depth, buf = 1, []
        while True:
            t = self.take()
            if t is None:
                raise TexError('unclosed {')
            if t == ('ch', '{'):
                depth += 1
            elif t == ('ch', '}'):
                depth -= 1
                if depth == 0:
                    return buf
            buf.append(t)

    def seq(self, until=None):
        out = []
        while self.peek() is not None and self.peek() != ('ch', until):
            if until is None and self.peek() == ('ch', '}'):
                raise TexError('unbalanced }')
            out.append(self.scripted())
        return out

    def scripted(self):
        base = self.atom()
        sub = sup = None
        while self.peek() in (('ch', '_'), ('ch', '^')):
            kind = self.take()[1]
            arg = self.group()
            if kind == '_':
                sub = arg
            else:
                sup = arg
        if sub is None and sup is None:
            return base
        under = base.startswith('<mo movablelimits')
        if sub is not None and sup is not None:
            tag = 'munderover' if under else 'msubsup'
            return f'<{tag}>{base}{sub}{sup}</{tag}>'
        if sub is not None:
            tag = 'munder' if under else 'msub'
            return f'<{tag}>{base}{sub}</{tag}>'
        tag = 'mover' if under else 'msup'
        return f'<{tag}>{base}{sup}</{tag}>'

    def atom(self):
        tok = self.take()
        if tok is None:
            raise TexError('unexpected end')
        kind, v = tok
        if kind == 'pre':
            return self.store[v]
        if kind == 'id':
            return f'<mi>{v}</mi>'
        if kind == 'num':
            return f'<mn>{v}</mn>'
        if kind == 'ch':
            if v == '{':
                out = self.seq('}')
                self.close()
                return _row(out)
            if v in '+-=<>()[]|,;:/!.*\'':
                ch = {'-': '−', '*': '∗', "'": '′'}.get(v, v)
                if v == "'":
                    return f'<mo>{ch}</mo>'
                stretch = ' stretchy="false"' if v in '()[]|' else ''
                return f'<mo{stretch}>{html.escape(ch)}</mo>'
            if v == '~':
                return '<mspace width="0.25em"/>'
            raise TexError(f'unsupported character {v!r}')
        # commands
        if v in SYMBOLS:
            tag, ch = SYMBOLS[v]
            return f'<{tag}>{html.escape(ch)}</{tag}>'
        if v in GREEK:
            return f'<mi>{GREEK[v]}</mi>'
        if v in BIG:
            return f'<mo movablelimits="true">{BIG[v]}</mo>'
        if v in FUNCS:
            return f'<mi>{v}</mi><mo>&#x2061;</mo>'
        if v in SPACES:
            return f'<mspace width="{SPACES[v]}"/>'
        if v in ('{', '}', '|', '#', '%', '&', '_'):
            return f'<mo>{html.escape(v)}</mo>' if v not in ('_', '#', '%', '&') else f'<mi>{html.escape(v)}</mi>'
        if v in FONTS:
            text = ''.join(t[1] for t in self.raw_group())
            return f'<mi mathvariant="{FONTS[v]}">{html.escape(text)}</mi>'
        if v in ('text', 'textrm', 'textsf', 'texttt', 'textit'):
            raw = self.raw_group()
            text = ''.join(('\\' + t[1] if t[0] == 'cmd' and len(t[1]) > 1 else t[1]) for t in raw)
            text = re.sub(r'\\(.)', r'\1', text)
            variant = {'texttt': ' mathvariant="monospace"', 'textsf': ' mathvariant="sans-serif"',
                       'textit': ' mathvariant="italic"'}.get(v, '')
            return f'<mtext{variant}>{html.escape(text)}</mtext>'
        if v == 'frac':
            return f'<mfrac>{self.group()}{self.group()}</mfrac>'
        if v == 'vec':
            return f'<mover accent="true">{self.group()}<mo stretchy="false">→</mo></mover>'
        if v == 'overline':
            return f'<mover>{self.group()}<mo>‾</mo></mover>'
        if v in ('left', 'right', 'bigl', 'bigr', 'Bigl', 'Bigr', 'big', 'Big'):
            nxt = self.take()
            if nxt is None:
                raise TexError(f'\\{v} needs a delimiter')
            if nxt == ('ch', '.'):
                return ''
            ch = nxt[1] if nxt[0] == 'ch' else SYMBOLS.get(nxt[1], (None, nxt[1]))[1]
            if nxt[0] == 'cmd' and nxt[1] in ('{', '}'):
                ch = nxt[1]
            return f'<mo>{html.escape(ch)}</mo>'
        raise TexError(f'unsupported command \\{v}')


def _row(items):
    return items[0] if len(items) == 1 else '<mrow>' + ''.join(items) + '</mrow>'


def _split_rows(tex):
    """Split display math at top-level \\\\ (outside braces) into rows."""
    rows, depth, cur, i = [], 0, [], 0
    while i < len(tex):
        c = tex[i]
        if c == '\\' and tex[i + 1:i + 2] == '\\' and depth == 0:
            rows.append(''.join(cur))
            cur, i = [], i + 2
            continue
        if c == '\\':
            cur.append(tex[i:i + 2])
            i += 2
            continue
        depth += c == '{'
        depth -= c == '}'
        cur.append(c)
        i += 1
    rows.append(''.join(cur))
    return [r for r in rows if r.strip()]


def _parse(tex):
    store = []
    p = _Parser(_tokens(tex, store), store)
    body = _row(p.seq())
    if p.peek() is not None:
        raise TexError('unbalanced }')
    return body


def width_estimate(tex):
    """Rough glyph count of the widest row, to flag formulas likely to overflow a phone column."""
    def glyphs(row):
        row = re.sub(r'\\(text|mathrm|mathit|mathsf|mathtt|operatorname)\{([^{}]*)\}', lambda m: m.group(2), row)
        row = re.sub(r'\\[A-Za-z]+', 'x', row)
        return len(re.sub(r'[\s{}_^]', '', row))
    return max(glyphs(r) for r in _split_rows(tex)) if tex.strip() else 0


def to_mathml(tex, display=False):
    rows = _split_rows(tex) if display else [tex]
    if not display and '\\\\' in tex:
        raise TexError('a line break needs display math')
    if len(rows) > 1:
        body = ('<mtable columnalign="left" displaystyle="true">'
                + ''.join(f'<mtr><mtd>{_parse(r)}</mtd></mtr>' for r in rows) + '</mtable>')
    else:
        body = _parse(tex)
    attrs = ' display="block"' if display else ''
    annotation = f'<annotation encoding="application/x-tex">{html.escape(tex)}</annotation>'
    return f'<math{attrs}><semantics>{body}{annotation}</semantics></math>'
