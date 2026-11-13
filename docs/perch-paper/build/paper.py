#!/usr/bin/env python3
"""Build both editions of the Perch paper from docs/perch-paper/source/.

    python3 docs/perch-paper/build/paper.py          # write index.html and latex/generated/
    python3 docs/perch-paper/build/paper.py --check  # fail if either is stale or inconsistent

Several documents share the data: the main paper and its companion papers,
listed in source/documents.json, each with its own outline, prose folder,
HTML page and (optionally) LaTeX folder. One outline per document orders the
sections, figures and tables of both of its editions. Facts, tables, formal statements, references and figure SVG are
shared data, rendered into the HTML edition and into LaTeX includes. Prose is
per edition: source/html/sections/<id>.html and latex/sections/<id>.tex.

index.html keeps four blocks that projects/perch-browser/build-page.mjs (in the
embedded source bundle) refreshes in place: MEASUREMENTS, MANIFEST_TABLE, GOLDEN
and EMBEDDED_ASSETS. This build copies them from the current index.html, so the
two tools can run in either order. Standard library only.
"""
import html
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import svg2tikz  # noqa: E402
import texmath  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / 'source'
LATEX = ROOT / 'latex'
GEN = LATEX / 'generated'
INDEX = ROOT / 'index.html'
WALKTHROUGH = ROOT.parent / 'oz-walkthrough' / 'index.html'
CARRIED = ('MEASUREMENTS', 'MANIFEST_TABLE', 'GOLDEN', 'EMBEDDED_ASSETS')
SHARED_HTML = SRC / 'html'
SITE = 'https://bitswell-hq.github.io/stellar-registry__perch/perch-paper/'
ERRORS = []
DOC = {}
HTMLDIR = SHARED_HTML
DEPTH = 0


def documents():
    path = SRC / 'documents.json'
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return [{'id': 'main', 'title': 'Perch', 'outline': 'outline.json', 'html_dir': 'html',
             'html_out': 'index.html', 'latex': 'latex', 'carried': True}]


def use_doc(d):
    """Point the module at one document: its outline, prose, page and LaTeX folder."""
    global DOC, HTMLDIR, INDEX, LATEX, GEN, DEPTH
    DOC = d
    HTMLDIR = SRC / d['html_dir']
    INDEX = ROOT / d['html_out']
    LATEX = ROOT / d['latex'] if d.get('latex') else None
    GEN = LATEX / 'generated' if LATEX else None
    DEPTH = len(Path(d['html_out']).parts) - 1


def html_file(name):
    """A document's own copy of a page part, else the shared one."""
    own = HTMLDIR / name
    return own if own.exists() else SHARED_HTML / name


def fail(msg):
    ERRORS.append(msg)


def read(p):
    return Path(p).read_text(encoding='utf-8')


# ---------------------------------------------------------------- shared data

class Paper:
    def __init__(self):
        self.outline = json.loads(read(SRC / DOC['outline']))
        self.facts = {}
        for fp in sorted((SRC / 'facts').glob('*.json')):
            for k, v in json.loads(read(fp)).items():
                if k in self.facts:
                    fail(f'fact {k!r} defined twice (second in facts/{fp.name})')
                self.facts[k] = v
        self.tables = {p.stem: json.loads(read(p)) for p in sorted((SRC / 'tables').glob('*.json'))}
        # Tables a figure generator writes (build/figures/) sit beside its figure as <id>.table.json.
        for tp in sorted((SRC / 'figures').glob('*.table.json')):
            tid = tp.name[:-len('.table.json')]
            if tid in self.tables:
                fail(f'table {tid} exists both in tables/ and as figures/{tp.name}')
            self.tables[tid] = json.loads(read(tp))
        self.all_statements = json.loads(read(SRC / 'statements.json'))
        # A statement may list the documents it appears in ("docs"); otherwise every document has it.
        self.statements = [x for x in self.all_statements if DOC['id'] in x.get('docs', [DOC['id']])]
        dp = SRC / 'definitions.json'
        self.all_definitions = json.loads(read(dp)) if dp.exists() else []
        self.definitions = [x for x in self.all_definitions if DOC['id'] in x.get('docs', [DOC['id']])]
        self.bib = parse_bib(read(SRC / 'refs.bib'))
        self.sections = self.outline['sections']
        fp = SRC / 'figures.json'
        self.figures = dict(json.loads(read(fp)) if fp.exists() else {})
        self.figures.update(self.outline.get('figures', {}))
        # An outline may set the editions of an exhibit for its own document, as a generated table cannot carry them.
        for xid, eds in self.outline.get('exhibit_editions', {}).items():
            for pool in (self.figures, self.tables):
                if xid in pool:
                    pool[xid] = {**pool[xid], 'editions': eds}
        self.sec_ids = [s['id'] for s in self.sections]
        used = [x for s in self.sections for x in s.get('figures', [])]
        for f in used:
            if f not in self.figures:
                fail(f'{DOC["id"]}: figure {f} has no entry in figures.json or the outline')
        self.figures = {f: self.figures[f] for f in used if f in self.figures}
        for s in self.sections:
            if (s.get('editions') and set(s['editions']) != {'html', 'latex'} and not (s.get('unnumbered') or s.get('appendix'))
                    and DOC.get('html_numbers', True)):
                fail(f'section {s["id"]} is in one edition only, so it must be unnumbered or an appendix')
        for s in self.sections:
            for t in s.get('tables', []):
                if t not in self.tables:
                    fail(f'{DOC["id"]}: table {t} is listed in the outline but source/tables/{t}.json does not exist')
                    self.tables[t] = {'title': '', 'columns': [], 'rows': []}
        self.numbers = {ed: self._number(ed) for ed in ('html', 'latex')}
        if LATEX:
            for k, n in self.numbers['html'].items():
                if k[:4] in ('fig:', 'tab:') and n and self.numbers['latex'].get(k) != n:
                    fail(f'{DOC["id"]}: {k[4:]} is {n} in the HTML but {self.numbers["latex"].get(k)} in the PDF '
                         f'(a latex_section move reorders it; move it in both editions or not at all)')

    def in_edition(self, item, ed):
        return ed in item.get('editions', ['html', 'latex'])

    def placed(self, ed, kind):
        # Exhibit ids per section for one edition, after latex_section overrides.
        items = self.figures if kind == 'figures' else self.tables
        out = {s['id']: [] for s in self.sections}
        for s in self.sections:
            for x in s.get(kind, []):
                target = items[x].get('latex_section', s['id']) if ed == 'latex' else s['id']
                out[target].append(x)
        return out

    def numbered(self, item, ed):
        # LaTeX numbers every float it places. In the HTML an exhibit takes a number only if every edition
        # shows it, so a number names the same exhibit in the HTML and the PDF; the others are titled and
        # cited by name. A document with "html_numbers": false numbers nothing in its HTML edition.
        if ed == 'latex':
            return True
        if not DOC.get('html_numbers', True):
            return False
        return all(self.in_edition(item, e) for e in (('html', 'latex') if LATEX else ('html',)))

    def _number(self, ed):
        nums, fig, tab, main, app = {}, 0, 0, 0, 0
        figs, tabs = self.placed(ed, 'figures'), self.placed(ed, 'tables')
        for s in self.sections:
            if not self.in_edition(s, ed):
                continue
            if s.get('unnumbered'):
                pass
            elif ed == 'html' and not DOC.get('html_numbers', True):
                pass
            elif s.get('appendix'):
                nums['sec:' + s['id']] = 'ABCDEFGH'[app]
                app += 1
            else:
                main += 1
                nums['sec:' + s['id']] = f'{main:02d}' if ed == 'html' else str(main)
            for f in figs[s['id']]:
                if self.in_edition(self.figures[f], ed):
                    fig += self.numbered(self.figures[f], ed)
                    nums['fig:' + f] = str(fig) if self.numbered(self.figures[f], ed) else ''
            for t in tabs[s['id']]:
                if self.in_edition(self.tables[t], ed):
                    tab += self.numbered(self.tables[t], ed)
                    nums['tab:' + t] = str(tab) if self.numbered(self.tables[t], ed) else ''
        return nums


def parse_bib(text):
    """Parse the restricted BibTeX this repo writes: @type{key, field = {value}, ...}."""
    entries = {}
    text = re.sub(r'^%.*$', '', text, flags=re.M)
    for m in re.finditer(r'@(\w+)\s*\{\s*([^,\s]+)\s*,(.*?)\n\}', text, re.S):
        fields = {}
        for fm in re.finditer(r'(\w+)\s*=\s*\{((?:[^{}]|\{[^{}]*\})*)\}', m.group(3), re.S):
            fields[fm.group(1).lower()] = ' '.join(fm.group(2).split())
        fields['_type'] = m.group(1).lower()
        entries[m.group(2)] = fields
    return entries


# ---------------------------------------------------------------- inline markup
# Shared strings (captions, cells, statements, facts) use a small markup:
# `code`, **strong**, *em*, [text](url), and {{fact:k}} {{ref:fig:id}}
# {{ref:tab:id}} {{ref:sec:id}} {{cite:key}} {{badge:kind:LABEL}}.

TOKEN = re.compile(r'(\\\(.+?\\\)|`[^`]+`|\*\*.+?\*\*|\*[^*\s][^*]*?\*|\[[^\]]+\]\([^)\s]+\)|\{\{[^}]+\}\})')
MATH_INLINE = re.compile(r'\\\((.+?)\\\)', re.S)
MATH_DISPLAY = re.compile(r'\\\[(.+?)\\\]', re.S)


WIDE_MATH = 38  # glyphs in one display row; wider rows likely overflow a 360 px column


def mathml(tex, display, ctx):
    if display and texmath.width_estimate(tex) > WIDE_MATH:
        LINT.append(f'math in {ctx} may overflow a phone column; break it with \\\\ into rows: {tex[:60]!r}')
    try:
        return texmath.to_mathml(tex.strip(), display)
    except texmath.TexError as e:
        fail(f'math in {ctx}: {e}: {tex!r}')
        return html.escape(tex)


def _directive(p, body, ed, ctx):
    kind, _, arg = body.partition(':')
    if kind == 'fact':
        if arg not in p.facts:
            fail(f'unknown fact {arg!r} in {ctx}')
            return '??'
        return r'\fact{' + arg + '}' if ed == 'latex' else fact_value(p, arg, ed)
    if kind == 'ref' and arg.split(':')[0] in ('stmt', 'def'):
        return formal_ref(p, arg, ed, ctx)
    if kind == 'ref':
        arg, _, opt = arg.partition('|')
        if arg not in p.numbers[ed] and not (arg.startswith('sec:') and arg[4:] in p.sec_ids):
            fail(f'unknown or excluded reference {arg!r} in {ctx} ({ed})')
            return '??'
        appendix = arg.startswith('sec:') and any(x['id'] == arg[4:] and x.get('appendix') for x in p.sections)
        if ed == 'latex':
            if arg.startswith('sec:') and arg not in p.numbers['latex']:
                fail(f'reference {arg!r} in {ctx} names a section that has no number in the LaTeX edition')
            pre = 'Appendix~' if appendix else {'sec': r'\S', 'fig': r'Figure~', 'tab': r'Table~'}[arg[:3]]
            return pre + r'\ref{' + arg + '}'
        n = p.numbers['html'].get(arg)
        if n is None and arg.startswith('sec:'):
            sec = next(x for x in p.sections if x['id'] == arg[4:])
            return f'<a href="#{arg[4:]}">{html.escape(sec["title_html"])}</a>'
        target = arg[4:]
        if n == '':
            item = (p.figures if arg.startswith('fig:') else p.tables)[target]
            short = item.get('short')
            if not short:
                fail(f'{ctx}: {target} has no number in this edition; give its entry a "short" name to be cited by')
            name = render(p, short or target, 'html', ctx)
            return f'<a href="#{target}">{name[:1].upper() + name[1:] if opt == "cap" else name}</a>'
        label = ('Appendix ' if appendix else {'sec': '§', 'fig': 'Figure ', 'tab': 'Table '}[arg[:3]]) + (n or '??')
        return f'<a href="#{target}">{label}</a>'
    if kind == 'cite':
        keys = arg.split(',')
        for k in keys:
            if k not in p.bib:
                fail(f'unknown citation {k!r} in {ctx}')
        if ed == 'latex':
            return r'\cite{' + ','.join(keys) + '}'
        for k in keys:
            if k in p.bib and p.cite_number(k) == '?':
                fail(f'citation {k!r} in {ctx} is not in the reference list (the build did not see it cited)')
        return '[' + ', '.join(f'<a class="cite" href="#ref-{k}">{p.cite_number(k)}</a>' for k in keys) + ']'
    if kind == 'root':
        return '../' * DEPTH if ed == 'html' else ''
    if kind == 'doc':
        target = next((d for d in documents() if d['id'] == arg), None)
        if not target:
            fail(f'unknown document {arg!r} in {ctx}')
            return '??'
        if ed == 'latex':
            return r'\companion{' + SITE + target['html_out'].replace('index.html', '') + '}{' + svg2tikz.tex_escape(target['title']) + '}'
        rel = os.path.relpath(ROOT / target['html_out'], (ROOT / DOC['html_out']).parent)
        return html.escape(rel)
    if kind == 'obj':
        if ed == 'latex':
            return r'\statusobj{' + svg2tikz.tex_escape(arg) + '}'
        return f'<span class="obj">{html.escape(arg, quote=False)}</span>'
    if kind == 'badge':
        b, _, label = arg.partition(':')
        if ed == 'latex':
            return r'\badge{' + svg2tikz.tex_escape(label) + '}'
        return f'<span class="badge {html.escape(b)}">{html.escape(label)}</span>'
    fail(f'unknown directive {{{{{body}}}}} in {ctx}')
    return '??'


def render(p, s, ed, ctx=''):
    out = []
    for part in TOKEN.split(s):
        if not part:
            continue
        if part.startswith('\\(') and part.endswith('\\)'):
            out.append(part if ed == 'latex' else mathml(part[2:-2], False, ctx))
        elif part.startswith('`') and part.endswith('`') and len(part) > 1:
            inner = part[1:-1]
            if ed == 'latex':
                bits = re.split(r'(\{\{fact:[^}]+\}\})', inner)
                body = ''.join(r'\fact{' + b[7:-2] + '}' if b.startswith('{{fact:') and b[7:-2] in p.facts
                               else tex_code(b) for b in bits)
                out.append(r'\code{' + body + '}')
            else:
                inner = re.sub(r'\{\{fact:([^}]+)\}\}', lambda m: plain_fact(p, m.group(1), ctx), inner)
                out.append('<code>' + html.escape(inner, quote=False) + '</code>')
        elif part.startswith('**') and part.endswith('**'):
            inner = render(p, part[2:-2], ed, ctx)
            out.append(r'\textbf{' + inner + '}' if ed == 'latex' else f'<strong>{inner}</strong>')
        elif part.startswith('*') and part.endswith('*') and len(part) > 2:
            inner = render(p, part[1:-1], ed, ctx)
            out.append(r'\emph{' + inner + '}' if ed == 'latex' else f'<em>{inner}</em>')
        elif part.startswith('[') and part.endswith(')') and '](' in part:
            text, url = part[1:-1].split('](', 1)
            inner = render(p, text, ed, ctx)
            if ed == 'latex':
                cmd = r'\repolink' if SELF_REPOS.match(url) else r'\href'
                out.append(cmd + '{' + url.replace('%', r'\%').replace('#', r'\#') + '}{' + inner + '}')
            else:
                out.append(f'<a href="{html.escape(url)}">{inner}</a>')
        elif part.startswith('{{') and part.endswith('}}'):
            out.append(_directive(p, part[2:-2], ed, ctx))
        else:
            out.append(svg2tikz.tex_escape(part) if ed == 'latex' else html.escape(part, quote=False))
    return ''.join(out)


def number_of(label):
    """'T6' -> '6', 'D2' -> '2': both editions print the number without its letter."""
    return re.sub(r'^[A-Za-z]+', '', label or '')


def html_cards(p, kind):
    """Ids of the statement or definition cards this document's HTML edition places."""
    directive = 'statements' if kind == 'stmt' else 'definitions'
    pool = p.statements if kind == 'stmt' else p.definitions
    ids = set()
    for s in p.sections:
        if p.in_edition(s, 'html'):
            for arg in re.findall(r'\{\{' + directive + r'(?::([^}]*))?\}\}', read(HTMLDIR / 'sections' / f'{s["id"]}.html')):
                ids |= {x['id'] for x in pick(pool, arg)}
    return ids


def formal_ref(p, arg, ed, ctx):
    kind, _, ident = arg.partition(':')
    pool = p.all_statements if kind == 'stmt' else p.all_definitions
    item = next((x for x in pool if x['id'] == ident), None)
    if not item:
        fail(f'unknown {kind} {ident!r} in {ctx}')
        return '??'
    word = ('Proposition' if item.get('argued') else 'Theorem') if kind == 'stmt' else 'Definition'
    here = ident in {x['id'] for x in (p.statements if kind == 'stmt' else p.definitions)}
    if ed == 'html':
        # In the HTML a reference stays on the page only if the page places that card.
        here = ident in html_cards(p, kind)
    n = number_of(item.get('label'))
    if ed == 'latex':
        return f'{word}~\\ref{{{kind}:{ident}}}' if here else f'{word}~{n}'
    href = f'#{kind}-{ident}' if here else _directive(p, 'doc:verification', 'html', ctx) + f'#{kind}-{ident}'
    return f'<a href="{href}">{word} {n}</a>'


def plain_fact(p, key, ctx):
    if key not in p.facts:
        fail(f'unknown fact {key!r} in {ctx}')
        return '??'
    f = p.facts[key]
    return f['value'] if isinstance(f, dict) else f


SELF_REPOS = re.compile(r'https://github\.com/(bitswell|bitswell-hq|theahaco|nidohq)/')


def tex_code(s):
    # Inline code in LaTeX: escaped, with break points after path and hash separators in
    # long spans, since \texttt does not hyphenate and table columns are narrow.
    out = svg2tikz.tex_escape(s)
    if len(s) > 16:
        out = re.sub(r'(/|\\_|\.|:|-|,)', r'\1\\allowbreak{}', out)
        out = re.sub(r'([0-9a-f]{8})(?=[0-9a-f]{8})', r'\1\\allowbreak{}', out)
    return out


def fact_value(p, key, ed, anon=False):
    f = p.facts[key]
    if not isinstance(f, dict):
        f = {'value': f}
    v = f['anon'] if anon and 'anon' in f else f['value']
    if f.get('markup'):
        return render(p, v, ed, key)
    if ed == 'latex':
        return r'\code{' + tex_code(v) + '}' if f.get('code') else svg2tikz.tex_escape(v)
    v = html.escape(v, quote=False)
    return f'<code>{v}</code>' if f.get('code') else v


# ---------------------------------------------------------------- HTML edition

def html_caption(item):
    """An exhibit's caption in the HTML edition: the entry's "caption_html", else the caption both editions share."""
    return item.get('caption_html') or item.get('caption', '')


def html_figure(p, fid):
    f = p.figures[fid]
    n = p.numbers['html']['fig:' + fid]
    lead = f'Figure {n}. ' if n else ''
    title = render(p, f['title'], 'html', fid)
    cap = render(p, html_caption(f), 'html', fid)
    cls = 'fig' + (' interactive' if f.get('interactive') else '')
    attrs = f' data-interactive="{f["interactive"]}"' if f.get('interactive') else ''
    if f.get('scenarios'):
        attrs += f' data-scenarios="{html.escape(f["scenarios"])}"'
    if f.get('kind') == 'table':
        body = html_table_body(p, p.tables[f['table']], f['table'])
        return (f'<figure class="{cls} fig-table" id="{fid}"{attrs}>{body}'
                f'<figcaption><span class="figure-title" id="{fid}-title">{lead}{title}</span> {cap}</figcaption></figure>')
    if f.get('kind') == 'code':
        panels = ''.join(
            f'<div class="code-panel"><p class="panel-title">{render(p, pa["title"], "html", fid)}</p>'
            f'<pre>{html.escape(read(SRC / "figures" / f"{fid}.{pa["file"]}.txt").rstrip())}</pre></div>'
            for pa in f['panels'])
        return (f'<figure class="{cls} fig-code" id="{fid}"{attrs}><div class="code-panels">{panels}</div>'
                f'<figcaption><span class="figure-title" id="{fid}-title">{lead}{title}</span> {cap}</figcaption></figure>')
    wide = read(SRC / 'figures' / f'{fid}.svg').strip()
    narrow_p = SRC / 'figures' / f'{fid}.narrow.svg'
    narrow = read(narrow_p).strip() if narrow_p.exists() else ''
    controls = ''
    cp = SRC / 'figures' / f'{fid}.controls.html'
    if cp.exists():
        controls = read(cp).strip()
    text_p = SRC / 'figures' / f'{fid}.text.html'
    steps = load_steps(fid)
    alt_body = html_steps(p, fid, steps) if steps else (read(text_p).strip() if text_p.exists() else '')
    alt = (f'<details class="fig-text" id="{fid}-text"><summary>{f"Figure {n}" if n else "This figure"} as text</summary>{alt_body}</details>'
           if alt_body else '')
    return (f'<figure class="{cls}" id="{fid}"{attrs}>{controls}{wide}{narrow}'
            f'<figcaption><span class="figure-title" id="{fid}-title">{lead}{title}</span> {cap}</figcaption>{alt}</figure>')


def slug(text):
    return re.sub(r'[^a-z0-9]+', '-', re.sub(r'`', '', text).lower()).strip('-')


GLOSS_LINK = re.compile(r'<dfn><a href="#glossary">(.*?)</a></dfn>')


def link_glossary(p, page):
    # Point each <dfn> link at its glossary row: exact term, a plural, or one name of a "A, B" row.
    own = p.outline.get('glossary')
    gid = own or next((json.loads(read(SRC / d['outline'])).get('glossary') for d in documents() if d['id'] == 'main'), None)
    t = p.tables.get(gid) if gid else None
    if not t:
        return page
    base = '' if own else _directive(p, 'doc:main', 'html', 'glossary')
    names, defs = {}, {}
    def plain(cell):
        return html.unescape(re.sub(r'<[^>]+>', '', render(p, cell, 'html', 'glossary'))).strip()
    for r in t['rows']:
        # The hover: every meaning column that has an entry ("—" marks none), named when there are several.
        parts = [(col, plain(cell)) for col, cell in zip(t['columns'][1:], r[1:])
                 if not col.lower().startswith('name') and cell.strip() not in ('—', '-', '')]
        text = parts[0][1] if len(parts) == 1 else '; '.join(f'{col}: {txt}' for col, txt in parts)
        defs[slug(r[0])] = html.escape(text)
        for name in [r[0]] + [x.strip() for x in re.split(r',| and ', r[0])]:
            names.setdefault(slug(name), slug(r[0]))

    def sub(m):
        key = slug(re.sub(r'<[^>]+>', '', m.group(1)))
        for k in (key, key[:-1] if key.endswith('s') else key, key[:-2] if key.endswith('es') else key):
            if k in names:
                return f'<dfn><a href="{base}#{t["row_ids"]}-{names[k]}" title="{defs[names[k]]}">{m.group(1)}</a></dfn>'
        fail(f'glossary link {m.group(1)!r} matches no glossary row')
        return m.group(0)
    return GLOSS_LINK.sub(sub, page)


def load_steps(fid):
    sp = SRC / 'figures' / f'{fid}.steps.json'
    return json.loads(read(sp)) if sp.exists() else None


def html_steps(p, fid, st):
    def item(x):
        scen = f' data-scenario="{x["scenario"]}"' if x.get('scenario') else ''
        exits = ''.join(f'<br>→ {render(p, e, "html", fid)}' for e in x.get('exits', []))
        return f'<li data-step="{x["n"]}"{scen}>{render(p, x["text"], "html", fid)}{exits}</li>'
    intro = f'<p>{render(p, st["intro"], "html", fid)}</p>' if st.get('intro') else ''
    outro = f'<p>{render(p, st["outro"], "html", fid)}</p>' if st.get('outro') else ''
    first = str(st['steps'][0]['n']) if st['steps'] else '1'
    start = f' start="{first}"' if first.isdigit() and first != '1' else ''
    return intro + f'<ol{start}>' + ''.join(item(x) for x in st['steps']) + '</ol>' + outro


def latex_steps(p, fid, st):
    # An algorithm figure: one row per step (number, action, exits with codes, assurance).
    rows = []
    for x in st['steps']:
        if x.get('latex') is False:
            continue
        exits = '; '.join(render(p, e, 'latex', fid) for e in x.get('exits', [])) or '--'
        rows.append(f'{x["n"]} & {render(p, x["text"], "latex", fid)} & {exits} & {render(p, x.get("assurance", ""), "latex", fid)} \\\\')
    intro = render(p, st['intro'], 'latex', fid) + '\\par\\smallskip\n' if st.get('intro') else ''
    outro = '\n\\par\\smallskip ' + render(p, st['outro'], 'latex', fid) if st.get('outro') else ''
    size, exit_w = p.figures[fid].get('latex_size', 'footnotesize'), p.figures[fid].get('latex_exit_width', '0.3')
    return (intro + f'\\{size}\\begin{{tabularx}}{{\\linewidth}}{{@{{}}r>{{\\raggedright\\arraybackslash}}X'
            f'>{{\\raggedright\\arraybackslash}}p{{{exit_w}\\linewidth}}l@{{}}}}\n\\toprule\n'
            '\\textbf{No.} & \\textbf{Step} & \\textbf{Exit and code} & \\textbf{Assurance} \\\\\n\\midrule\n'
            + '\n'.join(rows) + '\n\\bottomrule\n\\end{tabularx}' + outro)


def html_table_body(p, t, tid):
    head = ''.join(f'<th>{render(p, c, "html", tid)}</th>' for c in t['columns'])
    def tr(r):
        rid = f' id="{t["row_ids"]}-{slug(r[0])}"' if t.get('row_ids') else ''
        return f'<tr{rid}>' + ''.join(f'<td>{render(p, c, "html", tid)}</td>' for c in r) + '</tr>'
    rows = ''.join(tr(r) for r in t['rows'])
    cls = f' class="{t["html_class"]}"' if t.get('html_class') else ''
    return f'<div class="table-wrap"><table{cls}><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div>'


def html_table(p, tid, numbered=True):
    t = p.tables[tid]
    body = html_table_body(p, t, tid)
    if numbered and 'tab:' + tid not in p.numbers['html']:
        fail(f'{DOC["id"]}: {{{{table:{tid}}}}} is placed but this document\'s outline does not list it '
             f'(list it, or place it as {{{{table:{tid}|unnumbered}}}})')
        numbered = False
    if tid not in p.tables:
        fail(f'{DOC["id"]}: table {tid} does not exist')
        return ''
    lead = f'Table {p.numbers["html"]["tab:" + tid]}. ' if numbered and p.numbers['html']['tab:' + tid] else ''
    cap = (f'<caption>{lead}{render(p, t["title"], "html", tid)} '
           f'{render(p, html_caption(t), "html", tid)}</caption>')
    return body.replace('</tbody></table>', f'</tbody>{cap}</table>', 1).replace('<table', f'<table id="{tid}"', 1)


def pick(items, arg):
    """All items, or those whose label or id is listed (comma-separated)."""
    if not arg:
        return items
    want = [a.strip() for a in arg.split(',')]
    out = [x for w in want for x in items if w in (x.get('label'), x['id'])]
    if len(out) != len(want):
        fail(f'unknown statement or definition in {arg!r}')
    return out


def html_statements(p, arg=''):
    def item(st):
        data = ''.join(f' data-{k}="{html.escape(" ".join(st[k]))}"' for k in ('objects', 'assumes') if st.get(k))
        ctx = st['id']
        argued = st.get('argued')
        word = 'Proposition' if argued else 'Theorem'
        tag = ' <span class="thm-tag">argued, not mechanized</span>' if argued else ''
        head = f'<p class="thm-head"><strong>{word} {number_of(st.get("label"))}</strong> ({render(p, st["title"], "html", ctx).rstrip(".")}){tag}</p>'
        rid = f'stmt-{ctx}-reading'
        math = (f'<div class="thm-math" aria-describedby="{rid}">{mathml(st["math"], True, ctx)}</div>' if st.get('math') else '')
        reading = (f'<p class="thm-reading" id="{rid}"><span class="thm-tag">In words</span> {render(p, st["reading"], "html", ctx)}</p>'
                   if st.get('reading') else '')
        precise = f'<p class="thm-text"><span class="thm-tag">Precisely</span> {render(p, st["text"], "html", ctx)}</p>'
        hyp = (f'<p class="hyp"><span class="thm-tag">Hypotheses</span> {render(p, st["hypotheses"], "html", ctx)}</p>'
               if st.get('hypotheses') else '')
        instance = (f'<details class="thm-try"><summary>Try an instance</summary><div class="thm-instance" '
                    f'data-instance="{html.escape(st["instance"])}" data-statement="{ctx}"></div></details>'
                    if st.get('instance') else '')
        lean = f'<div class="artifact"><span class="thm-tag">Lean</span> {render(p, st["evidence"], "html", ctx)}</div>'
        cls = 'thm argued' if argued else 'thm'
        return f'<li id="stmt-{ctx}" class="{cls}"{data}>{head}{math}{reading}{precise}{hyp}{instance}{lean}</li>'
    return '<ol class="proof-list">' + ''.join(item(st) for st in pick(p.statements, arg)) + '</ol>'


def html_definitions(p, arg=''):
    def item(d):
        ctx = d['id']
        rid = f'def-{ctx}-reading'
        math = (f'<div class="thm-math" aria-describedby="{rid}">{mathml(d["math"], True, ctx)}</div>'
                if d.get('math') else '')
        reading = (f'<p class="thm-reading" id="{rid}"><span class="thm-tag">In words</span> {render(p, d["reading"], "html", ctx)}</p>'
                   if d.get('reading') else '')
        lean = f' <span class="obj">{render(p, d["lean"], "html", ctx)}</span>' if d.get('lean') else ''
        tag = '<span class="thm-tag">Precisely</span> ' if reading else ''
        return (f'<li id="def-{ctx}" class="defn"><p class="thm-head"><strong>Definition {number_of(d["label"])}</strong> '
                f'({render(p, d["title"], "html", ctx).rstrip(".")})</p>{math}{reading}'
                f'<p class="thm-text">{tag}{render(p, d["text"], "html", ctx)}{lean}</p></li>')
    return '<ol class="def-list">' + ''.join(item(d) for d in pick(p.definitions, arg)) + '</ol>'


def html_references(p):
    items = []
    for k in p.cite_order:
        e = p.bib[k]
        items.append(f'<li id="ref-{k}">{bib_html(e)}</li>')
    return '<ol class="refs">' + ''.join(items) + '</ol>'


TEX_ACCENTS = {r"\\'U": 'Ú', r"\\'u": 'ú', r'\\"o': 'ö', r'\\"u': 'ü', r"\\'e": 'é', r'\\#': '#', r'\\_': '_', r'\\&': '&'}


def bib_text(s):
    for k, v in TEX_ACCENTS.items():
        s = re.sub(k, v, s)
    return re.sub(r'[{}]', '', s).replace('--', '–')


def bib_html(e):
    def t(s):
        return html.escape(bib_text(s), quote=False)
    parts = []
    if e.get('author'):
        names = [n.strip() for n in e['author'].split(' and ')]
        parts.append(t(names[0] + ' et al.' if len(names) > 3 else ', '.join(names[:-1]) + (' and ' if len(names) > 1 else '') + names[-1])
                     + ('' if len(names) > 3 else '.'))
    title = t(e.get('title', ''))
    url = e.get('url')
    parts.append(f'<a href="{html.escape(url)}">{title}.</a>' if url else title + '.')
    venue = e.get('booktitle') or e.get('journal') or e.get('howpublished') or e.get('publisher')
    vol = (f' {t(e["volume"])}' + (f'({t(e["number"])})' if e.get('number') else '')) if e.get('volume') else ''
    tail = ', '.join(x for x in [(f'<em>{t(venue)}</em>{vol}' if e.get('journal') else (t(venue) if venue else '')),
                                 t(e['year']) if e.get('year') else ''] if x)
    if tail:
        parts.append(tail + '.')
    if e.get('note'):
        parts.append(t(e['note']) + ('' if e['note'].endswith('.') else '.'))
    return ' '.join(parts)


DIRECTIVE = re.compile(r'\{\{([a-z-]+):?([^}]*)\}\}')


def card_heads(body):
    # A theorem or definition card's head is a heading one level below the last heading before it in
    # its section (the section's own <h2> comes first), without JavaScript.
    level = 2

    def sub(m):
        nonlocal level
        if m.group(1):
            level = int(m.group(1))
            return m.group(0)
        return f'<p class="thm-head" role="heading" aria-level="{min(6, level + 1)}">'
    return re.sub(r'<h([2-6])\b|<p class="thm-head">', sub, body)


def html_step_list(p, ctx):
    """{{steps}}: the walkthrough's steps as a list, from the outline's "steps" (HTML only)."""
    steps = p.outline.get('steps', [])
    if not steps:
        fail(f'{DOC["id"]}: {{{{steps}}}} in {ctx}, but the outline has no "steps"')
    return '<ol class="steps">' + ''.join(
        f'<li><a href="#{html.escape(s["anchor"])}">{render(p, s["text"], "html", ctx)}</a></li>' for s in steps) + '</ol>'


def mark_steps(p, bodies):
    """Give each walkthrough step a "Step n of N" label on its heading.

    A step's anchor is either a section id (its <h2>) or the id of a heading inside a section. Returns
    {anchor: home section id} and the extra head text for sections that are steps themselves."""
    steps = p.outline.get('steps', [])
    home, heads = {}, {}
    for st in steps:
        a = st['anchor']
        if a in bodies:
            home[a] = a
        else:
            owners = [sid for sid, b in bodies.items() if re.search(rf'<h[3-6] id="{re.escape(a)}">', b)]
            if len(owners) != 1:
                fail(f'{DOC["id"]}: step anchor {a!r} must be an HTML section or a heading id in exactly one section')
                continue
            home[a] = owners[0]
    if len(home) != len(steps):
        return home, heads
    total = len(steps)
    for i, st in enumerate(steps, 1):
        a, sid = st['anchor'], home[st['anchor']]
        mark = f'<span class="step-mark">Step {i} of {total}</span>'
        if a == sid:
            heads[sid] = mark
        else:
            bodies[sid] = re.sub(rf'(<h[3-6] id="{re.escape(a)}">)', rf'\1{mark}', bodies[sid], count=1)
    return home, heads


def expand_html(p, text, ctx, blocks, seen):
    # A reference that opens a sentence is marked, so an unnumbered exhibit's short name is capitalized there.
    text = re.sub(r'((?:^|<p>|<p [^>]*>|<li>|[.!?]\s)\s*)\{\{ref:((?:fig|tab):[\w-]+)\}\}', r'\1{{ref:\2|cap}}', text)

    def sub(m):
        kind, arg = m.group(1), m.group(2)
        if kind == 'fig':
            seen['fig'].append(arg)
            if arg not in p.figures:
                fail(f'{DOC["id"]}: {{{{fig:{arg}}}}} is not in this document\'s outline')
                return ''
            try:
                return html_figure(p, arg)
            except FileNotFoundError as e:
                fail(f'{DOC["id"]}: figure {arg} is missing its source file {Path(e.filename).name}')
                return ''
        if kind == 'table':
            tid, _, flag = arg.partition('|')
            if flag == 'unnumbered':
                return html_table(p, tid, numbered=False)
            seen['tab'].append(tid)
            return html_table(p, tid)
        if kind == 'if-walkthrough':
            return expand_html(p, read(html_file(arg)), arg, blocks, seen) if WALKTHROUGH.exists() else ''
        if kind == 'statements':
            return html_statements(p, arg)
        if kind == 'definitions':
            return html_definitions(p, arg)
        if kind == 'block':
            if arg not in blocks:
                fail(f'missing carried block {arg}')
            return blocks.get(arg, '')
        if kind == 'include':
            return expand_html(p, read(html_file(arg)), arg, blocks, seen)
        if kind == 'references':
            return html_references(p)
        if kind == 'steps':
            return html_step_list(p, ctx)
        return render(p, m.group(0), 'html', ctx)
    text = MATH_DISPLAY.sub(lambda m: mathml(m.group(1), True, ctx), text)
    text = MATH_INLINE.sub(lambda m: mathml(m.group(1), False, ctx), text)
    return DIRECTIVE.sub(sub, text)


def build_html(p, blocks):
    o = p.outline
    seen = {'fig': [], 'tab': []}
    # Citation numbers follow first use across the page: its header and abstract, then each section's prose,
    # includes, figures, tables and formal cards. The reference list holds only what the page cites.
    order = []

    def cites(text):
        for k in re.findall(r'\{\{cite:([^}]+)\}\}', text):
            for kk in k.split(','):
                if kk not in order:
                    order.append(kk)
    for name in ('header.html', 'abstract.html'):
        cites(read(html_file(name)))
    for s in p.sections:
        if not p.in_edition(s, 'html'):
            continue
        src = read(HTMLDIR / 'sections' / f'{s["id"]}.html')
        for inc in re.findall(r'\{\{include:([^}]+)\}\}', src):
            src += read(html_file(inc))
        cites(src)
        for f in s.get('figures', []):
            cites(json.dumps(p.figures.get(f, {}), ensure_ascii=False))
        for t in s.get('tables', []):
            cites(json.dumps(p.tables.get(t, {}), ensure_ascii=False))
        for arg in re.findall(r'\{\{statements(?::([^}]*))?\}\}', src):
            cites(json.dumps(pick(p.statements, arg), ensure_ascii=False))
        for arg in re.findall(r'\{\{definitions(?::([^}]*))?\}\}', src):
            cites(json.dumps(pick(p.definitions, arg), ensure_ascii=False))
    cites(read(html_file('footer.html')))
    p.cite_order = order
    p.cite_number = lambda k: order.index(k) + 1 if k in order else '?'

    css = '\n'.join(read(SHARED_HTML / n).strip() for n in ('style.css', 'page.css', 'figures.css')
                    if (SHARED_HTML / n).exists())
    font = SHARED_HTML / 'fonts' / 'perch-math.woff2'
    if font.exists():
        import base64
        css = ('/* PerchMath: a subset of STIX Two Math (c) The STIX Fonts Project Authors, SIL Open Font License 1.1; '
               'see source/html/fonts/. */\n@font-face{font-family:PerchMath;src:url(data:font/woff2;base64,'
               + base64.b64encode(font.read_bytes()).decode() + ') format("woff2");font-display:swap}'
               '\nmath{font-family:PerchMath,math}\n' + css)
    head = read(html_file('head.html')).replace('{{style}}', css).replace('{{title}}', html.escape(DOC['title']))
    head_html = expand_html(p, head, 'head', blocks, seen).strip()
    header_html = expand_html(p, read(html_file('header.html')), 'header', blocks, seen).strip()
    abstract_html = expand_html(p, read(html_file('abstract.html')), 'abstract', blocks, seen).strip()
    sections = [s for s in p.sections if p.in_edition(s, 'html')]
    bodies = {s['id']: card_heads(expand_html(p, read(HTMLDIR / 'sections' / f'{s["id"]}.html'), s['id'], blocks, seen).strip())
              for s in sections}
    steps = o.get('steps', [])
    step_home, step_heads = mark_steps(p, bodies)

    # The walkthrough's steps are one group in the sidebar, placed where the first step starts; a section that
    # is itself a step appears only in that group.
    group = ''
    if steps:
        group = (f'<div class="nav-steps" role="group" aria-label="{html.escape(o.get("steps_title", "Steps"))}">'
                 f'<p class="nav-group">{html.escape(o.get("steps_title", "Steps"))}</p>'
                 + ''.join(f'<a href="#{html.escape(st["anchor"])}"><span class="k">{i}</span>{html.escape(st["nav"])}</a>'
                           for i, st in enumerate(steps, 1)) + '</div>')
    first_home = step_home.get(steps[0]['anchor']) if steps else None
    nav = ['<nav aria-label="Paper sections"><a class="brand" href="#top">PERCH</a><div class="nav-links">']
    for s in sections:
        if s['id'] in step_home and step_home[s['id']] == s['id']:
            if group and s['id'] == first_home:
                nav.append(group)
            continue
        if s.get('nav'):
            n = p.numbers['html'].get('sec:' + s['id'])
            label = f'{n} · {s["nav"]}' if n and n.isdigit() else s['nav']
            nav.append(f'<a href="#{s["id"]}">{html.escape(label)}</a>')
        if group and s['id'] == first_home:
            nav.append(group)
    nav.append(f'</div><small>{o["nav_note"]}</small></nav>')
    parts = [head_html, ''.join(nav), '']
    wt = f' data-walkthrough="{"../" * (DEPTH + 1)}oz-walkthrough/index.html"' if WALKTHROUGH.exists() else ''
    parts.append(f'<main id="main"{wt}>' + read(SHARED_HTML / 'sprite.svg').strip() + header_html)
    parts.append(abstract_html)
    for s in sections:
        n = p.numbers['html'].get('sec:' + s['id'])
        body = bodies[s['id']]
        num = f'<span class="n">{n}</span>' if n else ''
        head = f'<h2>{num}{step_heads.get(s["id"], "")}{html.escape(s["title_html"])}</h2>'
        alias = ''.join(f'<span class="alias" id="{a}"></span>' for a in s.get('aliases', []))
        parts.append(f'<section id="{s["id"]}">{alias}{head}{body}</section>')
    parts.append(expand_html(p, read(html_file('footer.html')), 'footer', blocks, seen).strip())
    parts.append('</main></div>')
    if DOC.get('carried'):
        parts.append(blocks['EMBEDDED_ASSETS'])
    for js in ('model.js', 'figures.js'):
        if (SHARED_HTML / js).exists():
            parts.append('<script>' + read(SHARED_HTML / js).strip() + '</script>')
    parts.append('</body></html>\n')
    want_f = [f for s in p.sections if p.in_edition(s, 'html') for f in s.get('figures', []) if p.in_edition(p.figures[f], 'html')]
    want_t = [t for s in p.sections if p.in_edition(s, 'html') for t in s.get('tables', []) if p.in_edition(p.tables[t], 'html')]
    if seen['fig'] != want_f:
        fail(f'HTML figure order {seen["fig"]} != outline {want_f}')
    if seen['tab'] != want_t:
        fail(f'HTML table order {seen["tab"]} != outline {want_t}')
    page = link_glossary(p, '\n'.join(parts))
    # build-page.mjs refreshes these blocks in place, so each must survive a rebuild in
    # the document that carries the live experiment, and appear in no other.
    for name in CARRIED:
        n = page.count(f'<!-- {name}_START -->')
        if DOC.get('carried') and n != 1:
            fail(f'{DOC["id"]}: the {name} block must appear exactly once (place {{{{block:{name}}}}})')
        if not DOC.get('carried') and n:
            fail(f'{DOC["id"]}: the {name} block belongs only to the document with "carried": true')
    return page


MEASURED = {'Install transfer grant': 'cpu-install-grant', 'Spend six demo XLM': 'cpu-spend-6',
            'Complete guardian recovery': 'cpu-complete', 'Spend with fresh grant': 'cpu-spend-grant2',
            'Losing game guess': 'cpu-guess-1', 'Winning game guess': 'cpu-win'}


def check_measurements(p, block):
    for label, value in re.findall(r'<tr><td>([^<]+)</td><td>([\d,]+)</td>', block):
        key = MEASURED.get(label)
        if key and key in p.facts and p.facts[key]['value'] != value:
            fail(f'MEASUREMENTS row {label!r} is {value} but fact {key} is {p.facts[key]["value"]}')


def carried_blocks(text):
    blocks = {}
    for name in CARRIED:
        m = re.search(f'<!-- {name}_START -->.*?<!-- {name}_END -->', text, re.S)
        if not m:
            fail(f'index.html lacks the {name} block')
        else:
            blocks[name] = m.group(0)
    return blocks


# ---------------------------------------------------------------- LaTeX edition

LINT = []


def lint_svg(fid, f):
    for suffix in ('svg', 'narrow.svg'):
        path = SRC / 'figures' / f'{fid}.{suffix}'
        if not path.exists():
            continue
        t = read(path)
        if ' style="' in t or ' opacity="' in t:
            LINT.append(f'{path.name}: no style= or opacity attributes')
        for size in re.findall(r'font-size="([\d.]+)"', t):
            if not 14 <= float(size) <= 17:
                LINT.append(f'{path.name}: font-size {size} outside 14-17')
                break
        vb = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', t)
        want = 340 if suffix == 'narrow.svg' else 760
        if vb and float(vb.group(1)) != want:
            LINT.append(f'{path.name}: width {vb.group(1)}, want {want}')
        if suffix == 'svg' and vb and float(vb.group(2)) > 900 and f.get('kind') != 'algorithm':
            LINT.append(f'{path.name}: height {vb.group(2)} > 900 (redesign, or make it an algorithm figure)')


def latex_figure(p, fid):
    f = p.figures[fid]
    env = "figure*" if f.get("latex_span") == "full" else "figure"
    cap = r'\textbf{' + render(p, f['title'], 'latex', fid) + '} ' + render(p, f.get('caption', ''), 'latex', fid)
    if f.get('kind') == 'table':
        body = latex_tabular(p, p.tables[f['table']], f['table'])
    elif f.get('kind') == 'algorithm':
        st = load_steps(fid)
        if not st:
            fail(f'{fid}: kind algorithm needs source/figures/{fid}.steps.json')
            return ''
        body = latex_steps(p, fid, st)
    elif f.get('kind') == 'code':
        parts = []
        for pa in f['panels']:
            w = pa.get('latex_width', 1)
            text = read(SRC / 'figures' / f'{fid}.{pa["file"]}.txt').rstrip()
            parts.append(f'\\begin{{minipage}}[t]{{{w}\\linewidth}}\\footnotesize\\textbf{{{render(p, pa["title"], "latex", fid)}}}\n'
                         f'\\begin{{Verbatim}}[fontsize=\\scriptsize,frame=single,framesep=1.5mm]\n{text}\n\\end{{Verbatim}}\n\\end{{minipage}}')
        body = ''
        for i, part in enumerate(parts):
            body += part
            if i + 1 < len(parts):
                a, b = f['panels'][i].get('latex_width', 1), f['panels'][i + 1].get('latex_width', 1)
                body += '\\hfill\n' if a < 1 and b < 1 and a + b <= 1 else '\\par\\medskip\n'
    else:
        tikz, w, h = svg2tikz.convert(read(SRC / 'figures' / f'{fid}.svg'))
        maxh = f.get('latex_max_height', '0.8\\textheight')
        body = (r'\begin{adjustbox}{max width=\linewidth,max totalheight=' + maxh + '}%\n'
                + tikz + '%\n\\end{adjustbox}')
    return (f'% Generated from source/outline.json and source/figures/{fid}.svg; edit those.\n'
            f'\\begin{{{env}}}[{f.get("latex_place", "tbp")}]\n\\centering\n{body}\n'
            f'\\caption{{{cap}}}\\label{{fig:{fid}}}\n\\end{{{env}}}\n')


def latex_tabular(p, t, tid):
    # Default: every column wraps (ragged right) across the text width. A table
    # may give `latex_colspec` in tabularx terms, using L for a wrapping column.
    spec = t.get('latex_colspec') or ('@{}' + 'L' * len(t['columns']) + '@{}')
    size = t.get('latex_size', 'scriptsize')
    head = ' & '.join(r'\textbf{' + render(p, c, 'latex', tid) + '}' for c in t['columns']) + r' \\'
    rows = '\n'.join(' & '.join(render(p, c, 'latex', tid) for c in r) + r' \\' for r in t['rows'])
    return (f'\\{size}\\begin{{tabularx}}{{\\linewidth}}{{{spec}}}\n\\toprule\n{head}\n\\midrule\n{rows}\n'
            f'\\bottomrule\n\\end{{tabularx}}')


def latex_table(p, tid):
    t = p.tables[tid]
    cap = r'\textbf{' + render(p, t['title'], 'latex', tid) + '} ' + render(p, t.get('caption', ''), 'latex', tid)
    if t.get('latex_long'):
        # A table that may break across pages (xltabular): not a float.
        spec = t.get('latex_colspec') or ('@{}' + 'L' * len(t['columns']) + '@{}')
        head = ' & '.join(r'\textbf{' + render(p, c, 'latex', tid) + '}' for c in t['columns']) + r' \\'
        rows = '\n'.join(' & '.join(render(p, c, 'latex', tid) for c in r) + r' \\' for r in t['rows'])
        return (f'% Generated from source/tables/{tid}.json; edit that.\n'
                f'{{\\{t.get("latex_size", "scriptsize")}\n\\begin{{xltabular}}{{\\linewidth}}{{{spec}}}\n'
                f'\\caption{{{cap}}}\\label{{tab:{tid}}}\\\\\n\\toprule\n{head}\n\\midrule\n\\endfirsthead\n'
                f'\\toprule\n{head}\n\\midrule\n\\endhead\n\\bottomrule\n\\endlastfoot\n{rows}\n\\end{{xltabular}}}}\n')
    env = "table*" if t.get("latex_span") == "full" else "table"
    return (f'% Generated from source/tables/{tid}.json; edit that.\n'
            f'\\begin{{{env}}}[{t.get("latex_place", "tbp")}]\n\\centering\n'
            f'\\caption{{{cap}}}\\label{{tab:{tid}}}\n{latex_tabular(p, t, tid)}\n\\end{{{env}}}\n')


def latex_math(tex):
    if '\\\\' in tex:
        rows = [r for r in texmath._split_rows(tex)]
        return '\\[\\begin{aligned}' + '\\\\\n'.join('&' + r.strip() for r in rows) + '\\end{aligned}\\]\n'
    return '\\[' + tex + '\\]\n'


def latex_statement(p, st):
    text = st.get('latex') or render(p, st['text'], 'latex', st['id'])
    if st.get('math'):
        text = latex_math(st['math']) + text
    hyp = ''
    if st.get('hypotheses'):
        hyp = '\\statementhypotheses{' + render(p, st['hypotheses'], 'latex', st['id']) + '}\n'
    env = 'perchproposition' if st.get('argued') else 'perchstatement'
    return (f'\\begin{{{env}}}{{{number_of(st.get("label"))}}}{{{render(p, st["title"], "latex", st["id"])}}}\\label{{stmt:{st["id"]}}}\n'
            f'{text}\n{hyp}\\statementevidence{{{render(p, st["evidence"], "latex", st["id"])}}}\n'
            f'\\end{{{env}}}')


def latex_statements(p, body):
    # Statements with "latex_body": true go in the body (generated/statements-body.tex);
    # the rest in the formal appendix (generated/statements-appendix.tex).
    out = ['% Generated from source/statements.json; edit that.']
    for st in p.statements:
        if bool(st.get('latex_body')) != body:
            continue
        out.append(latex_statement(p, st))
    return '\n'.join(out) + '\n'


def latex_definition(p, d):
    math = latex_math(d['math']) if d.get('math') else ''
    lean = '\\leannames{' + render(p, d['lean'], 'latex', d['id']) + '}' if d.get('lean') else ''
    return (f'\\begin{{perchdefinition}}{{{number_of(d["label"])}}}{{{render(p, d["title"], "latex", d["id"])}}}\\label{{def:{d["id"]}}}\n'
            f'{math}{render(p, d["text"], "latex", d["id"])}{lean}\n\\end{{perchdefinition}}')


def latex_definitions(p):
    out = ['% Generated from source/definitions.json; edit that.']
    out += [latex_definition(p, d) for d in p.definitions]
    return '\n'.join(out) + '\n'


def latex_facts(p):
    out = ['% Generated from source/facts.json and source/documents.json; edit those.']
    for d in documents():
        url = SITE + d['html_out'].replace('index.html', '')
        title = svg2tikz.tex_escape(d.get('title_latex') or d['title'])
        out.append(f'\\expandafter\\def\\csname perchdoc@{d["id"]}\\endcsname{{\\companion{{{url}}}{{{title}}}}}')
    for k in sorted(p.facts):
        v = fact_value(p, k, 'latex')
        f = p.facts[k]
        if isinstance(f, dict) and 'anon' in f:
            v = '\\ifdefined\\anonymous ' + fact_value(p, k, 'latex', anon=True) + '\\else ' + v + '\\fi'
        out.append(f'\\expandafter\\def\\csname perchfact@{k}\\endcsname{{{v}}}')
    return '\n'.join(out) + '\n'


def latex_body(p):
    out = ['% Generated from source/outline.json; edit that.']
    appendix = False
    for s in p.sections:
        if not p.in_edition(s, 'latex'):
            continue
        if s.get('appendix') and not appendix:
            out.append(r'\appendix')
            appendix = True
        title = svg2tikz.tex_escape(s.get('title_latex', s['title_html']))
        cmd = r'\section*' if s.get('unnumbered') else r'\section'
        out.append(f'{cmd}{{{title}}}\\label{{sec:{s["id"]}}}')
        out.append(f'\\input{{sections/{s["id"]}}}')
    return '\n'.join(out) + '\n'


def latex_bib(p):
    out = ['% Generated from source/refs.bib; edit that.']
    src = read(SRC / 'refs.bib')
    out.append(re.sub(r'^\s*editions\s*=\s*\{[^}]*\},?\n', '', src, flags=re.M))
    return '\n'.join(out)


def build_latex(p):
    files = {'body.tex': latex_body(p), 'facts.tex': latex_facts(p),
             'colors.tex': '% Generated from build/svg2tikz.py (the page\'s light theme).\n' + svg2tikz.color_definitions() + '\n',
             'statements-body.tex': latex_statements(p, True),
             'statements-appendix.tex': latex_statements(p, False), 'refs.bib': latex_bib(p),
             'definitions.tex': latex_definitions(p)}
    # One include per label, so a section can place a single theorem or definition.
    for st in p.statements:
        if st.get('label'):
            files[f'statements/{st["label"]}.tex'] = '% Generated from source/statements.json.\n' + latex_statement(p, st) + '\n'
    for d in p.definitions:
        files[f'definitions/{d["label"]}.tex'] = '% Generated from source/definitions.json.\n' + latex_definition(p, d) + '\n'
    for f in p.figures:
        if p.figures[f].get('kind') not in ('table', 'code', 'html'):
            lint_svg(f, p.figures[f])
        if p.in_edition(p.figures[f], 'latex'):
            try:
                files[f'figures/{f}.tex'] = latex_figure(p, f)
            except FileNotFoundError as e:
                fail(f'{DOC["id"]}: figure {f} is missing its source file {Path(e.filename).name}')
    # Only the tables this document places (its outline), not every table in the pool.
    placed = {t for ts in p.placed('latex', 'tables').values() for t in ts}
    for t in sorted(placed):
        if p.in_edition(p.tables[t], 'latex') and not any(fg.get('table') == t for fg in p.figures.values()):
            files[f'tables/{t}.tex'] = latex_table(p, t)
    # Section sources must place exactly the outline's figures and tables, in order.
    seen_f, seen_t, used_facts = [], [], set()
    for s in p.sections:
        if not p.in_edition(s, 'latex'):
            continue
        sp = LATEX / 'sections' / f'{s["id"]}.tex'
        if not sp.exists():
            fail(f'missing {sp.relative_to(ROOT)}')
            continue
        tex = read(sp)
        seen_f += re.findall(r'\\perchfigure\{([^}]+)\}', tex)
        seen_t += re.findall(r'\\perchtable\{([^}]+)\}', tex)
        used_facts |= set(re.findall(r'\\fact\{([^}]+)\}', tex))
    for extra in ('abstract.tex',):
        if (LATEX / 'sections' / extra).exists():
            used_facts |= set(re.findall(r'\\fact\{([^}]+)\}', read(LATEX / 'sections' / extra)))
    figs, tabs = p.placed('latex', 'figures'), p.placed('latex', 'tables')
    want_f = [f for s in p.sections if p.in_edition(s, 'latex') for f in figs[s['id']] if p.in_edition(p.figures[f], 'latex')]
    want_t = [t for s in p.sections if p.in_edition(s, 'latex') for t in tabs[s['id']] if p.in_edition(p.tables[t], 'latex')]
    if seen_f != want_f:
        fail(f'LaTeX figure order {seen_f} != outline {want_f}')
    if seen_t != want_t:
        fail(f'LaTeX table order {seen_t} != outline {want_t}')
    for k in sorted(used_facts - set(p.facts)):
        fail(f'LaTeX uses unknown fact {k!r}')
    return files


# ---------------------------------------------------------------- main

def check_sim_facts(facts):
    import hashlib
    run_path = SRC / 'figures' / 'fig-sim.run.json'
    page = ROOT / 'sim' / 'index.html'
    if not run_path.exists() or not page.exists():
        return
    run = json.loads(read(run_path))
    actual = {'sim-page-sha256': hashlib.sha256(page.read_bytes()).hexdigest(),
              'sim-golden-sha256': run.get('golden_sha256'), 'sim-replies-sha256': run.get('replies_sha256')}
    if run.get('page_sha256') != actual['sim-page-sha256']:
        fail('fig-sim.run.json page_sha256 does not match docs/perch-paper/sim/index.html')
    for key, value in actual.items():
        f = facts.get(key)
        if f is not None and (f['value'] if isinstance(f, dict) else f) != value:
            fail(f'fact {key} is not the recorded value {value}')


def doc_blocks(d):
    """The blocks build-page.mjs refreshes: from this document's page, or (first build
    after they move) from whichever document's page holds them now."""
    if not d.get('carried'):
        return {}
    pages = [ROOT / d['html_out']] + [ROOT / x['html_out'] for x in documents() if x is not d]
    for page in pages:
        if page.exists() and '<!-- EMBEDDED_ASSETS_START -->' in read(page):
            return carried_blocks(read(page))
    fail(f'{d["id"]}: no page holds the carried blocks')
    return {}


def build_doc(d, check):
    use_doc(d)
    p = Paper()
    current = read(INDEX) if INDEX.exists() else ''
    blocks = doc_blocks(d)
    if 'MEASUREMENTS' in blocks:
        check_measurements(p, blocks['MEASUREMENTS'])
    page = build_html(p, blocks) if not ERRORS else ''
    latex = build_latex(p) if LATEX else {}
    out = {INDEX: page}
    out.update({GEN / rel: text for rel, text in latex.items()})
    orphans = ([q for q in GEN.rglob('*') if q.is_file() and q not in out] if GEN and GEN.exists() else [])
    return out, orphans


def main(argv):
    check = '--check' in argv
    files, orphans = {}, []
    use_doc(documents()[0])
    check_sim_facts(Paper().facts)
    for d in documents():
        out, orph = build_doc(d, check)
        files.update(out)
        orphans += orph
    if LINT:
        print('\n'.join(('error: ' if check else 'warning: ') + 'figure lint: ' + e for e in LINT), file=sys.stderr)
        if check:
            ERRORS.extend(LINT)
    if ERRORS:
        print('\n'.join('error: ' + e for e in ERRORS if e not in LINT), file=sys.stderr)
        return 1
    top = ROOT.parent.parent
    stale = [str(f.relative_to(top)) for f, text in files.items() if not f.exists() or read(f) != text]
    if check:
        import subprocess
        figs = subprocess.run([sys.executable, str(Path(__file__).resolve().parent / 'figures' / 'make.py'), '--check'])
        if figs.returncode:
            return 1
        if stale or orphans:
            print('stale generated files (run python3 docs/perch-paper/build/paper.py):', file=sys.stderr)
            for s in stale + [str(o.relative_to(top)) for o in orphans]:
                print('  ' + s, file=sys.stderr)
            return 1
        print('paper sources and generated files agree')
        return 0
    for f, text in files.items():
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding='utf-8')
    for o in orphans:
        o.unlink()
    pages = [f for f in files if f.suffix == '.html']
    print(f'wrote {len(pages)} pages ({", ".join(str(f.relative_to(top)) for f in pages)}) '
          f'and {len(files) - len(pages)} LaTeX includes')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
