"""Write standalone.html: index.html with its three module scripts (the component, the recorded previews and the
page glue) inlined, so the page also works from file://. Run from this directory: python3 build-standalone.py"""
from pathlib import Path
here = Path(__file__).resolve().parent
page = (here / 'index.html').read_text(encoding='utf-8')
assert page.count('<title>Café Perch sign mock</title>') == 1
page = page.replace('<title>Café Perch sign mock</title>', '<title>Café Perch sign mock (single file)</title>', 1)
for name in ('soroban-sign-dialog.js', 'canned-previews.js', 'app.js'):
    tag = f'<script type="module" src="{name}"></script>'
    assert page.count(tag) == 1, name
    body = (here / name).read_text(encoding='utf-8').replace('</script>', '<\\/script>')
    page = page.replace(tag, f'<script type="module">\n{body}\n</script>', 1)
(here / 'standalone.html').write_text(page, encoding='utf-8')
