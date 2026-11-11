// Toy dapp glue for the mock. It uses only the component's public API:
// labels, previewProvider, request(), and the approve / reject / preview events.
const C = globalThis.CANNED;
const dialog = document.getElementById('dialog');
const log = document.getElementById('log');
const short = (s) => (s ? `${s.slice(0, 4)}…${s.slice(-4)}` : '');
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

dialog.labels = C.labels;

// Canned stand-in for the simulator engine: same request in, same
// PreviewResult shape out as the real engine module.
dialog.previewProvider = ({ transaction, signal }) =>
  new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      const result = C.previews[transaction];
      resolve(result ? structuredClone(result) : { status: 'fallback', notice: 'No canned preview for this transaction.' });
    }, 700);
    signal?.addEventListener('abort', () => { clearTimeout(t); reject(new DOMException('aborted', 'AbortError')); });
  });

const set = (id, fn) => document.getElementById(id).addEventListener('change', (e) => fn(e.target.value));
set('theme', (v) => {
  v ? document.documentElement.setAttribute('data-theme', v) : document.documentElement.removeAttribute('data-theme');
  v ? dialog.setAttribute('theme', v) : dialog.removeAttribute('theme');
});
set('brand', (v) => dialog.classList.toggle('brand', v === 'brand'));
set('preview', (v) => dialog.setAttribute('preview', v));
dialog.setAttribute('preview', 'manual');

for (const button of document.querySelectorAll('[data-scenario]')) {
  button.addEventListener('click', async () => {
    const s = C.scenarios.find((x) => x.id === button.dataset.scenario);
    const r = await dialog.request({ transaction: s.transaction, network: C.network, signer: C.signer, dapp: 'cafe-perch.example' });
    const item = document.createElement('div');
    item.className = 'ev';
    if (r.approved) {
      const mine = r.entries.filter((e) => e.forSigner);
      item.innerHTML = `<b class="ok">approve</b> · ${esc(s.title)}<br>
        The wallet now signs ${mine.length} entr${mine.length === 1 ? 'y' : 'ies'} for ${esc(short(r.signer))}:
        <pre>${esc(mine.map((e) => `#${e.index + 1} ${e.credentials} nonce ${e.nonce}\n   invocationHash ${e.invocationHash}`).join('\n'))}</pre>
        ${r.flags.length ? `Signed despite: ${esc(r.flags.map((f) => f.kind).join(', '))}` : 'No flags.'}`;
    } else {
      item.innerHTML = `<b class="no">reject</b> · ${esc(s.title)} · reason <code>${esc(r.reason)}</code>`;
    }
    log.prepend(item);
    button.focus();
  });
}
