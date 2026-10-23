// npm install && npm run bench   (after `npm run build` in packages/perch-zk)
// Starts the page under Vite and runs it in headless Chromium. Set CHROMIUM
// to a browser binary to use one Playwright did not download.
import { chromium } from 'playwright';
import { createServer } from 'vite';

const server = await createServer({ configFile: new URL('./vite.config.js', import.meta.url).pathname, root: new URL('.', import.meta.url).pathname });
await server.listen();
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, headless: true });
try {
  const page = await browser.newPage();
  await page.goto('http://localhost:5199/?runs=5');
  await page.waitForFunction(() => /^(DONE|ERROR)/.test(document.getElementById('out').textContent), null, {
    timeout: 600_000,
  });
  console.log((await page.textContent('#out')).replace(/^DONE /, ''));
} finally {
  await browser.close();
  await server.close();
}
