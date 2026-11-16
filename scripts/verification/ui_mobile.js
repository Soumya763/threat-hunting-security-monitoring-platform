const { chromium } = require('playwright');
const path = require('path'), fs = require('fs');
const SHOTS = path.join(__dirname, '.fixtures', 'shots'); fs.mkdirSync(SHOTS, { recursive: true });
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const p = await ctx.newPage();
  const errs = []; p.on('pageerror', (e) => errs.push(e.message)); p.on('console', (m) => { if (m.type() === 'error' && !/422|401/.test(m.text())) errs.push(m.text()); });
  await p.goto('http://localhost:5173/login', { waitUntil: 'networkidle' });
  await p.fill('#login-username', 'analyst1'); await p.fill('#login-password', process.env.ANALYST1_PASSWORD);
  await p.click('button[type="submit"]'); await p.waitForURL('http://localhost:5173/', { timeout: 15000 });
  const routes = ['/', '/alerts', '/incidents', '/logs', '/files', '/urls', '/search', '/history', '/reports', '/settings'];
  for (const r of routes) {
    await p.goto('http://localhost:5173' + r, { waitUntil: 'load' });
    await p.waitForTimeout(1800);
    const m = await p.evaluate(() => ({ overflow: document.documentElement.scrollWidth - window.innerWidth, text: (document.querySelector('main') || document.body).innerText.trim().length }));
    console.log(`MOBILE ${r.padEnd(10)} horizontal overflow=${m.overflow}px  content_chars=${m.text}`);
    if (r === '/history' || r === '/alerts') await p.screenshot({ path: path.join(SHOTS, `mobile${r.replace(/\//g, '-')}.png`) });
  }
  console.log('CONSOLE/PAGE ERRORS:', errs.length ? errs.slice(0, 4) : 'none');
  if (errs.length) process.exitCode = 1;
  await b.close();
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
