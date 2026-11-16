// Browser check: every page that shows analyst data redirects to /login when logged out,
// and loads for a logged-in user. Usage:
//   BASE=http://localhost:5173 PW_FILE=/path/to/password-file node ui_auth_guard.js
// The password file must contain a line "password: <value>". Never commit that file.
const { chromium } = require('playwright');
const fs = require('fs');
const BASE = process.env.BASE || 'http://localhost:5173';
const PW = fs.readFileSync(process.env.PW_FILE, 'utf8').match(/^password: (.*)$/m)[1].trim();
const PROTECTED = ['/', '/alerts', '/incidents', '/logs', '/files', '/urls', '/search', '/history', '/reports', '/settings'];
const results = [];
const check = (name, ok, extra = '') => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${name} ${extra}`); };

(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();

  for (const route of PROTECTED) {
    await page.goto(BASE + route, { waitUntil: 'networkidle' });
    await page.waitForTimeout(300);
    check(`logged out: ${route} redirects to login`, page.url().includes('/login'), page.url());
  }

  await page.locator('input[type=text]').first().fill('analyst');
  await page.locator('input[type=password]').fill(PW);
  await page.locator('button[type=submit]').click();
  await page.waitForTimeout(1500);

  for (const route of ['/', '/alerts', '/incidents']) {
    await page.goto(BASE + route, { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    check(`logged in: ${route} loads`, !page.url().includes('/login'), page.url());
  }

  await browser.close();
  const passed = results.filter(Boolean).length;
  console.log(`SUMMARY ${passed}/${results.length}`);
  process.exit(passed === results.length ? 0 : 1);
})().catch((e) => { console.error('ERROR', e.message); process.exit(1); });
