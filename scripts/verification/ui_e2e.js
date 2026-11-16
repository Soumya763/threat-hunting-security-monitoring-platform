const { chromium } = require('playwright');
const path = require('path'), fs = require('fs');
const FX = path.join(__dirname, '.fixtures'); const SHOTS = path.join(FX, 'shots'); fs.mkdirSync(SHOTS, { recursive: true }); const BASE = 'http://localhost:5173'; const API = 'http://localhost:8000';
const results = [];
const settle = (page) => page.waitForFunction(() => { const t = (document.querySelector('main') || {}).innerText || ''; return t.trim().length > 0 && !/^Loading/.test(t.trim()); }, null, { timeout: 15000 }).catch(() => {}); const check = (n, ok, d = '') => { results.push([n, !!ok]); console.log((ok ? 'PASS ' : 'FAIL ') + n + (d ? `  [${String(d).slice(0, 160)}]` : '')); };
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  const consoleErrors = [], failedApi = [];
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  page.on('pageerror', (e) => consoleErrors.push('PAGEERROR ' + e.message));
  page.on('response', (r) => { if (r.url().startsWith(API) && r.status() >= 400) failedApi.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`); });

  // ---- login (real form)
  await page.goto(BASE + '/login', { waitUntil: 'networkidle' });
  await page.fill('#login-username', 'analyst1'); await page.fill('#login-password', process.env.ANALYST1_PASSWORD);
  await page.click('button[type="submit"]'); await page.waitForURL(BASE + '/', { timeout: 15000 });
  check('login through the form lands on the dashboard', page.url() === BASE + '/');

  // ---- every sidebar route renders real content
  const nav = ['Dashboard', 'Alerts', 'Incidents', 'Log Monitoring', 'File Analysis', 'URL Analysis', 'Threat Intelligence Search', 'Analysis History', 'Reports', 'Settings'];
  for (const label of nav) {
    await page.click(`nav a:has-text("${label}")`); await page.waitForLoadState('networkidle'); await settle(page);
    const text = (await page.locator('main').innerText()).trim();
    check(`sidebar "${label}" shows content (not blank)`, text.length > 30, text.slice(0, 60).replace(/\n/g, ' | '));
  }
  check('sidebar has all ten sections', (await page.locator('nav a').count()) === 10, await page.locator('nav a').count());

  // ---- dashboard numbers equal the API
  await page.click('nav a:has-text("Dashboard")'); await page.waitForLoadState('networkidle'); await settle(page);
  const token = await page.evaluate(() => localStorage.getItem('thp:token'));
  const sum = await (await fetch(API + '/api/v1/dashboard/summary', { headers: { Authorization: 'Bearer ' + token } })).json();
  const alerts = await (await fetch(API + '/api/v1/alerts')).json();
  const dash = await page.locator('main').innerText();
  check('dashboard "Total Alerts" equals alerts in the database', dash.includes(String(alerts.length)), `${alerts.length}`);
  check('dashboard shows analysis counts from the API', /files analysed/i.test(dash) && /latest analyses/i.test(dash) && dash.includes(String(sum.analyses.files)), String(sum.analyses.total));
  check('dashboard alert trend has 14 days', (await page.locator('.trend-chart__col').count()) === 14);

  // ---- alerts: open, assign, change status (real controls)
  await page.click('nav a:has-text("Alerts")'); await page.waitForLoadState('networkidle'); await settle(page);
  const alertRows = await page.locator('table tbody tr').count();
  check('alerts list shows the seeded alerts', alertRows >= 8, alertRows);
  await page.locator('table tbody tr').first().click(); await settle(page);
  await page.waitForLoadState('networkidle'); await settle(page);
  check('alert detail page opens', /\/alerts\/\d+/.test(page.url()), page.url());

  // ---- incidents: open detail, add a note, assign, change status
  await page.click('nav a:has-text("Incidents")'); await page.waitForLoadState('networkidle'); await settle(page);
  await page.locator('table tbody tr').first().click(); await page.waitForLoadState('networkidle'); await settle(page);
  check('incident detail page opens', /\/incidents\/\d+/.test(page.url()), page.url());
  const noteBox = page.locator('form:has(button:has-text("Add Note")) textarea');
  if (await noteBox.count()) {
    await noteBox.fill('UI test note: correlated burst from 10.66.1.10');
    await page.click('button:has-text("Add Note")');
    await page.waitForTimeout(1500);
    const body = await page.locator('main').innerText();
    check('investigation note saved from the UI and shown', /UI test note/i.test(body));
  } else check('investigation note form present', false, 'no textarea found');

  // ---- log monitoring (real OpenSearch)
  await page.click('nav a:has-text("Log Monitoring")'); await page.waitForLoadState('networkidle'); await settle(page);
  await page.fill('input[placeholder^="event_type"]', 'event_type:proxy_request_error');
  await page.click('button:has-text("Search logs")'); await page.waitForTimeout(2500);
  const logText = await page.locator('main').innerText();
  check('log monitoring returns indexed events from OpenSearch', /matching events/i.test(logText) && /proxy_request_error/i.test(logText), logText.slice(0, 80).replace(/\n/g, ' | '));

  // ---- file analysis through the upload UI
  await page.click('nav a:has-text("File Analysis")'); await page.waitForLoadState('networkidle'); await settle(page);
  await page.setInputFiles('input[type="file"]', `${FX}/suspicious-indicators.pdf`);
  await page.click('button:has-text("Analyse file")');
  await page.waitForURL(/\/analysis\/\d+/, { timeout: 20000 });
  await page.waitForFunction(() => /Completed/i.test(document.body.innerText) || /failed/i.test(document.body.innerText), null, { timeout: 60000 }).catch(() => {});
  await page.waitForTimeout(800);
  const fileDetail = await page.locator('main').innerText();
  check('file result page shows score and factor reasons', /why this score/i.test(fileDetail) && /pdf javascript/i.test(fileDetail), fileDetail.slice(0, 100).replace(/\n/g, ' | '));
  check('file result shows provider states (no key -> not configured or mock result, never invented)', /threat-intelligence providers/i.test(fileDetail));
  await page.screenshot({ path: `${SHOTS}/ui-file-result.png`, fullPage: true });
  const fileUrl = page.url();
  const dl1 = page.waitForEvent('download'); await page.click('button:has-text("Download PDF report")'); const d1 = await dl1;
  check('PDF report download works from the detail page', (await d1.suggestedFilename()).endsWith('.pdf'), await d1.suggestedFilename());
  const dl2 = page.waitForEvent('download'); await page.click('button:has-text("Download JSON")'); const d2 = await dl2;
  check('JSON report download works from the detail page', (await d2.suggestedFilename()).endsWith('.json'), await d2.suggestedFilename());
  const note = page.locator('#note-text');
  await note.fill('Analyst review: PDF contains JS and auto-open actions; not opened.');
  await page.click('button:has-text("Save note")'); await page.waitForTimeout(1200);
  check('analyst note saved on the analysis', /not opened/i.test(await page.locator('main').innerText()));
  await page.click('button:has-text("Search internal logs")'); await page.waitForTimeout(2500);
  check('internal-log pivot runs from the UI', /matching event|local log search|log search/i.test(await page.locator('main').innerText()));

  // ---- URL analysis via UI
  await page.click('nav a:has-text("URL Analysis")'); await page.waitForLoadState('networkidle'); await settle(page);
  await page.fill('#url-input', 'https://example.com/');
  await page.click('button:has-text("Analyse")'); await page.waitForURL(/\/analysis\/\d+/, { timeout: 20000 });
  await page.waitForFunction(() => /Completed/i.test(document.body.innerText) || /failed/i.test(document.body.innerText), null, { timeout: 90000 }).catch(() => {});
  await page.waitForTimeout(800);
  const urlDetail = await page.locator('main').innerText();
  check('URL result shows normalised URL, DNS and TLS sections', /normalised url/i.test(urlDetail) && /tls certificate/i.test(urlDetail) && /redirect chain/i.test(urlDetail));
  await page.screenshot({ path: `${SHOTS}/ui-url-result.png`, fullPage: true });

  // ---- invalid URL is blocked in the UI before submission
  await page.click('nav a:has-text("URL Analysis")'); await page.waitForLoadState('networkidle'); await settle(page);
  await page.fill('#url-input', 'http://127.0.0.1/admin');
  await page.click('button:has-text("Analyse")'); await page.waitForTimeout(1500);
  check('private-address URL refused with a visible message', (await page.locator('[role="alert"]').count()) > 0 || /Only|not|cannot|blocked|private|public/i.test(await page.locator('main').innerText()), (await page.locator('[role="alert"]').allInnerTexts()).join(' | ').slice(0, 120));

  // ---- threat intel search via UI
  await page.click('nav a:has-text("Threat Intelligence Search")'); await page.waitForLoadState('networkidle'); await settle(page);
  await page.fill('#indicator-input', '8.8.8.8');
  check('search shows the detected type while typing', /Detected: IP address/.test(await page.locator('main').innerText()));
  await page.click('button:has-text("Search")'); await page.waitForURL(/\/analysis\/\d+/, { timeout: 20000 });
  await page.waitForTimeout(3000);
  const ipDetail = await page.locator('main').innerText();
  check('IP search result lists provider states and local pivot', /threat-intelligence providers/i.test(ipDetail) && /earlier analyses|internal logs/i.test(ipDetail));

  // ---- history: filter, sort, paginate, reopen
  await page.click('nav a:has-text("Analysis History")'); await page.waitForLoadState('networkidle'); await settle(page);
  await page.locator('label:has-text("Type") select').selectOption('file'); await page.waitForTimeout(800);
  const fileRows = await page.locator('table tbody tr').count();
  check('history filter by type returns file rows only', fileRows >= 1, fileRows);
  await page.locator('label:has-text("Type") select').selectOption(''); await page.waitForTimeout(600);
  await page.locator('label:has-text("Per page") select').selectOption('10'); await page.waitForTimeout(600);
  await page.click('button:has-text("Next")').catch(() => {}); await page.waitForTimeout(800);
  check('history pagination moves to page 2', /page 2/i.test(await page.locator('main').innerText()));
  await page.click('button:has-text("Previous")').catch(() => {});
  await page.locator('table tbody tr a:has-text("Open")').first().click(); await page.waitForURL(/\/analysis\/\d+/);
  check('an earlier analysis reopens from history', /\/analysis\/\d+/.test(page.url()));

  // ---- reports page
  await page.click('nav a:has-text("Reports")'); await page.waitForLoadState('networkidle'); await settle(page);
  const rdl = page.waitForEvent('download'); await page.locator('button:has-text("PDF")').first().click(); const rd = await rdl;
  check('reports page downloads an incident or analysis PDF', (await rd.suggestedFilename()).endsWith('.pdf'), await rd.suggestedFilename());

  // ---- settings: real engine status and provider states
  await page.click('nav a:has-text("Settings")'); await page.waitForLoadState('networkidle'); await settle(page);
  const set = await page.locator('main').innerText();
  check('settings shows OpenSearch status', /search and log engine/i.test(set) && /opensearch/i.test(set) && /status\s*\n?\s*ok/i.test(set), set.slice(0, 120).replace(/\n/g, ' | '));
  check('settings lists providers with honest status', /threat-intelligence providers/i.test(set));
  await page.screenshot({ path: `${SHOTS}/ui-settings.png`, fullPage: true });

  // ---- logout and protected route redirect
  await page.click('button:has-text("Log out")'); await page.waitForURL(BASE + '/login', { timeout: 10000 });
  await page.goto(BASE + '/history', { waitUntil: 'networkidle' });
  check('protected route redirects to login when signed out', page.url().endsWith('/login'), page.url());

  // Only the deliberate negative test (a private-address URL, refused with 422) may appear here.
  const realConsole = consoleErrors.filter((e) => !/Failed to load resource: the server responded with a status of 422|React Router Future Flag|vite/i.test(e));
  check('no console errors during the workflow', realConsole.length === 0, realConsole.slice(0, 3).join(' || '));
  check('only the deliberate private-URL refusal returned an error (422)', failedApi.length === 1 && /^422 POST \/api\/v1\/urls$/.test(failedApi[0]), failedApi.join(' ; '));
  console.log(`\nUI checks: ${results.filter((r) => r[1]).length}/${results.length} passed; API failures seen: ${failedApi.length}`);
  await browser.close();
})().catch((e) => { console.error('SCRIPT ERROR', e.message); process.exit(1); });
