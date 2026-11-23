/** Run against an operator-provided localhost server and an isolated measured case. */
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PF_PLAYWRIGHT_MODULE || 'playwright');
const axePath = process.env.PF_AXE_SCRIPT || require.resolve('axe-core/axe.min.js');
const base = new URL(process.env.PF_BROWSER_URL || 'http://127.0.0.1:8769');
assert(['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname), 'Use a local test server');
const caseId = process.env.PF_BROWSER_CASE;
assert.match(caseId ?? '', /^[a-f0-9]{32}$/, 'Provide the disposable case ID');
const out = resolve(process.env.PF_SCREENSHOTS || 'docs/design/screenshots');
const sizes = [[1440, 900], [1920, 1080], [1280, 800]];
const routes = [
  ['design-system', 'Design system', 'D2', 3072],
  ['overview', 'Investigation Overview', 'D4', 3072],
  ['investigations', 'Investigations', 'D4', 3072],
  ['evidence', 'Evidence', 'D4', 3072],
  ['datasets', 'Dataset Explorer', 'D4', 4096],
  ['correlation', 'Event Correlation', 'D5', 4096],
  ['privacy-assessment', 'Privacy assessment', 'D6', 3072],
  ['protection', 'Privacy protection', 'D6', 3072],
  ['analysis', 'AI analysis', 'D7', 4096],
  ['evaluation', 'Privacy–Utility Evaluation Lab', 'D7', 4096],
  ['privacy-diagnostics', 'Privacy diagnostics', 'D7', 4096],
  ['performance', 'Performance', 'D7', 4096],
  ['reports', 'Reports', 'D8', 3072],
  ['audit', 'Audit History', 'D8', 3072],
  ['settings', 'Settings', 'D8', 3072],
];

const browser = await chromium.launch({ headless: true,
  ...(process.env.PF_BROWSER_EXECUTABLE ? {executablePath: process.env.PF_BROWSER_EXECUTABLE} : {}),
});
const context = await browser.newContext({ reducedMotion: 'reduce' });
const page = await context.newPage();
const offOrigin = new Set();
const appErrors = [];
await page.route('**/*', async request => {
  const url = new URL(request.request().url());
  if ((url.protocol === 'https:' || url.protocol === 'http:') && url.origin !== base.origin) {
    offOrigin.add(url.origin);
    await request.abort();
  } else {
    await request.continue();
  }
});
page.on('pageerror', err => appErrors.push(err.message));
page.on('console', msg => {
  if (msg.type() === 'error') appErrors.push(msg.text());
});

async function initialize(route, heading, { advanced = false } = {}) {
  const url = new URL('/', base);
  url.searchParams.set('page', route);
  url.searchParams.set('case', caseId);
  if (advanced) url.searchParams.set('mode', 'advanced');
  if (route === 'correlation') url.searchParams.set('anchor', process.env.PF_BROWSER_ANCHOR || '3');
  const start = Date.now();
  await page.goto(url.toString(), {waitUntil: 'domcontentloaded'});
  await page.getByRole('heading', { name: heading, exact: true, level: 1 }).waitFor();
  await page.getByText('Case records and stored measurements', { exact: true }).waitFor();
  return Date.now() - start;
}

async function record(route, stage) {
  const directory = join(out, stage);
  await mkdir(directory, { recursive: true });
  for (const [width, height] of sizes) {
    await page.setViewportSize({width, height});
    await page.evaluate(async () => {
      await document.fonts.ready;
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    });
    if (route === 'correlation') {
      await page.getByRole('heading', {name:'Evidence timeline',exact:true})
        .evaluate(element => element.scrollIntoView({block: 'center'}));
    }
    await page.screenshot({ path: join(directory, route + '-' + width + '.jpg'), type: 'jpeg', quality: 81 });
  }
  await page.setViewportSize({width: 1440, height: 900});
}

async function select(name, option) {
  await page.getByRole('combobox', { name, exact: true }).click();
  await page.getByRole('option', { name: option }).first().click();
}

async function inspect(route) {
  if (route === 'correlation') {
    await page.waitForFunction(() => Array.from(document.querySelectorAll('.window_brush_bg, .window_brush'))
      .every(element => !element.hasAttribute('role') && element.getAttribute('aria-hidden') === 'true'));
  }
  await page.addScriptTag({ path: axePath });
  const accessibility = await page.evaluate(async () => {
    const result = await window.axe.run({ runOnly: { type: 'tag',
      values: ['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa','best-practice'] }});
    return result.violations.map(violation => ({
      id: violation.id, impact: violation.impact,
      selectors: violation.nodes.slice(0, 4).map(node => node.target.join(' ')),
    }));
  });
  const bytes = await page.evaluate(() => performance.getEntriesByType('resource').reduce((total, entry) =>
    /\.js($|\?)/.test(entry.name) && new URL(entry.name).origin === location.origin
      ? total + (entry.encodedBodySize || entry.transferSize) : total, 0));
  const errors = await page.locator('[data-testid="stException"], [data-testid="stAlert"] [data-testid="stAlertContentError"]').count();
  assert.equal(errors, 0, 'No application exceptions on ' + route);
  return {axe: accessibility, loadedJsKiB: Math.round(bytes / 1024)};
}

try {
  await page.setViewportSize({width:1440,height:900});
  const measured = {};
  for (const [route, heading, stage, budgetKiB] of routes) {
    appErrors.length = 0;
    const firstViewMs = await initialize(route, heading);
    if (route === 'correlation') {
      await page.getByRole('heading', {name:'Evidence timeline', exact:true}).waitFor();
    } else if (route === 'evaluation') {
      await page.getByRole('heading', {name:'Set up an experiment',exact:true}).waitFor();
      await record('lab-setup', stage);
      await page.getByText('Frontier', {exact:true}).click();
      await page.getByRole('heading', {name:'Privacy–Utility Frontier', exact:true}).waitFor();
      await page.getByText('F1 versus accounted epsilon', {exact:true}).waitFor();
    }
    await record(route, stage);
    if (route === 'correlation') {
      await mkdir(join(out, 'D9'), {recursive: true});
      const devTools = await context.newCDPSession(page);
      await devTools.send('Emulation.setEmulatedVisionDeficiency', {type:'deuteranopia'});
      await page.screenshot({path:join(out, 'D9', 'correlation-deuteranopia-1440.jpg'), type:'jpeg', quality:81});
      await devTools.send('Emulation.setEmulatedVisionDeficiency', {type:'none'});
      await devTools.detach();
    }
    if (route === 'overview') await record('shell', 'D3');
    if (['overview','correlation','evaluation','reports'].includes(route)) await record(route, 'D9');
    const observed = await inspect(route);
    measured[route] = {firstViewMs, budgetKiB, ...observed, browserErrors: [...appErrors]};
    console.log(route, JSON.stringify(measured[route]));
  }
  await writeFile(join(out, 'browser-partial.json'),
    JSON.stringify({browser: browser.version(), measured, offOrigin: [...offOrigin]}, null, 2) + '\n');
  await initialize('overview', 'Investigation Overview');
  await page.keyboard.press('Control+k');
  await page.getByRole('textbox', { name: 'Search workspace' }).waitFor({timeout:6000});
  const search = page.getByRole('textbox', { name: 'Search workspace' });
  await search.fill('Evaluation Lab');
  await search.press('Enter');
  await page.getByRole('combobox', {name:'Search results'}).waitFor();
  await page.getByRole('button', { name:'Open result', exact:true }).click();
  await page.getByRole('heading', {name:'Privacy–Utility Evaluation Lab', exact:true}).waitFor();
  assert.equal(new URL(page.url()).searchParams.get('case'), caseId);
  await page.getByText('Advanced', {exact:true}).click();
  await page.getByRole('spinbutton', {name:'Training epochs'}).waitFor();
  await page.keyboard.press('Escape');
  await page.locator('h1').click();
  await page.keyboard.press('g');
  await page.keyboard.press('r');
  await page.getByRole('heading', {name:'Reports', exact:true, level:1}).waitFor();
  const pdfButton = page.getByRole('button', {name:'Download investigation PDF', exact:true});
  await pdfButton.waitFor();
  const pending = page.waitForEvent('download');
  await pdfButton.click();
  const pdf = await pending;
  assert.match(pdf.suggestedFilename(), /^privforensics-[a-f0-9]{8}\.pdf$/);

  const findings = Object.entries(measured).flatMap(([route, result]) =>
    result.axe.filter(item => item.impact === 'serious' || item.impact === 'critical').map(item => ({route, ...item})));
  await writeFile(join(out, 'browser-verification.json'),
    JSON.stringify({browser:browser.version(), measured, highImpactViolations:findings, offOrigin:[...offOrigin]}, null, 2) + '\n');
  assert.deepEqual(findings, [], 'No serious or critical axe findings');
  assert.ok(Object.values(measured).every(item => !item.browserErrors.length), 'No browser console errors');
  assert.deepEqual([...offOrigin], [], 'All browser resources stayed on localhost');
  console.log('Verified ' + routes.length + ' routes, three screenshot widths and keyboard navigation.');
} finally {
  await browser.close();
}
