import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { openDatabase } from '../src/database.mjs';
import { PassportService, DEMO_MEMBER } from '../src/service.mjs';
import { createCredentials } from '../src/auth.mjs';
import { createApp } from '../src/http.mjs';
import { verifyExport } from '../src/export-verifier.mjs';

let playwright;
try { playwright = await import('playwright'); }
catch {
  if (process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES) playwright = await import(pathToFileURL(join(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES, 'playwright/index.mjs')).href);
  else throw new Error('UI 检查需要 Playwright：npm install --no-save playwright，再运行 npx playwright install chromium。');
}
const directory = mkdtempSync(join(tmpdir(), 'symsoil-ui-'));
const artifacts = resolve(process.env.PASSPORT_UI_ARTIFACTS || 'test-results/ui');
mkdirSync(artifacts, { recursive: true });
const db = openDatabase(join(directory, 'ledger.sqlite'));
const service = new PassportService(db); service.seed({ openingPoints: 100 });
const credentials = createCredentials();
const server = createApp({ service, credentials, demo: true, publicDir: resolve(import.meta.dirname, '../public') });
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await playwright.chromium.launch({ headless: true, ...(process.env.PASSPORT_BROWSER_BIN ? { executablePath: process.env.PASSPORT_BROWSER_BIN } : {}) });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, colorScheme: 'light' });
  const page = await context.newPage(), errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    window.cspErrors = [];
    document.addEventListener('securitypolicyviolation', event => window.cspErrors.push(event.violatedDirective));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const snapshot = () => service.snapshot(DEMO_MEMBER);
  const tab = name => page.locator(`[data-tab="${name}"]`).click();
  const stage = value => page.waitForFunction(value => document.querySelector('#device-screen').dataset.stage === value, value);
  async function shortOK() { await page.locator('[data-key="ok"]').click(); }
  async function holdOK(duration = 2250) {
    const box = await page.locator('[data-key="ok"]').boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down(); await page.waitForTimeout(duration); await page.mouse.up();
  }
  async function confirm(choiceIndex = 0) {
    await stage('review'); await shortOK(); await stage('choose');
    for (let i = 0; i < choiceIndex; i++) await page.locator('[data-key="down"]').click();
    await shortOK(); await stage('confirm'); await holdOK(); await stage('result');
  }
  async function order(item = 'harvest') {
    await tab('terminal'); await page.locator('#catalog-select').selectOption(item);
    await page.locator('#order-form button').click();
    await page.waitForFunction(() => document.querySelector('#prepared-operation').textContent.includes('−'));
    await page.locator('#simulated-tap').click(); await stage('review');
  }
  async function noOverflow() {
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, 'page must fit the viewport');
  }
  await page.goto(base); await page.locator('#demo-login').click();
  await page.locator('#workspace').waitFor({ state: 'visible' });
  await page.waitForFunction(() => document.querySelector('#greeting').textContent.includes('菡白'));
  assert.equal(snapshot().balance, 100);
  await tab('terminal'); await page.locator('#contribution-form button').click();
  await page.waitForFunction(() => document.querySelector('#prepared-operation').textContent.includes('+30'));
  await page.locator('#simulated-tap').click(); await stage('review');
  assert.equal(snapshot().balance, 100); assert.equal(snapshot().receipts.length, 0);
  await shortOK(); await stage('choose'); await shortOK(); await stage('confirm');
  await shortOK(); await holdOK(250);
  assert.equal(snapshot().receipts.length, 0, 'short press and early release must not approve');
  await holdOK(); await stage('result'); assert.equal(snapshot().balance, 130);
  await tab('terminal'); await page.locator('#simulated-tap').click();
  await page.waitForFunction(() => document.querySelector('#device-screen').textContent.includes('此单已处理'));
  assert.equal(snapshot().balance, 130); assert.equal(snapshot().receipts.length, 1);
  await order(); await confirm(); assert.equal(snapshot().balance, 110);
  await tab('terminal'); await page.locator('#refund').click();
  await page.waitForFunction(() => document.querySelector('#prepared-operation').textContent.includes('按原单退回'));
  await page.locator('#simulated-tap').click(); await confirm(); assert.equal(snapshot().balance, 130);
  await order('workshop'); await confirm();
  assert.equal(snapshot().balance, 130); assert.equal(snapshot().receipts.length, 3);
  assert.ok((await page.locator('#device-screen').textContent()).includes('积分不足'));
  await tab('terminal'); await page.locator('#prepare-expression').click(); await confirm(2);
  assert.equal(snapshot().receipts[0].decision, 'original_only');
  await tab('terminal'); await page.locator('#revise-expression').click(); await stage('review');
  assert.equal(snapshot().receipts[0].superseded_by !== null, true);
  assert.equal(snapshot().grants.length, 0);
  await tab('terminal'); await page.locator('#prepare-grant').click(); await confirm();
  await tab('grants'); await page.locator('[data-execute]').click();
  await page.waitForFunction(() => document.querySelector('#grants-list').textContent.includes('已使用'));
  assert.equal(snapshot().grants[0].used, 1);
  assert.equal(snapshot().asset.value, '周六上午：菡白协助新宅菜园维护');
  await tab('terminal'); await page.locator('#prepare-grant').click(); await confirm();
  await tab('grants'); await page.locator('[data-revoke]').click();
  await page.waitForFunction(() => document.querySelector('#grants-list').textContent.includes('已撤销'));
  assert.equal(snapshot().grants[0].revoked, 1);
  await order(); await confirm(); assert.equal(snapshot().balance, 110);
  await tab('terminal'); await page.locator('[data-fulfill]').click();
  await page.waitForFunction(() => document.querySelector('#fulfillment-list').textContent.includes('已交付'));
  await tab('points');
  const downloadEvent = page.waitForEvent('download'); await page.locator('#export').click();
  const download = await downloadEvent; await download.saveAs(join(artifacts, 'member-export.json'));
  const exported = await fetch(base + '/api/me/export', { headers: { Authorization: 'Bearer ' + credentials.member.token } }).then(r => r.json());
  verifyExport(exported);
  await page.reload(); await page.locator('#demo-login').click();
  await page.waitForFunction(() => document.querySelector('#device-info').textContent.includes('设备 D-'));
  assert.equal(snapshot().balance, 110); assert.equal(snapshot().receipts.length, 7);
  await page.screenshot({ path: join(artifacts, 'desktop.png'), fullPage: true });
  await noOverflow();
  await page.setViewportSize({ width: 320, height: 800 }); await page.emulateMedia({ colorScheme: 'dark' });
  for (const name of ['card', 'points', 'grants', 'receipts', 'terminal']) { await tab(name); await noOverflow(); }
  await tab('card'); await page.screenshot({ path: join(artifacts, 'mobile-dark.png'), fullPage: true });
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.cspErrors), []);
  console.log('UI flow passed: NFC simulation, hold/release, credit/debit/refund, versioning, grants, export, reload, 320px layout.');
  console.log(`Screenshots: ${artifacts}`);
} finally {
  if (browser) await browser.close();
  server.closeIdleConnections(); await new Promise(resolve => server.close(resolve));
  db.close(); rmSync(directory, { recursive: true, force: true });
}
