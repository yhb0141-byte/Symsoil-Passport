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
  const stage = (value, target = page) => target.waitForFunction(value => document.querySelector('#device-screen').dataset.stage === value, value);
  async function shortOK(target = page) { await target.locator('[data-key="ok"]').click(); }
  async function holdOK(duration = 2250, target = page) {
    const box = await target.locator('[data-key="ok"]').boundingBox();
    await target.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await target.mouse.down(); await target.waitForTimeout(duration); await target.mouse.up();
  }
  async function confirm(choiceIndex = 0, target = page) {
    await stage('review', target); await shortOK(target); await stage('choose', target);
    for (let i = 0; i < choiceIndex; i++) await target.locator('[data-key="down"]').click();
    await shortOK(target); await stage('confirm', target); await holdOK(2250, target); await stage('result', target);
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
  const operator = await context.newPage(); operator.on('pageerror', error => errors.push(error.message));
  await operator.goto(base + '/operator.html'); await operator.locator('#operator-demo').click();
  await operator.locator('#operator-workspace').waitFor({ state: 'visible' });
  await operator.locator('[data-operator-tab="members"]').click();
  await operator.locator('#operator-member [name="name"]').fill('共创伙伴二');
  await operator.locator('#operator-member [name="id"]').fill('M-UI-02');
  await operator.locator('#operator-member button').click();
  await operator.waitForFunction(() => document.querySelector('#operator-members').textContent.includes('M-UI-02'));
  await operator.locator('#operator-credential button').click();
  await operator.locator('#issued-credential').waitFor({ state: 'visible' });
  const memberToken = await operator.locator('#issued-secret').inputValue();
  const memberContext = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const second = await memberContext.newPage(); second.on('pageerror', error => errors.push(error.message));
  async function enterMember(token) {
    await second.goto(base); await second.locator('#access-form [name="member"]').fill(token);
    await second.locator('#access-form button[type="submit"]').click();
    await second.locator('#workspace').waitFor({ state: 'visible' });
    await second.waitForFunction(() => document.querySelector('#greeting').textContent.includes('共创伙伴二'));
  }
  await enterMember(memberToken); assert.equal(service.balance('M-UI-02'), 0);
  const originalDevice = service.snapshot('M-UI-02').device.id;
  const originalCard = service.ensureCard('M-UI-02').payload;
  await operator.locator('[data-operator-tab="exchange"]').click();
  await operator.locator('#operator-contribution [name="memberId"]').selectOption('M-UI-02');
  await operator.locator('#operator-contribution [name="title"]').fill('维护邻里花园');
  await operator.locator('#operator-contribution button').click();
  await operator.waitForFunction(() => document.querySelector('#scan-kind').value === 'contribution' && document.querySelector('#scan-source').value.length > 0);
  await operator.locator('.nfc-terminal details summary').click();
  async function sendAndConfirm() {
    await operator.locator('#operator-manual-scan [name="cardPayload"]').fill(originalCard);
    await operator.locator('#operator-manual-scan button').click();
    await operator.waitForFunction(() => document.querySelector('#operator-nfc-status').textContent.includes('事项已发送'));
    await second.locator('#refresh').click();
    await second.locator('[data-open]').first().click(); await confirm(0, second);
  }
  await sendAndConfirm(); assert.equal(service.balance('M-UI-02'), 30); assert.equal(snapshot().balance, 110);
  await operator.locator('#operator-order button').click();
  await operator.waitForFunction(() => document.querySelector('#scan-kind').value === 'order');
  await sendAndConfirm(); assert.equal(service.balance('M-UI-02'), 10);
  await operator.locator('#operator-refresh').click();
  await operator.locator('[data-deliver]').click();
  await operator.waitForFunction(() => document.querySelector('#operator-notice').textContent.includes('交付已登记'));
  await operator.locator('[data-operator-tab="members"]').click();
  await operator.locator('[data-recover="M-UI-02"]').click();
  await operator.locator('#recovery-dialog').waitFor({ state: 'visible' });
  await operator.locator('#confirm-recovery').click();
  await operator.locator('#recovery-dialog').waitFor({ state: 'hidden' });
  const denied = await fetch(base + '/api/me', { headers: { Authorization: 'Bearer ' + memberToken } }); assert.equal(denied.status, 401);
  await operator.locator('#operator-credential button').click();
  await operator.locator('#issued-credential').waitFor({ state: 'visible' });
  const replacementToken = await operator.locator('#issued-secret').inputValue();
  await enterMember(replacementToken);
  assert.notEqual(service.snapshot('M-UI-02').device.id, originalDevice);
  assert.notEqual(service.ensureCard('M-UI-02').payload, originalCard);
  assert.equal(service.balance('M-UI-02'), 10); assert.equal(service.snapshot('M-UI-02').receipts.length, 2);
  const secondExport = await fetch(base + '/api/me/export', { headers: { Authorization: 'Bearer ' + replacementToken } }).then(response => response.json());
  verifyExport(secondExport);
  await operator.locator('#clear-issued').click(); assert.equal(await operator.locator('#issued-secret').inputValue(), '');
  await operator.setViewportSize({ width: 320, height: 800 }); await operator.emulateMedia({ colorScheme: 'dark' });
  for (const name of ['exchange', 'members', 'audit']) {
    await operator.locator(`[data-operator-tab="${name}"]`).click();
    assert.equal(await operator.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  }
  await operator.locator('[data-operator-tab="members"]').click();
  await operator.screenshot({ path: join(artifacts, 'operator-mobile-dark.png'), fullPage: true });
  await operator.locator('#operator-logout').click();
  const terminalContext = await browser.newContext(), terminalPage = await terminalContext.newPage();
  await terminalPage.goto(base + '/operator.html'); await terminalPage.locator('#operator-access [name="role"]').selectOption('terminal');
  await terminalPage.locator('#operator-access [name="token"]').fill(credentials.terminal.token);
  await terminalPage.locator('#operator-access button').click(); await terminalPage.locator('#operator-workspace').waitFor({ state: 'visible' });
  assert.equal(await terminalPage.locator('[data-operator-tab="members"]').isVisible(), false);
  assert.equal(await terminalPage.locator('#operator-contribution').isVisible(), false);
  await terminalContext.close(); await memberContext.close();
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.cspErrors), []);
  console.log('UI flow passed: points, grants, versions, independent operator, multi-member isolation, credential issuance, lost-device recovery, export and 320px layouts.');
  console.log(`Screenshots: ${artifacts}`);
} finally {
  if (browser) await browser.close();
  server.closeIdleConnections(); await new Promise(resolve => server.close(resolve));
  db.close(); rmSync(directory, { recursive: true, force: true });
}
