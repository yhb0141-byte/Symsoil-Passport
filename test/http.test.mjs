import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { request as httpRequest } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { createApp } from '../src/http.mjs';
import { createCredentials } from '../src/auth.mjs';
import { fixture } from './helpers.mjs';

async function app(t, options = {}) {
  const f = fixture(), credentials = createCredentials();
  const server = createApp({ service: f.service, credentials, publicDir: resolve(import.meta.dirname, '../public'), ...options });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { server.closeIdleConnections(); await new Promise(resolve => server.close(resolve)); f.close(); });
  async function request(path, { role = 'member', method = 'GET', body, headers = {} } = {}) {
    const response = await fetch(base + path, { method, headers: { ...(role ? { Authorization: 'Bearer ' + credentials[role].token } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { response, body: await response.json() };
  }
  return { ...f, credentials, base, request, server };
}

test('member, terminal and agent identities cannot issue community points', async t => {
  const a = await app(t);
  for (const role of ['member', 'terminal', 'agent']) {
    const { response, body } = await a.request('/api/contributions', { role, method: 'POST', body: { memberId: 'M-017', title: '维护', points: 30 } });
    assert.equal(response.status, 403); assert.equal(body.error.code, 'FORBIDDEN');
  }
  const approved = await a.request('/api/contributions', { role: 'admin', method: 'POST', body: { memberId: 'M-017', title: '维护', points: 30 } });
  assert.equal(approved.response.status, 200); assert.equal(a.service.balance('M-017'), 100);
});
test('anonymous users cannot access balances, public keys, records or enrollment', async t => {
  const a = await app(t);
  for (const path of ['/api/me', '/api/me/export', '/api/admin']) assert.equal((await a.request(path, { role: null })).response.status, 401);
  assert.equal((await a.request('/api/devices', { role: 'terminal', method: 'POST', body: {} })).response.status, 403);
  assert.equal((await a.request('/api/admin', { role: 'member' })).response.status, 403);
});
test('the production entry does not expose demo tokens; demo entry is explicit and local', async t => {
  const normal = await app(t), demo = await app(t, { demo: true });
  assert.equal((await normal.request('/api/demo/session', { role: null, method: 'POST', body: {} })).response.status, 403);
  const reply = await demo.request('/api/demo/session', { role: null, method: 'POST', body: {} });
  assert.equal(reply.response.status, 200); assert.equal(reply.body.member, demo.credentials.member.token);
});
test('cross-origin requests, unexpected Host and form posts are rejected', async t => {
  const a = await app(t, { demo: true });
  const cross = await a.request('/api/demo/session', { role: null, method: 'POST', body: {}, headers: { Origin: 'https://other.example' } });
  assert.equal(cross.response.status, 403);
  const hostStatus = await new Promise((resolve, reject) => {
    const req = httpRequest(a.base + '/api/config', { headers: { Host: 'attacker.example' } }, response => { response.resume(); response.on('end', () => resolve(response.statusCode)); });
    req.on('error', reject); req.end();
  });
  assert.equal(hostStatus, 403);
  const form = await fetch(a.base + '/api/demo/session', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'x=1' }); assert.equal(form.status, 415);
  const preflight = await a.request('/api/demo/session', { role: null, method: 'OPTIONS' }); assert.equal(preflight.response.status, 404);
});
test('terminal NFC response reveals no balance or private history and does not itself debit', async t => {
  const a = await app(t);
  const order = await a.request('/api/orders', { role: 'terminal', method: 'POST', body: { id: 'HTTP-ORDER', itemId: 'harvest' } });
  assert.equal(order.response.status, 200);
  const value = await a.request('/api/nfc/scan', { role: 'terminal', method: 'POST', body: { kind: 'order', sourceId: order.body.id, cardPayload: a.service.ensureCard('M-017').payload } });
  assert.deepEqual(Object.keys(value.body), ['requestId']); assert.equal(a.service.balance('M-017'), 100);
  const req = a.service.request('M-017', value.body.requestId);
  const responded = await a.request('/api/requests/' + req.id + '/respond', { method: 'POST', body: a.response(req) });
  assert.equal(responded.body.balance, 80); assert.equal(responded.response.status, 200);
  const terminal = await a.request('/api/terminal', { role: 'terminal' });
  assert.deepEqual(Object.keys(terminal.body), ['catalog', 'orders']);
  assert.equal(terminal.body.orders[0].paid, 1);
  assert.equal(terminal.body.orders[0].refunded, 0);
  assert.equal(terminal.body.orders[0].balance, undefined);
  assert.equal((await a.request('/api/terminal', { role: 'member' })).response.status, 403);
  assert.equal((await a.request('/api/terminal', { role: 'admin' })).body.orders.length, 0);
  assert.equal((await a.request('/api/orders/' + order.body.id + '/fulfill', { role: 'terminal', method: 'POST', body: {} })).response.status, 200);
});
test('a second member cannot read the first member request or export', async t => {
  const a = await app(t), req = a.credit();
  const issued = await a.request('/api/credentials', { role: 'admin', method: 'POST', body: { role: 'member', subject: 'M-018' } });
  a.credentials.member.token = issued.body.token;
  assert.equal((await a.request('/api/requests/' + req.id)).response.status, 404);
  const own = await a.request('/api/me/export'); assert.equal(own.body.memberId, 'M-018'); assert.equal(own.body.receipts.length, 0);
});
test('oversized requests are rejected and secret runtime files are never served', async t => {
  const a = await app(t);
  const tooLarge = await a.request('/api/contributions', { role: 'admin', method: 'POST', body: { title: 'x'.repeat(70000) } }); assert.equal(tooLarge.response.status, 413);
  const privatePath = await fetch(a.base + '/data/access.json'); assert.equal(privatePath.status, 404);
  const encodedTraversal = await fetch(a.base + '/%2e%2e%2fpackage.json'); assert.equal(encodedTraversal.status, 404);
  const page = await fetch(a.base + '/'); assert.equal(page.status, 200);
  assert.ok(page.headers.get('content-security-policy').includes("script-src 'self'"));
  assert.equal(page.headers.get('cache-control'), 'no-store');
});
test('member creation and credential issuance are admin-only and reveal no stored secrets', async t => {
  const a = await app(t);
  for (const role of ['member', 'terminal', 'agent']) {
    assert.equal((await a.request('/api/members', { role, method: 'POST', body: { id: 'M-HTTP', name: '新伙伴' } })).response.status, 403);
    assert.equal((await a.request('/api/credentials', { role, method: 'POST', body: { role: 'member', subject: 'M-018' } })).response.status, 403);
    assert.equal((await a.request('/api/credentials', { role })).response.status, 403);
  }
  const created = await a.request('/api/members', { role: 'admin', method: 'POST', body: { id: 'M-HTTP', name: '新伙伴' } });
  assert.equal(created.response.status, 200); assert.equal(a.service.balance(created.body.id), 0);
  const issued = await a.request('/api/credentials', { role: 'admin', method: 'POST', body: { role: 'member', subject: created.body.id, ttlHours: 1 } });
  assert.equal(issued.response.status, 200); assert.match(issued.body.token, /^[A-Za-z0-9_-]{43}$/);
  const list = await a.request('/api/credentials', { role: 'admin' });
  assert.equal(JSON.stringify(list.body).includes(issued.body.token), false);
  assert.equal(list.body.credentials.some(c => c.token_hash), false);
  const own = await a.request('/api/me', { role: null, headers: { Authorization: 'Bearer ' + issued.body.token } });
  assert.equal(own.body.member.id, created.body.id); assert.equal(own.body.balance, 0); assert.equal(own.body.receipts.length, 0);
  await a.request('/api/credentials/' + issued.body.credential.id + '/revoke', { role: 'admin', method: 'POST', body: {} });
  assert.equal((await a.request('/api/me', { role: null, headers: { Authorization: 'Bearer ' + issued.body.token } })).response.status, 401);
});
test('a credential revoked while an enrollment body arrives cannot enroll a new device', async t => {
  const a = await app(t);
  const arrived = new Promise(resolve => a.server.once('request', resolve));
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  let request;
  const finished = new Promise((resolve, reject) => {
    request = httpRequest(a.base + '/api/devices', { method: 'POST', headers: { Authorization: 'Bearer ' + a.credentials.member.token, 'Content-Type': 'application/json' } }, response => {
      const parts = []; response.on('data', chunk => parts.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(parts).toString()) }));
    });
    request.on('error', reject); request.write('{"publicKey":');
  });
  await arrived; a.service.revokeDevice('admin', 'M-017');
  request.end(JSON.stringify(pair.publicKey.export({ format: 'jwk' })) + '}');
  const response = await finished;
  assert.equal(response.status, 401); assert.equal(response.body.error.code, 'UNAUTHORIZED');
  assert.equal(a.service.snapshot('M-017').device, null);
});
test('HTTP authorization and nested transactions still roll back an insufficient exchange completely', async t => {
  const a = await app(t);
  const order = await a.request('/api/orders', { role: 'terminal', method: 'POST', body: { id: 'EXPENSIVE-HTTP', itemId: 'workshop' } });
  const scanned = await a.request('/api/nfc/scan', { role: 'terminal', method: 'POST', body: { kind: 'order', sourceId: order.body.id, cardPayload: a.service.ensureCard('M-017').payload } });
  const request = a.service.request('M-017', scanned.body.requestId), before = a.service.snapshot('M-017');
  const reply = await a.request('/api/requests/' + request.id + '/respond', { method: 'POST', body: a.response(request) });
  assert.equal(reply.response.status, 409); assert.equal(reply.body.error.code, 'INSUFFICIENT_POINTS');
  const after = a.service.snapshot('M-017');
  assert.equal(after.balance, before.balance); assert.equal(after.ledger.length, before.ledger.length);
  assert.equal(after.receipts.length, 0); assert.equal(after.device.counter, before.device.counter);
  assert.equal(after.catalog.find(item => item.id === 'workshop').stock, before.catalog.find(item => item.id === 'workshop').stock);
});
