import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, verify } from 'node:crypto';
import { resolve } from 'node:path';
import { request as httpRequest } from 'node:http';
import { createApp } from '../src/http.mjs';
import { createCredentials } from '../src/auth.mjs';
import { DeliverySigner } from '../src/delivery-signer.mjs';
import { createTrustBundle } from '../scripts/trust-config.mjs';
import { canonical } from '../public/protocol.mjs';
import { fixture } from './helpers.mjs';

async function app(t, enabled = true) {
  const f = fixture();
  const credentials = createCredentials();
  const authority = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const serviceKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const bundle = createTrustBundle({ communityId: 'jiuhua-symsoil', epoch: 1,
    state: 'active', servicePublicKey: serviceKey.publicKey.export({ format: 'jwk' }) }, authority.privateKey.export({ format: 'jwk' }));
  const deliverySigner = enabled ? new DeliverySigner({ privateJwk: serviceKey.privateKey.export({ format: 'jwk' }),
    trustBundle: bundle, authorityPublicJwk: authority.publicKey.export({ format: 'jwk' }) }) : null;
  const server = createApp({ service: f.service, credentials, deliverySigner, publicDir: resolve(import.meta.dirname, '../public') });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { server.closeIdleConnections(); await new Promise(resolve => server.close(resolve)); f.close(); });
  const request = async (path, { token = credentials.member.token, body, method = 'POST' } = {}) => {
    const response = await fetch(base + path, { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: response.status, data: await response.json() };
  };
  const check = value => verify('sha256', Buffer.from(canonical(value.frame)),
    { key: serviceKey.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(value.signature, 'base64url'));
  return { ...f, credentials, request, check, base, server };
}

test('delivery results sign only the persisted original receipt and never repeat its ledger mutation', async t => {
  const a = await app(t), req = a.credit(), reply = a.response(req);
  const accepted = a.service.respond('M-017', req.id, reply);
  const counterBefore = a.service.one('SELECT counter FROM devices WHERE id=?', reply.deviceId).counter;
  const eventsBefore = a.service.one('SELECT COUNT(*) AS n FROM events').n;
  const path = `/api/requests/${req.id}/delivery-result`;
  const first = await a.request(path, { body: { signature: reply.signature, transferId: 42 } });
  const retry = await a.request(path, { body: { signature: reply.signature, transferId: 42 } });
  assert.equal(first.status, 200);
  assert.deepEqual(retry.data.frame, first.data.frame);
  assert.equal(first.data.frame.resultId, accepted.receipt.id);
  assert.equal(first.data.frame.replySignature, reply.signature);
  assert.equal(first.data.frame.outcome, 'accepted');
  assert.equal(first.data.trustEpoch, 1);
  assert.equal(a.check(first.data), true);
  assert.equal(a.check(retry.data), true);
  assert.equal(a.service.balance('M-017'), 130);
  assert.equal(a.service.one('SELECT COUNT(*) AS n FROM ledger WHERE receipt_id=?', accepted.receipt.id).n, 1);
  assert.equal(a.service.one('SELECT counter FROM devices WHERE id=?', reply.deviceId).counter, counterBefore);
  assert.equal(a.service.one('SELECT COUNT(*) AS n FROM events').n, eventsBefore);
  assert.deepEqual(Object.keys(first.data).sort(), ['frame', 'signature', 'trustEpoch']);
  const alternativeTransfer = await a.request(path, { body: { signature: reply.signature, transferId: 43 } });
  assert.equal(alternativeTransfer.data.frame.resultId, accepted.receipt.id);
  assert.equal(alternativeTransfer.data.frame.transferId, 43);
  assert.equal(a.check(alternativeTransfer.data), true);
});

test('pending submissions, failed spending and changed signatures do not receive final signed rejections', async t => {
  const a = await app(t), req = a.order('workshop'), reply = a.response(req);
  const path = `/api/requests/${req.id}/delivery-result`;
  const pending = await a.request(path, { body: { signature: reply.signature, transferId: 42 } });
  assert.equal(pending.status, 409);
  assert.equal(pending.data.error.code, 'RESULT_NOT_RECORDED');
  assert.throws(() => a.service.respond('M-017', req.id, reply), { code: 'INSUFFICIENT_POINTS' });
  const failed = await a.request(path, { body: { signature: reply.signature, transferId: 42 } });
  assert.equal(failed.data.error.code, 'RESULT_NOT_RECORDED');
  assert.equal(failed.data.signature, undefined);
  assert.equal(a.service.balance('M-017'), 100);
  const credit = a.credit(), creditedReply = a.response(credit);
  a.service.respond('M-017', credit.id, creditedReply);
  const mismatched = await a.request(`/api/requests/${credit.id}/delivery-result`, { body: { signature: reply.signature, transferId: 42 } });
  assert.equal(mismatched.data.error.code, 'RECEIPT_MISMATCH');
  for (const transferId of [0, -1, 1.5, '42', 0x100000000]) {
    const invalid = await a.request(`/api/requests/${credit.id}/delivery-result`, { body: { signature: creditedReply.signature, transferId } });
    assert.equal(invalid.status, 400);
  }
});

test('result lookup enforces member isolation and signing remains explicitly disabled without configuration', async t => {
  const a = await app(t), req = a.credit(), reply = a.response(req);
  a.service.respond('M-017', req.id, reply);
  const path = `/api/requests/${req.id}/delivery-result`, body = { signature: reply.signature, transferId: 42 };
  assert.equal((await a.request(path, { token: null, body })).status, 401);
  for (const role of ['terminal', 'admin', 'agent']) assert.equal((await a.request(path, { token: a.credentials[role].token, body })).status, 403);
  const issued = await a.request('/api/credentials', { token: a.credentials.admin.token, body: { role: 'member', subject: 'M-018' } });
  assert.equal((await a.request(path, { token: issued.data.token, body })).status, 404);
  const disabled = await app(t, false);
  const unavailable = await disabled.request('/api/requests/unknown/delivery-result', { body });
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.data.error.code, 'DELIVERY_SIGNING_UNAVAILABLE');
  const config = await disabled.request('/api/config', { method: 'GET' });
  assert.equal(config.data.signedDeliveryResults.enabled, false);
});

test('accepted refusals and historical replies remain recorded facts, never fresh permission', async t => {
  const a = await app(t), req = a.statement('grant', { value: '周六上午：维护菜园' }), reply = a.response(req, 'decline');
  a.service.respond('M-017', req.id, reply);
  a.advance(2 * 86400000);
  a.service.revise('admin', req.id, { value: '周六下午：维护菜园' });
  const result = await a.request(`/api/requests/${req.id}/delivery-result`, { body: { signature: reply.signature, transferId: 42 } });
  assert.equal(result.status, 200);
  assert.equal(a.check(result.data), true);
  assert.equal(a.service.one('SELECT COUNT(*) AS n FROM grants').n, 0);
  assert.equal(a.service.balance('M-017'), 100);
  assert.equal(result.data.frame.outcome, 'accepted'); // Recorded reply was a decline.
});

test('credential revocation during upload blocks result signing; a new member session can recover historical proof', async t => {
  const a = await app(t), req = a.credit(), reply = a.response(req);
  a.service.respond('M-017', req.id, reply);
  const arrived = new Promise(resolve => a.server.once('request', resolve));
  let upload;
  const finished = new Promise((resolve, reject) => {
    upload = httpRequest(a.base + `/api/requests/${req.id}/delivery-result`, { method: 'POST', headers: {
      Authorization: `Bearer ${a.credentials.member.token}`, 'Content-Type': 'application/json',
    } }, response => {
      const parts = [];
      response.on('data', chunk => parts.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, data: JSON.parse(Buffer.concat(parts).toString()) }));
    });
    upload.on('error', reject);
    upload.write('{"signature":');
  });
  await arrived;
  a.service.revokeDevice('admin', 'M-017');
  upload.end(JSON.stringify(reply.signature) + ',"transferId":42}');
  const blocked = await finished;
  assert.equal(blocked.status, 401);
  assert.equal(blocked.data.signature, undefined);
  const issued = await a.request('/api/credentials', { token: a.credentials.admin.token,
    body: { role: 'member', subject: 'M-017' } });
  const recovered = await a.request(`/api/requests/${req.id}/delivery-result`, { token: issued.data.token,
    body: { signature: reply.signature, transferId: 42 } });
  assert.equal(recovered.status, 200);
  assert.equal(a.check(recovered.data), true);
  assert.equal(a.service.balance('M-017'), 130);
  assert.equal(a.service.snapshot('M-017').device, null);
});

test('damaged persisted receipt bindings are refused rather than endorsed by a fresh service signature', async t => {
  const a = await app(t), req = a.credit(), reply = a.response(req);
  a.service.respond('M-017', req.id, reply);
  // Fault injection only: normal service operations cannot edit receipts.
  a.db.exec('DROP TRIGGER receipts_no_update');
  a.db.prepare('UPDATE receipts SET decision=? WHERE request_id=?').run('approve', req.id);
  const result = await a.request(`/api/requests/${req.id}/delivery-result`, { body: { signature: reply.signature, transferId: 42 } });
  assert.equal(result.status, 409);
  assert.equal(result.data.error.code, 'RECEIPT_INVALID');
  assert.equal(result.data.signature, undefined);
  assert.equal(a.service.balance('M-017'), 130);
});
