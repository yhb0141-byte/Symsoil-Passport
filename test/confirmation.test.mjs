import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { canonical, confirmationFrame } from '../public/protocol.mjs';
import { DEMO_MEMBER } from '../src/service.mjs';
import { fixture, fails } from './helpers.mjs';

test('a modified signature and a signature transplanted to another request fail', t => {
  const f = fixture(); t.after(f.close); const req = f.credit(), input = f.response(req);
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, { ...input, signature: 'A'.repeat(86) }), fails('BAD_SIGNATURE'));
  const other = f.credit(20, 'CT-002'); assert.throws(() => f.service.respond(DEMO_MEMBER, other.id, input), fails('BAD_SIGNATURE'));
  assert.equal(f.service.snapshot(DEMO_MEMBER).receipts.length, 0);
});
test('the member binding, device key and explicit decision cannot be substituted', t => {
  const f = fixture(); t.after(f.close); const req = f.credit(), input = f.response(req);
  assert.throws(() => f.service.respond('M-018', req.id, input), fails('REQUEST_NOT_FOUND'));
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, { ...input, decision: 'decline' }), fails('BAD_SIGNATURE'));
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, { ...input, deviceId: 'other' }), fails('DEVICE_INACTIVE'));
});
test('stale versions fail and historical receipts remain visible after a revision', t => {
  const f = fixture(); t.after(f.close); const payload = { original: '只能留到中午', retelling: '参与上午的菜园维护' };
  const req = f.statement('expression', payload), input = f.response(req, 'original_only');
  const newVersion = f.service.revise('admin', req.id, { ...payload, retelling: '参与下午的菜园维护' });
  assert.equal(newVersion.version, 2); assert.notEqual(newVersion.digest, req.digest);
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, input), fails('STALE_VERSION'));
  f.service.respond(DEMO_MEMBER, newVersion.id, f.response(newVersion, 'no_retelling'));
  f.service.revise('admin', newVersion.id, payload);
  const history = f.service.snapshot(DEMO_MEMBER).receipts[0]; assert.equal(history.decision, 'no_retelling'); assert.ok(history.superseded_by);
});
test('expired requests cannot debit, and renewed challenge supersedes the old one', t => {
  const f = fixture(); t.after(f.close); const req = f.order(), input = f.response(req); f.advance(120001);
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, input), fails('REQUEST_EXPIRED'));
  const refreshed = f.scan('order', { id: 'EX-001' }); assert.notEqual(refreshed.nonce, req.nonce); assert.equal(refreshed.version, 2);
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, input), fails('STALE_VERSION'));
});
test('a counter can retry its exact accepted receipt but cannot authorize a new action', t => {
  const f = fixture(); t.after(f.close); const req = f.credit(), input = f.response(req);
  f.service.respond(DEMO_MEMBER, req.id, input);
  const other = f.order(); assert.throws(() => f.service.respond(DEMO_MEMBER, other.id, f.response(other, 'spend', { counter: input.counter })), fails('REPLAY'));
});
test('a changed response to an already answered request is rejected', t => {
  const f = fixture(); t.after(f.close); const req = f.credit(); f.service.respond(DEMO_MEMBER, req.id, f.response(req));
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, f.response(req, 'decline')), fails('ALREADY_RESPONDED'));
});
test('device enrollment cannot silently replace an existing key; revocation stops old keys and cards', t => {
  const f = fixture(); t.after(f.close); const req = f.credit(), input = f.response(req), oldCard = f.service.ensureCard(DEMO_MEMBER).payload;
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  assert.throws(() => f.service.enroll(DEMO_MEMBER, other.publicKey.export({ format: 'jwk' })), fails('DEVICE_ALREADY_ENROLLED'));
  const replacement = f.service.revokeDevice('admin', DEMO_MEMBER); assert.notEqual(replacement.payload, oldCard);
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, input), fails('DEVICE_INACTIVE'));
  assert.throws(() => f.service.scan('terminal', { kind: 'contribution', sourceId: req.sourceId, cardPayload: oldCard }), fails('CARD_INACTIVE'));
  assert.ok(f.service.enroll(DEMO_MEMBER, other.publicKey.export({ format: 'jwk' })).active);
});
test('WebCrypto browser-style P-256 signatures are accepted without exporting a private key', async t => {
  const f = fixture(); t.after(f.close); f.service.revokeDevice('admin', DEMO_MEMBER);
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  assert.equal(pair.privateKey.extractable, false);
  const publicKey = await webcrypto.subtle.exportKey('jwk', pair.publicKey), device = f.service.enroll(DEMO_MEMBER, publicKey), req = f.credit();
  const frame = confirmationFrame(req, device.id, 'receive', 1);
  const signature = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(canonical(frame)))).toString('base64url');
  const value = f.service.respond(DEMO_MEMBER, req.id, { deviceId: device.id, decision: 'receive', counter: 1, signature }); assert.equal(value.balance, 130);
});
test('semantic refusals, modification requests and original-only permission are distinct records', t => {
  const f = fixture(); t.after(f.close);
  for (const decision of ['accurate', 'needs_change', 'original_only', 'no_retelling']) {
    const req = f.statement('expression', { original: '原话', retelling: '转述稿' });
    f.service.respond(DEMO_MEMBER, req.id, f.response(req, decision));
  }
  assert.deepEqual(new Set(f.service.snapshot(DEMO_MEMBER).receipts.map(r => r.decision)), new Set(['accurate', 'needs_change', 'original_only', 'no_retelling']));
  assert.equal(f.service.balance(DEMO_MEMBER), 100); assert.equal(f.service.snapshot(DEMO_MEMBER).grants.length, 0);
});
