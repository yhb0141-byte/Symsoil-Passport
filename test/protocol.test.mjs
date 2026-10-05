import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonical, confirmationFrame } from '../public/protocol.mjs';
import { digest, verifyConfirmation } from '../src/crypto.mjs';

const document = JSON.parse(readFileSync(new URL('../firmware/protocol-vectors/confirmation-v1.json', import.meta.url), 'utf8'));
const deliveryDocument = JSON.parse(readFileSync(new URL('../firmware/protocol-vectors/delivery-result-v1.json', import.meta.url), 'utf8'));
test('fixed hardware conformance vectors bind UTF-8 content and P1363 signatures', () => {
  assert.equal(document.synthetic, true);
  for (const vector of document.vectors) {
    const request = vector.request;
    const content = { communityId: request.communityId, memberId: request.memberId, kind: request.kind, sourceId: request.sourceId, version: request.version, payload: request.payload };
    assert.equal(canonical(content), vector.canonicalContent); assert.equal(digest(content), request.digest);
    const frame = confirmationFrame(request, vector.deviceId, vector.decision, vector.counter);
    assert.equal(canonical(frame), vector.canonicalFrame); assert.equal(verifyConfirmation(vector.publicKey, frame, vector.signature), true);
    assert.equal(vector.publicKey.d, undefined);
  }
});
test('changed frame semantics and counters cannot reuse fixed signatures', () => {
  for (const vector of document.vectors) {
    const frame = confirmationFrame(vector.request, vector.deviceId, vector.decision, vector.counter);
    assert.equal(verifyConfirmation(vector.publicKey, { ...frame, counter: frame.counter + 1 }, vector.signature), false);
    assert.equal(verifyConfirmation(vector.publicKey, { ...frame, decision: 'decline' }, vector.signature), false);
  }
});
test('canonical JSON uses UTF-16 key order, UTF-8 values, escaped controls and lone surrogates', () => {
  for (const example of document.serializerCases) assert.equal(canonical(example.value), example.expected);
});
test('protocol rejects unsafe numbers and values absent from JSON', () => {
  for (const value of [1.5, NaN, Infinity, 9007199254740992, 1n, undefined, new Date(), [undefined], new Array(1), { missing: undefined }]) assert.throws(() => canonical(value), TypeError);
  assert.equal(canonical(-0), '0');
});
test('fixed delivery result vector binds the exact member reply to a public-only service key', () => {
  const vector = deliveryDocument.vector;
  assert.equal(deliveryDocument.synthetic, true);
  assert.equal(canonical(vector.frame), vector.canonicalFrame);
  assert.equal(verifyConfirmation(vector.publicKey, vector.frame, vector.signature), true);
  assert.equal(vector.publicKey.d, undefined);
});
test('delivery result signature rejects changed outcome, transfer or member reply', () => {
  const vector = deliveryDocument.vector;
  assert.equal(verifyConfirmation(vector.publicKey, { ...vector.frame, outcome: 'rejected' }, vector.signature), false);
  assert.equal(verifyConfirmation(vector.publicKey, { ...vector.frame, transferId: vector.frame.transferId + 1 }, vector.signature), false);
  assert.equal(verifyConfirmation(vector.publicKey, { ...vector.frame, replySignature: 'A'.repeat(86) }, vector.signature), false);
});
