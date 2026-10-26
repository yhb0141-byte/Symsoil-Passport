// Ephemeral, synthetic HTTP-to-firmware conformance material. Private keys and
// access tokens stay in this process and are never written into the header.
import { generateKeyPairSync } from 'node:crypto';
import { resolve } from 'node:path';
import { fixture } from '../test/helpers.mjs';
import { createCredentials } from '../src/auth.mjs';
import { createApp } from '../src/http.mjs';
import { DeliverySigner } from '../src/delivery-signer.mjs';
import { canonical } from '../public/protocol.mjs';
import { createTrustBundle, keyFingerprint } from './trust-config.mjs';

const f = fixture();
const authority = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const serviceKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const authorityPublicJwk = authority.publicKey.export({ format: 'jwk' });
const trustBundle = createTrustBundle({ communityId: 'jiuhua-symsoil', epoch: 1, state: 'active',
  servicePublicKey: serviceKey.publicKey.export({ format: 'jwk' }) }, authority.privateKey.export({ format: 'jwk' }));
const signer = new DeliverySigner({ privateJwk: serviceKey.privateKey.export({ format: 'jwk' }), trustBundle, authorityPublicJwk });
const credentials = createCredentials();
const server = createApp({ service: f.service, credentials, deliverySigner: signer,
  publicDir: resolve(import.meta.dirname, '../public') });
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = f.credit();
  const reply = f.response(request);
  async function post(path, body) {
    const response = await fetch(base + path, { method: 'POST', headers: {
      Authorization: `Bearer ${credentials.member.token}`, 'Content-Type': 'application/json',
    }, body: JSON.stringify(body) });
    if (!response.ok) throw new Error(`Synthetic conformance request failed: HTTP ${response.status}`);
    return response.json();
  }
  const accepted = await post(`/api/requests/${request.id}/respond`, reply);
  const result = await post(`/api/requests/${request.id}/delivery-result`, { signature: reply.signature, transferId: 42 });
  if (f.service.balance('M-017') !== 130 || result.frame.resultId !== accepted.receipt.id) throw new Error('Synthetic result binding failed');
  const array = (name, bytes) => `static const uint8_t ${name}[] = { ${[...bytes].map(b => `0x${b.toString(16).padStart(2, '0')}`).join(', ')} };`;
  const text = (name, value) => `static const char ${name}[] = ${JSON.stringify(value)};`;
  console.log('#pragma once\n#include <stdint.h>');
  for (const [prefix, key] of [['ROOT', authorityPublicJwk], ['SERVICE', trustBundle.servicePublicKey], ['MEMBER', f.pair.publicKey.export({ format: 'jwk' })]]) {
    console.log(array(`LIVE_${prefix}_X`, Buffer.from(key.x, 'base64url')));
    console.log(array(`LIVE_${prefix}_Y`, Buffer.from(key.y, 'base64url')));
  }
  console.log(array('LIVE_TRUST_SIGNATURE', Buffer.from(trustBundle.signature, 'base64url')));
  console.log(array('LIVE_MEMBER_SIGNATURE', Buffer.from(reply.signature, 'base64url')));
  console.log(array('LIVE_SERVICE_SIGNATURE', Buffer.from(result.signature, 'base64url')));
  console.log(text('LIVE_ROOT_FINGERPRINT', keyFingerprint(authorityPublicJwk)));
  console.log(text('LIVE_CONFIRMATION', accepted.receipt.frame));
  console.log(text('LIVE_RESULT_CANONICAL', canonical(result.frame)));
  console.log(text('LIVE_REPLY_SIGNATURE_TEXT', reply.signature));
  console.log(text('LIVE_REQUEST_ID', result.frame.requestId));
  console.log(text('LIVE_RESULT_ID', result.frame.resultId));
} finally {
  server.closeIdleConnections();
  if (server.listening) await new Promise(resolve => server.close(resolve));
  f.close();
}
