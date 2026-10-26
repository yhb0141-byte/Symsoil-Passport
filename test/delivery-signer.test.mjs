import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonical } from '../public/protocol.mjs';
import { createTrustBundle } from '../scripts/trust-config.mjs';
import { DeliverySigner, loadDeliverySigner } from '../src/delivery-signer.mjs';
import { DEMO_MEMBER, PassportService } from '../src/service.mjs';
import { openDatabase } from '../src/database.mjs';
import { fixture } from './helpers.mjs';

function pair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { private: privateKey.export({ format: 'jwk' }), public: publicKey.export({ format: 'jwk' }) };
}

function configuration({ epoch = 1, state = 'active', communityId = 'jiuhua-symsoil' } = {}) {
  const authority = pair(), service = pair();
  const manifest = { communityId, epoch, state,
    servicePublicKey: state === 'active' ? service.public : null };
  const bundle = createTrustBundle(manifest, authority.private);
  return { authority, service, bundle, input: { privateJwk: service.private,
    trustBundle: bundle, authorityPublicJwk: authority.public, communityId } };
}

function acceptedReceipt(f, decision) {
  const request = f.credit();
  const input = f.response(request, decision);
  return f.service.respond(DEMO_MEMBER, request.id, input).receipt;
}

function verifies(value, publicJwk) {
  return verify('sha256', Buffer.from(canonical(value.frame)), {
    key: createPublicKey({ key: publicJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
  }, Buffer.from(value.signature, 'base64url'));
}

function files(directory, config) {
  const paths = { privateKeyPath: join(directory, 'service-private.json'),
    trustBundlePath: join(directory, 'trust.json'),
    authorityPublicKeyPath: join(directory, 'authority.json') };
  writeFileSync(paths.privateKeyPath, JSON.stringify(config.service.private), { mode: 0o600 });
  writeFileSync(paths.trustBundlePath, JSON.stringify(config.bundle));
  writeFileSync(paths.authorityPublicKeyPath, JSON.stringify(config.authority.public));
  return paths;
}

test('service signer binds a committed receipt and transfer to real raw64 signatures', () => {
  const f = fixture();
  try {
    const config = configuration({ epoch: 11 });
    const signer = new DeliverySigner(config.input);
    const receipt = acceptedReceipt(f);
    const original = JSON.stringify(receipt);
    const result = signer.signReceipt(receipt, 0xffffffff);
    assert.deepEqual(result.frame, { communityId: 'jiuhua-symsoil', outcome: 'accepted',
      protocol: 'symsoil-delivery-result/1', replySignature: receipt.signature,
      requestId: receipt.request_id, resultId: receipt.id, transferId: 0xffffffff });
    assert.equal(result.trustEpoch, 11);
    assert.equal(Buffer.from(result.signature, 'base64url').length, 64);
    assert.equal(result.signature.length, 86);
    assert.equal(verifies(result, config.service.public), true);
    assert.equal(verifies(result, config.authority.public), false);
    assert.equal(verifies({ ...result, frame: { ...result.frame, transferId: 1 } }, config.service.public), false);
    assert.equal(verifies({ ...result, frame: { ...result.frame, replySignature: 'A'.repeat(86) } }, config.service.public), false);
    assert.equal(JSON.stringify(receipt), original);
    const retried = signer.signReceipt(receipt, 0xffffffff);
    assert.deepEqual(retried.frame, result.frame); // ECDSA signatures may differ.
    assert.equal(verifies(retried, config.service.public), true);
    assert.equal(signer.communityId, 'jiuhua-symsoil');
    assert.equal(signer.trustEpoch, 11);
    assert.equal(JSON.stringify(signer), '{}');
  } finally { f.close(); }
});

test('recorded decline gets delivery acceptance without becoming an affirmative decision', () => {
  const f = fixture();
  try {
    const config = configuration();
    const receipt = acceptedReceipt(f, 'decline');
    assert.equal(f.service.balance(DEMO_MEMBER), 100);
    assert.equal(receipt.decision, 'decline');
    const result = new DeliverySigner(config.input).signReceipt(receipt, 7);
    assert.equal(result.frame.outcome, 'accepted');
    assert.equal(result.frame.replySignature, receipt.signature);
    assert.equal(JSON.parse(receipt.frame).decision, 'decline');
    assert.equal(verifies(result, config.service.public), true);
  } finally { f.close(); }
});

test('configuration rejects wrong, mixed or suspended keys and signed-bundle tampering', () => {
  const config = configuration();
  const alternatives = [
    { ...config.input, privateJwk: pair().private },
    { ...config.input, privateJwk: config.service.public },
    { ...config.input, privateJwk: { ...config.service.private, d: `${config.service.private.d}=` } },
    { ...config.input, privateJwk: { ...config.service.private, d: pair().private.d } },
    { ...config.input, authorityPublicJwk: pair().public },
    { ...config.input, authorityPublicJwk: config.authority.private },
    { ...config.input, communityId: 'another-community' },
    { ...config.input, trustBundle: { ...config.bundle, epoch: 2 } },
    { ...config.input, trustBundle: { ...config.bundle, signature: 'A'.repeat(86) } },
    { ...config.input, trustBundle: { ...config.bundle, servicePublicKey: pair().public } },
    configuration({ state: 'suspended' }).input,
  ];
  for (const input of alternatives) assert.throws(() => new DeliverySigner(input), /Invalid delivery signing configuration/);
  // Build the invalid mixed-key bundle manually: signing tool itself rejects it.
  const rootAsService = { ...config.bundle, servicePublicKey: config.authority.public };
  assert.throws(() => new DeliverySigner({ ...config.input, privateJwk: config.authority.private,
    trustBundle: rootAsService }), /Invalid delivery signing configuration/);
  assert.throws(() => new DeliverySigner(), /Invalid delivery signing configuration/);
});

test('signer configuration is an immutable snapshot and reload is required for rotation', () => {
  const f = fixture();
  try {
    const config = configuration();
    const signer = new DeliverySigner(config.input);
    const receipt = acceptedReceipt(f);
    const expectedPublic = structuredClone(config.service.public);
    config.bundle.epoch = 200;
    config.bundle.state = 'suspended';
    config.input.privateJwk.d = pair().private.d;
    config.authority.public.x = pair().public.x;
    assert.equal(signer.trustEpoch, 1);
    assert.equal(verifies(signer.signReceipt(receipt, 2), expectedPublic), true);
    assert.throws(() => { signer.trustEpoch = 8; }, TypeError);
  } finally { f.close(); }
});

test('malformed or mismatched receipt bindings cannot be signed', () => {
  const f = fixture();
  try {
    const signer = new DeliverySigner(configuration().input);
    const receipt = acceptedReceipt(f);
    const frame = JSON.parse(receipt.frame);
    const tamperedFrames = [
      { ...frame, communityId: 'other-community' }, { ...frame, requestId: 'other-request' },
      { ...frame, memberId: 'M-018' }, { ...frame, deviceId: 'D-another' },
      { ...frame, protocol: 'other-protocol' }, { ...frame, decision: 'approve' },
      { ...frame, requestDigest: 'g'.repeat(64) }, { ...frame, requestDigest: [frame.requestDigest] },
      { ...frame, counter: 0 }, { ...frame, counter: 1.5 }, { ...frame, counter: Number.MAX_SAFE_INTEGER + 1 },
      { ...frame, requestVersion: 0 }, { ...frame, expiresAt: -1 },
      { ...frame, nonce: 'not-a-nonce' }, { ...frame, extra: 'unsigned-field' },
    ];
    for (const modified of tamperedFrames) {
      assert.throws(() => signer.signReceipt({ ...receipt, frame: canonical(modified) }, 1));
    }
    for (const modified of [
      null, {}, { ...receipt, id: '' }, { ...receipt, device_id: '' },
      { ...receipt, frame: '{' }, { ...receipt, frame: JSON.stringify(frame, null, 2) },
      { ...receipt, frame: ` ${receipt.frame}` }, { ...receipt, frame: ' '.repeat(769) },
      { ...receipt, signature: `${receipt.signature}=` }, { ...receipt, signature: 'A'.repeat(85) },
      { ...receipt, signature: receipt.signature.slice(0, -1) + 'B' },
      { ...receipt, decision: 'approve' },
    ]) assert.throws(() => signer.signReceipt(modified, 1));
    for (const transfer of [0, -1, 1.5, 0x100000000, NaN, Infinity, '1', null]) {
      assert.throws(() => signer.signReceipt(receipt, transfer), /uint32/);
    }
    const longCommunity = 'a'.repeat(64);
    const longSigner = new DeliverySigner(configuration({ communityId: longCommunity }).input);
    assert.throws(() => longSigner.signReceipt({ ...receipt, id: 'r'.repeat(128),
      request_id: 'q'.repeat(128), frame: canonical({ ...frame, communityId: longCommunity,
        requestId: 'q'.repeat(128) }) }, 0xffffffff), /device frame limit/);
  } finally { f.close(); }
});

test('receipt from a real database reopen can be signed again without changing business records', () => {
  const directory = mkdtempSync(join(tmpdir(), 'passport-delivery-receipt-'));
  const path = join(directory, 'passport.sqlite');
  let f, reopenedDb;
  try {
    const config = configuration();
    f = fixture({ path });
    const receipt = acceptedReceipt(f);
    const result = new DeliverySigner(config.input).signReceipt(receipt, 13);
    const balance = f.service.balance(DEMO_MEMBER);
    f.close();
    f = undefined;
    reopenedDb = openDatabase(path);
    const service = new PassportService(reopenedDb);
    const reopened = service.one('SELECT * FROM receipts WHERE id=?', receipt.id);
    const retried = new DeliverySigner(config.input).signReceipt(reopened, 13);
    assert.deepEqual(result.frame, retried.frame);
    assert.equal(verifies(retried, config.service.public), true);
    assert.equal(service.balance(DEMO_MEMBER), balance);
    assert.equal(service.one('SELECT COUNT(*) AS count FROM receipts').count, 1);
  } finally { if (f) f.close(); if (reopenedDb) reopenedDb.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('optional loader requires a complete bounded configuration and protects private files', () => {
  const directory = mkdtempSync(join(tmpdir(), 'passport-delivery-loader-'));
  try {
    assert.equal(loadDeliverySigner(), null);
    assert.equal(loadDeliverySigner({ privateKeyPath: '' }), null);
    assert.throws(() => loadDeliverySigner({ privateKeyPath: 'one-file' }), /requires/);
    const config = configuration();
    const paths = files(directory, config);
    assert.equal(loadDeliverySigner(paths).trustEpoch, 1);
    const original = readFileSync(paths.privateKeyPath, 'utf8');
    for (const contents of ['', '{', ' '.repeat(65537)]) {
      writeFileSync(paths.privateKeyPath, contents);
      assert.throws(() => loadDeliverySigner(paths), /Unable to load/);
    }
    writeFileSync(paths.privateKeyPath, original);
    const linkPath = join(directory, 'key-link.json');
    symlinkSync(paths.privateKeyPath, linkPath);
    assert.throws(() => loadDeliverySigner({ ...paths, privateKeyPath: linkPath }), /Unable to load/);
    const subdirectory = join(directory, 'key-directory');
    mkdirSync(subdirectory);
    assert.throws(() => loadDeliverySigner({ ...paths, privateKeyPath: subdirectory }), /Unable to load/);
    if (process.platform !== 'win32') {
      for (const mode of [0o640, 0o604, 0o644, 0o660]) {
        chmodSync(paths.privateKeyPath, mode);
        assert.throws(() => loadDeliverySigner(paths), /Unable to load/);
      }
      chmodSync(paths.privateKeyPath, 0o600);
    }
    assert.equal(loadDeliverySigner(paths).communityId, 'jiuhua-symsoil');
    writeFileSync(paths.authorityPublicKeyPath, JSON.stringify(pair().public));
    assert.throws(() => loadDeliverySigner(paths), /Unable to load/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('loader restart adopts a newly root-signed service key and never rewrites secret files', () => {
  const directory = mkdtempSync(join(tmpdir(), 'passport-delivery-reload-'));
  const f = fixture();
  try {
    const config = configuration();
    const paths = files(directory, config);
    const oldSigner = loadDeliverySigner(paths);
    const receipt = acceptedReceipt(f);
    const replacement = pair();
    const bundle = createTrustBundle({ communityId: 'jiuhua-symsoil', epoch: 2,
      state: 'active', servicePublicKey: replacement.public }, config.authority.private);
    writeFileSync(paths.privateKeyPath, JSON.stringify(replacement.private));
    writeFileSync(paths.trustBundlePath, JSON.stringify(bundle));
    const before = readFileSync(paths.privateKeyPath, 'utf8');
    const nextSigner = loadDeliverySigner(paths);
    assert.equal(nextSigner.trustEpoch, 2);
    assert.equal(verifies(nextSigner.signReceipt(receipt, 99), replacement.public), true);
    assert.equal(verifies(oldSigner.signReceipt(receipt, 99), config.service.public), true);
    assert.equal(verifies(nextSigner.signReceipt(receipt, 99), config.service.public), false);
    assert.equal(readFileSync(paths.privateKeyPath, 'utf8'), before);
  } finally { f.close(); rmSync(directory, { recursive: true, force: true }); }
});
