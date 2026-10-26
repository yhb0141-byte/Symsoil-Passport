import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createPublicKey, verify } from 'node:crypto';
import { readFileSync, mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { encodeTrustFrame, createTrustBundle, verifyTrustBundle, keyFingerprint } from '../scripts/trust-config.mjs';
const fixture = JSON.parse(readFileSync(new URL('../firmware/protocol-vectors/trust-v1.json', import.meta.url), 'utf8'));
const pair = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { private: privateKey.export({ format: 'jwk' }), public: publicKey.export({ format: 'jwk' }) };
};

test('public trust fixtures bind exact frame bytes, authority, epoch, state and current service', () => {
  assert.equal(fixture.synthetic, true);
  assert.doesNotMatch(JSON.stringify(fixture), /"d"\s*:/);
  for (const bundle of fixture.bundles) {
    const result = verifyTrustBundle(bundle, fixture.authorityPublicKey);
    assert.equal(result.epoch, bundle.epoch);
    assert.equal(encodeTrustFrame(bundle).length, 88 + bundle.communityId.length);
    for (const field of ['communityId', 'epoch', 'state']) {
      const modified = structuredClone(bundle);
      modified[field] = field === 'communityId' ? 'other-community' : field === 'epoch' ? bundle.epoch + 1 : 'unknown';
      assert.throws(() => verifyTrustBundle(modified, fixture.authorityPublicKey));
    }
    const signature = Buffer.from(bundle.signature, 'base64url');
    signature[0] ^= 1;
    assert.throws(() => verifyTrustBundle({ ...bundle, signature: signature.toString('base64url') }, fixture.authorityPublicKey));
    assert.throws(() => verifyTrustBundle(bundle, pair().public), /pinned/);
  }
  const resultBytes = Buffer.from(fixture.result.canonicalFrame);
  const old = fixture.bundles[0].servicePublicKey;
  const current = fixture.bundles[1].servicePublicKey;
  const checks = (key, signature) => verify('sha256', resultBytes, { key: createPublicKey({ key, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url'));
  assert.equal(checks(old, fixture.result.oldSignature), true);
  assert.equal(checks(current, fixture.result.oldSignature), false);
  assert.equal(checks(current, fixture.result.currentSignature), true);
});

test('trust encoder rejects ambiguous wire values and private or invalid service points', () => {
  const base = fixture.bundles[0];
  for (const communityId of ['', 'a'.repeat(65), '九华', 'with space', 'name\0suffix', 'a.b']) assert.throws(() => encodeTrustFrame({ ...base, communityId }));
  assert.doesNotThrow(() => encodeTrustFrame({ ...base, communityId: 'village:01_A-b' }));
  for (const epoch of [0, -1, 1.2, 0x100000000, NaN, '1']) assert.throws(() => encodeTrustFrame({ ...base, epoch }));
  assert.equal(encodeTrustFrame({ ...base, epoch: 0xffffffff }).readUInt32LE(20), 0xffffffff);
  assert.throws(() => encodeTrustFrame({ ...base, state: 'suspended' }));
  assert.throws(() => encodeTrustFrame({ ...base, servicePublicKey: pair().private }));
  assert.throws(() => encodeTrustFrame({ ...base, servicePublicKey: { kty: 'EC', crv: 'P-256', x: Buffer.alloc(32).toString('base64url'), y: Buffer.alloc(32).toString('base64url') } }));
  assert.throws(() => verifyTrustBundle({ ...base, signature: `${base.signature}=` }, fixture.authorityPublicKey));
});

test('offline signing separates recovery authority from service key and never exports a private key', () => {
  const authority = pair();
  const service = pair();
  const manifest = { communityId: 'test-community', epoch: 1, state: 'active', servicePublicKey: service.public };
  const bundle = createTrustBundle(manifest, authority.private);
  assert.equal(verifyTrustBundle(bundle, authority.public).authorityFingerprint, keyFingerprint(authority.public));
  assert.doesNotMatch(JSON.stringify(bundle), /"d"\s*:/);
  assert.throws(() => createTrustBundle({ ...manifest, servicePublicKey: authority.public }, authority.private), /separate/);
});

test('signing CLI creates a public bundle once; inspection requires a separately supplied authority', () => {
  const directory = mkdtempSync(join(tmpdir(), 'passport-trust-'));
  try {
    const authority = pair();
    const service = pair();
    const privatePath = join(directory, 'authority-private.json');
    const publicPath = join(directory, 'authority-public.json');
    const manifestPath = join(directory, 'manifest.json');
    const outputPath = join(directory, 'bundle.json');
    writeFileSync(privatePath, JSON.stringify(authority.private), { mode: 0o600 });
    writeFileSync(publicPath, JSON.stringify(authority.public));
    writeFileSync(manifestPath, JSON.stringify({ communityId: 'test-community', epoch: 7, state: 'active', servicePublicKey: service.public }));
    const command = new URL('../scripts/trust-config.mjs', import.meta.url);
    const run = args => spawnSync(process.execPath, [command.pathname, ...args], { encoding: 'utf8' });
    const args = ['sign', '--manifest', manifestPath, '--authority-private', privatePath, '--out', outputPath];
    assert.equal(run(args).status, 0);
    const saved = readFileSync(outputPath, 'utf8');
    assert.doesNotMatch(saved, /"d"\s*:/);
    assert.notEqual(run(args).status, 0);
    assert.equal(readFileSync(outputPath, 'utf8'), saved);
    assert.equal(run(['inspect', '--bundle', outputPath, '--authority-public', publicPath]).status, 0);
    assert.notEqual(run(['inspect', '--bundle', outputPath]).status, 0);
    assert.equal(existsSync(privatePath), true);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
