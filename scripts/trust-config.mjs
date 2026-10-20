import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

export const TRUST_PROTOCOL = 'symsoil-trust/1';
const DOMAIN = Buffer.from(`${TRUST_PROTOCOL}\0`, 'ascii');

function bytes(value, length, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`Invalid ${label}`);
  const result = Buffer.from(value, 'base64url');
  if (result.length !== length || result.toString('base64url') !== value) throw new Error(`Invalid ${label}`);
  return result;
}

export function publicP256(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || 'd' in jwk) throw new Error('Expected a public-only P-256 JWK');
  bytes(jwk.x, 32, 'public x');
  bytes(jwk.y, 32, 'public y');
  const result = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  createPublicKey({ key: result, format: 'jwk' }); // Reject points off the curve.
  return result;
}

export function keyFingerprint(jwk) {
  const key = publicP256(jwk);
  return createHash('sha256').update(Buffer.concat([Buffer.from([4]), bytes(key.x, 32, 'x'), bytes(key.y, 32, 'y')])).digest('hex');
}

export function encodeTrustFrame(manifest) {
  if (!manifest || typeof manifest.communityId !== 'string' || !/^[A-Za-z0-9:_-]{1,64}$/.test(manifest.communityId)) throw new Error('Invalid community ID');
  if (!Number.isInteger(manifest.epoch) || manifest.epoch < 1 || manifest.epoch > 0xffffffff) throw new Error('Invalid trust epoch');
  if (!['active', 'suspended'].includes(manifest.state)) throw new Error('Invalid trust state');
  if (manifest.state === 'suspended' && manifest.servicePublicKey !== null) throw new Error('Suspended state requires a null service key');
  const community = Buffer.from(manifest.communityId, 'ascii');
  const frame = Buffer.alloc(88 + community.length);
  DOMAIN.copy(frame);
  frame[16] = manifest.state === 'active' ? 1 : 2;
  frame[17] = community.length;
  frame.writeUInt32LE(manifest.epoch, 20);
  community.copy(frame, 24);
  if (manifest.state === 'active') {
    const key = publicP256(manifest.servicePublicKey);
    bytes(key.x, 32, 'x').copy(frame, 24 + community.length);
    bytes(key.y, 32, 'y').copy(frame, 56 + community.length);
  }
  return frame;
}

export function createTrustBundle(manifest, authorityPrivateJwk) {
  const privateKey = createPrivateKey({ key: authorityPrivateJwk, format: 'jwk' });
  const authorityPublicKey = publicP256(createPublicKey(privateKey).export({ format: 'jwk' }));
  const frame = encodeTrustFrame(manifest);
  const servicePublicKey = manifest.state === 'active' ? publicP256(manifest.servicePublicKey) : null;
  if (servicePublicKey && keyFingerprint(authorityPublicKey) === keyFingerprint(servicePublicKey)) throw new Error('Authority and service keys must be separate');
  return {
    protocol: TRUST_PROTOCOL,
    communityId: manifest.communityId,
    epoch: manifest.epoch,
    state: manifest.state,
    servicePublicKey,
    authorityPublicKey,
    frameHex: frame.toString('hex'),
    signature: sign('sha256', frame, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url'),
  };
}

// The expected authority is supplied separately; a bundle cannot declare its
// own signer trusted. Epoch acceptance/persistence belongs to the device.
export function verifyTrustBundle(bundle, expectedAuthorityPublicJwk) {
  const authority = publicP256(expectedAuthorityPublicJwk);
  if (!bundle || bundle.protocol !== TRUST_PROTOCOL) throw new Error('Invalid trust protocol');
  if (keyFingerprint(bundle.authorityPublicKey) !== keyFingerprint(authority)) throw new Error('Authority does not match the pinned key');
  if (bundle.servicePublicKey && keyFingerprint(bundle.servicePublicKey) === keyFingerprint(authority)) throw new Error('Authority and service keys must be separate');
  const frame = encodeTrustFrame(bundle);
  if (bundle.frameHex !== frame.toString('hex')) throw new Error('Trust frame mismatch');
  if (!verify('sha256', frame, { key: createPublicKey({ key: authority, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, bytes(bundle.signature, 64, 'signature'))) throw new Error('Untrusted signature');
  return { communityId: bundle.communityId, epoch: bundle.epoch, state: bundle.state,
    authorityFingerprint: keyFingerprint(authority),
    serviceFingerprint: bundle.servicePublicKey ? keyFingerprint(bundle.servicePublicKey) : null,
    frameLength: frame.length };
}

function main() {
  const [command, ...args] = process.argv.slice(2);
  const { values } = parseArgs({ args, options: {
    manifest: { type: 'string' }, 'authority-private': { type: 'string' },
    'authority-public': { type: 'string' }, bundle: { type: 'string' }, out: { type: 'string' },
  } });
  const read = path => JSON.parse(readFileSync(path, 'utf8'));
  if (command === 'sign' && values.manifest && values['authority-private'] && values.out) {
    const bundle = createTrustBundle(read(values.manifest), read(values['authority-private']));
    writeFileSync(values.out, `${JSON.stringify(bundle, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    console.log('Signed public bundle written. No device configuration has been changed.');
  } else if (command === 'inspect' && values.bundle && values['authority-public']) {
    console.log(JSON.stringify(verifyTrustBundle(read(values.bundle), read(values['authority-public'])), null, 2));
  } else {
    throw new Error('Usage: trust-config.mjs sign --manifest FILE --authority-private FILE --out NEW_FILE | inspect --bundle FILE --authority-public PINNED_JWK');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(); } catch (error) { console.error(`Trust configuration failed: ${error.message}`); process.exitCode = 1; }
}
