import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { constants, openSync, closeSync, fstatSync, lstatSync, readSync } from 'node:fs';
import { canonical, DECISIONS, PROTOCOL } from '../public/protocol.mjs';
import { publicP256, verifyTrustBundle } from '../scripts/trust-config.mjs';

const FILE_LIMIT = 64 * 1024;
const CONFIRMATION_KEYS = ['communityId', 'counter', 'decision', 'deviceId', 'expiresAt',
  'memberId', 'nonce', 'protocol', 'requestDigest', 'requestId', 'requestVersion'].sort();
const ALL_DECISIONS = new Set(Object.values(DECISIONS).flat());
const DELIVERY_PROTOCOL = 'symsoil-delivery-result/1';

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function canonicalBytes(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length === length && decoded.toString('base64url') === value;
}

function identifier(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$/.test(value);
}

function validateReceipt(receipt, communityId) {
  requireValue(receipt && typeof receipt === 'object' &&
    ['id', 'request_id', 'member_id', 'device_id'].every(field => identifier(receipt[field])) &&
    typeof receipt.frame === 'string' && Buffer.byteLength(receipt.frame, 'utf8') <= 768 &&
    canonicalBytes(receipt.signature, 64), 'Invalid persisted delivery receipt');
  let frame;
  try { frame = JSON.parse(receipt.frame); }
  catch { throw new Error('Invalid persisted confirmation frame'); }
  requireValue(frame && !Array.isArray(frame) &&
    Object.keys(frame).sort().join(',') === CONFIRMATION_KEYS.join(',') &&
    frame.protocol === PROTOCOL && frame.communityId === communityId &&
    frame.requestId === receipt.request_id && frame.memberId === receipt.member_id &&
    frame.deviceId === receipt.device_id && frame.decision === receipt.decision &&
    ALL_DECISIONS.has(frame.decision) && typeof frame.requestDigest === 'string' &&
    /^[0-9a-f]{64}$/.test(frame.requestDigest) &&
    canonicalBytes(frame.nonce, 24) && Number.isSafeInteger(frame.counter) && frame.counter > 0 &&
    Number.isSafeInteger(frame.requestVersion) && frame.requestVersion > 0 &&
    Number.isSafeInteger(frame.expiresAt) && frame.expiresAt >= 0,
  'Persisted confirmation bindings are invalid');
  requireValue(canonical(frame) === receipt.frame, 'Persisted confirmation is not canonical');
}

// This signer accepts only rows already committed by the service. It validates
// their structural bindings, not the member's identity or original public key;
// callers must fetch the immutable receipt themselves, never accept a row from
// an HTTP request. 'accepted' means the explicit response was durably recorded,
// including a decline. It does not turn a decline into affirmative consent.
export class DeliverySigner {
  #key;
  #communityId;
  #epoch;

  constructor({ privateJwk, trustBundle, authorityPublicJwk, communityId = 'jiuhua-symsoil' } = {}) {
    try {
      requireValue(typeof communityId === 'string' && /^[A-Za-z0-9:_-]{1,64}$/.test(communityId),
        'Invalid signing community');
      const bundle = structuredClone(trustBundle);
      const authority = publicP256(authorityPublicJwk);
      const verified = verifyTrustBundle(bundle, authority);
      requireValue(bundle.state === 'active' && verified.communityId === communityId,
        'Delivery trust must be active for this community');
      requireValue(privateJwk?.kty === 'EC' && privateJwk.crv === 'P-256' &&
        canonicalBytes(privateJwk.d, 32), 'A service P-256 private JWK is required');
      const key = createPrivateKey({ key: privateJwk, format: 'jwk' });
      const derived = publicP256(createPublicKey(key).export({ format: 'jwk' }));
      const service = publicP256(bundle.servicePublicKey);
      requireValue(derived.x === service.x && derived.y === service.y,
        'Service private key does not match the signed trust bundle');
      // Some JWK importers retain supplied X/Y rather than deriving them from
      // d. A domain-separated self-check detects inconsistent public/private
      // coordinates before any receipt is signed.
      const check = Buffer.from('symsoil-delivery-signer/key-check/1', 'utf8');
      const proof = sign('sha256', check, { key, dsaEncoding: 'ieee-p1363' });
      requireValue(verify('sha256', check, {
        key: createPublicKey({ key: service, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
      }, proof), 'Service private key is inconsistent');
      // verifyTrustBundle already rejects root/service reuse. Keep it explicit
      // here so future codec changes cannot silently widen this boundary.
      requireValue(derived.x !== authority.x || derived.y !== authority.y,
        'Recovery authority cannot sign daily delivery results');
      this.#key = key;
      this.#communityId = communityId;
      this.#epoch = verified.epoch;
      Object.freeze(this);
    } catch {
      // Configuration and crypto exceptions must never echo secret JWK fields.
      throw new Error('Invalid delivery signing configuration');
    }
  }

  get communityId() { return this.#communityId; }
  get trustEpoch() { return this.#epoch; }

  signReceipt(receipt, transferId) {
    requireValue(Number.isInteger(transferId) && transferId > 0 && transferId <= 0xffffffff,
      'Delivery transfer ID must be a nonzero uint32');
    validateReceipt(receipt, this.#communityId);
    const frame = {
      communityId: this.#communityId,
      outcome: 'accepted',
      protocol: DELIVERY_PROTOCOL,
      replySignature: receipt.signature,
      requestId: receipt.request_id,
      resultId: receipt.id,
      transferId,
    };
    const serialized = canonical(frame);
    // Device protocol capacity includes the terminating NUL byte.
    requireValue(Buffer.byteLength(serialized, 'utf8') < 512,
      'Delivery result exceeds the device frame limit');
    const signature = sign('sha256', Buffer.from(serialized, 'utf8'),
      { key: this.#key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    return { frame, signature, trustEpoch: this.#epoch };
  }
}

function readJsonFile(path, privateFile) {
  let descriptor;
  try {
    requireValue(lstatSync(path).isFile(), 'Configuration must be a regular file, not a symlink');
    // O_NONBLOCK avoids waiting forever on a FIFO before its type is checked.
    // O_NOFOLLOW rejects a symlink in the final path component on POSIX.
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) |
      (constants.O_NONBLOCK ?? 0));
    const info = fstatSync(descriptor);
    requireValue(info.isFile() && info.size > 0 && info.size <= FILE_LIMIT,
      'Configuration must be a bounded regular file');
    if (privateFile && process.platform !== 'win32') {
      requireValue((info.mode & 0o077) === 0, 'Private key file permissions are too broad');
    }
    const buffer = Buffer.alloc(FILE_LIMIT + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(descriptor, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    requireValue(length > 0 && length <= FILE_LIMIT, 'Configuration exceeds size limit');
    return JSON.parse(buffer.subarray(0, length).toString('utf8'));
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

// Loading is opt-in and never generates a service or recovery key. The signer
// holds one immutable in-memory snapshot; a rotation requires a fresh load.
export function loadDeliverySigner({ privateKeyPath, trustBundlePath, authorityPublicKeyPath,
  communityId = 'jiuhua-symsoil' } = {}) {
  const paths = [privateKeyPath, trustBundlePath, authorityPublicKeyPath];
  if (paths.every(path => path === undefined || path === null || path === '')) return null;
  requireValue(paths.every(path => typeof path === 'string' && path.length > 0),
    'Delivery signing requires private key, trust bundle and pinned authority files');
  try {
    return new DeliverySigner({ privateJwk: readJsonFile(privateKeyPath, true),
      trustBundle: readJsonFile(trustBundlePath, false),
      authorityPublicJwk: readJsonFile(authorityPublicKeyPath, false), communityId });
  } catch {
    throw new Error('Unable to load delivery signing configuration');
  }
}
