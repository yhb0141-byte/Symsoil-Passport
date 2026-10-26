import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { canonical } from '../public/protocol.mjs';
import { requireCondition } from './errors.mjs';

export const digest = value => createHash('sha256').update(canonical(value)).digest('hex');
export const nonce = () => randomBytes(24).toString('base64url');

export function validatePublicKey(jwk) {
  requireCondition(jwk?.kty === 'EC' && jwk.crv === 'P-256' && !jwk.d &&
    typeof jwk.x === 'string' && typeof jwk.y === 'string' &&
    /^[A-Za-z0-9_-]{43}$/.test(jwk.x) && /^[A-Za-z0-9_-]{43}$/.test(jwk.y),
  'INVALID_KEY', '须登记 P-256 公钥，不能提交私钥', 400);
  const clean = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  try { createPublicKey({ key: clean, format: 'jwk' }); }
  catch { requireCondition(false, 'INVALID_KEY', '公钥无效', 400); }
  return clean;
}

export function verifyConfirmation(jwk, frame, signature) {
  if (typeof signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  try {
    return verify('sha256', Buffer.from(canonical(frame)),
      { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'));
  } catch { return false; }
}
