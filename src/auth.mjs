import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { DomainError, requireCondition } from './errors.mjs';

export function createCredentials() {
  const token = () => randomBytes(32).toString('base64url');
  return {
    member: { role: 'member', subject: 'M-017', token: token() },
    admin: { role: 'admin', subject: 'community-admin', token: token() },
    terminal: { role: 'terminal', subject: 'community-terminal', token: token() },
    agent: { role: 'agent', subject: 'xiaorang', token: token() },
  };
}

export function loadCredentials(path) {
  if (!existsSync(path)) writeFileSync(path, JSON.stringify(createCredentials(), null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  chmodSync(path, 0o600);
  const credentials = JSON.parse(readFileSync(path, 'utf8'));
  for (const role of ['member', 'admin', 'terminal', 'agent']) {
    requireCondition(credentials[role]?.role === role && typeof credentials[role]?.subject === 'string' &&
      /^[A-Za-z0-9_-]{43}$/.test(credentials[role]?.token), 'BAD_CONFIG', '本地访问凭证格式错误', 500);
  }
  return credentials;
}

export function authenticate(header, credentials, roles) {
  if (typeof header !== 'string' || !header.startsWith('Bearer ') || header.length > 200) throw new DomainError('UNAUTHORIZED', '请提供访问凭证', 401);
  const candidate = createHash('sha256').update(header.slice(7)).digest();
  const identity = Object.values(credentials).find(entry => timingSafeEqual(candidate, createHash('sha256').update(entry.token).digest()));
  requireCondition(identity, 'UNAUTHORIZED', '访问凭证无效', 401);
  requireCondition(roles.includes(identity.role), 'FORBIDDEN', '当前身份没有此操作权限', 403);
  return identity;
}
