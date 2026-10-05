import { randomBytes, createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { requireCondition, text } from './errors.mjs';
import { canonical } from '../public/protocol.mjs';
import { transaction } from './database.mjs';

const tokenHash = token => createHash('sha256').update(token).digest('hex');
const publicCredential = row => ({ id: row.id, role: row.role, subject: row.subject, label: row.label,
  issuedBy: row.issued_by, createdAt: row.created_at, expiresAt: row.expires_at,
  active: Boolean(row.active), revokedAt: row.revoked_at });

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

export class CredentialStore {
  constructor(db, { clock = Date.now } = {}) { this.db = db; this.clock = clock; }
  audit(actor, type, target, details = {}) {
    this.db.prepare('INSERT INTO events(actor,type,target,details,created_at) VALUES(?,?,?,?,?)').run(actor, type, target, canonical(details), this.clock());
  }
  importBootstrap(credentials) {
    transaction(this.db, () => {
      for (const entry of Object.values(credentials)) {
        const hash = tokenHash(entry.token);
        const existing = this.db.prepare('SELECT role,subject FROM credentials WHERE token_hash=?').get(hash);
        requireCondition(!existing || (existing.role === entry.role && existing.subject === entry.subject), 'BAD_CONFIG', '同一凭证不能改变身份或角色', 500);
        if (existing) continue; // Never resurrect a revoked credential on restart.
        const id = randomUUID();
        this.db.prepare('INSERT INTO credentials(id,role,subject,token_hash,label,issued_by,created_at) VALUES(?,?,?,?,?,?,?)').run(id, entry.role, entry.subject, hash, '本机初始入口', 'local-bootstrap', this.clock());
        this.audit('local-bootstrap', 'credential_imported', id, { role: entry.role, subject: entry.subject });
      }
    });
  }
  authenticate(header, roles) {
    requireCondition(typeof header === 'string' && /^Bearer [A-Za-z0-9_-]{43}$/.test(header), 'UNAUTHORIZED', '请提供有效访问凭证', 401);
    const row = this.db.prepare('SELECT * FROM credentials WHERE token_hash=?').get(tokenHash(header.slice(7)));
    requireCondition(row && row.active && (row.expires_at === null || row.expires_at > this.clock()), 'UNAUTHORIZED', '访问凭证无效、已撤销或过期', 401);
    if (row.role === 'member') requireCondition(this.db.prepare('SELECT id FROM members WHERE id=? AND active=1').get(row.subject), 'MEMBER_INACTIVE', '成员不存在或已停用', 403);
    requireCondition(roles.includes(row.role), 'FORBIDDEN', '当前身份没有此操作权限', 403);
    return publicCredential(row);
  }
  issue(actor, input) {
    const role = input.role;
    requireCondition(['member', 'admin', 'terminal', 'agent'].includes(role), 'INVALID_ROLE', '凭证角色无效', 400);
    const subject = text(input.subject, '凭证对象', 80), label = text(input.label || '社区访问入口', '凭证说明', 100);
    requireCondition(/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(subject), 'INVALID_SUBJECT', '对象编号仅支持字母、数字、短横线或下划线', 400);
    const ttlHours = input.ttlHours ?? (role === 'agent' ? 24 : 168);
    requireCondition(Number.isSafeInteger(ttlHours) && ttlHours >= 1 && ttlHours <= 720, 'INVALID_EXPIRY', '有效期须为1至720小时', 400);
    requireCondition(role !== 'agent' || subject === 'xiaorang', 'INVALID_SUBJECT', '本版本仅支持小壤执行者', 400);
    return transaction(this.db, () => {
      if (role === 'member') requireCondition(this.db.prepare('SELECT id FROM members WHERE id=? AND active=1').get(subject), 'MEMBER_INACTIVE', '成员不存在或已停用', 404);
      const id = randomUUID(), token = randomBytes(32).toString('base64url');
      this.db.prepare('INSERT INTO credentials(id,role,subject,token_hash,label,issued_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)').run(id, role, subject, tokenHash(token), label, actor, this.clock(), this.clock() + ttlHours * 3600000);
      this.audit(actor, 'credential_issued', id, { role, subject, ttlHours });
      return { credential: publicCredential(this.db.prepare('SELECT * FROM credentials WHERE id=?').get(id)), token };
    });
  }
  list() { return this.db.prepare('SELECT * FROM credentials ORDER BY rowid DESC').all().map(publicCredential); }
  revoke(actor, id) {
    return transaction(this.db, () => {
      const row = this.db.prepare('SELECT * FROM credentials WHERE id=?').get(id);
      requireCondition(row, 'CREDENTIAL_NOT_FOUND', '凭证不存在', 404);
      if (!row.active) return { revoked: true };
      if (row.role === 'admin' && (row.expires_at === null || row.expires_at > this.clock())) {
        const count = this.db.prepare("SELECT count(*) AS total FROM credentials WHERE role='admin' AND active=1 AND (expires_at IS NULL OR expires_at>?)").get(this.clock()).total;
        requireCondition(count > 1, 'LAST_ADMIN', '请先签发并保存另一个核定人入口，再撤销最后一个有效入口');
      }
      this.db.prepare('UPDATE credentials SET active=0,revoked_at=? WHERE id=?').run(this.clock(), id);
      this.audit(actor, 'credential_revoked', id, { role: row.role, subject: row.subject });
      return { revoked: true };
    });
  }
}

export const authenticate = (header, credentials, roles) => credentials.authenticate(header, roles);
