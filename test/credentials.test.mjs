import test from 'node:test';
import assert from 'node:assert/strict';
import { createCredentials, CredentialStore } from '../src/auth.mjs';
import { fixture, fails } from './helpers.mjs';

function storeFixture(t) {
  const f = fixture(); t.after(f.close);
  const bootstrap = createCredentials(), access = new CredentialStore(f.db, { clock: f.service.clock });
  access.importBootstrap(bootstrap);
  return { ...f, bootstrap, access };
}
test('new members have isolated zero balances and cannot reuse another member ID', t => {
  const f = storeFixture(t);
  const member = f.service.createMember('admin', { id: 'M-NEW', name: '新伙伴' });
  assert.equal(f.service.balance(member.id), 0);
  assert.equal(f.service.snapshot(member.id).ledger.length, 0);
  assert.equal(f.service.createMember('admin', { id: member.id, name: member.name }).id, member.id);
  assert.throws(() => f.service.createMember('admin', { id: member.id, name: '另一个人' }), fails('MEMBER_CONFLICT'));
  assert.throws(() => f.service.createMember('admin', { id: '../member', name: '新伙伴' }), fails('INVALID_MEMBER_ID'));
  assert.equal(f.service.balance('M-017'), 100);
});
test('issued credentials contain a one-time secret; DB, lists and audit logs contain only hashes or metadata', t => {
  const f = storeFixture(t);
  const result = f.access.issue('admin', { role: 'member', subject: 'M-018', ttlHours: 2 });
  assert.match(result.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(f.access.authenticate('Bearer ' + result.token, ['member']).subject, 'M-018');
  assert.equal(f.access.list().some(c => c.token || c.token_hash), false);
  const serialized = JSON.stringify(f.db.prepare('SELECT * FROM credentials').all()) + JSON.stringify(f.db.prepare('SELECT * FROM events').all());
  assert.equal(serialized.includes(result.token), false);
  assert.throws(() => f.access.authenticate('Bearer ' + result.token, ['admin']), fails('FORBIDDEN'));
});
test('expired and revoked credentials cannot regain access through bootstrap import or restart', t => {
  const f = storeFixture(t);
  const timed = f.access.issue('admin', { role: 'terminal', subject: 'tool-cabinet', ttlHours: 1 });
  f.advance(3600000);
  assert.throws(() => f.access.authenticate('Bearer ' + timed.token, ['terminal']), fails('UNAUTHORIZED'));
  const member = f.access.authenticate('Bearer ' + f.bootstrap.member.token, ['member']);
  f.access.revoke('admin', member.id); f.access.importBootstrap(f.bootstrap);
  const afterRestart = new CredentialStore(f.db, { clock: f.service.clock }); afterRestart.importBootstrap(f.bootstrap);
  assert.throws(() => afterRestart.authenticate('Bearer ' + f.bootstrap.member.token, ['member']), fails('UNAUTHORIZED'));
  assert.equal(afterRestart.list().find(c => c.id === member.id).active, false);
});
test('last active admin is protected while an explicit replacement permits rotation', t => {
  const f = storeFixture(t), original = f.access.authenticate('Bearer ' + f.bootstrap.admin.token, ['admin']);
  assert.throws(() => f.access.revoke('admin', original.id), fails('LAST_ADMIN'));
  const replacement = f.access.issue('admin', { role: 'admin', subject: 'community-admin', ttlHours: 24 });
  f.access.revoke('admin', original.id);
  assert.throws(() => f.access.authenticate('Bearer ' + f.bootstrap.admin.token, ['admin']), fails('UNAUTHORIZED'));
  assert.throws(() => f.access.revoke('admin', replacement.credential.id), fails('LAST_ADMIN'));
});
test('credential subject, role and expiry validation prevents arbitrary grants', t => {
  const f = storeFixture(t);
  assert.throws(() => f.access.issue('admin', { role: 'owner', subject: 'M-018' }), fails('INVALID_ROLE'));
  assert.throws(() => f.access.issue('admin', { role: 'member', subject: 'M-404' }), fails('MEMBER_INACTIVE'));
  assert.throws(() => f.access.issue('admin', { role: 'agent', subject: 'another-agent' }), fails('INVALID_SUBJECT'));
  for (const ttlHours of [0, -1, 721, 1.5, '24']) assert.throws(() => f.access.issue('admin', { role: 'member', subject: 'M-018', ttlHours }), fails('INVALID_EXPIRY'));
  const changed = structuredClone(f.bootstrap); changed.member.subject = 'M-018';
  assert.throws(() => f.access.importBootstrap(changed), fails('BAD_CONFIG'));
});
test('lost-device revocation also stops member sessions and outstanding AI grants', t => {
  const f = storeFixture(t), request = f.statement('grant', { value: '周六上午维护菜园' });
  const reply = f.service.respond('M-017', request.id, f.response(request));
  const oldCard = f.service.ensureCard('M-017').payload;
  const renewed = f.service.revokeDevice('admin', 'M-017');
  assert.notEqual(renewed.payload, oldCard);
  assert.throws(() => f.access.authenticate('Bearer ' + f.bootstrap.member.token, ['member']), fails('UNAUTHORIZED'));
  assert.throws(() => f.service.execute('xiaorang', reply.grant.id, { executionId: 'lost-device-action', action: reply.grant.action }), fails('GRANT_INACTIVE'));
  const replacement = f.access.issue('admin', { role: 'member', subject: 'M-017' });
  assert.equal(f.access.authenticate('Bearer ' + replacement.token, ['member']).subject, 'M-017');
  assert.equal(f.service.snapshot('M-017').device, null);
  assert.equal(f.service.snapshot('M-017').receipts.length, 1);
});
