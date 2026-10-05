import test from 'node:test';
import assert from 'node:assert/strict';
import { DEMO_MEMBER } from '../src/service.mjs';
import { fixture, fails } from './helpers.mjs';
function grant(f) { const req = f.statement('grant', { value: '周六上午：菡白参与维护' }); return f.service.respond(DEMO_MEMBER, req.id, f.response(req, 'approve')).grant; }

test('single-use grant updates only the exact approved asset content and retries idempotently', t => {
  const f = fixture(); t.after(f.close); const g = grant(f), input = { executionId: 'action-1', action: g.action };
  const result = f.service.execute('xiaorang', g.id, input); assert.equal(result.result.value, g.action.value);
  assert.equal(f.service.execute('xiaorang', g.id, input).duplicate, true);
  assert.throws(() => f.service.execute('xiaorang', g.id, { ...input, executionId: 'action-2' }), fails('GRANT_CONSUMED'));
  assert.equal(f.service.balance(DEMO_MEMBER), 100);
});
test('wrong agent, resource and text cannot spend an authorized action', t => {
  const f = fixture(); t.after(f.close); const g = grant(f);
  assert.throws(() => f.service.execute('other-agent', g.id, { executionId: 'x', action: g.action }), fails('GRANT_NOT_FOUND'));
  assert.throws(() => f.service.execute('xiaorang', g.id, { executionId: 'x', action: { ...g.action, value: '下午' } }), fails('SCOPE_MISMATCH'));
  assert.throws(() => f.service.execute('xiaorang', g.id, { executionId: 'x', action: { ...g.action, resource: 'other' } }), fails('SCOPE_MISMATCH'));
  assert.equal(f.service.snapshot(DEMO_MEMBER).grants[0].used, 0);
});
test('revoked and expired grants cannot execute', t => {
  const f = fixture(); t.after(f.close); const g = grant(f); f.service.revokeGrant(DEMO_MEMBER, g.id);
  assert.throws(() => f.service.execute('xiaorang', g.id, { executionId: 'x', action: g.action }), fails('GRANT_INACTIVE'));
  const g2 = grant(f); f.advance(24 * 3600000 + 1);
  assert.throws(() => f.service.execute('xiaorang', g2.id, { executionId: 'y', action: g2.action }), fails('GRANT_INACTIVE'));
});
test('a request revision revokes its previously issued visa and preserves the old receipt', t => {
  const f = fixture(); t.after(f.close); const req = f.statement('grant', { value: '上午维护' });
  const g = f.service.respond(DEMO_MEMBER, req.id, f.response(req, 'approve')).grant;
  f.service.revise('admin', req.id, { value: '下午维护' });
  assert.throws(() => f.service.execute('xiaorang', g.id, { executionId: 'x', action: g.action }), fails('GRANT_INACTIVE'));
  assert.equal(f.service.snapshot(DEMO_MEMBER).receipts.length, 1);
});
test('understanding or requesting changes does not generate an execution visa', t => {
  const f = fixture(); t.after(f.close); const req = f.statement('grant', { value: '上午维护' });
  f.service.respond(DEMO_MEMBER, req.id, f.response(req, 'needs_change')); assert.equal(f.service.snapshot(DEMO_MEMBER).grants.length, 0);
});
