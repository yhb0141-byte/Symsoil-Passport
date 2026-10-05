import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../src/database.mjs';
import { PassportService, DEMO_MEMBER } from '../src/service.mjs';
import { fixture, fails } from './helpers.mjs';

test('NFC tap and viewing do not create an approval or change points', t => {
  const f = fixture(); t.after(f.close); const req = f.credit();
  assert.equal(f.service.balance(DEMO_MEMBER), 100);
  assert.deepEqual(f.service.viewed(DEMO_MEMBER, req.id), { viewed: true, approved: false });
  assert.equal(f.service.snapshot(DEMO_MEMBER).receipts.length, 0);
});
test('credit records one immutable transaction; retry and repeated NFC tap are idempotent', t => {
  const f = fixture(); t.after(f.close); const req = f.credit(), input = f.response(req);
  const first = f.service.respond(DEMO_MEMBER, req.id, input), retry = f.service.respond(DEMO_MEMBER, req.id, input);
  assert.equal(first.balance, 130); assert.equal(retry.duplicate, true);
  assert.equal(first.transaction.id, retry.transaction.id);
  const repeated = f.service.scan('terminal', { kind: 'contribution', sourceId: 'CT-001', cardPayload: f.service.ensureCard(DEMO_MEMBER).payload });
  assert.equal(repeated.completed, true); assert.equal(f.service.balance(DEMO_MEMBER), 130);
  assert.throws(() => f.service.run('DELETE FROM ledger WHERE id=?', first.transaction.id), /append-only/);
  assert.throws(() => f.service.run('UPDATE receipts SET decision=?', 'approve'), /immutable/);
});
test('debit and original-order refund each run once and preserve full ledger history', t => {
  const f = fixture(); t.after(f.close); const req = f.order();
  const paid = f.service.respond(DEMO_MEMBER, req.id, f.response(req));
  assert.equal(paid.balance, 80); assert.equal(f.service.one('SELECT stock FROM catalog WHERE id=?', 'harvest').stock, 19);
  const refund = f.service.approveRefund('admin', { entryId: paid.transaction.id });
  assert.equal(f.service.approveRefund('admin', { entryId: paid.transaction.id }).id, refund.id);
  const refundReq = f.scan('refund', refund), input = f.response(refundReq);
  const restored = f.service.respond(DEMO_MEMBER, refundReq.id, input);
  assert.equal(restored.balance, 100); assert.equal(restored.transaction.original_entry, paid.transaction.id);
  f.service.respond(DEMO_MEMBER, refundReq.id, input); assert.equal(f.service.balance(DEMO_MEMBER), 100);
  assert.equal(f.service.one('SELECT stock FROM catalog WHERE id=?', 'harvest').stock, 20);
  assert.throws(() => f.service.fulfill('terminal', 'EX-001'), fails('REFUND_PENDING'));
});
test('insufficient balance rolls back receipt, counter, inventory and ledger atomically', t => {
  const f = fixture(); t.after(f.close); const req = f.order('workshop');
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, f.response(req)), fails('INSUFFICIENT_POINTS'));
  assert.equal(f.service.balance(DEMO_MEMBER), 100); assert.equal(f.service.snapshot(DEMO_MEMBER).receipts.length, 0);
  assert.equal(f.service.one('SELECT counter FROM devices WHERE id=?', f.device.id).counter, 0);
  assert.equal(f.service.one('SELECT stock FROM catalog WHERE id=?', 'workshop').stock, 8);
  assert.equal(f.service.request(DEMO_MEMBER, req.id).state, 'pending');
});
test('out-of-stock failure also rolls back a valid signed confirmation', t => {
  const f = fixture(); t.after(f.close); const req = f.order();
  f.service.run('UPDATE catalog SET stock=0 WHERE id=?', 'harvest');
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, f.response(req)), fails('OUT_OF_STOCK'));
  assert.equal(f.service.balance(DEMO_MEMBER), 100); assert.equal(f.service.snapshot(DEMO_MEMBER).receipts.length, 0);
});
test('cancellation and refusal leave balance unchanged', t => {
  const f = fixture(); t.after(f.close); const req = f.order(); f.service.cancel(DEMO_MEMBER, req.id);
  assert.throws(() => f.service.respond(DEMO_MEMBER, req.id, f.response(req)), fails('REQUEST_CLOSED'));
  const second = f.order('harvest', 'EX-002'); f.service.respond(DEMO_MEMBER, second.id, f.response(second, 'decline'));
  assert.equal(f.service.balance(DEMO_MEMBER), 100); assert.equal(f.service.snapshot(DEMO_MEMBER).receipts[0].decision, 'decline');
});
test('fulfilled exchanges cannot be refunded and a pending refund cannot be fulfilled', t => {
  const f = fixture(); t.after(f.close); const req = f.order();
  const paid = f.service.respond(DEMO_MEMBER, req.id, f.response(req)); f.service.fulfill('terminal', 'EX-001');
  assert.throws(() => f.service.approveRefund('admin', { entryId: paid.transaction.id }), fails('ALREADY_DELIVERED'));
});
test('wrong terminal and already-bound member cannot reuse an order', t => {
  const f = fixture(); t.after(f.close); const req = f.order();
  assert.throws(() => f.service.scan('wrong-terminal', { kind: 'order', sourceId: req.sourceId, cardPayload: f.service.ensureCard(DEMO_MEMBER).payload }), fails('SOURCE_NOT_FOUND'));
  assert.throws(() => f.service.scan('terminal', { kind: 'order', sourceId: req.sourceId, cardPayload: f.service.ensureCard('M-018').payload }), fails('ORDER_BOUND'));
});
test('NFC tag contents cannot directly credit points; unregistered card is rejected', t => {
  const f = fixture(); t.after(f.close); const req = f.credit();
  assert.throws(() => f.service.scan('terminal', { kind: 'contribution', sourceId: req.sourceId, cardPayload: 'sp:1:' + 'A'.repeat(32) }), fails('CARD_INACTIVE'));
  assert.throws(() => f.service.scan('terminal', { kind: 'contribution', sourceId: req.sourceId, cardPayload: '{"balance":100000}' }), fails('INVALID_CARD'));
  assert.equal(f.service.balance(DEMO_MEMBER), 100);
});
test('contribution id conflicts and issuance limits are checked before publishing requests', t => {
  const f = fixture(); t.after(f.close); f.credit();
  assert.throws(() => f.service.approveContribution('admin', { id: 'CT-001', memberId: DEMO_MEMBER, title: '菜园维护', points: 31 }), fails('IDEMPOTENCY_CONFLICT'));
  for (let i = 0; i < 4; i++) f.service.approveContribution('admin', { id: 'bulk-' + i, memberId: DEMO_MEMBER, title: '贡献', points: 100 });
  assert.throws(() => f.service.approveContribution('admin', { id: 'over-limit', memberId: DEMO_MEMBER, title: '贡献', points: 100 }), fails('ISSUANCE_LIMIT'));
});
test('ledger and nonce consumption survive a database reopen and a second connection', t => {
  const directory = mkdtempSync(join(tmpdir(), 'passport-')); t.after(() => rmSync(directory, { recursive: true }));
  const path = join(directory, 'ledger.sqlite'), f = fixture({ path }), req = f.credit(), input = f.response(req);
  f.service.respond(DEMO_MEMBER, req.id, input);
  const db2 = openDatabase(path), service2 = new PassportService(db2);
  assert.equal(service2.respond(DEMO_MEMBER, req.id, input).duplicate, true); db2.close(); f.close();
  const reopened = openDatabase(path); t.after(() => reopened.close()); const service = new PassportService(reopened);
  assert.equal(service.balance(DEMO_MEMBER), 130); assert.equal(service.snapshot(DEMO_MEMBER).ledger.reduce((sum, row) => sum + row.delta, 0), 130);
});
