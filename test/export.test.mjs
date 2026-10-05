import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyExport } from '../src/export-verifier.mjs';
import { fixture, fails } from './helpers.mjs';
function exported(f) { const s = f.service.snapshot('M-017'); return { ...s, memberId: s.member.id }; }

test('exported signatures verify offline and changed readable content fails verification', t => {
  const f = fixture(); t.after(f.close); const req = f.credit(); f.service.respond('M-017', req.id, f.response(req));
  const document = exported(f); assert.equal(verifyExport(document).verifiedReceipts, 1);
  document.requests[0].payload.points = 100; assert.throws(() => verifyExport(document), fails('CONTENT_TAMPERED'));
});
test('export verifier rejects a modified ledger balance and modified signature', t => {
  const f = fixture(); t.after(f.close); const req = f.credit(); f.service.respond('M-017', req.id, f.response(req));
  const document = exported(f); document.ledger[0].balance_after++;
  assert.throws(() => verifyExport(document), fails('LEDGER_MISMATCH'));
  const second = exported(f); second.receipts[0].signature = 'A'.repeat(86); assert.throws(() => verifyExport(second), fails('BAD_SIGNATURE'));
});
test('unsigned credits and duplicated receipts cannot pass export verification', t => {
  const f = fixture(); t.after(f.close); const req = f.credit(); f.service.respond('M-017', req.id, f.response(req));
  const unsigned = exported(f); unsigned.ledger[0].receipt_id = null;
  assert.throws(() => verifyExport(unsigned), fails('LEDGER_MISMATCH'));
  const duplicate = exported(f); duplicate.receipts.push(duplicate.receipts[0]);
  assert.throws(() => verifyExport(duplicate), fails('BAD_EXPORT'));
});
test('a refund must reference its exact original debit in an export', t => {
  const f = fixture(); t.after(f.close); const req = f.order(); f.service.respond('M-017', req.id, f.response(req));
  const original = f.service.snapshot('M-017').ledger[0];
  const refund = f.scan('refund', f.service.approveRefund('admin', { entryId: original.id }));
  f.service.respond('M-017', refund.id, f.response(refund));
  const valid = exported(f); assert.equal(verifyExport(valid).ledgerBalance, 100);
  valid.ledger[0].original_entry = valid.ledger[2].id;
  assert.throws(() => verifyExport(valid), fails('LEDGER_MISMATCH'));
});
