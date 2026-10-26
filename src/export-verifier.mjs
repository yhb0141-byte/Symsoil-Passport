import { canonical, confirmationFrame } from '../public/protocol.mjs';
import { digest, verifyConfirmation } from './crypto.mjs';
import { requireCondition } from './errors.mjs';

export function verifyExport(document) {
  requireCondition(document && Array.isArray(document.receipts) && Array.isArray(document.requests) && Array.isArray(document.verificationKeys) && Array.isArray(document.ledger), 'BAD_EXPORT', '导出文件缺少核验所需数据', 400);
  const requestIds = new Set(), receiptIds = new Set(), answeredRequests = new Set();
  for (const request of document.requests) {
    requireCondition(!requestIds.has(request.id) && request.communityId === document.communityId && request.memberId === document.memberId, 'BAD_EXPORT', '事项重复或归属不符', 400);
    requestIds.add(request.id);
  }
  for (const receipt of document.receipts) {
    const request = document.requests.find(r => r.id === receipt.request_id), key = document.verificationKeys.find(k => k.id === receipt.device_id);
    requireCondition(request && key && receipt.member_id === document.memberId && !receiptIds.has(receipt.id) && !answeredRequests.has(request.id), 'BAD_EXPORT', '回执重复、归属不符或设备公钥缺失', 400);
    receiptIds.add(receipt.id); answeredRequests.add(request.id);
    const recomputed = digest({ communityId: request.communityId, memberId: request.memberId, kind: request.kind, sourceId: request.sourceId, version: request.version, payload: request.payload });
    requireCondition(recomputed === request.digest, 'CONTENT_TAMPERED', '事项内容与签名绑定的摘要不同', 400);
    const frame = JSON.parse(receipt.frame), expected = confirmationFrame(request, receipt.device_id, receipt.decision, frame.counter);
    requireCondition(Number.isSafeInteger(frame.counter) && frame.counter > 0 && canonical(frame) === canonical(expected) && verifyConfirmation(key.publicKey, frame, receipt.signature), 'BAD_SIGNATURE', '回执签名或绑定内容无效', 400);
  }
  let balance = 0;
  const entryIds = new Set(), sources = new Set(), refunded = new Set();
  for (const entry of [...document.ledger].reverse()) {
    requireCondition(!entryIds.has(entry.id) && !sources.has(entry.source) && Number.isSafeInteger(entry.delta) && entry.delta !== 0 && entry.member_id === document.memberId && entry.balance_before === balance && entry.balance_after === balance + entry.delta && entry.balance_after >= 0, 'LEDGER_MISMATCH', '积分流水重复或不连续', 400);
    entryIds.add(entry.id); sources.add(entry.source);
    balance = entry.balance_after;
    if (entry.kind === 'opening') {
      requireCondition(entry.balance_before === 0 && !entry.receipt_id && entry.delta > 0 && entry.source === 'opening:' + document.memberId, 'LEDGER_MISMATCH', '起始积分记录无效', 400);
    } else {
      const receipt = document.receipts.find(r => r.id === entry.receipt_id), request = document.requests.find(r => r.id === receipt?.request_id);
      const multiplier = entry.kind === 'debit' ? -1 : 1;
      const requiredDecision = { credit: 'receive', debit: 'spend', refund: 'receive_refund' }[entry.kind];
      const requiredKind = { credit: 'contribution', debit: 'order', refund: 'refund' }[entry.kind];
      requireCondition(requiredDecision && request && request.kind === requiredKind && receipt.decision === requiredDecision && request.payload.points > 0 && entry.delta === multiplier * request.payload.points && entry.source === `${requiredKind}:${request.sourceId}`, 'LEDGER_MISMATCH', '积分变化与明确回复不匹配', 400);
      if (entry.kind === 'refund') {
        const original = document.ledger.find(e => e.id === entry.original_entry);
        requireCondition(original?.kind === 'debit' && entryIds.has(original.id) && !refunded.has(original.id) && entry.delta === -original.delta && request.payload.originalEntry === original.id, 'LEDGER_MISMATCH', '退回记录与原扣分交易不符', 400);
        refunded.add(original.id);
      } else requireCondition(!entry.original_entry, 'LEDGER_MISMATCH', '原交易关联只适用于退回', 400);
    }
  }
  requireCondition(balance === document.balance, 'LEDGER_MISMATCH', '积分余额与流水不同', 400);
  return { verifiedReceipts: document.receipts.length, ledgerBalance: balance, scope: '核验成员回复签名与积分算术，不证明持有人身份、签发者信任或当前撤销状态' };
}
