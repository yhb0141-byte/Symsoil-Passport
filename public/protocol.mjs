// Shared by the browser and server. Only integer numeric fields are permitted.
export const PROTOCOL = 'symsoil-passport/1';
export const CARD_PREFIX = 'sp:1:';
export const DECISIONS = Object.freeze({
  contribution: ['receive', 'needs_change', 'decline'],
  order: ['spend', 'decline'],
  refund: ['receive_refund', 'decline'],
  borrow: ['accept_task', 'needs_change', 'decline'],
  expression: ['accurate', 'needs_change', 'original_only', 'no_retelling'],
  grant: ['approve', 'needs_change', 'decline'],
});
export const LABELS = Object.freeze({
  receive: '确认领取积分', needs_change: '需要修改', decline: '暂不接受',
  spend: '同意扣除这笔积分', receive_refund: '确认原单退回',
  accept_task: '同意承担这次借用', accurate: '表达准确',
  original_only: '仅保留原话', no_retelling: '不允许转述', approve: '批准这项有限授权',
});

export function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  throw new TypeError('协议只支持对象、数组、字符串、布尔值、空值和安全整数');
}

export function confirmationFrame(request, deviceId, decision, counter) {
  return {
    protocol: PROTOCOL, communityId: request.communityId, requestId: request.id,
    requestDigest: request.digest, requestVersion: request.version, nonce: request.nonce,
    expiresAt: request.expiresAt, memberId: request.memberId, deviceId, decision, counter,
  };
}

export function parseCardPayload(payload) {
  if (typeof payload !== 'string' || !/^sp:1:[A-Za-z0-9_-]{32}$/.test(payload)) {
    throw new TypeError('不是共壤卡片入口');
  }
  return payload.slice(CARD_PREFIX.length);
}
