import { randomUUID } from 'node:crypto';
import { canonical, CARD_PREFIX, DECISIONS, confirmationFrame, parseCardPayload } from '../public/protocol.mjs';
import { digest, nonce, validatePublicKey, verifyConfirmation } from './crypto.mjs';
import { DomainError, positiveInteger, requireCondition, text } from './errors.mjs';
import { transaction } from './database.mjs';

export const COMMUNITY_ID = 'jiuhua-symsoil';
export const DEMO_MEMBER = 'M-017';
const unpackRequest = row => row && ({ id: row.id, communityId: row.community_id, memberId: row.member_id,
  kind: row.kind, sourceId: row.source_id, version: row.version, payload: JSON.parse(row.payload), digest: row.digest,
  nonce: row.nonce, expiresAt: row.expires_at, state: row.state, supersededBy: row.superseded_by, createdAt: row.created_at });
const unpackGrant = row => row && ({ ...row, action: JSON.parse(row.action) });

export class PassportService {
  constructor(db, { clock = Date.now } = {}) { this.db = db; this.clock = clock; }
  one(sql, ...args) { return this.db.prepare(sql).get(...args); }
  all(sql, ...args) { return this.db.prepare(sql).all(...args); }
  run(sql, ...args) { return this.db.prepare(sql).run(...args); }
  atomic(fn) { return transaction(this.db, fn); }
  event(actor, type, target, details = {}) {
    this.run('INSERT INTO events(actor,type,target,details,created_at) VALUES(?,?,?,?,?)', actor, type, target, canonical(details), this.clock());
  }
  member(memberId) {
    const row = this.one('SELECT * FROM members WHERE id=? AND active=1', memberId);
    requireCondition(row, 'MEMBER_INACTIVE', '成员不存在或已停用', 403); return row;
  }
  balance(memberId) { this.member(memberId); return this.one('SELECT balance FROM accounts WHERE member_id=?', memberId).balance; }
  createMember(actor, input) {
    const id = text(input.id || 'M-' + randomUUID(), '成员编号', 40), name = text(input.name, '成员名称', 100);
    requireCondition(/^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/.test(id), 'INVALID_MEMBER_ID', '成员编号仅支持字母、数字、短横线或下划线', 400);
    return this.atomic(() => {
      const existing = this.one('SELECT * FROM members WHERE id=?', id);
      if (existing) { requireCondition(existing.name === name && existing.active, 'MEMBER_CONFLICT', '成员编号已登记其他名称或已停用'); return existing; }
      this.run('INSERT INTO members(id,name) VALUES(?,?)', id, name);
      this.run('INSERT INTO accounts(member_id) VALUES(?)', id);
      this.ensureCard(id); this.event(actor, 'member_created', id);
      return this.member(id);
    });
  }
  seed({ openingPoints = 0 } = {}) {
    this.atomic(() => {
      this.run('INSERT OR IGNORE INTO members(id,name) VALUES(?,?)', DEMO_MEMBER, '菡白');
      this.run('INSERT OR IGNORE INTO members(id,name) VALUES(?,?)', 'M-018', '共创伙伴');
      this.run('INSERT OR IGNORE INTO accounts(member_id) VALUES(?)', DEMO_MEMBER);
      this.run('INSERT OR IGNORE INTO accounts(member_id) VALUES(?)', 'M-018');
      if (openingPoints > 0 && !this.one('SELECT id FROM ledger WHERE source=?', 'opening:M-017')) this.postPoints(DEMO_MEMBER, openingPoints, 'opening', 'opening:M-017', '试用起始积分');
      this.run('INSERT OR IGNORE INTO catalog(id,name,cost,stock) VALUES(?,?,?,?)', 'harvest', '菜园收获包 1 份', 20, 20);
      this.run('INSERT OR IGNORE INTO catalog(id,name,cost,stock) VALUES(?,?,?,?)', 'workshop', '维修工坊名额', 200, 8);
      this.run('INSERT OR IGNORE INTO assets(id,value,updated_at) VALUES(?,?,?)', 'garden-roster', '周六上午：等待成员认领', this.clock());
      this.ensureCard(DEMO_MEMBER);
    });
  }
  ensureCard(memberId) {
    this.member(memberId);
    let card = this.one('SELECT * FROM cards WHERE member_id=? AND active=1', memberId);
    if (!card) { const token = nonce(); this.run('INSERT INTO cards(token,member_id) VALUES(?,?)', token, memberId); card = { token, member_id: memberId, active: 1 }; }
    return { memberId, payload: CARD_PREFIX + card.token };
  }
  enroll(memberId, publicKey) {
    const jwk = validatePublicKey(publicKey), id = 'D-' + digest(jwk).slice(0, 24);
    return this.atomic(() => {
      this.member(memberId);
      const current = this.one('SELECT * FROM devices WHERE member_id=? AND active=1', memberId);
      requireCondition(!current || current.id === id, 'DEVICE_ALREADY_ENROLLED', '此成员已登记其他设备，换机请先由管理员停用原设备');
      const existing = this.one('SELECT * FROM devices WHERE id=?', id);
      requireCondition(!existing || (existing.member_id === memberId && existing.active), 'DEVICE_INACTIVE', '该设备不可登记');
      this.run('INSERT OR IGNORE INTO devices(id,member_id,public_key) VALUES(?,?,?)', id, memberId, canonical(jwk));
      if (!existing) this.event(memberId, 'device_enrolled', id);
      return this.one('SELECT id,counter,active FROM devices WHERE id=?', id);
    });
  }
  revokeDevice(actor, memberId) {
    return this.atomic(() => {
      this.member(memberId); this.run('UPDATE devices SET active=0 WHERE member_id=?', memberId);
      this.run('UPDATE cards SET active=0 WHERE member_id=?', memberId);
      this.run('UPDATE requests SET state=? WHERE member_id=? AND state=?', 'cancelled', memberId, 'pending');
      this.run('UPDATE grants SET revoked=1 WHERE member_id=? AND used=0', memberId);
      this.run("UPDATE credentials SET active=0,revoked_at=? WHERE role='member' AND subject=? AND active=1", this.clock(), memberId);
      this.event(actor, 'device_revoked', memberId, { unusedGrantsRevoked: true, memberCredentialsRevoked: true }); return this.ensureCard(memberId);
    });
  }
  approveContribution(actor, input) {
    const id = text(input.id || randomUUID(), '贡献单号', 80), memberId = text(input.memberId, '成员编号', 40);
    const title = text(input.title, '贡献事项'), points = positiveInteger(input.points, '积分数');
    return this.atomic(() => {
      this.member(memberId);
      const existing = this.one('SELECT * FROM contributions WHERE id=?', id);
      if (existing) {
        requireCondition(existing.member_id === memberId && existing.title === title && existing.points === points,
          'IDEMPOTENCY_CONFLICT', '同一贡献单号不能更换内容'); return existing;
      }
      const day = Math.floor((this.clock() + 8 * 3600000) / 86400000) * 86400000 - 8 * 3600000;
      const issued = this.one('SELECT COALESCE(SUM(points),0) AS total FROM contributions WHERE approved_by=? AND approved_at>=?', actor, day).total;
      requireCondition(issued + points <= 500, 'ISSUANCE_LIMIT', '本核定人当日核定额度上限为500积分');
      this.run('INSERT INTO contributions VALUES(?,?,?,?,?,?,?)', id, memberId, title, points, actor, this.clock(), 'contribution-v1');
      this.event(actor, 'contribution_approved', id, { memberId, points }); return this.one('SELECT * FROM contributions WHERE id=?', id);
    });
  }
  createOrder(terminalId, input) {
    const id = text(input.id || randomUUID(), '兑换单号', 80), itemId = text(input.itemId, '兑换项', 80);
    return this.atomic(() => {
      const item = this.one('SELECT * FROM catalog WHERE id=?', itemId);
      requireCondition(item, 'ITEM_NOT_FOUND', '兑换项不存在', 404);
      const existing = this.one('SELECT * FROM orders WHERE id=?', id);
      if (existing) { requireCondition(existing.item_id === itemId && existing.terminal_id === terminalId, 'IDEMPOTENCY_CONFLICT', '兑换单号已绑定其他内容'); return existing; }
      requireCondition(item.stock > 0, 'OUT_OF_STOCK', '当前无可兑换库存');
      this.run('INSERT INTO orders(id,item_id,cost,terminal_id) VALUES(?,?,?,?)', id, itemId, item.cost, terminalId);
      this.event(terminalId, 'order_created', id); return this.one('SELECT * FROM orders WHERE id=?', id);
    });
  }
  approveRefund(actor, input) {
    const entryId = text(input.entryId, '原交易编号', 80), reason = text(input.reason || '未交付，按原单退回', '退回原因');
    return this.atomic(() => {
      const original = this.one('SELECT * FROM ledger WHERE id=? AND kind=?', entryId, 'debit');
      requireCondition(original, 'NO_DEBIT', '没有对应扣分交易', 404);
      const order = this.one('SELECT * FROM orders WHERE id=?', original.source.slice('order:'.length));
      requireCondition(!order.fulfilled, 'ALREADY_DELIVERED', '此兑换已交付，不能按未交付退回');
      const existing = this.one('SELECT * FROM refunds WHERE original_entry=?', entryId);
      if (existing) return existing;
      const id = randomUUID(); this.run('INSERT INTO refunds VALUES(?,?,?,?,?)', id, entryId, original.member_id, actor, reason);
      this.event(actor, 'refund_approved', id, { original: entryId }); return this.one('SELECT * FROM refunds WHERE id=?', id);
    });
  }
  postPoints(memberId, delta, kind, source, title, receiptId = null, originalEntry = null) {
    const before = this.balance(memberId), after = before + delta;
    requireCondition(after >= 0, 'INSUFFICIENT_POINTS', '积分不足，本次未扣除');
    requireCondition(after <= 2147483647, 'BALANCE_LIMIT', '积分账户超过上限');
    const id = randomUUID();
    this.run('UPDATE accounts SET balance=? WHERE member_id=?', after, memberId);
    this.run('INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)', id, memberId, kind, delta, before, after, source, originalEntry, receiptId, title, this.clock());
    return this.one('SELECT * FROM ledger WHERE id=?', id);
  }
  sourcePayload(kind, sourceId, memberId, terminalId) {
    if (kind === 'contribution') {
      const row = this.one('SELECT * FROM contributions WHERE id=?', sourceId);
      requireCondition(row && row.member_id === memberId, 'SOURCE_NOT_FOUND', '没有此成员的已核定贡献单', 404);
      return { title: row.title, points: row.points, approvedBy: row.approved_by, policy: row.policy, terminalId };
    }
    if (kind === 'order') {
      const row = this.one('SELECT o.*,c.name FROM orders o JOIN catalog c ON c.id=o.item_id WHERE o.id=?', sourceId);
      requireCondition(row && row.terminal_id === terminalId, 'SOURCE_NOT_FOUND', '兑换单不属于当前终端', 404);
      requireCondition(!row.member_id || row.member_id === memberId, 'ORDER_BOUND', '兑换单已绑定其他成员');
      this.run('UPDATE orders SET member_id=? WHERE id=? AND member_id IS NULL', memberId, sourceId);
      return { title: row.name, itemId: row.item_id, points: row.cost, terminalId };
    }
    if (kind === 'refund') {
      const row = this.one('SELECT r.*,l.delta FROM refunds r JOIN ledger l ON l.id=r.original_entry WHERE r.id=?', sourceId);
      requireCondition(row && row.member_id === memberId, 'SOURCE_NOT_FOUND', '没有此成员的已核定退回单', 404);
      return { title: row.reason, points: -row.delta, originalEntry: row.original_entry, approvedBy: row.approved_by, terminalId };
    }
    throw new DomainError('INVALID_INPUT', 'NFC积分类型无效', 400);
  }
  scan(terminalId, input) {
    let token;
    try { token = parseCardPayload(input.cardPayload); } catch { throw new DomainError('INVALID_CARD', '卡片内容不是有效账户入口', 400); }
    const sourceId = text(input.sourceId, '单据编号', 80), kind = input.kind;
    requireCondition(['contribution', 'order', 'refund'].includes(kind), 'INVALID_INPUT', '积分事项类型无效', 400);
    return this.atomic(() => {
      const card = this.one('SELECT * FROM cards WHERE token=? AND active=1', token);
      requireCondition(card, 'CARD_INACTIVE', '卡片未登记或已停用', 403); this.member(card.member_id);
      const payload = this.sourcePayload(kind, sourceId, card.member_id, terminalId);
      const source = `${kind}:${sourceId}`;
      const entry = this.one('SELECT id FROM ledger WHERE source=?', source);
      if (entry) return { completed: true, transactionId: entry.id }; // No balance or private history at the public terminal.
      const current = this.one('SELECT * FROM requests WHERE group_key=? ORDER BY version DESC LIMIT 1', source);
      if (current && !current.superseded_by && ((current.state === 'pending' && current.expires_at > this.clock()) || current.state === 'responded')) return { requestId: current.id };
      const req = this.makeRequest(card.member_id, kind, sourceId, payload, source, current);
      this.event(terminalId, 'nfc_request_sent', req.id); return { requestId: req.id };
    });
  }
  makeRequest(memberId, kind, sourceId, payload, groupKey, previous = null) {
    const id = randomUUID(), version = previous ? previous.version + 1 : 1;
    const content = { communityId: COMMUNITY_ID, memberId, kind, sourceId, version, payload };
    const now = this.clock(), expiresAt = now + 120000;
    this.run('INSERT INTO requests(id,group_key,community_id,member_id,kind,source_id,version,payload,digest,nonce,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
      id, groupKey, COMMUNITY_ID, memberId, kind, sourceId, version, canonical(payload), digest(content), nonce(), expiresAt, now);
    if (previous) this.run('UPDATE requests SET superseded_by=? WHERE id=?', id, previous.id);
    this.event(memberId, 'invited', id); return this.request(memberId, id);
  }
  createStatement(actor, input) {
    const memberId = text(input.memberId, '成员编号', 40), kind = input.kind;
    requireCondition(['borrow', 'expression', 'grant'].includes(kind), 'INVALID_INPUT', '事项类型无效', 400);
    return this.atomic(() => {
      this.member(memberId); const payload = this.validateStatement(kind, input.payload);
      const sourceId = randomUUID(), req = this.makeRequest(memberId, kind, sourceId, payload, `${kind}:${sourceId}`);
      this.event(actor, 'statement_created', req.id); return req;
    });
  }
  validateStatement(kind, payload) {
    requireCondition(payload && typeof payload === 'object' && !Array.isArray(payload), 'INVALID_INPUT', '事项内容无效', 400);
    if (kind === 'borrow') return { title: text(payload.title, '工具名称'), returnBy: text(payload.returnBy, '归还时间'), note: text(payload.note || '仅登记这次借用', '说明') };
    if (kind === 'expression') return { title: '核对我的转述', original: text(payload.original, '原话', 2000), retelling: text(payload.retelling, '拟转述', 2000) };
    return { title: '授权小壤更新菜园排班', agentId: 'xiaorang', expiresInHours: 24, maxUses: 1,
      action: { resource: 'garden-roster', action: 'update', value: text(payload.value, '排班内容', 1000) },
      boundaries: '不外发 不转授权 不操作其他资源' };
  }
  revise(actor, requestId, payload) {
    return this.atomic(() => {
      const row = this.one('SELECT * FROM requests WHERE id=?', requestId);
      requireCondition(row, 'REQUEST_NOT_FOUND', '事项不存在', 404);
      requireCondition(!row.superseded_by, 'STALE_VERSION', '请修改当前版本');
      requireCondition(['borrow', 'expression', 'grant'].includes(row.kind), 'INVALID_INPUT', '积分交易不得改写，需重新开单', 400);
      const revised = this.makeRequest(row.member_id, row.kind, row.source_id, this.validateStatement(row.kind, payload), row.group_key, row);
      // Revised permissions stop future execution under the previous grant, while preserving evidence.
      this.run('UPDATE grants SET revoked=1 WHERE receipt_id IN (SELECT id FROM receipts WHERE request_id=?)', requestId);
      this.event(actor, 'statement_revised', revised.id, { previous: requestId }); return revised;
    });
  }
  request(memberId, requestId) {
    this.member(memberId); const row = this.one('SELECT * FROM requests WHERE id=? AND member_id=?', requestId, memberId);
    requireCondition(row, 'REQUEST_NOT_FOUND', '没有此成员的事项', 404); return unpackRequest(row);
  }
  viewed(memberId, requestId) {
    this.request(memberId, requestId);
    if (!this.one('SELECT id FROM events WHERE actor=? AND type=? AND target=?', memberId, 'viewed', requestId)) this.event(memberId, 'viewed', requestId);
    return { viewed: true, approved: false };
  }
  cancel(memberId, requestId) {
    return this.atomic(() => {
      const request = this.request(memberId, requestId);
      requireCondition(request.state !== 'responded', 'ALREADY_RESPONDED', '已提交回复不能当作未回复取消');
      this.run('UPDATE requests SET state=? WHERE id=?', 'cancelled', requestId);
      this.event(memberId, 'request_cancelled', requestId); return { cancelled: true };
    });
  }
  respond(memberId, requestId, input) {
    return this.atomic(() => {
      const req = this.request(memberId, requestId);
      const device = this.one('SELECT * FROM devices WHERE id=? AND member_id=? AND active=1', input.deviceId, memberId);
      requireCondition(device, 'DEVICE_INACTIVE', '设备未登记或已停用', 403);
      requireCondition(DECISIONS[req.kind].includes(input.decision), 'INVALID_DECISION', '回复含义不适用于此事项', 400);
      requireCondition(Number.isSafeInteger(input.counter) && input.counter > 0, 'INVALID_COUNTER', '设备计数器无效', 400);
      const frame = confirmationFrame(req, input.deviceId, input.decision, input.counter);
      requireCondition(verifyConfirmation(JSON.parse(device.public_key), frame, input.signature), 'BAD_SIGNATURE', '确认签名无效或事项已改变', 403);
      const existing = this.one('SELECT * FROM receipts WHERE request_id=?', requestId);
      if (existing) {
        requireCondition(existing.frame === canonical(frame), 'ALREADY_RESPONDED', '此事项已有不同回复');
        return this.responseResult(existing.id, true);
      }
      requireCondition(!req.supersededBy, 'STALE_VERSION', '事项已改版，旧版本不能确认');
      requireCondition(req.state === 'pending', 'REQUEST_CLOSED', '事项已取消或关闭');
      requireCondition(req.expiresAt > this.clock(), 'REQUEST_EXPIRED', '事项已过期，请重新发起');
      requireCondition(input.counter > device.counter, 'REPLAY', '设备计数器已使用');
      const id = randomUUID();
      this.run('INSERT INTO receipts VALUES(?,?,?,?,?,?,?,?)', id, requestId, memberId, device.id, input.decision, canonical(frame), input.signature, this.clock());
      this.run('UPDATE devices SET counter=? WHERE id=?', input.counter, device.id);
      if (req.kind === 'contribution' && input.decision === 'receive') {
        const approved = this.one('SELECT * FROM contributions WHERE id=?', req.sourceId);
        requireCondition(approved?.member_id === memberId && approved.points === req.payload.points, 'SOURCE_CHANGED', '贡献核定内容已改变');
        this.postPoints(memberId, approved.points, 'credit', `contribution:${req.sourceId}`, approved.title, id);
      } else if (req.kind === 'order' && input.decision === 'spend') {
        const order = this.one('SELECT * FROM orders WHERE id=?', req.sourceId);
        requireCondition(order?.member_id === memberId && order.cost === req.payload.points, 'SOURCE_CHANGED', '兑换单已改变');
        const updated = this.run('UPDATE catalog SET stock=stock-1 WHERE id=? AND stock>0', order.item_id);
        requireCondition(updated.changes === 1, 'OUT_OF_STOCK', '兑换库存不足，本次未扣除');
        this.postPoints(memberId, -order.cost, 'debit', `order:${req.sourceId}`, req.payload.title, id);
      } else if (req.kind === 'refund' && input.decision === 'receive_refund') {
        const approved = this.one('SELECT * FROM refunds WHERE id=?', req.sourceId);
        const original = this.one('SELECT * FROM ledger WHERE id=? AND kind=? AND member_id=?', approved?.original_entry || '', 'debit', memberId);
        requireCondition(original, 'NO_DEBIT', '原扣分交易不存在');
        const orderId = original.source.slice('order:'.length), order = this.one('SELECT * FROM orders WHERE id=?', orderId);
        requireCondition(!order.fulfilled, 'ALREADY_DELIVERED', '原兑换已交付，不能按未交付退回');
        this.postPoints(memberId, -original.delta, 'refund', `refund:${req.sourceId}`, '原单退回', id, original.id);
        this.run('UPDATE catalog SET stock=stock+1 WHERE id=?', order.item_id);
      } else if (req.kind === 'grant' && input.decision === 'approve') {
        const grantId = randomUUID(), action = req.payload.action;
        this.run('INSERT INTO grants(id,member_id,receipt_id,agent_id,action,action_digest,expires_at,max_uses) VALUES(?,?,?,?,?,?,?,?)',
          grantId, memberId, id, req.payload.agentId, canonical(action), digest(action), this.clock() + 24 * 3600000, 1);
      }
      this.run('UPDATE requests SET state=? WHERE id=?', 'responded', requestId);
      this.event(memberId, 'explicit_response', requestId, { decision: input.decision, receiptId: id });
      return this.responseResult(id, false);
    });
  }
  responseResult(receiptId, duplicate) {
    const receipt = this.one('SELECT * FROM receipts WHERE id=?', receiptId);
    return { receipt, duplicate, balance: this.balance(receipt.member_id),
      transaction: this.one('SELECT * FROM ledger WHERE receipt_id=?', receiptId) || null,
      grant: unpackGrant(this.one('SELECT * FROM grants WHERE receipt_id=?', receiptId)) || null };
  }
  fulfill(terminalId, orderId) {
    return this.atomic(() => {
      const order = this.one('SELECT * FROM orders WHERE id=? AND terminal_id=?', orderId, terminalId);
      requireCondition(order, 'ORDER_NOT_FOUND', '没有此终端的兑换单', 404);
      const entry = this.one('SELECT * FROM ledger WHERE source=?', `order:${orderId}`);
      requireCondition(entry, 'NOT_PAID', '尚未确认扣分，不能交付');
      requireCondition(!this.one('SELECT id FROM refunds WHERE original_entry=?', entry.id), 'REFUND_PENDING', '此单已发起退回，不能交付');
      if (!order.fulfilled) { this.run('UPDATE orders SET fulfilled=1 WHERE id=?', orderId); this.event(terminalId, 'order_fulfilled', orderId); }
      return { fulfilled: true };
    });
  }
  revokeGrant(memberId, id) {
    return this.atomic(() => {
      this.member(memberId); requireCondition(this.one('SELECT id FROM grants WHERE id=? AND member_id=?', id, memberId), 'GRANT_NOT_FOUND', '授权不存在', 404);
      this.run('UPDATE grants SET revoked=1 WHERE id=?', id); this.event(memberId, 'grant_revoked', id); return { revoked: true };
    });
  }
  execute(agentId, grantId, input) {
    const executionId = text(input.executionId, '执行单号', 80);
    return this.atomic(() => {
      const grant = this.one('SELECT * FROM grants WHERE id=? AND agent_id=?', grantId, agentId);
      requireCondition(grant, 'GRANT_NOT_FOUND', '没有此代理的授权', 404);
      const actionDigest = digest(input.action);
      requireCondition(actionDigest === grant.action_digest, 'SCOPE_MISMATCH', '执行内容超出授权范围', 403);
      const existing = this.one('SELECT * FROM executions WHERE id=?', executionId);
      if (existing) { requireCondition(existing.grant_id === grantId && existing.action_digest === actionDigest, 'IDEMPOTENCY_CONFLICT', '执行单号已绑定其他行动'); return { ...existing, duplicate: true }; }
      this.member(grant.member_id);
      requireCondition(!grant.revoked && grant.expires_at > this.clock(), 'GRANT_INACTIVE', '授权已撤销或过期', 403);
      requireCondition(grant.used < grant.max_uses, 'GRANT_CONSUMED', '单次授权已使用');
      const action = JSON.parse(grant.action);
      requireCondition(action.resource === 'garden-roster' && action.action === 'update', 'SCOPE_MISMATCH', '执行器不支持此动作', 403);
      this.run('UPDATE grants SET used=used+1 WHERE id=?', grantId);
      this.run('UPDATE assets SET value=?,updated_at=? WHERE id=?', action.value, this.clock(), action.resource);
      const result = canonical({ resource: action.resource, value: action.value });
      this.run('INSERT INTO executions VALUES(?,?,?,?,?)', executionId, grantId, actionDigest, result, this.clock());
      this.event(agentId, 'grant_executed', grantId, { executionId });
      return { executionId, result: JSON.parse(result), duplicate: false };
    });
  }
  snapshot(memberId) {
    const member = this.member(memberId);
    return { communityId: COMMUNITY_ID, member, balance: this.balance(memberId), card: this.ensureCard(memberId),
      device: this.one('SELECT id,counter,active FROM devices WHERE member_id=? AND active=1', memberId) || null,
      verificationKeys: this.all('SELECT id,public_key,active FROM devices WHERE member_id=?', memberId).map(d => ({ id: d.id, publicKey: JSON.parse(d.public_key), active: Boolean(d.active) })),
      requests: this.all('SELECT * FROM requests WHERE member_id=? ORDER BY created_at DESC,version DESC', memberId).map(unpackRequest),
      receipts: this.all('SELECT r.*,q.kind,q.payload,q.version,q.superseded_by FROM receipts r JOIN requests q ON q.id=r.request_id WHERE r.member_id=? ORDER BY r.created_at DESC', memberId),
      ledger: this.all('SELECT * FROM ledger WHERE member_id=? ORDER BY created_at DESC,rowid DESC', memberId),
      grants: this.all('SELECT * FROM grants WHERE member_id=? ORDER BY rowid DESC', memberId).map(unpackGrant),
      catalog: this.all('SELECT * FROM catalog ORDER BY cost'), asset: this.one('SELECT * FROM assets WHERE id=?', 'garden-roster') };
  }
  adminSnapshot() {
    return { members: this.all('SELECT m.id,m.name,m.active,d.id AS deviceId FROM members m LEFT JOIN devices d ON d.member_id=m.id AND d.active=1'), catalog: this.all('SELECT * FROM catalog ORDER BY cost'),
      contributions: this.all('SELECT * FROM contributions ORDER BY approved_at DESC'), orders: this.all('SELECT * FROM orders ORDER BY rowid DESC'),
      refunds: this.all('SELECT * FROM refunds ORDER BY rowid DESC'), ledger: this.all('SELECT * FROM ledger ORDER BY rowid DESC LIMIT 100'),
      requests: this.all('SELECT * FROM requests ORDER BY rowid DESC LIMIT 100').map(unpackRequest),
      events: this.all('SELECT * FROM events ORDER BY id DESC LIMIT 100') };
  }
  terminalSnapshot(terminalId) {
    return { catalog: this.all('SELECT * FROM catalog ORDER BY cost'), orders: this.all(`SELECT o.*,c.name,
      CASE WHEN l.id IS NULL THEN 0 ELSE 1 END AS paid, l.id AS transactionId,
      EXISTS(SELECT 1 FROM ledger r WHERE r.original_entry=l.id) AS refunded,
      EXISTS(SELECT 1 FROM refunds f WHERE f.original_entry=l.id) AS refundPending
      FROM orders o JOIN catalog c ON c.id=o.item_id
      LEFT JOIN ledger l ON l.source='order:'||o.id
      WHERE o.terminal_id=? ORDER BY o.rowid DESC LIMIT 100`, terminalId) };
  }
}
