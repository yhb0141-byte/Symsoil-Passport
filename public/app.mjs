import { DECISIONS, LABELS, canonical, confirmationFrame } from './protocol.mjs';
import { deviceKey, signResponse, pendingResponse, clearPendingResponse } from './device.mjs';
import { hasWebNFC, writeCard, scanCard } from './nfc.mjs';

const $ = selector => document.querySelector(selector);
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const date = value => new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(value));
const signed = value => (value > 0 ? '+' : '') + value;
const kindLabel = { contribution: '贡献积分', order: '积分兑换', refund: '原单退回', borrow: '工具借用', expression: '转述许可', grant: '有限授权' };
let tokens = {}, data = null, terminalData = null, storageId = '', selected = 0, stage = 'home', current = null;
let decision = null, result = null, prepared = null, hold = null, holdTimer = null, sending = false, epoch = 0;
let pending = null;
const home = ['社区积分', '借用电钻', '核对我的转述', '授权小壤行动', '查看我的回执'];

async function api(path, { role = 'member', method = 'GET', body } = {}) {
  const token = tokens[role] || (role === 'terminal' ? tokens.admin : null);
  const response = await fetch(path, { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const value = await response.json();
  if (!response.ok) { const error = new Error(value.error?.message || '操作未完成'); error.code = value.error?.code; error.status = response.status; throw error; }
  return value;
}
function notify(message, error = false) { const notice = $('#notice'); notice.hidden = false; notice.textContent = message; notice.classList.toggle('error', error); notice.setAttribute('role', error ? 'alert' : 'status'); }
const safely = fn => async event => { try { await fn(event); } catch (error) { notify(error.message, true); } };
function tab(name) {
  if (sending) return;
  cancelHold();
  for (const button of document.querySelectorAll('[data-tab]')) { const active = button.dataset.tab === name; if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current'); }
  for (const panel of document.querySelectorAll('.panel')) panel.hidden = panel.id !== name + '-panel';
}
const activeRequests = () => data.requests.filter(r => !r.supersededBy && r.state === 'pending' && r.expiresAt > Date.now());
function screenList(labels) { return '<ul class="screen-list">' + labels.map((label, i) => '<li class="' + (i === selected ? 'selected' : '') + '">' + escape(label) + '</li>').join('') + '</ul>'; }
function screenFields(fields) { return '<dl class="screen-fields">' + fields.map(([label, value]) => '<div><dt>' + escape(label) + '</dt><dd>' + escape(value) + '</dd></div>').join('') + '</dl>'; }
function requestBody(req) {
  const p = req.payload;
  if (['contribution', 'order', 'refund'].includes(req.kind)) {
    const delta = req.kind === 'order' ? -p.points : p.points;
    return screenFields([['事项', p.title], [delta < 0 ? '扣除' : '增加', Math.abs(delta) + ' 积分'], ['预计', data.balance + delta + ' 积分'], ['单据', req.sourceId]]) + (p.approvedBy ? '<p class="screen-note">已核定 · ' + escape(p.policy || p.approvedBy) + '</p>' : '');
  }
  if (req.kind === 'borrow') return screenFields([['工具', p.title], ['归还', p.returnBy]]) + '<p>' + escape(p.note) + '</p>';
  if (req.kind === 'expression') return '<p>原话：' + escape(p.original) + '</p><p>拟转述：' + escape(p.retelling) + '</p>';
  return screenFields([['对象', '新宅菜园排班'], ['期限', '24 小时'], ['次数', '最多 1 次']]) + '<p>' + escape(p.action.value) + '</p><p class="screen-note">' + escape(p.boundaries) + '</p>';
}
function renderScreen() {
  if (!data) return;
  const screen = $('#device-screen'); screen.dataset.stage = stage;
  let content = '<div class="device-status"><span>共壤确认卡</span><span>浏览器设备</span></div>';
  if (stage === 'home') content += '<p class="device-name">' + escape(data.member.name) + '</p><p class="screen-note">' + data.balance + ' 积分 · ' + activeRequests().length + ' 条待回复</p>' + screenList(home) + '<p class="screen-hint">上 / 下选择 · 短按 OK 打开</p>';
  else if (stage === 'points') content += '<h2>我的社区积分</h2><p class="device-name">' + data.balance + ' 积分</p><p class="screen-note">以社区本地账本为准</p>' + screenList(['查看积分明细', '返回首页']) + '<p class="screen-hint">领取或兑换时，请碰社区终端<br>短按 OK 打开</p>';
  else if (stage === 'review') content += '<h2>' + escape(kindLabel[current.kind]) + '</h2><p class="screen-note">内容 v' + current.version + ' · ' + date(current.expiresAt) + ' 前</p>' + requestBody(current) + '<p class="screen-hint">短按 OK 选择回复<br>上键返回 · 查看不产生同意</p>';
  else if (stage === 'choose') content += '<h2>选择你的回复</h2><p class="screen-note">' + escape(kindLabel[current.kind]) + ' · v' + current.version + '</p>' + screenList(DECISIONS[current.kind].map(d => LABELS[d])) + '<p class="screen-hint">上 / 下选择 · 短按 OK 继续</p>';
  else if (stage === 'confirm') content += '<h2>' + escape(LABELS[decision]) + '</h2><p class="screen-note">仅对应这份 v' + current.version + ' 内容</p>' + requestBody(current) + '<p class="screen-hint">' + (sending ? '正在核验和保存' : '长按 OK 两秒提交<br>上键返回 · 松手可取消') + '</p><div class="hold-track" aria-hidden="true"><div class="hold-fill"></div></div>';
  else if (stage === 'result') content += '<h2>' + escape(result.title) + '</h2><p>' + escape(result.detail) + '</p><p class="screen-note">' + escape(result.note || '') + '</p><p class="screen-hint">短按 OK 返回首页</p>';
  else if (stage === 'receipts') content += '<h2>我的回执</h2>' + (data.receipts.length ? '<ul class="screen-list">' + data.receipts.slice(0, 3).map(r => '<li>' + escape(LABELS[r.decision]) + '<br>' + escape(kindLabel[r.kind]) + ' · v' + r.version + (r.superseded_by ? ' · 旧版本' : '') + '</li>').join('') + '</ul>' : '<p class="screen-note">暂没有明确回复记录</p>') + '<p class="screen-hint">短按 OK 返回首页</p>';
  screen.innerHTML = content;
}
function render() {
  if (!data) return;
  $('#greeting').textContent = data.member.name + '，这是你的社区入口。';
  const pending = activeRequests(); $('#pending-count').textContent = pending.length + ' 条';
  $('#inbox-list').innerHTML = pending.length ? pending.map(r => '<div class="inbox-item"><div><h3>' + escape(kindLabel[r.kind]) + ' · ' + escape(r.payload.title) + '</h3><p>内容 v' + r.version + ' · ' + date(r.expiresAt) + ' 前回复</p></div><button class="secondary" data-open="' + escape(r.id) + '">查看</button></div>').join('') : '<p class="empty">现在没有待回复事项。NFC 碰卡后，新的积分事项会显示在这里。</p>';
  for (const button of $('#inbox-list').querySelectorAll('[data-open]')) button.addEventListener('click', safely(() => openRequest(button.dataset.open)));
  $('#device-info').innerHTML = '<p>成员 ' + escape(data.member.id) + '</p><p>设备 ' + escape(data.device?.id || '尚未登记') + '</p><p>卡片入口 ' + escape(data.card.payload) + '</p><p>标签入口不会授予扣分权限。换机需由核定人停用旧设备。</p>';
  $('#points-balance').textContent = data.balance;
  $('#ledger-table').innerHTML = '<table><thead><tr><th>事项与时间</th><th>类型</th><th>增减</th><th>之后余额</th></tr></thead><tbody>' + data.ledger.map(e => '<tr><td>' + escape(e.title) + '<br><span class="muted small">' + date(e.created_at) + '</span></td><td>' + escape({ opening: '起始', credit: '入账', debit: '兑换', refund: '退回' }[e.kind]) + '</td><td class="numeric">' + signed(e.delta) + '</td><td class="numeric">' + e.balance_after + '</td></tr>').join('') + '</tbody></table>';
  $('#receipt-list').innerHTML = data.receipts.length ? data.receipts.map(r => '<article class="record"><h3>' + escape(LABELS[r.decision]) + '</h3><p>' + escape(kindLabel[r.kind]) + ' · v' + r.version + (r.superseded_by ? ' · 对应旧版本' : '') + ' · ' + date(r.created_at) + '</p><p>' + escape(JSON.parse(r.payload).title) + '</p><p>回执 ' + escape(r.id) + '</p></article>').join('') : '<p class="empty">打开事项和查看积分都不会产生批准回执。</p>';
  $('#roster').textContent = data.asset?.value || '尚未设置';
  $('#grants-list').innerHTML = data.grants.length ? data.grants.map(g => {
    const active = !g.revoked && g.used < g.max_uses && g.expires_at > Date.now();
    const status = g.revoked ? '已撤销' : g.expires_at <= Date.now() ? '已过期' : g.used >= g.max_uses ? '已使用' : '有效';
    return '<article class="record"><h3>小壤 · 菜园排班 · ' + status + '</h3><p>' + escape(g.action.value) + '</p><p>最多1次 · ' + date(g.expires_at) + ' 到期 · 不外发 不转授权</p><div class="record-actions">' + (active && tokens.agent ? '<button class="secondary" data-execute="' + escape(g.id) + '">让小壤执行这次更新</button>' : '') + (!g.revoked && !g.used ? '<button class="quiet" data-revoke="' + escape(g.id) + '">撤销授权</button>' : '') + '</div></article>';
  }).join('') : '<p class="empty">暂没有授权。看清行动内容并明确批准后，这里才会出现授权签证。</p>';
  for (const button of $('#grants-list').querySelectorAll('[data-revoke]')) button.addEventListener('click', safely(async () => { await api('/api/grants/' + button.dataset.revoke + '/revoke', { method: 'POST', body: {} }); await refresh(); notify('授权已撤销'); }));
  for (const button of $('#grants-list').querySelectorAll('[data-execute]')) button.addEventListener('click', safely(async () => { const grant = data.grants.find(g => g.id === button.dataset.execute); await api('/api/grants/' + grant.id + '/execute', { role: 'agent', method: 'POST', body: { executionId: crypto.randomUUID(), action: grant.action } }); await refresh(); notify('小壤已完成获准的单次更新'); }));
  const isOperator = Boolean(tokens.admin || tokens.terminal); $('#operator-required').hidden = isOperator; $('#operator-tools').hidden = !isOperator;
  $('#contribution-form').hidden = !tokens.admin; $('#refund').hidden = !tokens.admin;
  for (const id of ['prepare-borrow', 'prepare-expression', 'revise-expression', 'prepare-grant']) $('#' + id).disabled = !tokens.admin;
  $('#catalog-select').innerHTML = data.catalog.map(item => '<option value="' + escape(item.id) + '">' + escape(item.name) + ' · ' + item.cost + ' 积分</option>').join('');
  $('#real-tap').disabled = !hasWebNFC(); $('#write-card').disabled = !hasWebNFC();
  renderFulfillment(); renderScreen();
  renderPending();
}
function renderPending() {
  $('#pending-response').hidden = !pending;
  if (!pending) return;
  $('#pending-response-description').textContent = pending.status === 'ready' ? kindLabel[pending.request.kind] + ' · 单据 ' + pending.request.sourceId + ' · 已签名，结果待核对' : '上一次回复尚未完成签名准备。稍后刷新状态；未保存完整签名前不会发出请求。';
  $('#retry-response').disabled = sending || pending.status !== 'ready';
}
async function syncPending() {
  if (!storageId || !data) return;
  pending = await pendingResponse(storageId);
  if (pending?.status === 'ready') {
    const receipt = data.receipts.find(receipt => receipt.request_id === pending.request.id);
    const expected = canonical(confirmationFrame(pending.request, pending.reply.deviceId, pending.reply.decision, pending.reply.counter));
    if (receipt?.frame === expected) {
      await clearPendingResponse(storageId, pending.claimId); pending = null;
      notify('上次的明确回复已保存在账本中，没有再次记账');
    }
  }
  renderPending();
}
function renderFulfillment() {
  const orders = terminalData?.orders || [];
  const ready = orders.filter(o => o.member_id === data.member.id && o.paid);
  $('#fulfillment-list').innerHTML = ready.length ? ready.slice(0, 5).map(o => {
    const refunded = o.refunded;
    return '<div class="record"><h3>' + escape(data.catalog.find(i => i.id === o.item_id)?.name) + '</h3><p>' + (refunded ? '积分已退回' : o.fulfilled ? '已交付' : o.refundPending ? '原单退回处理中' : '扣分完成，等待交付') + '</p>' + (!refunded && !o.refundPending && !o.fulfilled ? '<button class="secondary" data-fulfill="' + escape(o.id) + '">登记物品已交付</button>' : '') + '</div>';
  }).join('') : '<p class="empty">扣分成功后，才可登记对应兑换的交付结果。</p>';
  for (const button of $('#fulfillment-list').querySelectorAll('[data-fulfill]')) button.addEventListener('click', safely(async () => { await api('/api/orders/' + button.dataset.fulfill + '/fulfill', { role: 'terminal', method: 'POST', body: {} }); await refresh(); notify('物品交付已登记'); }));
}
async function refresh() {
  if (!tokens.member) return;
  const snapshot = await api('/api/me'); data = snapshot;
  if (tokens.admin || tokens.terminal) terminalData = await api('/api/terminal', { role: 'terminal' });
  if (current) { const latest = snapshot.requests.find(r => r.id === current.id); if (latest?.supersededBy && !sending) { cancelHold(); stage = 'home'; current = null; notify('事项已修改，旧版本需要重新征询'); } }
  await syncPending();
  render();
}
async function login(nextTokens) {
  tokens = nextTokens; data = await api('/api/me'); storageId = data.communityId + '/' + data.member.id;
  let key = await deviceKey(storageId);
  try { await api('/api/devices', { method: 'POST', body: { publicKey: key.publicKey } }); }
  catch (error) {
    if (error.code !== 'DEVICE_INACTIVE' || data.device) throw error;
    key = await deviceKey(storageId, true);
    await api('/api/devices', { method: 'POST', body: { publicKey: key.publicKey } });
  }
  $('#login').hidden = true; $('#workspace').hidden = false; $('#logout').hidden = false;
  stage = 'home'; selected = 0; current = null; await refresh();
}
async function openRequest(id) {
  if (sending) return; cancelHold();
  if (pending) throw new Error('请先核对上一笔已签名回复的结果，再打开新的事项');
  current = await api('/api/requests/' + id);
  if (current.supersededBy || current.state !== 'pending' || current.expiresAt <= Date.now()) throw new Error('此事项已关闭、改版或过期，请刷新');
  await api('/api/requests/' + id + '/view', { method: 'POST', body: {} });
  stage = 'review'; selected = 0; epoch++; tab('card'); renderScreen();
}
function showResult(title, detail, note = '') { stage = 'result'; result = { title, detail, note }; renderScreen(); }
function cancelHold() { if (holdTimer) clearInterval(holdTimer); holdTimer = null; hold = null; const fill = $('.hold-fill'); if (fill) fill.style.width = '0%'; }
function move(direction) {
  if (sending) return; cancelHold();
  if (['home', 'choose', 'points'].includes(stage)) { const count = stage === 'home' ? home.length : stage === 'points' ? 2 : DECISIONS[current.kind].length; selected = (selected + direction + count) % count; }
  else if (direction < 0) { if (stage === 'confirm') stage = 'choose'; else { stage = 'home'; selected = 0; } }
  renderScreen();
}
async function shortOK() {
  if (sending) return;
  if (stage === 'home') {
    if (selected === 0) { stage = 'points'; selected = 0; }
    else if (selected === 4) stage = 'receipts';
    else { const kind = ['borrow', 'expression', 'grant'][selected - 1], request = activeRequests().find(r => r.kind === kind); if (request) return openRequest(request.id); showResult('暂没有此类事项', '请在运营终端发起具体事项。'); }
  } else if (stage === 'points') { if (selected === 0) tab('points'); else stage = 'home'; selected = 0; }
  else if (stage === 'review') { stage = 'choose'; selected = 0; }
  else if (stage === 'choose') { decision = DECISIONS[current.kind][selected]; stage = 'confirm'; }
  else if (stage === 'result' || stage === 'receipts') { stage = 'home'; selected = 0; current = null; }
  renderScreen();
}
async function submit() {
  if (sending || !current || stage !== 'confirm') return;
  if (pending) { notify('请先核对上一笔提交结果', true); return; }
  sending = true; renderScreen(); const req = current;
  try {
    const latest = await api('/api/requests/' + req.id);
    if (latest.supersededBy || latest.digest !== req.digest || latest.expiresAt <= Date.now()) throw new Error('事项已修改或过期，请刷新后重新确认');
    await signResponse(storageId, data.device, req, decision);
    pending = await pendingResponse(storageId);
    await transmitPending();
  } catch (error) { pending = await pendingResponse(storageId); showResult(pending ? '上次结果待核对' : '尚未提交回复', error.message, '结果以社区账本记录为准'); notify(error.message, true); }
  finally { sending = false; renderScreen(); renderPending(); }
}
async function transmitPending() {
  const operation = pending;
  if (operation?.status !== 'ready') throw new Error('没有已保存的完整签名可供核对');
  try {
    const response = await api('/api/requests/' + operation.request.id + '/respond', { method: 'POST', body: operation.reply });
    await clearPendingResponse(storageId, operation.claimId); pending = null;
    data.balance = response.balance;
    if (data.device?.id === operation.reply.deviceId) data.device.counter = Math.max(data.device.counter, operation.reply.counter);
    const cachedRequest = data.requests.find(request => request.id === operation.request.id);
    if (cachedRequest) cachedRequest.state = 'responded';
    if (!data.receipts.some(receipt => receipt.id === response.receipt.id)) data.receipts.unshift({ ...response.receipt, kind: operation.request.kind, version: operation.request.version, payload: JSON.stringify(operation.request.payload), superseded_by: cachedRequest?.supersededBy || null });
    if (response.transaction && !data.ledger.some(entry => entry.id === response.transaction.id)) data.ledger.unshift(response.transaction);
    if (response.grant) { data.grants = data.grants.filter(grant => grant.id !== response.grant.id); data.grants.unshift(response.grant); }
    let synced = true;
    try { await refresh(); } catch { synced = false; render(); }
    if (response.transaction) showResult(response.duplicate ? '此单已记账' : response.transaction.kind === 'refund' ? '积分已退回' : response.transaction.delta > 0 ? '积分已入账' : '积分已扣除', signed(response.transaction.delta) + ' 积分 · 当前 ' + response.balance + ' 积分', '交易 ' + response.transaction.id);
    else showResult('回复已保存', LABELS[operation.reply.decision], response.grant ? '已记录这份具体授权，请查看授权的当前状态' : '仅对应这份内容，未授予其他权限');
    notify(synced ? '回复已核验并保存' : '明确回复已保存，其他列表暂未同步。请稍后刷新。');
  } catch (error) {
    if (error.status >= 400 && error.status < 500) {
      await clearPendingResponse(storageId, operation.claimId); pending = null;
      showResult('此回复未被接受', error.message, '请刷新核对事项、已有回复与积分。');
    } else showResult('提交结果待核对', '连接中断或服务暂不可用。此笔可能已保存，请核对同一单据。', '原签名已保存在当前设备，恢复连接后重发原回复。');
    notify(error.message, true);
  }
}
$('#retry-response').addEventListener('click', safely(async () => {
  if (sending) return; pending = await pendingResponse(storageId); if (pending?.status !== 'ready') return;
  sending = true; renderPending();
  try { await transmitPending(); tab('card'); }
  finally { sending = false; tab('card'); renderScreen(); renderPending(); }
}));
function startHold() {
  if (hold || sending) return;
  hold = { start: performance.now(), stage, epoch, completed: false };
  if (stage === 'confirm') holdTimer = setInterval(() => {
    if (!hold || hold.completed) return;
    const progress = Math.min(1, (performance.now() - hold.start) / 2000), fill = $('.hold-fill'); if (fill) fill.style.width = progress * 100 + '%';
    if (progress >= 1 && stage === hold.stage && epoch === hold.epoch) { hold.completed = true; clearInterval(holdTimer); holdTimer = null; void submit(); }
  }, 30);
}
function releaseHold() { if (!hold) return; const previous = hold; cancelHold(); if (!previous.completed && previous.stage !== 'confirm' && stage === previous.stage) safely(shortOK)(); }
for (const button of document.querySelectorAll('[data-key]')) {
  if (button.dataset.key !== 'ok') { button.addEventListener('click', () => move(button.dataset.key === 'up' ? -1 : 1)); continue; }
  button.addEventListener('pointerdown', event => { if (event.button !== 0) return; event.preventDefault(); button.focus(); button.setPointerCapture(event.pointerId); startHold(); });
  button.addEventListener('pointerup', releaseHold); button.addEventListener('pointercancel', cancelHold); button.addEventListener('lostpointercapture', cancelHold); button.addEventListener('blur', cancelHold);
  button.addEventListener('keydown', event => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); if (!event.repeat) startHold(); } });
  button.addEventListener('keyup', event => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); releaseHold(); } });
  button.addEventListener('click', event => { if (event.detail === 0 && !hold) safely(shortOK)(); });
}
document.addEventListener('visibilitychange', () => { if (document.hidden) cancelHold(); });
window.addEventListener('blur', cancelHold);
for (const button of document.querySelectorAll('[data-tab]')) button.addEventListener('click', () => tab(button.dataset.tab));
$('#demo-login').addEventListener('click', safely(async () => login(await api('/api/demo/session', { method: 'POST', body: {} }))));
$('#access-form').addEventListener('submit', safely(async event => { event.preventDefault(); const fields = new FormData(event.target); await login(Object.fromEntries(['member', 'admin', 'terminal', 'agent'].map(role => [role, String(fields.get(role) || '').trim()]))); }));
$('#logout').addEventListener('click', () => { if (sending) return; cancelHold(); tokens = {}; data = null; terminalData = null; prepared = null; current = null; pending = null; storageId = ''; epoch++; $('#login').hidden = false; $('#workspace').hidden = true; $('#logout').hidden = true; $('#notice').hidden = true; $('#access-form').reset(); for (const id of ['device-screen', 'inbox-list', 'device-info', 'ledger-table', 'grants-list', 'receipt-list', 'fulfillment-list']) $('#' + id).replaceChildren(); $('#points-balance').textContent = '0'; });
$('#refresh').addEventListener('click', safely(async () => { if (!sending) { await refresh(); notify('事项与积分已更新'); } }));
function prepare(kind, row, title) { prepared = { kind, sourceId: row.id, title }; $('#prepared-operation').textContent = title + ' · 单据 ' + row.id; $('#nfc-status').textContent = '单据已准备，等待碰卡。'; notify('已准备具体单据，碰卡后由成员回复'); }
$('#contribution-form').addEventListener('submit', safely(async event => { event.preventDefault(); const form = new FormData(event.target); const row = await api('/api/contributions', { role: 'admin', method: 'POST', body: { id: crypto.randomUUID(), memberId: data.member.id, title: form.get('title'), points: Number(form.get('points')) } }); prepare('contribution', row, row.title + ' +' + row.points + ' 积分'); await refresh(); }));
$('#order-form').addEventListener('submit', safely(async event => { event.preventDefault(); const form = new FormData(event.target); const row = await api('/api/orders', { role: 'terminal', method: 'POST', body: { id: crypto.randomUUID(), itemId: form.get('itemId') } }); prepare('order', row, data.catalog.find(i => i.id === row.item_id).name + ' −' + row.cost + ' 积分'); await refresh(); }));
async function tapCard(payload) {
  if (!prepared) throw new Error('请先准备一张积分单据');
  const value = await api('/api/nfc/scan', { role: 'terminal', method: 'POST', body: { cardPayload: payload, kind: prepared.kind, sourceId: prepared.sourceId } });
  await refresh();
  if (value.completed) { $('#nfc-status').textContent = '该单已记账，重复碰卡未再次扣除或入账。'; showResult('此单已处理', '重复碰卡没有再次记账。', '交易 ' + value.transactionId); tab('card'); }
  else if (data.requests.some(r => r.id === value.requestId && r.state === 'pending')) { await openRequest(value.requestId); $('#nfc-status').textContent = '事项已发送，等待成员在卡上确认。'; }
  else { $('#nfc-status').textContent = '事项已发送对应成员，碰卡不代表确认。'; }
}
$('#simulated-tap').addEventListener('click', safely(() => tapCard(data.card.payload)));
$('#real-tap').addEventListener('click', safely(async () => tapCard(await scanCard())));
$('#write-card').addEventListener('click', safely(async () => { await writeCard(data.card.payload); $('#nfc-status').textContent = 'NFC 账户入口已写入，积分余额以本地账本为准。'; notify('账户入口已写入 NFC 标签'); }));
$('#refund').addEventListener('click', safely(async () => { const entry = data.ledger.find(e => e.kind === 'debit' && !data.ledger.some(refund => refund.original_entry === e.id)); if (!entry) throw new Error('没有尚未退回的扣分交易'); const row = await api('/api/refunds', { role: 'admin', method: 'POST', body: { entryId: entry.id, reason: '未交付，按原单退回' } }); prepare('refund', row, '按原单退回 +' + -entry.delta + ' 积分'); await refresh(); }));
const statementTemplates = {
  borrow: { title: 'TL-003 电钻', returnBy: '今天18:00', note: '仅确认这次借用登记，不附带其他议题' },
  expression: { original: '我愿意周六来帮忙，但只能留到中午。', retelling: '菡白愿意参与周六上午的菜园维护。' },
  grant: { value: '周六上午：菡白协助新宅菜园维护' },
};
for (const kind of ['borrow', 'expression', 'grant']) $('#prepare-' + kind).addEventListener('click', safely(async () => { const request = await api('/api/requests', { role: 'admin', method: 'POST', body: { memberId: data.member.id, kind, payload: statementTemplates[kind] } }); await refresh(); await openRequest(request.id); notify('具体事项已发起'); }));
$('#revise-expression').addEventListener('click', safely(async () => { const request = data.requests.find(r => r.kind === 'expression' && !r.supersededBy); if (!request) throw new Error('先发起一份转述稿'); const revised = await api('/api/requests/' + request.id + '/revise', { role: 'admin', method: 'POST', body: { payload: { ...statementTemplates.expression, retelling: request.payload.retelling.endsWith('（待核对）') ? statementTemplates.expression.retelling : statementTemplates.expression.retelling + '（待核对）' } } }); await refresh(); await openRequest(revised.id); notify('新版本已生成，需要重新回复'); }));
$('#export').addEventListener('click', safely(async () => { const value = await api('/api/me/export'); const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'symsoil-passport-' + data.member.id + '.json'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }));
const config = await api('/api/config'); $('#demo-login').hidden = !config.demo; $('#demo-footnote').hidden = !config.demo; $('#mode-label').textContent = config.demo ? '本地试用' : '本地账本';
