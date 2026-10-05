import { hasWebNFC, scanCard } from './nfc.mjs';

const $ = selector => document.querySelector(selector);
const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
const date = value => value ? new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(value)) : '本机初始入口';
const roleLabel = { member: '成员', admin: '核定人', terminal: '兑换终端', agent: '小壤' };
let tokens = {}, community = null, terminal = null, credentials = [], recoveryMember = null;

async function api(path, { role = 'admin', method = 'GET', body } = {}) {
  const token = tokens[role] || (role === 'terminal' ? tokens.admin : null);
  const response = await fetch(path, { method, headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error?.message || '操作未完成');
  return value;
}
function notify(message, error = false) {
  const notice = $('#operator-notice'); notice.hidden = false; notice.textContent = message;
  notice.classList.toggle('error', error); notice.setAttribute('role', error ? 'alert' : 'status');
}
const safely = fn => async event => { try { await fn(event); } catch (error) { notify(error.message, true); } };
function tab(name) {
  if (name !== 'exchange' && !tokens.admin) return;
  for (const button of document.querySelectorAll('[data-operator-tab]')) {
    if (button.dataset.operatorTab === name) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
  }
  for (const panel of document.querySelectorAll('.operator-panel')) panel.hidden = panel.id !== name + '-operator-panel';
}
function clearIssued() { $('#issued-secret').value = ''; $('#issued-summary').textContent = ''; $('#issued-credential').hidden = true; }
function chooseSubject() {
  const role = $('#credential-role').value;
  $('#member-subject-label').hidden = role !== 'member'; $('#other-subject-label').hidden = role === 'member';
  $('#credential-subject').required = role !== 'member';
  if (role === 'agent') { $('#credential-subject').value = 'xiaorang'; $('#operator-credential [name="ttlHours"]').value = 24; }
}
function prepare(kind, sourceId) {
  $('#scan-kind').value = kind; $('#scan-source').value = sourceId;
  $('#operator-nfc-status').textContent = '单据已准备，等待对应成员碰卡。';
}
async function scan(payload) {
  const sourceId = $('#scan-source').value.trim();
  if (!sourceId) throw new Error('请先准备一张具体单据');
  const value = await api('/api/nfc/scan', { role: 'terminal', method: 'POST', body: { cardPayload: payload, kind: $('#scan-kind').value, sourceId } });
  $('#operator-nfc-status').textContent = value.completed ? '该单已记账，重复碰卡没有再次记账。' : '事项已发送。请成员在自己的随身卡上核对并回复。';
  await refresh();
}
function render() {
  for (const node of document.querySelectorAll('[data-admin-only]')) node.hidden = !tokens.admin;
  for (const select of document.querySelectorAll('[data-members]')) {
    const previous = select.value;
    select.innerHTML = (community?.members || []).map(member => '<option value="' + escape(member.id) + '">' + escape(member.name) + ' · ' + escape(member.id) + '</option>').join('');
    if ([...select.options].some(option => option.value === previous)) select.value = previous;
  }
  const catalog = $('#operator-catalog'), previousItem = catalog.value;
  catalog.innerHTML = terminal.catalog.map(item => '<option value="' + escape(item.id) + '">' + escape(item.name) + ' · ' + item.cost + ' 积分 · 库存 ' + item.stock + '</option>').join('');
  if ([...catalog.options].some(option => option.value === previousItem)) catalog.value = previousItem;
  $('#operator-nfc-read').disabled = !hasWebNFC();
  $('#operator-orders').innerHTML = terminal.orders.length ? terminal.orders.map(order => {
    const status = order.refunded ? '积分已退回' : order.fulfilled ? '已交付' : order.refundPending ? '原单退回处理中' : order.paid ? '已扣分，等待交付' : '等待成员确认';
    return '<article class="record"><div><h3>' + escape(order.name) + ' · ' + order.cost + ' 积分</h3><p>' + escape(order.id) + '</p><p>' + status + (order.member_id ? ' · 成员 ' + escape(order.member_id) : '') + '</p></div><div class="record-actions">' + (order.paid && !order.fulfilled && !order.refundPending ? '<button class="secondary" data-deliver="' + escape(order.id) + '">登记交付</button>' + (tokens.admin ? '<button class="quiet" data-refund="' + escape(order.id) + '">按原单退回</button>' : '') : '') + '</div></article>';
  }).join('') : '<p class="empty">这个终端还没有兑换单。</p>';
  for (const button of document.querySelectorAll('[data-deliver]')) button.addEventListener('click', safely(async () => {
    await api('/api/orders/' + button.dataset.deliver + '/fulfill', { role: 'terminal', method: 'POST', body: {} });
    await refresh(); notify('交付已登记');
  }));
  for (const button of document.querySelectorAll('[data-refund]')) button.addEventListener('click', safely(async () => {
    const order = terminal.orders.find(order => order.id === button.dataset.refund);
    const row = await api('/api/refunds', { method: 'POST', body: { entryId: order.transactionId, reason: '未交付，按原单退回' } });
    prepare('refund', row.id); await refresh(); notify('退回单已准备，请原成员单独确认领取');
  }));
  if (!tokens.admin) return;
  $('#operator-members').innerHTML = community.members.map(member => '<article class="record"><div><h3>' + escape(member.name) + '</h3><p>' + escape(member.id) + '</p><p>' + (member.deviceId ? '设备 ' + escape(member.deviceId) : '尚未登记有效设备') + '</p></div><div class="record-actions"><button class="quiet" data-recover="' + escape(member.id) + '">失物停用 / 换机</button></div></article>').join('');
  for (const button of document.querySelectorAll('[data-recover]')) button.addEventListener('click', () => {
    recoveryMember = community.members.find(member => member.id === button.dataset.recover);
    $('#recovery-member').textContent = recoveryMember.name + ' · ' + recoveryMember.id;
    $('#recovery-dialog').showModal();
  });
  $('#operator-credentials').innerHTML = '<table><thead><tr><th>用途与主体</th><th>角色</th><th>到期 / 状态</th><th>操作</th></tr></thead><tbody>' + credentials.map(credential => {
    const active = credential.active && (!credential.expiresAt || credential.expiresAt > Date.now());
    return '<tr><td>' + escape(credential.label) + '<br>' + escape(credential.subject) + '</td><td>' + roleLabel[credential.role] + '</td><td>' + date(credential.expiresAt) + '<br>' + (credential.active ? active ? '有效' : '已过期' : '已撤销') + '</td><td>' + (active ? '<button class="quiet" data-revoke-credential="' + escape(credential.id) + '">撤销入口</button>' : '') + '</td></tr>';
  }).join('') + '</tbody></table>';
  for (const button of document.querySelectorAll('[data-revoke-credential]')) button.addEventListener('click', safely(async () => {
    await api('/api/credentials/' + button.dataset.revokeCredential + '/revoke', { method: 'POST', body: {} });
    await refresh(); notify('入口已撤销');
  }));
  $('#operator-events').innerHTML = '<table><thead><tr><th>时间</th><th>操作人</th><th>事件</th><th>对象</th></tr></thead><tbody>' + community.events.map(event => '<tr><td>' + date(event.created_at) + '</td><td>' + escape(event.actor) + '</td><td>' + escape(event.type) + '</td><td>' + escape(event.target) + '</td></tr>').join('') + '</tbody></table>';
}
async function refresh() {
  terminal = await api('/api/terminal', { role: 'terminal' });
  if (tokens.admin) {
    community = await api('/api/admin'); credentials = (await api('/api/credentials')).credentials;
  }
  render();
}
async function login(nextTokens) {
  clearIssued(); tokens = nextTokens; await refresh();
  $('#operator-login').hidden = true; $('#operator-workspace').hidden = false; $('#operator-logout').hidden = false;
  $('#operator-role').textContent = tokens.admin ? '社区核定人 · 可管理成员与凭证' : '兑换终端 · 只管理自己的兑换单';
  tab('exchange');
}
$('#operator-access').addEventListener('submit', safely(async event => {
  event.preventDefault(); const form = new FormData(event.target);
  await login({ [form.get('role')]: String(form.get('token')).trim() }); event.target.reset();
}));
$('#operator-demo').addEventListener('click', safely(async () => {
  const value = await api('/api/demo/session', { method: 'POST', body: {} });
  await login({ admin: value.admin, terminal: value.terminal });
}));
$('#operator-logout').addEventListener('click', () => {
  clearIssued(); tokens = {}; community = terminal = null; credentials = []; recoveryMember = null;
  $('#recovery-dialog').close(); $('#operator-login').hidden = false; $('#operator-workspace').hidden = true;
  $('#operator-logout').hidden = true; $('#operator-notice').hidden = true; $('#operator-access').reset();
  $('#operator-workspace').querySelectorAll('form').forEach(form => form.reset());
});
for (const button of document.querySelectorAll('[data-operator-tab]')) button.addEventListener('click', () => tab(button.dataset.operatorTab));
$('#operator-refresh').addEventListener('click', safely(async () => { await refresh(); notify('运营记录已更新'); }));
$('#operator-contribution').addEventListener('submit', safely(async event => {
  event.preventDefault(); const form = new FormData(event.target);
  const row = await api('/api/contributions', { method: 'POST', body: { id: crypto.randomUUID(), memberId: form.get('memberId'), title: form.get('title'), points: Number(form.get('points')) } });
  prepare('contribution', row.id); await refresh(); notify('贡献已核定，等待成员碰卡领取');
}));
$('#operator-order').addEventListener('submit', safely(async event => {
  event.preventDefault(); const form = new FormData(event.target);
  const row = await api('/api/orders', { role: 'terminal', method: 'POST', body: { id: crypto.randomUUID(), itemId: form.get('itemId') } });
  prepare('order', row.id); await refresh(); notify('兑换单已准备');
}));
$('#operator-nfc-read').addEventListener('click', safely(async () => scan(await scanCard())));
$('#operator-manual-scan').addEventListener('submit', safely(async event => {
  event.preventDefault(); await scan(String(new FormData(event.target).get('cardPayload')).trim()); event.target.reset();
}));
$('#operator-member').addEventListener('submit', safely(async event => {
  event.preventDefault(); const form = new FormData(event.target), id = String(form.get('id')).trim();
  const member = await api('/api/members', { method: 'POST', body: { ...(id ? { id } : {}), name: form.get('name') } });
  await refresh(); $('#operator-credential [name="memberSubject"]').value = member.id;
  $('#credential-role').value = 'member'; chooseSubject(); event.target.reset(); notify('成员已创建，请为其签发独立入口');
}));
$('#credential-role').addEventListener('change', chooseSubject);
$('#operator-credential').addEventListener('submit', safely(async event => {
  event.preventDefault(); clearIssued(); const form = new FormData(event.target), role = form.get('role');
  const value = await api('/api/credentials', { method: 'POST', body: { role, subject: role === 'member' ? form.get('memberSubject') : form.get('otherSubject'), label: form.get('label'), ttlHours: Number(form.get('ttlHours')) } });
  $('#issued-credential').hidden = false; $('#issued-secret').value = value.token;
  $('#issued-summary').textContent = roleLabel[role] + ' · ' + value.credential.subject + ' · ' + date(value.credential.expiresAt) + ' 到期';
  await refresh(); notify('入口已签发，仅本次显示访问凭证');
}));
$('#copy-issued').addEventListener('click', safely(async () => { await navigator.clipboard.writeText($('#issued-secret').value); notify('访问凭证已复制，请只交给对应持有人'); }));
$('#clear-issued').addEventListener('click', clearIssued);
$('#cancel-recovery').addEventListener('click', () => { $('#recovery-dialog').close(); recoveryMember = null; });
$('#confirm-recovery').addEventListener('click', safely(async () => {
  if (!recoveryMember) return; const member = recoveryMember;
  await api('/api/members/' + member.id + '/revoke-device', { method: 'POST', body: {} });
  $('#recovery-dialog').close(); recoveryMember = null; await refresh();
  $('#credential-role').value = 'member'; chooseSubject(); $('#operator-credential [name="memberSubject"]').value = member.id;
  clearIssued(); notify('旧设备、成员入口与未使用授权已停用。核对持有人后请重新签发成员入口。');
}));
const config = await api('/api/config'); $('#operator-demo').hidden = !config.demo; chooseSubject();
