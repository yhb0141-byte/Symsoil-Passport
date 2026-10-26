import { canonical, confirmationFrame } from './protocol.mjs';

function database() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('symsoil-passport-devices', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('devices');
    open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error);
  });
}
async function stored(id) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('devices', 'readonly'), request = tx.objectStore('devices').get(id);
    let value; request.onsuccess = () => { value = request.result; };
    tx.oncomplete = () => { db.close(); resolve(value); }; tx.onerror = () => { db.close(); reject(tx.error); };
  });
}
async function modify(id, change) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('devices', 'readwrite'), store = tx.objectStore('devices'), request = store.get(id);
    let value, failure;
    request.onsuccess = () => {
      try { value = change(request.result); store.put(value, id); }
      catch (error) { failure = error; tx.abort(); }
    };
    tx.oncomplete = () => { db.close(); resolve(value); }; tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(failure || tx.error || new Error('设备状态未保存')); };
  });
}
export async function deviceKey(storageId, rotate = false) {
  const previous = await stored(storageId);
  if (previous && !rotate) return previous;
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return modify(storageId, latest => {
    if (latest && (!rotate || !previous || canonical(latest.publicKey) !== canonical(previous.publicKey))) return latest;
    return { privateKey: pair.privateKey, publicKey, counter: 0, pending: null };
  });
}
export async function pendingResponse(storageId) {
  const value = await stored(storageId), pending = value?.pending || null;
  if (pending?.status === 'preparing' && Date.now() - pending.createdAt > 60000) {
    const latest = await modify(storageId, record => {
      if (record?.pending?.claimId === pending.claimId && record.pending.status === 'preparing' && Date.now() - record.pending.createdAt > 60000) record.pending = null;
      return record;
    });
    return latest?.pending || null; // Never clear a signature that another tab just finished saving.
  }
  return pending;
}
export async function clearPendingResponse(storageId, claimId) {
  return modify(storageId, value => {
    if (!value) throw new Error('浏览器设备密钥不存在');
    if (value.pending?.claimId === claimId) value.pending = null;
    return value;
  });
}
export async function signResponse(storageId, device, request, decision) {
  await pendingResponse(storageId);
  const claimId = crypto.randomUUID();
  const key = await modify(storageId, value => {
    if (!value) throw new Error('浏览器设备密钥不存在');
    if (value.pending) throw new Error('请先核对上一笔已签名回复的结果');
    value.counter = Math.max(value.counter, device.counter) + 1;
    value.pending = { status: 'preparing', claimId, createdAt: Date.now(), request };
    return value;
  });
  try {
    const frame = confirmationFrame(request, device.id, decision, key.counter);
    const bytes = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, new TextEncoder().encode(canonical(frame))));
    const signature = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const reply = { deviceId: device.id, decision, counter: key.counter, signature };
    await modify(storageId, latest => {
      if (latest?.pending?.claimId !== claimId) throw new Error('签名准备状态已改变，请刷新');
      latest.pending = { ...latest.pending, status: 'ready', reply }; return latest;
    });
    return reply;
  } catch (error) { await clearPendingResponse(storageId, claimId); throw error; }
}
