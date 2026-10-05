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
async function save(id, value) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('devices', 'readwrite'); tx.objectStore('devices').put(value, id);
    tx.oncomplete = () => { db.close(); resolve(value); }; tx.onerror = () => { db.close(); reject(tx.error); };
  });
}
export async function deviceKey(storageId, rotate = false) {
  const previous = rotate ? null : await stored(storageId);
  if (previous) return previous;
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return save(storageId, { privateKey: pair.privateKey, publicKey, counter: 0 });
}
async function nextCounter(storageId, minimum) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('devices', 'readwrite'), store = tx.objectStore('devices'), request = store.get(storageId);
    let value;
    request.onsuccess = () => { value = request.result; if (!value) { tx.abort(); return; } value.counter = Math.max(value.counter, minimum) + 1; store.put(value, storageId); };
    tx.oncomplete = () => { db.close(); resolve(value.counter); }; tx.onabort = tx.onerror = () => { db.close(); reject(tx.error || new Error('设备密钥未保存')); };
  });
}
export async function signResponse(storageId, device, request, decision) {
  const key = await stored(storageId), counter = await nextCounter(storageId, device.counter);
  if (!key) throw new Error('浏览器设备密钥不存在');
  const frame = confirmationFrame(request, device.id, decision, counter);
  const bytes = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, new TextEncoder().encode(canonical(frame))));
  const signature = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  return { deviceId: device.id, decision, counter, signature };
}
