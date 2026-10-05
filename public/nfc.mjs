import { parseCardPayload } from './protocol.mjs';

export const hasWebNFC = () => window.isSecureContext && 'NDEFReader' in window;
export async function writeCard(payload) {
  parseCardPayload(payload);
  if (!hasWebNFC()) throw new Error('此浏览器不支持 NFC 写卡，请使用兼容的手机或读写器');
  const reader = new NDEFReader();
  // A 37-byte ASCII token plus a small NDEF text-record envelope fits NTAG213.
  await reader.write({ records: [{ recordType: 'text', encoding: 'utf-8', lang: 'en', data: payload }] }, { overwrite: true });
}
export async function scanCard() {
  if (!hasWebNFC()) throw new Error('此浏览器不支持 NFC 读卡，可使用模拟碰卡验证流程');
  const controller = new AbortController(), reader = new NDEFReader();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { controller.abort(); reject(new Error('等待读卡超时')); }, 30000);
    function finish(error, value) { clearTimeout(timer); controller.abort(); error ? reject(error) : resolve(value); }
    reader.onreadingerror = () => finish(new Error('读卡失败，请确认标签保存了共壤入口'));
    reader.onreading = event => {
      try {
        const record = event.message.records.find(r => r.recordType === 'text');
        if (!record) throw new Error('卡片没有社区入口');
        const payload = new TextDecoder(record.encoding || 'utf-8').decode(record.data);
        parseCardPayload(payload); finish(null, payload);
      } catch (error) { finish(error); }
    };
    reader.scan({ signal: controller.signal }).catch(error => finish(error));
  });
}
