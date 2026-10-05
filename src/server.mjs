import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase } from './database.mjs';
import { PassportService } from './service.mjs';
import { loadCredentials } from './auth.mjs';
import { createApp } from './http.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const demo = process.argv.includes('--demo');
const host = process.env.PASSPORT_HOST || '127.0.0.1';
const port = Number(process.env.PASSPORT_PORT || 8787);
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('PASSPORT_PORT 须为有效端口');
if (demo && host !== '127.0.0.1') throw new Error('试用模式只能监听127.0.0.1');
const directory = resolve(process.env.PASSPORT_DATA_DIR || resolve(root, 'data', demo ? 'demo' : 'local'));
mkdirSync(directory, { recursive: true, mode: 0o700 });
const db = openDatabase(resolve(directory, 'passport.sqlite'));
const service = new PassportService(db);
service.seed({ openingPoints: demo ? 100 : 0 });
if (demo) {
  service.approveContribution('community-admin', { id: 'demo-contribution-001', memberId: 'M-017', title: '菜园维护', points: 30 });
  const examples = {
    borrow: { title: 'TL-003 电钻', returnBy: '今天18:00', note: '仅登记这次借用，不附带其他议题' },
    expression: { original: '我愿意周六来帮忙，但只能留到中午。', retelling: '菡白愿意参与周六上午的菜园维护。' },
    grant: { value: '周六上午：菡白协助新宅菜园维护' },
  };
  for (const [kind, payload] of Object.entries(examples)) {
    if (!service.one('SELECT id FROM requests WHERE kind=?', kind)) service.createStatement('community-admin', { memberId: 'M-017', kind, payload });
  }
}
const credentials = loadCredentials(resolve(directory, 'access.json'));
const publicOrigin = process.env.PASSPORT_ORIGIN || null;
if (publicOrigin && (new URL(publicOrigin).origin !== publicOrigin || !publicOrigin.startsWith('https://'))) throw new Error('PASSPORT_ORIGIN 须为不带路径的 HTTPS 来源');
if (demo && publicOrigin) throw new Error('试用模式不得设置外部访问来源');
const server = createApp({ service, credentials, demo, publicDir: resolve(root, 'public'), allowedHost: host, publicOrigin });
server.listen(port, host, () => {
  console.log(`共壤 Passport 已运行：http://${host}:${port}`);
  console.log(demo ? '本地试用：使用独立的示例账本。真实 NFC 需要兼容设备。' : `本地访问凭证：${resolve(directory, 'access.json')}（不会通过公开接口提供）`);
});
function stop() { server.close(() => { db.close(); process.exit(0); }); }
process.on('SIGINT', stop); process.on('SIGTERM', stop);
