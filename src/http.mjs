import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { authenticate } from './auth.mjs';
import { DomainError, requireCondition } from './errors.mjs';

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), nfc=(self)',
  'Cache-Control': 'no-store',
};

async function readJSON(req) {
  requireCondition(req.headers['content-type']?.split(';')[0].trim() === 'application/json', 'JSON_REQUIRED', '请求须使用 JSON', 415);
  let size = 0, parts = [];
  for await (const chunk of req) { size += chunk.length; requireCondition(size <= 65536, 'BODY_TOO_LARGE', '请求超过64KB', 413); parts.push(chunk); }
  try { const value = JSON.parse(Buffer.concat(parts).toString('utf8')); requireCondition(value && typeof value === 'object' && !Array.isArray(value), 'INVALID_JSON', 'JSON 须为对象', 400); return value; }
  catch (error) { if (error instanceof DomainError) throw error; throw new DomainError('INVALID_JSON', 'JSON 格式无效', 400); }
}

export function createApp({ service, credentials, demo = false, publicDir, allowedHost = '127.0.0.1', publicOrigin = null }) {
  const root = resolve(publicDir);
  function json(res, value, status = 200) { res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value)); }
  return createServer(async (req, res) => {
    try {
      const host = req.headers.host;
      requireCondition(typeof host === 'string' && !/[\s/@\\]/.test(host), 'INVALID_HOST', '访问地址无效', 400);
      const origin = `http://${host}`, url = new URL(req.url, origin);
      const hostName = url.hostname;
      const acceptedHosts = new Set(['127.0.0.1', 'localhost', '[::1]', allowedHost, ...(publicOrigin ? [new URL(publicOrigin).hostname] : [])]);
      requireCondition(acceptedHosts.has(hostName), 'INVALID_HOST', '访问地址未授权', 403);
      if (req.headers.origin) requireCondition(req.headers.origin === (publicOrigin || origin), 'CROSS_ORIGIN', '仅接受同源请求', 403);
      if (req.headers['sec-fetch-site']) requireCondition(req.headers['sec-fetch-site'] !== 'cross-site', 'CROSS_ORIGIN', '不接受跨站请求', 403);
      const path = url.pathname, method = req.method;
      if (path === '/api/config' && method === 'GET') return json(res, { demo, community: '九华共壤社区', protocol: 'symsoil-passport/1', serverTime: service.clock() });
      if (path === '/api/demo/session' && method === 'POST') {
        await readJSON(req);
        requireCondition(demo && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress), 'DEMO_DISABLED', '本地试用入口未开启', 403);
        return json(res, Object.fromEntries(Object.entries(credentials).map(([role, entry]) => [role, entry.token])));
      }
      if (path.startsWith('/api/')) {
        const auth = roles => authenticate(req.headers.authorization, credentials, roles);
        const memberAuth = () => auth(['member']);
        const operatorAuth = () => auth(['admin', 'terminal']);
        if (path === '/api/me' && method === 'GET') return json(res, service.snapshot(memberAuth().subject));
        if (path === '/api/me/export' && method === 'GET') {
          const snapshot = service.snapshot(memberAuth().subject);
          return json(res, { communityId: snapshot.communityId, memberId: snapshot.member.id, exportedAt: service.clock(),
            balance: snapshot.balance, ledger: snapshot.ledger, receipts: snapshot.receipts, grants: snapshot.grants,
            requests: snapshot.requests, verificationKeys: snapshot.verificationKeys });
        }
        if (path === '/api/devices' && method === 'POST') { const actor = memberAuth(); return json(res, service.enroll(actor.subject, (await readJSON(req)).publicKey)); }
        if (path === '/api/admin' && method === 'GET') { auth(['admin']); return json(res, service.adminSnapshot()); }
        if (path === '/api/terminal' && method === 'GET') return json(res, service.terminalSnapshot(operatorAuth().subject));
        if (path === '/api/contributions' && method === 'POST') { const actor = auth(['admin']); return json(res, service.approveContribution(actor.subject, await readJSON(req))); }
        if (path === '/api/orders' && method === 'POST') { const actor = operatorAuth(); return json(res, service.createOrder(actor.subject, await readJSON(req))); }
        if (path === '/api/refunds' && method === 'POST') { const actor = auth(['admin']); return json(res, service.approveRefund(actor.subject, await readJSON(req))); }
        if (path === '/api/nfc/scan' && method === 'POST') { const actor = operatorAuth(); return json(res, service.scan(actor.subject, await readJSON(req))); }
        if (path === '/api/requests' && method === 'POST') { const actor = auth(['admin']); return json(res, service.createStatement(actor.subject, await readJSON(req))); }
        let match;
        if ((match = path.match(/^\/api\/requests\/([^/]+)$/)) && method === 'GET') return json(res, service.request(memberAuth().subject, match[1]));
        if ((match = path.match(/^\/api\/requests\/([^/]+)\/respond$/)) && method === 'POST') { const actor = memberAuth(); return json(res, service.respond(actor.subject, match[1], await readJSON(req))); }
        if ((match = path.match(/^\/api\/requests\/([^/]+)\/view$/)) && method === 'POST') { const actor = memberAuth(); await readJSON(req); return json(res, service.viewed(actor.subject, match[1])); }
        if ((match = path.match(/^\/api\/requests\/([^/]+)\/cancel$/)) && method === 'POST') { const actor = memberAuth(); await readJSON(req); return json(res, service.cancel(actor.subject, match[1])); }
        if ((match = path.match(/^\/api\/requests\/([^/]+)\/revise$/)) && method === 'POST') { const actor = auth(['admin']); return json(res, service.revise(actor.subject, match[1], (await readJSON(req)).payload)); }
        if ((match = path.match(/^\/api\/members\/([^/]+)\/revoke-device$/)) && method === 'POST') { const actor = auth(['admin']); await readJSON(req); return json(res, service.revokeDevice(actor.subject, match[1])); }
        if ((match = path.match(/^\/api\/orders\/([^/]+)\/fulfill$/)) && method === 'POST') { const actor = operatorAuth(); await readJSON(req); return json(res, service.fulfill(actor.subject, match[1])); }
        if ((match = path.match(/^\/api\/grants\/([^/]+)\/revoke$/)) && method === 'POST') { const actor = memberAuth(); await readJSON(req); return json(res, service.revokeGrant(actor.subject, match[1])); }
        if ((match = path.match(/^\/api\/grants\/([^/]+)\/execute$/)) && method === 'POST') { const actor = auth(['agent']); return json(res, service.execute(actor.subject, match[1], await readJSON(req))); }
        throw new DomainError('NOT_FOUND', '接口不存在', 404);
      }
      requireCondition(method === 'GET' || method === 'HEAD', 'METHOD_NOT_ALLOWED', '请求方法不适用', 405);
      let decoded; try { decoded = decodeURIComponent(path); } catch { throw new DomainError('INVALID_PATH', '路径无效', 400); }
      const filename = resolve(root, '.' + (decoded === '/' ? '/index.html' : decoded));
      requireCondition(filename.startsWith(root + sep) && MIME[extname(filename)], 'NOT_FOUND', '页面不存在', 404);
      let content; try { content = await readFile(filename); } catch { throw new DomainError('NOT_FOUND', '页面不存在', 404); }
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': MIME[extname(filename)] }); res.end(method === 'HEAD' ? undefined : content);
    } catch (error) {
      if (res.headersSent) return res.destroy();
      if (error instanceof DomainError) json(res, { error: { code: error.code, message: error.message } }, error.status);
      else { console.error('Request failed:', error.message); json(res, { error: { code: 'INTERNAL_ERROR', message: '操作失败，未完成的记账已回滚' } }, 500); }
    }
  });
}
