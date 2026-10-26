import { generateKeyPairSync, sign } from 'node:crypto';
import { openDatabase } from '../src/database.mjs';
import { PassportService, DEMO_MEMBER } from '../src/service.mjs';
import { canonical, confirmationFrame, DECISIONS } from '../public/protocol.mjs';

export function fixture({ path = ':memory:', openingPoints = 100 } = {}) {
  const db = openDatabase(path); let now = Date.parse('2026-10-05T02:48:08Z'), counter = 0;
  const service = new PassportService(db, { clock: () => now }); service.seed({ openingPoints });
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const device = service.enroll(DEMO_MEMBER, pair.publicKey.export({ format: 'jwk' }));
  function response(request, decision = DECISIONS[request.kind][0], overrides = {}) {
    const input = { deviceId: device.id, decision, counter: ++counter, ...overrides };
    const frame = confirmationFrame(request, input.deviceId, input.decision, input.counter);
    input.signature = sign('sha256', Buffer.from(canonical(frame)), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    return input;
  }
  function scan(kind, row, cardPayload = service.ensureCard(DEMO_MEMBER).payload) {
    const value = service.scan('terminal', { kind, sourceId: row.id, cardPayload });
    return value.requestId ? service.request(DEMO_MEMBER, value.requestId) : value;
  }
  function credit(points = 30, id = 'CT-001') { return scan('contribution', service.approveContribution('admin', { id, memberId: DEMO_MEMBER, title: '菜园维护', points })); }
  function order(itemId = 'harvest', id = 'EX-001') { return scan('order', service.createOrder('terminal', { id, itemId })); }
  function statement(kind, payload) { return service.createStatement('admin', { memberId: DEMO_MEMBER, kind, payload }); }
  return { db, service, pair, device, response, scan, credit, order, statement, advance: ms => { now += ms; }, close: () => db.close() };
}

export const fails = code => error => error.code === code;
