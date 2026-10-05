import test from 'node:test';
import assert from 'node:assert/strict';
import { SessionRequests, closedReason } from '../public/live-sync.mjs';

test('logout discards a late response even if the transport ignores abort', async t => {
  const session = new SessionRequests(); let resolveBody, signal;
  t.mock.method(globalThis, 'fetch', async (_path, options) => {
    signal = options.signal;
    return { ok: true, json: () => new Promise(resolve => { resolveBody = resolve; }) };
  });
  const response = session.json('/api/me', {});
  await Promise.resolve(); session.invalidate();
  assert.equal(signal.aborted, true);
  resolveBody({ member: { name: 'old member' } });
  await assert.rejects(response, error => error.name === 'AbortError');
  assert.equal(session.controllers.size, 0);
});

test('confirming a request requires the same pending content before expiry', () => {
  const current = { digest: 'exact', expiresAt: 2000 };
  const latest = { ...current, state: 'pending' };
  assert.equal(closedReason(current, latest, 1999), null);
  assert.match(closedReason(current, latest, 2000), /过期/);
  assert.match(closedReason(current, { ...latest, digest: 'changed' }, 1999), /修改/);
  assert.match(closedReason(current, { ...latest, supersededBy: 'new' }, 1999), /修改/);
  assert.match(closedReason(current, { ...latest, state: 'responded' }, 1999), /已有回复/);
  assert.match(closedReason(current, undefined, 1999), /修改/);
});
