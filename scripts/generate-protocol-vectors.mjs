// Maintainer utility: produces synthetic public test vectors, never device credentials.
import { generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { canonical, confirmationFrame, PROTOCOL } from '../public/protocol.mjs';
import { digest, validatePublicKey } from '../src/crypto.mjs';

const output = resolve(process.argv[2] || 'firmware/protocol-vectors/confirmation-v1.json');
const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const publicKey = validatePublicKey(pair.publicKey.export({ format: 'jwk' }));
const deviceId = 'D-' + digest(publicKey).slice(0, 24);
const examples = [
  { kind: 'contribution', decision: 'receive', payload: { title: '维护花园 🌱\n整理“工具架”', points: 30, approvedBy: 'synthetic-admin', policy: 'contribution-v1', terminalId: 'synthetic-terminal' } },
  { kind: 'order', decision: 'spend', payload: { title: '菜园收获包 1 份', points: 20, itemId: 'harvest', terminalId: 'synthetic-terminal' } },
  { kind: 'expression', decision: 'original_only', payload: { title: '核对我的转述', original: '我可以帮忙，但不能超过中午。', retelling: '伙伴愿意参与全天维护。' } },
  { kind: 'grant', decision: 'approve', payload: { title: '授权小壤更新菜园排班', agentId: 'xiaorang', expiresInHours: 24, maxUses: 1, action: { resource: 'garden-roster', action: 'update', value: '周六上午：合成测试成员维护菜园' }, boundaries: '不外发 不转授权 不操作其他资源' } },
];
const vectors = examples.map((example, index) => {
  const content = { communityId: 'synthetic-community', memberId: 'synthetic-member', kind: example.kind, sourceId: 'synthetic-source-' + (index + 1), version: 1, payload: example.payload };
  const request = { ...content, id: 'synthetic-request-' + (index + 1), digest: digest(content), nonce: Buffer.alloc(24, index + 1).toString('base64url'), expiresAt: 1925020860000 };
  const frame = confirmationFrame(request, deviceId, example.decision, index + 1);
  const canonicalFrame = canonical(frame);
  return { name: example.kind, publicKey, request, decision: example.decision, counter: index + 1, deviceId,
    canonicalContent: canonical(content), canonicalFrame,
    signature: sign('sha256', Buffer.from(canonicalFrame), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') };
});
const serializerCases = [
  { name: 'utf8-values-and-controls', value: { title: '花园 🌱', line: '第一行\n第二行\t"引号"\\斜线', enabled: true, empty: null, points: 9007199254740991 } },
  { name: 'utf16-key-order', value: { '\ue000': 2, '\ud800\udc00': 1, ASCII: 0 } },
  { name: 'lone-surrogate', value: { text: '\ud800' } },
  { name: 'array-order', value: [3, '共壤', false, null, { z: -7, a: 0 }] },
].map(example => ({ ...example, expected: canonical(example.value) }));
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, JSON.stringify({ protocol: PROTOCOL, synthetic: true, note: 'Public conformance material only. No private key, member credential or live authorization is included.', vectors, serializerCases }, null, 2) + '\n');
console.log(`Wrote ${vectors.length} public signing vectors to ${output}`);
