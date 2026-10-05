import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const vectors = JSON.parse(readFileSync(
  new URL('../firmware/protocol-vectors/confirmation-v1.json', import.meta.url),
  'utf8',
));
const delivery = JSON.parse(readFileSync(
  new URL('../firmware/protocol-vectors/delivery-result-v1.json', import.meta.url),
  'utf8',
));
const source = readFileSync(
  new URL('../firmware/folotoy/overlay/main/passport_vectors.c', import.meta.url),
  'utf8',
);

test('FoloToy firmware embeds every published protocol vector byte-for-byte', () => {
  assert.match(source, new RegExp(`#define SYNTHETIC_PUBLIC_X ${escapeRegExp(JSON.stringify(vectors.vectors[0].publicKey.x))}`));
  assert.match(source, new RegExp(`#define SYNTHETIC_PUBLIC_Y ${escapeRegExp(JSON.stringify(vectors.vectors[0].publicKey.y))}`));
  for (const vector of vectors.vectors) {
    assert.match(source, new RegExp(`\\.name = ${escapeRegExp(JSON.stringify(vector.name))},`));
    assert.match(source, new RegExp(`\\.canonical_content = ${escapeRegExp(JSON.stringify(vector.canonicalContent))},`));
    assert.match(source, new RegExp(`\\.canonical_frame = ${escapeRegExp(JSON.stringify(vector.canonicalFrame))},`));
    assert.match(source, new RegExp(`\\.signature = ${escapeRegExp(JSON.stringify(vector.signature))},`));
  }
});

test('FoloToy firmware embeds the signed delivery result vector byte-for-byte', () => {
  const vector = delivery.vector;
  assert.match(source, new RegExp(`\\.canonical_frame = ${escapeRegExp(JSON.stringify(vector.canonicalFrame))},`));
  assert.match(source, new RegExp(`\\.public_x = ${escapeRegExp(JSON.stringify(vector.publicKey.x))},`));
  assert.match(source, new RegExp(`\\.public_y = ${escapeRegExp(JSON.stringify(vector.publicKey.y))},`));
  assert.match(source, new RegExp(`\\.signature = ${escapeRegExp(JSON.stringify(vector.signature))},`));
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
