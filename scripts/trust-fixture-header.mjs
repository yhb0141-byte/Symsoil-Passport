// Emits public synthetic vectors only, for the independently linked C tests.
import { readFileSync } from 'node:fs';
import { encodeTrustFrame, verifyTrustBundle } from './trust-config.mjs';
const fixture = JSON.parse(readFileSync(new URL('../firmware/protocol-vectors/trust-v1.json', import.meta.url), 'utf8'));
const array = (name, bytes) => `static const uint8_t ${name}[] = { ${[...bytes].map(b => `0x${b.toString(16).padStart(2, '0')}`).join(', ')} };`;
console.log('#pragma once\n#include <stdint.h>');
console.log(array('TRUST_ROOT_X', Buffer.from(fixture.authorityPublicKey.x, 'base64url')));
console.log(array('TRUST_ROOT_Y', Buffer.from(fixture.authorityPublicKey.y, 'base64url')));
for (const [index, bundle] of fixture.bundles.entries()) {
  verifyTrustBundle(bundle, fixture.authorityPublicKey);
  console.log(array(`TRUST_FRAME_${index}`, encodeTrustFrame(bundle)));
  console.log(array(`TRUST_SIGNATURE_${index}`, Buffer.from(bundle.signature, 'base64url')));
  if (bundle.servicePublicKey) {
    console.log(array(`TRUST_SERVICE_X_${index}`, Buffer.from(bundle.servicePublicKey.x, 'base64url')));
    console.log(array(`TRUST_SERVICE_Y_${index}`, Buffer.from(bundle.servicePublicKey.y, 'base64url')));
  }
}
console.log(array('OLD_RESULT_SIGNATURE', Buffer.from(fixture.result.oldSignature, 'base64url')));
console.log(array('CURRENT_RESULT_SIGNATURE', Buffer.from(fixture.result.currentSignature, 'base64url')));
console.log(`static const char RESULT_CANONICAL[] = ${JSON.stringify(fixture.result.canonicalFrame)};`);
