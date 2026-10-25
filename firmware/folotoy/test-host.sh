#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
core_binary="$(mktemp /tmp/symsoil-passport-core.XXXXXX)"
outbox_binary="$(mktemp /tmp/symsoil-passport-outbox.XXXXXX)"
delivery_binary="$(mktemp /tmp/symsoil-passport-delivery.XXXXXX)"
trust_binary="$(mktemp /tmp/symsoil-passport-trust.XXXXXX)"
provision_binary="$(mktemp /tmp/symsoil-passport-provision.XXXXXX)"
crypto_directory="$(mktemp -d /tmp/symsoil-passport-crypto.XXXXXX)"
trap 'rm -f -- "${core_binary}" "${outbox_binary}" "${delivery_binary}" "${trust_binary}" "${provision_binary}"; rm -rf -- "${crypto_directory}"' EXIT
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"${root}/overlay/main" \
    "${root}/overlay/tests/test_passport_core.c" \
    "${root}/overlay/main/passport_core.c" \
    "${root}/overlay/main/passport_protocol.c" \
    "${root}/overlay/main/passport_vectors.c" \
    -o "${core_binary}"
"${core_binary}"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"${root}/overlay/main" \
    "${root}/overlay/tests/test_passport_outbox.c" \
    "${root}/overlay/main/passport_outbox.c" \
    "${root}/overlay/main/passport_transport.c" \
    -o "${outbox_binary}"
"${outbox_binary}"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"${root}/overlay/main" \
    "${root}/overlay/tests/test_passport_delivery.c" \
    "${root}/overlay/main/passport_delivery.c" \
    "${root}/overlay/main/passport_trust.c" \
    "${root}/overlay/main/passport_outbox.c" \
    "${root}/overlay/main/passport_protocol.c" \
    "${root}/overlay/main/passport_transport.c" \
    -o "${delivery_binary}"
"${delivery_binary}"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"${root}/overlay/main" \
    "${root}/overlay/tests/test_passport_trust.c" \
    "${root}/overlay/main/passport_trust.c" \
    "${root}/overlay/main/passport_outbox.c" \
    -o "${trust_binary}"
"${trust_binary}"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"${root}/overlay/main" \
    "${root}/overlay/tests/test_passport_provision.c" \
    "${root}/overlay/main/passport_provision.c" \
    "${root}/overlay/main/passport_trust.c" \
    "${root}/overlay/main/passport_outbox.c" \
    -o "${provision_binary}"
"${provision_binary}"
node "${root}/../../scripts/trust-fixture-header.mjs" > "${crypto_directory}/trust_fixture.h"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"${root}/overlay/main" -I"${crypto_directory}" \
    "${root}/overlay/tests/test_passport_trust_crypto.c" \
    "${root}/overlay/tests/passport_crypto_openssl.c" \
    "${root}/overlay/main/passport_trust.c" \
    "${root}/overlay/main/passport_delivery.c" \
    "${root}/overlay/main/passport_outbox.c" \
    "${root}/overlay/main/passport_protocol.c" \
    "${root}/overlay/main/passport_transport.c" \
    -lcrypto -o "${crypto_directory}/test"
"${crypto_directory}/test"
node "${root}/../../scripts/delivery-live-fixture-header.mjs" > "${crypto_directory}/delivery_live_fixture.h"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"${root}/overlay/main" -I"${crypto_directory}" \
    "${root}/overlay/tests/test_passport_delivery_live.c" \
    "${root}/overlay/tests/passport_crypto_openssl.c" \
    "${root}/overlay/main/passport_provision.c" \
    "${root}/overlay/main/passport_trust.c" \
    "${root}/overlay/main/passport_delivery.c" \
    "${root}/overlay/main/passport_outbox.c" \
    "${root}/overlay/main/passport_protocol.c" \
    "${root}/overlay/main/passport_transport.c" \
    -lcrypto -o "${crypto_directory}/live-test"
"${crypto_directory}/live-test"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"${root}/overlay/main" \
    "${root}/overlay/tests/test_passport_signer.c" \
    "${root}/overlay/tests/passport_crypto_openssl.c" \
    "${root}/overlay/main/passport_signer.c" \
    "${root}/overlay/main/passport_review.c" \
    "${root}/overlay/main/passport_core.c" \
    "${root}/overlay/main/passport_trust.c" \
    "${root}/overlay/main/passport_delivery.c" \
    "${root}/overlay/main/passport_outbox.c" \
    "${root}/overlay/main/passport_protocol.c" \
    "${root}/overlay/main/passport_transport.c" \
    -lcrypto -o "${crypto_directory}/signer-test"
"${crypto_directory}/signer-test"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"${root}/overlay/main" \
    "${root}/overlay/tests/test_passport_receiver.c" \
    "${root}/overlay/main/passport_receiver.c" \
    "${root}/overlay/main/passport_transport.c" \
    -o "${crypto_directory}/receiver-test"
"${crypto_directory}/receiver-test"
echo "FoloToy Passport host tests: PASS"
