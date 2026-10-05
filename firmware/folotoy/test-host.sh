#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
core_binary="$(mktemp /tmp/symsoil-passport-core.XXXXXX)"
outbox_binary="$(mktemp /tmp/symsoil-passport-outbox.XXXXXX)"
trap 'rm -f -- "${core_binary}" "${outbox_binary}"' EXIT
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
echo "FoloToy Passport host tests: PASS"
