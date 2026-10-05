#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
binary="$(mktemp /tmp/symsoil-passport-core.XXXXXX)"
trap 'rm -f -- "${binary}"' EXIT
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"${root}/overlay/main" \
    "${root}/overlay/tests/test_passport_core.c" \
    "${root}/overlay/main/passport_core.c" \
    "${root}/overlay/main/passport_protocol.c" \
    "${root}/overlay/main/passport_vectors.c" \
    -o "${binary}"
"${binary}"
echo "FoloToy Passport host tests: PASS"
