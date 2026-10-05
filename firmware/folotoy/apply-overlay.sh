#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
target="${1:-}"
source "${root}/upstream.env"

if [[ -z "${target}" || ! -d "${target}/.git" ]]; then
    echo "Usage: $0 /path/to/clean/folotoy-ai-passport" >&2
    exit 2
fi
if [[ "$(git -C "${target}" rev-parse HEAD)" != "${FOLOTOY_UPSTREAM_COMMIT}" ]]; then
    echo "Upstream checkout does not match ${FOLOTOY_UPSTREAM_COMMIT}." >&2
    exit 1
fi
if [[ -n "$(git -C "${target}" status --short)" ]]; then
    echo "Upstream checkout has changes; refusing to overwrite them." >&2
    exit 1
fi

git -C "${target}" apply --unidiff-zero --check "${root}/bsp-long-confirm.patch"
git -C "${target}" apply --unidiff-zero "${root}/bsp-long-confirm.patch"
install -m 0644 "${root}/overlay/main/CMakeLists.txt" "${target}/main/CMakeLists.txt"
install -m 0644 "${root}/overlay/main/main.c" "${target}/main/main.c"
install -m 0644 "${root}/overlay/main/passport_core.c" "${target}/main/passport_core.c"
install -m 0644 "${root}/overlay/main/passport_core.h" "${target}/main/passport_core.h"
install -m 0644 "${root}/overlay/tests/test_passport_core.c" "${target}/tests/test_passport_core.c"

echo "Applied Symsoil Passport hardware acceptance overlay to ${target}."
