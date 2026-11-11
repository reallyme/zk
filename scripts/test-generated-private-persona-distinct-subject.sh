#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

fail() {
  echo "generated private-persona distinct-subject gate failed: $1" >&2
  exit 2
}

TARGET_ROOT="$(cd "${ROOT}/target" && pwd -P)"
FIXTURE_ROOT="${GENERATED_PRIVATE_PERSONA_FIXTURE_ROOT:-${TARGET_ROOT}/private-persona-distinct-fixtures}"
FIXTURE_PARENT="$(dirname "${FIXTURE_ROOT}")"
FIXTURE_NAME="$(basename "${FIXTURE_ROOT}")"

if [[ "${FIXTURE_NAME}" == "." || "${FIXTURE_NAME}" == ".." ]]; then
  fail "GENERATED_PRIVATE_PERSONA_FIXTURE_ROOT must name a fixture directory"
fi

if [[ ! -d "${FIXTURE_PARENT}" ]]; then
  fail "GENERATED_PRIVATE_PERSONA_FIXTURE_ROOT parent must already exist"
fi
FIXTURE_PARENT="$(cd "${FIXTURE_PARENT}" && pwd -P)"

case "${FIXTURE_PARENT}/" in
  "${TARGET_ROOT}/"*) ;;
  *)
    fail "GENERATED_PRIVATE_PERSONA_FIXTURE_ROOT must be under ${TARGET_ROOT}"
    ;;
esac

FIXTURE_ROOT="${FIXTURE_PARENT}/${FIXTURE_NAME}"

(
  cd "${ROOT}"
  cargo run -p reallyme-zk-demo-fixture-generator \
    --bin generate-private-persona-distinct-fixtures \
    -- generate "${FIXTURE_ROOT}" "${ROOT}"
  cargo run -p reallyme-zk-demo-fixture-generator \
    --bin generate-private-persona-distinct-fixtures \
    -- check "${FIXTURE_ROOT}" "${ROOT}"
)

export REALLYME_PRIVATE_PERSONA_TWO_CREDENTIAL_ROOT="${FIXTURE_ROOT}"
exec "${ROOT}/scripts/test-linked-private-persona-distinct-subject.sh"
