#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CXX_BIN="${CXX:-c++}"
WORK_DIR="${TMPDIR:-/tmp}/reallyme-bbapi-linked-verify-$$"

: "${BARRETENBERG_LIB:?BARRETENBERG_LIB must point to libbb-external.a}"
: "${SRS_COMMAND:?SRS_COMMAND must point to an SrsInitSrs BBAPI command}"
: "${VERIFY_COMMAND:?VERIFY_COMMAND must point to a CircuitVerify BBAPI command}"

mkdir -p "${WORK_DIR}"
trap 'rm -rf "${WORK_DIR}"' EXIT

cat >"${WORK_DIR}/linked_verify.cc" <<'EOF'
#include "reallyme_bbapi_shim.h"

#include <stddef.h>
#include <stdint.h>

#include <fstream>
#include <ios>
#include <string>
#include <vector>

namespace {

constexpr uint8_t kCircuitVerifySuccess[] = {
    0x92, 0xb5, 'C', 'i', 'r', 'c', 'u', 'i', 't', 'V', 'e', 'r',
    'i',  'f',  'y', 'R', 'e', 's', 'p', 'o', 'n', 's', 'e', 0x81,
    0xa8, 'v',  'e', 'r', 'i', 'f', 'i', 'e', 'd', 0xc3,
};

bool read_file(const char *path, std::vector<uint8_t> *out) {
  std::ifstream file(path, std::ios::binary);
  if (!file.good()) {
    return false;
  }
  file.seekg(0, std::ios::end);
  const std::streamoff size = file.tellg();
  if (size <= 0) {
    return false;
  }
  file.seekg(0, std::ios::beg);
  out->resize(static_cast<size_t>(size));
  file.read(reinterpret_cast<char *>(out->data()), size);
  return file.good();
}

bool call_bbapi(const std::vector<uint8_t> &command, std::vector<uint8_t> *response) {
  uint8_t *output = nullptr;
  size_t output_len = 0;
  const uint32_t status =
      reallyme_bbapi_call(command.data(), command.size(), &output, &output_len);
  if (status != REALLYME_BBAPI_STATUS_OK || output == nullptr || output_len == 0) {
    return false;
  }
  response->assign(output, output + output_len);
  reallyme_bbapi_free(output, output_len);
  return true;
}

bool verify_response_is_success(const std::vector<uint8_t> &response) {
  if (response.size() != sizeof(kCircuitVerifySuccess)) {
    return false;
  }
  for (size_t index = 0; index < response.size(); ++index) {
    if (response[index] != kCircuitVerifySuccess[index]) {
      return false;
    }
  }
  return true;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    return 2;
  }
  std::vector<uint8_t> srs_command;
  std::vector<uint8_t> verify_command;
  if (!read_file(argv[1], &srs_command) || !read_file(argv[2], &verify_command)) {
    return 3;
  }
  std::vector<uint8_t> srs_response;
  if (!call_bbapi(srs_command, &srs_response)) {
    return 4;
  }
  std::vector<uint8_t> verify_response;
  if (!call_bbapi(verify_command, &verify_response)) {
    return 5;
  }
  if (!verify_response_is_success(verify_response)) {
    return 6;
  }
  return 0;
}
EOF

"${CXX_BIN}" \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -I "${ROOT}/crates/backend-bb/native" \
  "${ROOT}/crates/backend-bb/native/reallyme_bbapi_shim.cc" \
  "${WORK_DIR}/linked_verify.cc" \
  "${BARRETENBERG_LIB}" \
  -o "${WORK_DIR}/linked_verify"

"${WORK_DIR}/linked_verify" "${SRS_COMMAND}" "${VERIFY_COMMAND}"
