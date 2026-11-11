#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_source="${repo_root}/crates/noir-witness-core/src/bin/poseidon2-bounded-fixture.rs"
fixture_tests="${repo_root}/crates/noir-witness-core/src/bin/poseidon2_bounded_fixture/tests.rs"
vector_file="${repo_root}/vectors/poseidon2-crypto-contract-v1.tsv"
crypto_poseidon2_package="reallyme-crypto-poseidon2"
crypto_poseidon2_version="0.3.17"
target_parent="${repo_root}/target"
if [[ -L "${target_parent}" ]]; then
  echo "poseidon2 crypto contract: refusing to use symlinked target parent ${target_parent}" >&2
  exit 1
fi
mkdir -p "${target_parent}"
if [[ -L "${target_parent}" || ! -d "${target_parent}" ]]; then
  echo "poseidon2 crypto contract: target parent is not a plain directory ${target_parent}" >&2
  exit 1
fi
contract_root="$(mktemp -d "${target_parent}/poseidon2-crypto-contract.XXXXXX")"
contract_target="${contract_root}/cargo-target"
runner_manifest="${contract_root}/Cargo.toml"
runner_source="${contract_root}/src/main.rs"
oracle_input="${contract_root}/oracle-input.txt"
oracle_output="${contract_root}/oracle-output.txt"
expected_output="${contract_root}/expected-output.txt"
crypto_output="${contract_root}/crypto-output.txt"

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "poseidon2 crypto contract: missing ${path}" >&2
    exit 1
  fi
}

require_contains() {
  local path="$1"
  local needle="$2"
  if ! grep -Fq "${needle}" "${path}"; then
    echo "poseidon2 crypto contract: ${path} does not contain required contract: ${needle}" >&2
    exit 1
  fi
}

require_file "${fixture_source}"
require_file "${fixture_tests}"
require_file "${vector_file}"

require_contains "${fixture_source}" 'mod tests;'
require_contains "${fixture_tests}" 'poseidon2_bounded_matches_reviewed_noir_vector'
require_contains "${fixture_tests}" '35, 134, 74, 219, 22, 13, 221, 245'

node -e '
const fs = require("node:fs");
const [vectorPath, inputPath, outputPath] = process.argv.slice(1);
const lines = fs.readFileSync(vectorPath, "utf8").trimEnd().split("\n");
if (lines[0] !== "case\tinput\tcrypto_poseidon2_digest_bytes") {
  throw new Error("invalid vector header");
}
const inputs = [];
const outputs = [];
for (const line of lines.slice(1)) {
  const fields = line.split("\t");
  if (fields.length !== 3) {
    throw new Error("invalid vector row");
  }
  const input = fields[1] === "zero:515" ? Array(515).fill(0).join(",") : fields[1];
  inputs.push(input);
  outputs.push(fields[2]);
}
fs.writeFileSync(inputPath, `${inputs.join("\n")}\n`);
fs.writeFileSync(outputPath, `${outputs.join("\n")}\n`);
' "${vector_file}" "${oracle_input}" "${expected_output}"

cargo run \
  --manifest-path "${repo_root}/Cargo.toml" \
  --package reallyme-zk-noir-witness-core \
  --bin poseidon2-bounded-fixture \
  --quiet \
  < "${oracle_input}" \
  > "${oracle_output}"

if ! diff -u "${expected_output}" "${oracle_output}"; then
  echo "poseidon2 crypto contract: pinned reallyme-crypto-poseidon2 vectors do not match the ZK Noir fixture oracle" >&2
  exit 1
fi

mkdir -p "$(dirname "${runner_source}")"
cat > "${runner_manifest}" <<EOF
[package]
name = "reallyme-zk-poseidon2-crypto-contract-runner"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
${crypto_poseidon2_package} = { version = "=${crypto_poseidon2_version}", default-features = false }
EOF

cat > "${runner_source}" <<'EOF'
use crypto_poseidon2::{hash_bytes, Poseidon2Error};

fn print_hash(input: &[u8]) -> Result<(), Poseidon2Error> {
    let digest = hash_bytes(input)?;
    let bytes: Vec<String> = digest
        .as_bytes()
        .iter()
        .map(|byte| byte.to_string())
        .collect();
    println!("{}", bytes.join(","));
    Ok(())
}

fn main() -> Result<(), Poseidon2Error> {
    print_hash(&[])?;
    print_hash(&[0])?;
    print_hash(&[1, 2, 3])?;
    print_hash(&[1, 2, 3, 4])?;
    print_hash(&[0; 515])?;
    Ok(())
}
EOF

cargo generate-lockfile \
  --manifest-path "${runner_manifest}"

require_contains "${contract_root}/Cargo.lock" 'name = "reallyme-crypto-poseidon2"'
require_contains "${contract_root}/Cargo.lock" 'version = "0.3.17"'
require_contains "${contract_root}/Cargo.lock" 'source = "registry+https://github.com/rust-lang/crates.io-index"'

cargo run \
  --manifest-path "${runner_manifest}" \
  --locked \
  --target-dir "${contract_target}" \
  --quiet \
  > "${crypto_output}"

if ! diff -u "${oracle_output}" "${crypto_output}"; then
  echo "poseidon2 crypto contract: reallyme-crypto-poseidon2 output does not match the ZK Noir fixture oracle" >&2
  exit 1
fi

echo "poseidon2 crypto contract: reallyme-crypto-poseidon2 ${crypto_poseidon2_version} executable vectors match the ZK Noir fixture oracle"
