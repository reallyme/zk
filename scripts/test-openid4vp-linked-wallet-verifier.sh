#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENID4VP_DIR="${REALLYME_OPENID4VP_REPO:-$(cd "$ROOT_DIR/.." && pwd)/openid4vp}"
HARNESS_DIR="$ROOT_DIR/target/openid4vp-linked-wallet-verifier"
HARNESS_MANIFEST="$HARNESS_DIR/Cargo.toml"

if [[ ! -d "$OPENID4VP_DIR/crates/wallet" ]]; then
  echo "missing reallyme/openid4vp checkout at $OPENID4VP_DIR" >&2
  exit 1
fi

export REALLYME_ZK_ALL_CIRCUITS_V1_ROOT="${REALLYME_ZK_ALL_CIRCUITS_V1_ROOT:-$ROOT_DIR/circuits}"
export REALLYME_PRIVATE_PERSONA_TWO_CREDENTIAL_ROOT="${REALLYME_PRIVATE_PERSONA_TWO_CREDENTIAL_ROOT:-$ROOT_DIR/target/private-persona-openid4vp-fixtures-current}"
export REALLYME_PRIVATE_PERSONA_DIRECT_POST_ROOT="${REALLYME_PRIVATE_PERSONA_DIRECT_POST_ROOT:-$ROOT_DIR/target/private-persona-openid4vp-direct-post-fixtures-current}"
export REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_FIXTURE_ROOT="${REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_FIXTURE_ROOT:-$ROOT_DIR/target/common-credential-root-openid4vp-direct-post-fixtures-current}"
export REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_STAGE_REQUEST_ROOT="${REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_STAGE_REQUEST_ROOT:-$ROOT_DIR/target/common-credential-root-openid4vp-direct-post-stage-requests-current}"
export REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_SECOND_FIXTURE_ROOT="${REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_SECOND_FIXTURE_ROOT:-$ROOT_DIR/target/common-credential-root-openid4vp-second-request-fixtures-current}"
export REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_SECOND_STAGE_REQUEST_ROOT="${REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_SECOND_STAGE_REQUEST_ROOT:-$ROOT_DIR/target/common-credential-root-openid4vp-second-request-stage-requests-current}"
export REALLYME_BN254_G1_PATH="${REALLYME_BN254_G1_PATH:-$HOME/.bb-crs/bn254_g1.dat}"
export REALLYME_BN254_G2_PATH="${REALLYME_BN254_G2_PATH:-$HOME/.bb-crs/bn254_g2.dat}"
export REALLYME_BARRETENBERG_LIB_DIR="${REALLYME_BARRETENBERG_LIB_DIR:-$ROOT_DIR/build/native/apple-static-libs/darwinArm64}"
common_credential_root_release_root="${REALLYME_ZK_COMMON_CREDENTIAL_ROOT_RELEASE_ROOT:-$ROOT_DIR/build/native/ios-demo-resources/zk_demo}"
for required_asset in release-index.pb crs/bn254_g1.prover crs/bn254_g2; do
  if [[ ! -f "$common_credential_root_release_root/$required_asset" ]]; then
    echo "missing linked common-credential-root release asset: $common_credential_root_release_root/$required_asset" >&2
    exit 1
  fi
done
if [[ -n "${REALLYME_ZK_COMMON_CREDENTIAL_ROOT_RELEASE_ROOT:-}" ]]; then
  export REALLYME_ZK_DEMO_ASSET_ROOT="${REALLYME_ZK_DEMO_ASSET_ROOT:-$REALLYME_ZK_COMMON_CREDENTIAL_ROOT_RELEASE_ROOT}"
fi

mkdir -p "$HARNESS_DIR"
cat >"$HARNESS_MANIFEST" <<'HARNESS_CARGO_TOML'
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

[package]
name = "reallyme-zk-openid4vp-linked-wallet-verifier"
version = "0.1.0"
edition = "2021"
publish = false

[workspace]

[workspace.package]
edition = "2021"
rust-version = "1.99"
license = "MIT OR Apache-2.0"
repository = "https://github.com/reallyme/zk"
publish = false

[workspace.dependencies]
reallyme-openid4vp-runtime = { path = "../../../openid4vp/crates/runtime", default-features = false, features = ["native"] }
reallyme-openid4vp-types = { path = "../../../openid4vp/crates/types", default-features = false }
reallyme-openid4vp-verifier = { path = "../../../openid4vp/crates/verifier", default-features = false, features = ["native"] }
thiserror = "2.0"

[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "allow"

[workspace.lints.rustdoc]
broken_intra_doc_links = "deny"
bare_urls = "deny"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
unreachable = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
wildcard_imports = "deny"
large_include_file = "deny"

[[bin]]
name = "reallyme-zk-openid4vp-linked-wallet-verifier"
path = "../../conformance/openid4vp-linked-wallet-verifier/src/main.rs"

[dependencies]
openid4vci-issuer = { path = "../../../openid4vci/crates/issuer", features = ["identity-jose"] }
openid4vci-proto = { package = "reallyme-openid4vci-proto", path = "../../../openid4vci/crates/proto", features = ["generated"] }
openid4vci-proto-codec = { path = "../../../openid4vci/crates/proto-codec" }
openid4vci-types = { package = "reallyme-openid4vci-types", path = "../../../openid4vci/crates/types" }
reallyme-credential = { version = "=0.6.1", features = ["proto"] }
reallyme-credential-claims = { version = "=0.6.1" }
reallyme-credential-status = { version = "=0.6.1", features = ["proto"] }
reallyme-ssi-proto = { version = "=0.6.1" }
reallyme-identity = { path = "../../../identity/crates/identity" }
reallyme-identity-openid4vp-product = { path = "../../../identity/crates/openid4vp-product" }
reallyme-identity-openid4vp-product-store = { path = "../../../identity/crates/openid4vp-product-store" }
reallyme-openid4vp-dcql = { path = "../../../openid4vp/crates/dcql" }
reallyme-openid4vp-formats = { path = "../../../openid4vp/crates/formats", default-features = false, features = ["native"] }
reallyme-openid4vp-runtime = { path = "../../../openid4vp/crates/runtime", default-features = false, features = ["native"] }
reallyme-openid4vp-types = { path = "../../../openid4vp/crates/types", default-features = false }
reallyme-openid4vp-wallet = { path = "../../../openid4vp/crates/wallet", default-features = false, features = ["native", "jose"] }
reallyme-crypto = { version = "=0.3.17", default-features = false, features = ["dispatch", "ed25519", "jwk", "p256", "native"] }
crypto-p256 = { package = "reallyme-crypto-p256", version = "=0.3.17", default-features = false, features = ["native"] }
crypto-csprng = { package = "reallyme-crypto-csprng", version = "=0.3.17", default-features = false, features = ["native"] }
reallyme-jose = { version = "=0.4.6", default-features = false, features = ["jose-crypto"] }
reallyme-sd-jwt = { version = "=0.6.1", default-features = false, features = ["native"] }
reallyme-openid4vp-verifier = { path = "../../../openid4vp/crates/verifier", default-features = false, features = ["native"] }
reallyme-zk-api = { path = "../../crates/api" }
reallyme-zk-artifacts = { path = "../../crates/artifacts" }
reallyme-zk-backend-bb = { path = "../../crates/backend-bb", features = ["native"] }
reallyme-zk-platform-ffi = { path = "../../crates/platform-ffi", features = ["native"] }
reallyme-zk-proto = { path = "../../crates/proto", features = ["generated"] }
reallyme-zk-proto-codec = { path = "../../crates/proto-codec", features = ["native"] }
reallyme-zk-noir-witness-core = { path = "../../crates/noir-witness-core", default-features = false }
buffa = { version = "0.9.2", features = ["json"] }
libc = "0.2"
reallyme-codec = { version = "=0.3.2" }
secrecy = "0.10"
serde_json = "1.0"
sha2 = "0.10"
thiserror = "2.0"
toml = "1.2.1"
zeroize = "1.9"

[patch.crates-io]
openid4vci-issuer = { path = "../../../openid4vci/crates/issuer" }
reallyme-openid4vci-proto = { path = "../../../openid4vci/crates/proto" }
openid4vci-proto-codec = { path = "../../../openid4vci/crates/proto-codec" }
reallyme-openid4vci-types = { path = "../../../openid4vci/crates/types" }
reallyme-zk-api = { path = "../../crates/api" }
reallyme-openid4vp-dc-api = { path = "../../../openid4vp/crates/dc-api" }
reallyme-openid4vp-dcql = { path = "../../../openid4vp/crates/dcql" }
reallyme-openid4vp-formats = { path = "../../../openid4vp/crates/formats" }
reallyme-openid4vp-proto = { path = "../../../openid4vp/crates/proto" }
reallyme-openid4vp-proto-codec = { path = "../../../openid4vp/crates/proto-codec" }
reallyme-openid4vp-runtime = { path = "../../../openid4vp/crates/runtime" }
reallyme-openid4vp-types = { path = "../../../openid4vp/crates/types" }
reallyme-openid4vp-verifier = { path = "../../../openid4vp/crates/verifier" }
reallyme-openid4vp-wallet = { path = "../../../openid4vp/crates/wallet" }

[patch."https://github.com/reallyme/ssi"]
# Source-only adapters share the published public types with this harness.
reallyme-compression-brotli = { version = "=0.6.1" }
reallyme-credential = { version = "=0.6.1" }
reallyme-credential-audit = { version = "=0.6.1" }
reallyme-credential-claims = { version = "=0.6.1" }
reallyme-credential-status = { version = "=0.6.1" }
reallyme-did-types = { version = "=0.6.1" }
reallyme-disclosure-policy = { version = "=0.6.1" }
reallyme-mdoc = { version = "=0.6.1" }
reallyme-openid-oauth = { version = "=0.6.1" }
reallyme-openid4vc-profiles = { version = "=0.6.1" }
reallyme-revocation = { version = "=0.6.1" }
reallyme-sd-jwt = { version = "=0.6.1" }
reallyme-ssi-core = { version = "=0.6.1" }
reallyme-ssi-proto = { version = "=0.6.1" }
reallyme-ssi-proto-codec = { version = "=0.6.1" }
reallyme-trust-core = { version = "=0.6.1" }
reallyme-trust-x509 = { version = "=0.6.1" }
reallyme-vp-core = { version = "=0.6.1" }
HARNESS_CARGO_TOML

if [[ ! -d "$REALLYME_PRIVATE_PERSONA_TWO_CREDENTIAL_ROOT" ]]; then
  REALLYME_PRIVATE_PERSONA_BINDING_CONTEXT=openid4vp-dc-api cargo run \
    --offline \
    --manifest-path "$ROOT_DIR/crates/demo-fixture-generator/Cargo.toml" \
    --bin generate-private-persona-distinct-fixtures \
    -- generate "$REALLYME_PRIVATE_PERSONA_TWO_CREDENTIAL_ROOT"
else
  REALLYME_PRIVATE_PERSONA_BINDING_CONTEXT=openid4vp-dc-api cargo run \
    --offline \
    --manifest-path "$ROOT_DIR/crates/demo-fixture-generator/Cargo.toml" \
    --bin generate-private-persona-distinct-fixtures \
    -- check "$REALLYME_PRIVATE_PERSONA_TWO_CREDENTIAL_ROOT"
fi

if [[ ! -d "$REALLYME_PRIVATE_PERSONA_DIRECT_POST_ROOT" ]]; then
  REALLYME_PRIVATE_PERSONA_BINDING_CONTEXT=openid4vp-direct-post cargo run \
    --offline \
    --manifest-path "$ROOT_DIR/crates/demo-fixture-generator/Cargo.toml" \
    --bin generate-private-persona-distinct-fixtures \
    -- generate "$REALLYME_PRIVATE_PERSONA_DIRECT_POST_ROOT"
else
  REALLYME_PRIVATE_PERSONA_BINDING_CONTEXT=openid4vp-direct-post cargo run \
    --offline \
    --manifest-path "$ROOT_DIR/crates/demo-fixture-generator/Cargo.toml" \
    --bin generate-private-persona-distinct-fixtures \
    -- check "$REALLYME_PRIVATE_PERSONA_DIRECT_POST_ROOT"
fi

cargo generate-lockfile \
  --manifest-path "$HARNESS_MANIFEST" \
  --offline

binding_env="$HARNESS_DIR/common-credential-root-direct-post-binding.env"
cargo run \
  --manifest-path "$HARNESS_MANIFEST" \
  --offline \
  --locked \
  -- --write-common-credential-root-binding "$binding_env"

direct_post_challenge_hex="$(sed -n 's/^challenge_hex=//p' "$binding_env")"
direct_post_audience_hex="$(sed -n 's/^audience_hex=//p' "$binding_env")"
absent_transaction_hex="$(sed -n 's/^transaction_hex=//p' "$binding_env")"

python3 "$ROOT_DIR/circuits/sha256/families/common_credential_root_v1/generate_split_fixtures.py" \
  --output-root "$REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_FIXTURE_ROOT/sha256/families/common_credential_root_v1" \
  --challenge-hex "$direct_post_challenge_hex" \
  --audience-hex "$direct_post_audience_hex" \
  --transaction-hex "$absent_transaction_hex"
python3 "$ROOT_DIR/circuits/poseidon2/families/common_credential_root_v1/generate_split_fixtures.py" \
  --output-root "$REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_FIXTURE_ROOT/poseidon2/families/common_credential_root_v1" \
  --challenge-hex "$direct_post_challenge_hex" \
  --audience-hex "$direct_post_audience_hex" \
  --transaction-hex "$absent_transaction_hex"
python3 "$ROOT_DIR/scripts/generate-common-credential-root-stage-requests.py" \
  generate "$REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_STAGE_REQUEST_ROOT" \
  --fixture-root "$REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_FIXTURE_ROOT"

second_binding_env="$HARNESS_DIR/common-credential-root-second-binding.env"
cargo run \
  --manifest-path "$HARNESS_MANIFEST" \
  --offline \
  --locked \
  -- --write-second-common-credential-root-binding "$second_binding_env"
second_challenge_hex="$(sed -n 's/^challenge_hex=//p' "$second_binding_env")"
second_audience_hex="$(sed -n 's/^audience_hex=//p' "$second_binding_env")"
second_transaction_hex="$(sed -n 's/^transaction_hex=//p' "$second_binding_env")"
python3 "$ROOT_DIR/circuits/sha256/families/common_credential_root_v1/generate_split_fixtures.py" \
  --output-root "$REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_SECOND_FIXTURE_ROOT/sha256/families/common_credential_root_v1" \
  --challenge-hex "$second_challenge_hex" \
  --audience-hex "$second_audience_hex" \
  --transaction-hex "$second_transaction_hex"
python3 "$ROOT_DIR/circuits/poseidon2/families/common_credential_root_v1/generate_split_fixtures.py" \
  --output-root "$REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_SECOND_FIXTURE_ROOT/poseidon2/families/common_credential_root_v1" \
  --challenge-hex "$second_challenge_hex" \
  --audience-hex "$second_audience_hex" \
  --transaction-hex "$second_transaction_hex"
python3 "$ROOT_DIR/scripts/generate-common-credential-root-stage-requests.py" \
  generate "$REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_SECOND_STAGE_REQUEST_ROOT" \
  --fixture-root "$REALLYME_COMMON_CREDENTIAL_ROOT_DIRECT_POST_SECOND_FIXTURE_ROOT"

cargo run \
  --manifest-path "$HARNESS_MANIFEST" \
  --offline \
  --locked

REALLYME_ZK_PLATFORM_DEMO_FIXTURES_REQUIRED=1 \
cargo test -p reallyme-zk-platform-ffi \
  --offline \
  --locked \
  --test demo_fixture_witness_tests \
  mobile_package_verifies_both_hashes_and_persona_modes \
  --features native \
  -- --ignored --exact --nocapture

# This gate compares canonical mobile fixture bytes, including their fixed
# session binding. The linked protocol run above checks its own request bindings.
REALLYME_ZK_PLATFORM_DEMO_FIXTURES_REQUIRED=1 \
REALLYME_ZK_COMMON_CREDENTIAL_ROOT_FIXTURE_ROOT="$ROOT_DIR/circuits" \
REALLYME_ZK_COMMON_CREDENTIAL_ROOT_STAGE_REQUEST_ROOT="$ROOT_DIR/vectors/common-credential-root-stage-requests-v1" \
cargo test -p reallyme-zk-platform-ffi \
  --offline \
  --locked \
  --test demo_fixture_witness_tests \
  mobile_package_proves_every_common_credential_root_stage \
  --features native \
  -- --ignored --nocapture
