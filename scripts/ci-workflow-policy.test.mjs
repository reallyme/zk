#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const readWorkflow = (name) => readFileSync(`.github/workflows/${name}`, "utf8");

const PUBLIC_CRATES = [
  "reallyme-zk-api",
  "reallyme-zk-artifacts",
  "reallyme-zk-proto",
];

const workflows = [
  "crates-package-preflight.yml",
  "crates-release.yml",
  "fuzz.yml",
  "protobuf-ci.yml",
  "repository-security.yml",
  "rust-ci.yml",
  "secret-scan.yml",
  "sealed-release-attestation-policy.yml",
  "sealed-release-attestation.yml",
  "sealed-release-package-attestation.yml",
  "swift-package-preflight.yml",
  "swift-package-release.yml",
].map((name) => readWorkflow(name)).join("\n");

const count = (source, fragment) => source.split(fragment).length - 1;

const jobSource = (source, jobName) => {
  const marker = `  ${jobName}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, jobName);
  const remainder = source.slice(start + marker.length);
  const nextJob = remainder.search(/^  [a-z0-9][a-z0-9-]*:\n/mu);
  return nextJob === -1 ? source.slice(start) : source.slice(start, start + marker.length + nextJob);
};

test("Linux circuit gates select an executable identity present in the toolchain lock", () => {
  const lock = JSON.parse(readFileSync("circuits/toolchain-lock.json", "utf8"));
  for (const name of [
    "test-modern-production-circuits.sh",
    "test-modern-soundness-regressions.sh",
    "test-modern-linked-cli-cross-verify.sh",
  ]) {
    const source = readFileSync(`scripts/${name}`, "utf8");
    const host = /Linux:x86_64\)\s*(?:echo|printf)\s+["']([^"']+)["']/u.exec(source)?.[1];
    assert.ok(host, name);
    const identity = lock.candidateMatchedPair.localBinaryIdentities[host];
    assert.ok(identity, `${name}: missing executable identity`);
    assert.match(identity.nargoExecutableSha256, /^[0-9a-f]{64}$/u);
    assert.match(identity.barretenbergExecutableSha256, /^[0-9a-f]{64}$/u);
  }
});

test("expensive workspace validation has one CI owner", () => {
  for (const command of [
    "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
    "scripts/check-open-stack-boundaries.sh",
    "cargo deny --locked check",
  ]) {
    assert.equal(count(workflows, command), 1, command);
  }
  const protobuf = readWorkflow("protobuf-ci.yml");
  const preflight = readWorkflow("crates-package-preflight.yml");
  assert.equal(count(protobuf, "\n          scripts/check-generated-protos.sh\n"), 1);
  assert.match(protobuf, /buf format --diff --exit-code crates\/proto\/proto/u);
  assert.match(protobuf, /scripts\/check-proto-breaking[.]sh/u);
  assert.match(readFileSync("scripts/check-proto-breaking.sh", "utf8"), /buf breaking --against/u);
  assert.match(protobuf, /scripts\/check-generated-protos[.]sh/u);
  assert.match(
    readFileSync("scripts/check-generated-protos.sh", "utf8"),
    /scripts\/generate-zk-platform-protos[.]sh[\s\S]*diff -r -q/u,
  );
  assert.match(preflight, /scripts\/check-proto-breaking[.]sh/u);
});

test("Rust CI tests the public API without backend features", () => {
  const rustCi = readWorkflow("rust-ci.yml");
  assert.equal(
    count(rustCi, "cargo test --locked -p reallyme-zk-api --no-default-features"),
    1,
  );
});

test("package preflight consumes exact-commit CI evidence instead of rerunning CI", () => {
  const preflight = readWorkflow("crates-package-preflight.yml");
  assert.match(preflight, /node scripts\/verify_required_ci[.]mjs/u);
  for (const duplicate of [
    "cargo fmt",
    "cargo clippy",
    "cargo test",
    "cargo nextest",
    "buf lint",
    "check-generated-protos",
    "check-open-stack-boundaries",
    "cargo deny",
  ]) {
    assert.doesNotMatch(preflight, new RegExp(duplicate, "u"));
  }
  assert.match(preflight, /scripts\/run-gitleaks[.]sh/u);
  assert.match(preflight, /scripts\/audit_committed_lockfiles[.]sh/u);
  assert.match(preflight, /node [.]release-readiness\/scripts\/run-consumer-check[.]mjs/u);
  assert.match(preflight, /run-consumer-check[.]mjs --policy-only/u);
});

test("credentialed release consumes reviewed archives without rerunning package preflight", () => {
  const release = readWorkflow("crates-release.yml");
  assert.doesNotMatch(release, /publish-crates-in-order[.]mjs preflight/u);
  assert.match(release, /REVIEWED_CRATE_DIRECTORY: reviewed-crates/u);
  assert.match(release, /PUBLICATION_LEDGER_PATH:/u);
  assert.match(release, /gh attestation verify/u);
  assert.match(release, /prepare-source-release:/u);
  assert.match(release, /finalize:/u);
});

test("maintainer and release jobs use Rust 1.99.0 while one narrow job proves the public MSRV", () => {
  const repositoryToolchain = readFileSync("rust-toolchain.toml", "utf8");
  const workspaceManifest = readFileSync("Cargo.toml", "utf8");
  const rustCi = readWorkflow("rust-ci.yml");

  assert.match(repositoryToolchain, /channel = "1[.]99[.]0"/u);
  assert.match(workspaceManifest, /rust-version = "1[.]99"/u);

  for (const workflow of [
    "crates-package-preflight.yml",
    "crates-release.yml",
    "protobuf-ci.yml",
      "rust-ci.yml",
    "sealed-release-attestation.yml",
    "sealed-release-package-attestation.yml",
  ]) {
    assert.match(readWorkflow(workflow), /toolchain: 1[.]99[.]0/u, workflow);
  }

  const msrvJob = jobSource(rustCi, "public-crate-msrv");
  assert.match(msrvJob, /toolchain: 1[.]99[.]0/u);
  assert.match(msrvJob, /cargo [+]1[.]99[.]0 check --locked --all-features/u);
  assert.doesNotMatch(msrvJob, /--workspace/u);
  assert.deepEqual(
    [...msrvJob.matchAll(/--package ([a-z0-9-]+)/gu)].map((match) => match[1]),
    PUBLIC_CRATES,
  );
});

test("crates.io release uses the protected token environment without OIDC", () => {
  const release = readWorkflow("crates-release.yml");
  const prepare = jobSource(release, "prepare-source-release");
  const publish = jobSource(release, "publish");
  const finalize = jobSource(release, "finalize");
  assert.match(release, /environment: crates-io/u);
  assert.match(prepare, /environment: crates-io/u);
  assert.match(prepare, /contents: write/u);
  assert.match(publish, /environment: crates-io/u);
  assert.match(finalize, /environment: crates-io/u);
  assert.match(finalize, /contents: write/u);
  assert.match(release, /CARGO_REGISTRY_TOKEN: [$][{][{] secrets[.]CARGO_REGISTRY_TOKEN [}][}]/u);
  assert.doesNotMatch(release, /id-token: write/u);
  assert.doesNotMatch(release, /environment: crates-release/u);
});

test("Rust CI always reports an aggregate while its classifier skips unrelated work", () => {
  const rustCi = readWorkflow("rust-ci.yml");
  const triggers = rustCi.slice(rustCi.indexOf("on:"), rustCi.indexOf("permissions:"));
  assert.doesNotMatch(triggers, /paths(?:-ignore)?:/u);
  assert.match(jobSource(rustCi, "changes"), /node scripts\/select-ci-scope[.]mjs/u);
  for (const job of ["rust-checks", "workspace-tests", "package-archives", "semver", "security-mutations", "public-crate-msrv"]) {
    assert.ok(jobSource(rustCi, job).includes("if: needs.changes.outputs.source == 'true'"));
  }
});

test("Rust CI checks fuzz contracts and documentation misuse guards", () => {
  const rustCi = readWorkflow("rust-ci.yml");
  const audit = jobSource(rustCi, "rust-checks");
  assert.match(rustCi, /cargo check --locked --manifest-path fuzz\/Cargo[.]toml --bins/u);
  assert.match(rustCi, /cargo test --locked --workspace --all-features --doc/u);
  assert.match(rustCi, /cargo nextest run --locked -p reallyme-zk-cli --no-default-features/u);
  assert.match(rustCi, /node scripts\/check-release-readiness-policy-lock[.]mjs/u);
  assert.match(rustCi, /run-consumer-check[.]mjs --policy-only/u);
  assert.match(rustCi, /--exclude reallyme-zk-noir-witness-core[\s\S]*--target wasm32-unknown-unknown/u);
  assert.match(audit, /repository: reallyme\/ssi[\s\S]*ref: 77f5c5874403599e64c1bc79fe40ed54cfcf2e77/u);
  assert.match(audit, /repository: reallyme\/openid4vci[\s\S]*ref: 9ba35e61057dbbe1c56515c400636721469ba4b7/u);
  assert.match(audit, /repository: reallyme\/openid4vp[\s\S]*ref: 90d5a5a7349268aed2d2945b1f9f96b7fe9bd8db/u);
  assert.match(audit, /REALLYME_ZK_REQUIRED_OPEN_STACK_CHECKOUTS: ssi,openid4vci,openid4vp/u);
});

test("workspace test lanes bound debug output without reducing coverage", () => {
  const tests = jobSource(readWorkflow("rust-ci.yml"), "workspace-tests");
  assert.match(tests, /lane: \[native, all-features, default\]/u);
  assert.match(tests, /CARGO_PROFILE_DEV_DEBUG: "0"/u);
  assert.match(tests, /CARGO_PROFILE_TEST_DEBUG: "0"/u);
  assert.match(tests, /CARGO_INCREMENTAL: "0"/u);
  assert.match(tests, /node scripts\/run_bounded_nextest[.]mjs "\$TEST_LANE"/u);
});

test("circuit CI hydrates offline tests before proving and retains complete advisory ancestry", () => {
  const production = jobSource(readWorkflow("rust-ci.yml"), "production-circuits");
  const fetch = "cargo fetch --locked --target x86_64-unknown-linux-gnu";
  assert.ok(production.includes(fetch));
  assert.ok(production.indexOf(fetch) < production.indexOf("scripts/test-modern-production-circuits.sh"));
  const compile = "cargo test --locked --offline --no-run -p reallyme-zk-noir-witness-core";
  assert.ok(production.includes(compile));
  assert.ok(production.indexOf(compile) < production.indexOf("scripts/test-modern-production-circuits.sh"));
  assert.match(production, /RUSTFLAGS: -Dwarnings/u);
  assert.match(production, /CARGO_PROFILE_DEV_DEBUG: "0"/u);
  assert.match(production, /CARGO_PROFILE_TEST_DEBUG: "0"/u);
  assert.match(production, /path: noir\n\s+fetch-depth: 0\n[\s\S]*?filter: blob:none/u);
  const witnessTests = readFileSync("scripts/test-persona-credential-evidence-linked-proofs.py", "utf8");
  assert.ok(witnessTests.includes('"--offline"'));
  assert.ok(witnessTests.includes('"--locked"'));
});

test("canonical witness parity runs before joined gates reuse Nargo witness paths", () => {
  const production = jobSource(readWorkflow("rust-ci.yml"), "production-circuits");
  const prove = production.indexOf("scripts/test-modern-production-circuits.sh");
  const parity = production.indexOf("execution::tests::opt_in_all_circuits_v1_fixture_witness_parity");
  const joined = production.indexOf("scripts/test-common-credential-root-production-circuits.sh");
  assert.ok(prove !== -1 && parity !== -1 && joined !== -1);
  assert.ok(prove < parity && parity < joined);
});

test("platform source tests run on their own capable runners", () => {
  const rustCi = readWorkflow("rust-ci.yml");
  const swift = jobSource(rustCi, "swift-package");
  const kotlin = jobSource(rustCi, "kotlin-package");
  assert.match(swift, /runs-on: xcode-27/u);
  assert.match(swift, /scripts\/build_swift_xcframework[.]sh/u);
  assert.match(swift, /prepare_swift_binary_manifest[.]mjs/u);
  assert.match(swift, /--local-artifact-path build\/native\/apple-platform-ffi\/ReallyMeZKPlatformFFI[.]xcframework/u);
  assert.match(swift, /check-apple-platform-ffi-freshness[.]sh/u);
  assert.doesNotMatch(swift, /--hydrate --swift-only/u);
  assert.match(swift, /swift build -Xswiftc -warnings-as-errors/u);
  assert.match(swift, /swift test -Xswiftc -warnings-as-errors/u);
  assert.match(kotlin, /needs: \[changes, public-artifacts, android-target\]/u);
  assert.match(kotlin, /android-native-source-\$\{\{ github[.]sha \}\}/u);
  assert.match(kotlin, /--check --mobile-only --unpack-mobile-public-artifacts/u);
  assert.match(kotlin, /:android-native:check/u);
  assert.match(kotlin, /scripts\/prepare_android_native_manifest[.]mjs/u);
  assert.match(kotlin, /java-version: \|[\s\S]*\n\s+17[\s\S]*\n\s+21/u);
  assert.match(kotlin, /:demo-android:testDebugUnitTest/u);
  assert.match(kotlin, /ANDROID_PACKAGING_NDK_VERSION: 30[.]0[.]16248370/u);
  assert.match(kotlin, /sdkmanager" --install "ndk;\$\{ANDROID_PACKAGING_NDK_VERSION\}"/u);
  assert.match(kotlin, /test -x .*llvm-strip/u);
  assert.match(
    readFileSync("packages/kotlin/android-native/build.gradle.kts", "utf8"),
    /ndkVersion = "30[.]0[.]16248370"/u,
  );
});

test("Kotlin prepares its Rust integrity checker before offline demo asset staging", () => {
  const kotlin = jobSource(readWorkflow("rust-ci.yml"), "kotlin-package");
  const fetch = "cargo fetch --locked --target x86_64-unknown-linux-gnu";
  const build = "cargo build --locked --offline -p reallyme-zk-artifact-package --bin check-mobile-runtime";
  const gradle = "./packages/kotlin/gradlew";
  assert.match(kotlin, /name: Install Rust for offline mobile artifact validation[\s\S]*toolchain: 1[.]99[.]0/u);
  assert.match(kotlin, /shared-key: mobile-artifact-checker/u);
  assert.ok(kotlin.includes(fetch));
  assert.ok(kotlin.includes(build));
  assert.ok(kotlin.indexOf(fetch) < kotlin.indexOf(build));
  assert.ok(kotlin.indexOf(build) < kotlin.indexOf(gradle));
  assert.match(
    readFileSync("scripts/stage-demo-mobile-assets.mjs", "utf8"),
    /"cargo",[\s\S]*"run", "--quiet", "--locked", "--offline"/u,
  );
});

test("Android native CI reuses verified upstream libraries and builds only on a cache miss", () => {
  const rust = readWorkflow("rust-ci.yml");
  const mobile = jobSource(rust, "android-target");
  assert.match(mobile, /aarch64-linux-android/u);
  assert.match(mobile, /actions\/cache\/restore@caa296126883cff596d87d8935842f9db880ef25/u);
  assert.match(mobile, /actions\/cache\/save@caa296126883cff596d87d8935842f9db880ef25/u);
  assert.match(mobile, /hashFiles\('zk\/circuits\/toolchain-lock[.]json', 'zk\/scripts\/build_android_barretenberg_static_archive[.]sh', 'zk\/scripts\/install-android-native-ci-toolchain[.]sh'\)/u);
  assert.doesNotMatch(mobile, /restore-keys:/u);
  assert.match(mobile, /name: Install pinned Android native build tools\n\s+if: steps[.]android-libraries[.]outputs[.]cache-hit != 'true'/u);
  assert.match(mobile, /name: Build pinned Android Barretenberg static archive\n\s+if: steps[.]android-libraries[.]outputs[.]cache-hit != 'true'/u);
  assert.match(mobile, /scripts\/build_android_barretenberg_static_archive[.]sh --verify-only/u);
  assert.ok(mobile.indexOf("--verify-only") < mobile.indexOf("name: Cache verified Android upstream libraries"));
  assert.ok(mobile.indexOf("--verify-only") < mobile.indexOf("name: Check Android native platform FFI"));
  assert.match(mobile, /cache-hit != 'true' && github[.]event_name != 'pull_request'/u);
  assert.doesNotMatch(rust, /--android-libraries-only|native\/android-arm64/u);
  assert.match(mobile, /public-ci-artifacts-\$\{\{ github[.]sha \}\}/u);
  assert.match(
    mobile,
    /ANDROID_ARM64_BB_LIB_DIR=.*build\/native\/android-barretenberg-static\/arm64-v8a/u,
  );
  assert.match(mobile, /reallyme-zk-platform-ffi --features native --target/u);
  assert.match(mobile, /scripts\/build_android_platform_ffi_static[.]sh/u);
  const androidFfiBuild = readFileSync("scripts/build_android_platform_ffi_static.sh", "utf8");
  assert.match(androidFfiBuild, /CARGO_PROFILE="\$\{CARGO_PROFILE:-mobile-release\}"/u);
  assert.match(androidFfiBuild, /cargo build\s+\\\n\s+--locked\s+\\\n\s+--profile "\$\{CARGO_PROFILE\}"/u);
  assert.match(mobile, /--workspace --no-default-features --target/u);
  const androidBuilder = readFileSync("scripts/build_android_barretenberg_static_archive.sh", "utf8");
  assert.match(androidBuilder, /sourceArchiveName/u);
  assert.match(androidBuilder, /libdeflate-1[.]24/u);
  assert.match(androidBuilder, /-ffile-prefix-map=/u);
  assert.match(androidBuilder, /archive_identity="\$\{pin\}[.]linuxSourceBuild"/u);
  assert.match(androidFfiBuild, /linux_identity="\$\{ANDROID_LOCK_PATH\}[.]linuxSourceBuild"/u);
  const android = JSON.parse(readFileSync("circuits/toolchain-lock.json", "utf8"))
    .candidateMatchedPair.barretenberg.linkableStaticLibraries.androidArm64;
  assert.equal(android.sha256, "cc13d44bba54876d8d1faff871e41182865f09bdf0980c53ca61f3963d589033");
  assert.equal(android.linuxSourceBuild.size, android.size);
  assert.equal(android.linuxSourceBuild.sha256, "b96bea854cec9079a2427ba7edac3f36c92cba91be1b809dea84abbffc6b1f8f");
  assert.equal(android.linuxSourceBuild.companionStaticLibraries[0].sha256,
    "b498017ff17aa277f09fb7f0913c087404c0739bf6323b18ab44b118b5efc51a");
});

test("Swift binary release promotes the pinned XCFramework verified by preflight", () => {
  const preflight = readWorkflow("swift-package-preflight.yml");
  const release = readWorkflow("swift-package-release.yml");
  assert.match(preflight, /runs-on: xcode-27/u);
  assert.match(
    preflight,
    /uses: dtolnay\/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c[^\n]*\n +with:\n +toolchain: 1[.]99[.]0\n +components: llvm-tools-preview[\s\S]*?name: Verify SwiftPM manifest and pinned release archive/u,
  );
  assert.doesNotMatch(preflight, /scripts\/build_swift_xcframework[.]sh/u);
  assert.match(preflight, /REALLYME_ZK_ARTIFACT_TRANSPORT: r2/u);
  assert.match(preflight, /release-artifact-cache[.]mjs --hydrate --distribution-only --swift-only/u);
  assert.match(preflight, /packages\/swift\/ReallyMeZKPlatformFFI[.]xcframework[.]build[.]tsv/u);
  assert.match(preflight, /scripts\/check-apple-platform-ffi-freshness[.]sh/u);
  assert.match(preflight, /node scripts\/verify_required_ci[.]mjs/u);
  assert.match(preflight, /REQUIRED_CI_WAIT_SECONDS: "0"/u);
  assert.match(
    preflight,
    /swift-xcframework-\$\{\{ inputs[.]version \}\}-\$\{\{ needs[.]verify-source-sha[.]outputs[.]release_sha \}\}/u,
  );
  assert.match(preflight, /scripts\/verify_swift_release_artifact[.]mjs/u);
  assert.match(
    preflight,
    /--local-artifact-path build\/native\/apple-platform-ffi\/ReallyMeZKPlatformFFI[.]xcframework/u,
  );
  assert.match(preflight, /swift test -Xswiftc -warnings-as-errors[\s\S]*?name: Upload verified Swift release candidate/u);
  assert.match(preflight, /run-consumer-check[.]mjs --policy-only\s*$/mu);
  assert.match(preflight, /scripts\/verify_swift_release_preflight[.]test[.]mjs/u);
  assert.equal([...release.matchAll(/node scripts\/verify_swift_release_preflight[.]mjs/gu)].length, 2);
  assert.doesNotMatch(release, /verify_release_attestation[.]mjs|prepare_swift_binary_manifest[.]mjs/u);
  assert.match(
    release,
    /actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/u,
  );
  assert.match(release, /scripts\/verify_swift_release_artifact[.]mjs/u);
  assert.match(release, /git tag "v\$\{RELEASE_VERSION\}" "\$\{RELEASE_SHA\}"/u);
  assert.match(release, /gh release create "v\$\{RELEASE_VERSION\}"/u);
});

test("release gates use admitted inputs without probing public SDK download compatibility", () => {
  const crates = readWorkflow("crates-package-preflight.yml");
  const swift = readWorkflow("swift-package-release.yml");
  const manifest = readFileSync("Package.swift", "utf8");
  const cache = readFileSync("scripts/release-artifact-cache.mjs", "utf8");
  const rust = readWorkflow("rust-ci.yml");
  assert.doesNotMatch(crates, /--verify-remote/u);
  assert.doesNotMatch(swift, /--verify-remote/u);
  assert.ok(manifest.includes("https://static.reallyme.net/zk/swift/"));
  assert.ok(cache.includes('const defaultArtifactBaseUrl = "https://static.reallyme.net/zk";'));
  const artifactBases = [...rust.matchAll(/REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL: (\S+)/gu)];
  assert.ok(artifactBases.length > 0);
  for (const [, base] of artifactBases) {
    assert.equal(base, "https://static.reallyme.net/zk");
  }
  assert.doesNotMatch(manifest, /github[.]com\/reallyme\/zk\/releases\/download/u);
  const inputs = jobSource(rust, "public-artifacts");
  assert.match(inputs, /key: mobile-inputs-\$\{\{ hashFiles\('zk\/scripts\/release-artifact-cache[.]mjs', 'zk\/scripts\/release-artifact-manifest[.]mjs'\) \}\}/u);
  assert.ok(inputs.indexOf("name: Cache pinned circuit and CRS downloads") < inputs.indexOf("--hydrate --mobile-only"));
  assert.match(inputs, /REALLYME_ZK_ARTIFACT_TRANSPORT: \$\{\{ github[.]event_name == 'pull_request' && 'cdn' \|\| 'r2' \}\}/u);
  for (const secret of ["R2_ENDPOINT", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY"]) {
    const binding = secret + ": ${{ github.event_name != 'pull_request' && secrets." + secret + " || '' }}";
    assert.ok(inputs.includes(binding));
  }
  assert.doesNotMatch(workflows, /pull_request_target:/u);
});

test("preflight evidence and reviewed archives receive GitHub provenance attestations", () => {
  const preflight = readWorkflow("crates-package-preflight.yml");
  assert.match(preflight, /attestations: write/u);
  assert.match(preflight, /id-token: write/u);
  assert.equal(count(preflight, "actions/attest-build-provenance@"), 2);
  assert.match(preflight, /subject-path: release-attestation\/crates-preflight[.]json/u);
  assert.match(preflight, /subject-path: reviewed-crates\/[*][.]crate/u);
});

test("repository security workflows scan history and enforce private reporting", () => {
  const secretScan = readWorkflow("secret-scan.yml");
  const repositorySecurity = readWorkflow("repository-security.yml");
  assert.match(secretScan, /fetch-depth: 0/u);
  assert.match(secretScan, /scripts\/run-gitleaks[.]sh/u);
  assert.match(readFileSync("scripts/run-gitleaks.sh", "utf8"), /node scripts\/check-gitleaks-policy[.]mjs/u);
  assert.match(repositorySecurity, /private-vulnerability-reporting/u);
  assert.match(repositorySecurity, /grep -qx true/u);
});

test("native CI selects the pinned NDK and the matching Linux C++ runtime", () => {
  const rust = readWorkflow("rust-ci.yml");
  assert.match(jobSource(rust, "rust-checks"),
    /env:\n\s+CXX: clang[+][+]-20\n\s+REALLYME_ZK_REQUIRED_OPEN_STACK_CHECKOUTS: ssi,openid4vci,openid4vp/u);
  assert.match(rust, /ANDROID_PROVIDER_NDK_VERSION: 30[.]0[.]16248370/u);
  for (const tool of ["CC_aarch64_linux_android", "CXX_aarch64_linux_android", "AR_aarch64_linux_android",
    "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER", "LLVM_READELF"]) {
    assert.ok(rust.includes(`echo "${tool}=\${ndk_bin}/`));
  }
  for (const job of ["rust-checks", "workspace-tests", "production-circuits"]) {
    const source = jobSource(rust, job);
    assert.match(source, /CXX: clang[+][+]-20/u);
    assert.match(source, /apt-get install --yes clang-20 libc[+][+]-20-dev libc[+][+]abi-20-dev/u);
  }
  const mutation = jobSource(rust, "security-mutations");
  assert.match(mutation, /cargo mutants --gitignore true/u);
  assert.doesNotMatch(mutation, /--copy-target/u);
});

test("circuit fixtures use an explicit Python environment and verified binary dependencies", () => {
  const production = jobSource(readWorkflow("rust-ci.yml"), "production-circuits");
  assert.match(production, /actions\/setup-python@[0-9a-f]{40}/u);
  assert.match(production, /python-version: "3[.]12"/u);
  assert.match(production, /pip install --require-hashes --only-binary=:all: -r requirements-circuits-ci[.]txt/u);
});

test("release policy validates documentation-only changes", () => {
  const policy = readWorkflow("sealed-release-attestation-policy.yml");
  for (const governedPath of [
    '- "release-readiness-policy.lock.json"',
    '- "scripts/check-release-readiness-policy-lock.mjs"',
    '- "scripts/check-release-readiness-policy-lock.test.mjs"',
    '- "README.md"',
    '- "**/*.md"',
    '- "docs/**"',
    '- "provider_manifest.json"',
  ]) {
    assert.equal(count(policy, governedPath), 2, governedPath);
  }
  assert.match(policy, /reallyme-release-readiness --policy-only/u);
});

test("fuzz lanes build once and reuse bounded executables for every configured target", () => {
  const fuzz = readWorkflow("fuzz.yml");
  const runner = readFileSync("scripts/run-fuzz-smoke.sh", "utf8");
  const build = jobSource(fuzz, "build");
  const scheduled = jobSource(fuzz, "scheduled");
  assert.equal(count(build, 'cargo "+$FUZZ_TOOLCHAIN" fuzz build'), 1);
  assert.doesNotMatch(scheduled, /cargo .*fuzz (?:build|run)/u);
  assert.match(scheduled, /needs: build/u);
  assert.match(fuzz, /REALLYME_ZK_FUZZ_MAX_TOTAL_TIME: "20"/u);
  assert.match(fuzz, /REALLYME_ZK_FUZZ_MAX_TOTAL_TIME: "300"/u);
  assert.match(runner, /FUZZ_MAX_LEN=.*2097152/u);
  assert.match(runner, /FUZZ_RSS_LIMIT_MB=.*4096/u);
  assert.match(fuzz, /Retain evolved fuzz corpora/u);
  const targets = [...readFileSync("fuzz/Cargo.toml", "utf8").matchAll(/\[\[bin\]\]\s+name = "([a-z0-9_]+)"/gu)]
    .map((match) => match[1]).sort();
  const matrixTargets = [...scheduled.matchAll(/^          - ([a-z0-9_]+)$/gmu)]
    .map((match) => match[1]).sort();
  assert.deepEqual(matrixTargets, targets);
  for (const target of targets) assert.ok(runner.includes(`"${target}"`), target);
});

test("reusable sealed-release attestation admits only the main release caller", () => {
  const attestation = readWorkflow("sealed-release-attestation.yml");
  const caller = readWorkflow("sealed-release-package-attestation.yml");
  const admit = jobSource(attestation, "admit");
  const attest = jobSource(attestation, "attest");
  assert.doesNotMatch(attestation, /github[.]event_name == 'workflow_call'/u);
  assert.match(attestation, /github[.]ref == 'refs\/heads\/main'/u);
  assert.match(
    attestation,
    /github[.]workflow_ref == 'reallyme\/zk\/[.]github\/workflows\/sealed-release-package-attestation[.]yml@refs\/heads\/main'/u,
  );
  assert.match(caller, /require-attestation:/u);
  assert.match(caller, /needs: attest/u);
  assert.match(caller, /if: always\(\)/u);
  assert.match(caller, /ATTESTATION_RESULT: \$\{\{ needs[.]attest[.]result \}\}/u);
  assert.match(caller, /test "\$\{ATTESTATION_RESULT\}" = "success"/u);
  assert.doesNotMatch(caller, /file_count/u);
  assert.doesNotMatch(caller, /wc -l/u);
  assert.match(caller, /check-release-index-attestation/u);
  assert.match(caller, /check-release-source-attestation/u);
  assert.match(attestation, /check-release-source-attestation/u);
  assert.match(admit, /cargo run --locked -p reallyme-zk-artifact-package/u);
  assert.match(admit, /cargo run --locked -p reallyme-zk-release-assembly/u);
  assert.doesNotMatch(admit, /id-token: write/u);
  assert.match(attest, /needs: admit/u);
  assert.match(attest, /id-token: write/u);
  assert.doesNotMatch(attest, /cargo run/u);
  assert.match(attest, /sha256sum --check --strict/u);
});

test("Rust CI proves the hash-pinned toolchain and Noir regressions", () => {
  const rustCi = readWorkflow("rust-ci.yml");
  const production = jobSource(rustCi, "production-circuits");
  const download = production.indexOf("- name: Download admitted public mobile artifacts before proving");
  const toolchain = production.indexOf("- name: Install hash-pinned release binaries and full-prover CRS");
  assert.ok(download >= 0 && download < toolchain, "public download access is required before expensive proving");
  assert.equal(count(production, "--hydrate"), 0);
  const admission = jobSource(rustCi, "public-artifacts");
  assert.equal(count(admission, "--hydrate --mobile-only --unpack-mobile-public-artifacts"), 1);
  assert.match(production, /needs: \[changes, public-artifacts\]/u);
  assert.match(rustCi, /production-circuits:/u);
  assert.match(rustCi, /scripts\/install-modern-ci-toolchain[.]sh/u);
  assert.match(rustCi, /scripts\/check-noir-advisory-ancestry[.]sh/u);
  assert.match(rustCi, /scripts\/test-modern-production-circuits[.]sh/u);
  assert.match(rustCi, /REALLYME_ZK_ALL_CIRCUITS_V1_ROOT:.*\/zk\/circuits/u);
  assert.match(
    rustCi,
    /cargo test --locked -p reallyme-zk-noir-witness-core[\s\S]*execution::tests::opt_in_all_circuits_v1_fixture_witness_parity[\s\S]*-- --ignored --exact --nocapture/u,
  );
  assert.match(rustCi, /scripts\/check-poseidon2-crypto-contract[.]sh/u);
  assert.match(rustCi, /RUNS: \$\{\{ github[.]event_name == 'workflow_dispatch' && '3' \|\| '1' \}\}/u);
  assert.match(rustCi, /scripts\/test-modern-soundness-regressions[.]sh/u);
  assert.match(rustCi, /scripts\/test-modern-linked-all30-matrix[.]sh/u);
  assert.match(rustCi, /scripts\/test-modern-linked-cli-cross-verify[.]sh/u);
  assert.match(rustCi, /REALLYME_BN254_G1_PATH:.*modern-zk-tools\/crs\/bn254_g1[.]dat/u);
  assert.match(rustCi, /REALLYME_BN254_G2_PATH:.*modern-zk-tools\/crs\/bn254_g2[.]dat/u);
  assert.match(rustCi, /python3 scripts\/test-persona-credential-evidence-linked-proofs[.]py/u);
  const preparedPackStep = rustCi.indexOf("- name: Admit and stage sealed prepared mobile circuit pack");
  const preparedProofStep = rustCi.indexOf("- name: Prove and verify persona credential evidence claim and status circuits");
  assert.notEqual(preparedPackStep, -1);
  assert.notEqual(preparedProofStep, -1);
  assert.ok(
    preparedPackStep < preparedProofStep,
    "prepared FFI proofs require the admitted mobile artifact pack first",
  );
  assert.match(rustCi, /REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_NATIVE: '1'/u);
  assert.match(
    rustCi,
    /REALLYME_BARRETENBERG_LIB_DIR=\$\{RUNNER_TEMP\}\/modern-zk-tools\/lib\/linuxX86_64/u,
  );
  const preparedProofScript = readFileSync("scripts/test-persona-credential-evidence-linked-proofs.py", "utf8");
  assert.match(preparedProofScript, /mobile_package_verifies_prepared_proofs_from_exact_candidate/u);
  assert.match(preparedProofScript, /"--features", "native", "--lib"/u);
  assert.match(preparedProofScript, /"running 1 test"/u);
  assert.match(preparedProofScript, /run_exact_rust_test\([\s\S]*compiled_prepared_status_witness_matches_noir_in_both_lanes/u);
  assert.match(preparedProofScript, /run_exact_rust_test\([\s\S]*compiled_prepared_claim_witness_matches_noir_in_both_lanes/u);
  assert.match(preparedProofScript, /run_exact_rust_test\([\s\S]*fresh_prepared_proofs_verify_through_linked_library/u);
  assert.match(rustCi, /python3 scripts\/test-persona-credential-evidence-joined-circuits[.]py/u);
  assert.match(
    rustCi,
    /python3 scripts\/test-persona-credential-evidence-current-state-circuits[.]py/u,
  );
  assert.match(
    rustCi,
    /local_artifact_root="\$\{PWD\}\/build\/native"/u,
  );
  assert.match(
    rustCi,
    /demo_fixture="\$\{local_artifact_root\}\/ios-demo-resources\/zk_demo"/u,
  );
  assert.match(rustCi, /node scripts\/stage-demo-mobile-assets[.]mjs "\$\{demo_fixture\}"/u);
  assert.match(
    rustCi,
    /node scripts\/release-artifact-cache[.]mjs --check --mobile-only --unpack-mobile-public-artifacts/u,
  );
  assert.match(rustCi, /mobile-demo-artifacts-persona-credential-evidence-v1-candidate/u);
  assert.match(
    rustCi,
    /check-mobile-runtime -- \\\s*"\$\{persona_credential_evidence_artifacts\}" v1/u,
  );
  assert.match(rustCi, /generate-demo-flow-inputs -- check "\$\{PWD\}"/u);
  assert.match(rustCi, /REALLYME_ZK_PLATFORM_DEMO_FIXTURES_REQUIRED: "1"/u);
  assert.match(rustCi, /--test demo_fixture_witness_tests/u);
  assert.match(rustCi, /grep -Fq "running 0 tests"/u);
  assert.match(
    rustCi,
    /demo_stage_fixtures_dispatch_witness_release_prove_and_verify_through_platform_provider/u,
  );
  assert.match(
    rustCi,
    /test demo_stage_fixtures_dispatch_witness_release_prove_and_verify_through_platform_provider [.]{3} ok/u,
  );
  assert.match(rustCi, /mobile_package_verifies_both_hashes_and_persona_modes/u);
  assert.match(rustCi, /test mobile_package_verifies_both_hashes_and_persona_modes [.]{3} ok/u);
  assert.match(rustCi, /mobile_package_proves_every_common_credential_root_stage/u);
  assert.match(rustCi, /test mobile_package_proves_every_common_credential_root_stage [.]{3} ok/u);
  assert.match(rustCi, /repository: noir-lang\/noir/u);
  assert.match(rustCi, /ref: 275d3ab1a5c916c6ea73e8d6b943f685f574500c/u);
  assert.doesNotMatch(rustCi, /repository: reallyme\/crypto/u);
  assert.doesNotMatch(rustCi, /REALLYME_CRYPTO_REPO/u);
  assert.doesNotMatch(rustCi, /repository: reallyme\/noir(?:\n|\r)/u);
  assert.doesNotMatch(rustCi, /scripts\/test-production-circuits[.]sh/u);
});

test("pinned toolchain lock matches CI installer and proving gates", () => {
  const lock = JSON.parse(readFileSync("circuits/toolchain-lock.json", "utf8"));
  const rustCi = readWorkflow("rust-ci.yml");
  const installer = readFileSync("scripts/install-modern-ci-toolchain.sh", "utf8");
  const circuitTests = readFileSync("scripts/test-modern-production-circuits.sh", "utf8");
  const commonCredentialRootCircuitTests = readFileSync("scripts/test-common-credential-root-production-circuits.sh", "utf8");
  const soundnessTests = readFileSync("scripts/test-modern-soundness-regressions.sh", "utf8");
  assert.equal(lock.schemaVersion, 2);
  assert.equal(lock.candidateMatchedPair.status, "promoted");
  assert.equal(lock.candidateMatchedPair.expectedCircuitCount, 20);
  assert.match(rustCi, new RegExp(lock.candidateMatchedPair.noir.revision, "u"));
  assert.match(installer, /noir-x86_64-unknown-linux-gnu[.]tar[.]gz/u);
  assert.match(installer, /noir-aarch64-apple-darwin[.]tar[.]gz/u);
  assert.match(installer, /barretenberg-amd64-linux[.]tar[.]gz/u);
  assert.match(installer, /barretenberg-arm64-darwin[.]tar[.]gz/u);
  assert.match(installer, /darwinArm64/u);
  assert.match(installer, /linuxX86_64/u);
  assert.match(installer, /shasum -a 256/u);
  assert.match(installer, /crs[.]aztec-cdn[.]foundation\/g1[.]dat/u);
  assert.match(installer, /crs\/download-receipt[.]tsv/u);
  assert.match(installer, /--proto-redir '=https'/u);
  assert.match(rustCi, /name: Retain verified CRS download receipt/u);
  assert.match(rustCi, /modern-zk-tools\/crs\/download-receipt[.]tsv/u);
  assert.match(rustCi, /if-no-files-found: error/u);
  assert.match(circuitTests, /expected_g1_sha256/u);
  assert.match(circuitTests, /run_bb prove/u);
  assert.match(circuitTests, /run_bb verify/u);
  assert.match(rustCi, /scripts\/test-common-credential-root-production-circuits[.]sh/u);
  assert.match(rustCi, /scripts\/test-persona-credential-evidence-linked-proofs[.]py/u);
  assert.match(commonCredentialRootCircuitTests, /test-common-credential-root-joined-claims[.]sh/u);
  assert.match(commonCredentialRootCircuitTests, /generate-common-credential-root-stage-requests[.]py/u);
  assert.match(commonCredentialRootCircuitTests, /command -v protoc/u);
  assert.match(rustCi, /protoc-35[.]1-linux-x86_64[.]zip/u);
  assert.match(rustCi, /6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7/u);
  assert.match(rustCi, /libprotoc 35[.]1/u);
  assert.match(commonCredentialRootCircuitTests, /check-common-credential-root-ci-artifacts[.]mjs exact-artifacts/u);
  assert.doesNotMatch(commonCredentialRootCircuitTests, /write-exact-artifacts/u);
  assert.doesNotMatch(commonCredentialRootCircuitTests, /ISOLATED_HOME/u);
  assert.doesNotMatch(rustCi, /--bin generate-common-credential-root-mobile-fixtures/u);
  assert.match(rustCi, /check-common-credential-root-ci-artifacts[.]mjs mobile-fixtures/u);
  assert.match(soundnessTests, /expected_g1_sha256/u);
  assert.match(soundnessTests, /tampered-verify/u);
});

test("dependency policy evaluates the all-features graph", () => {
  const policy = readFileSync("deny.toml", "utf8");
  const rustCi = readWorkflow("rust-ci.yml");
  assert.match(policy, /^all-features = true$/mu);
  assert.match(rustCi, /--all-features --format-version 1/u);
  assert.match(rustCi, /[.]name == "reallyme-ssi-proto"/u);
});

test("package preflight enforces pinned public API compatibility", () => {
  const preflight = readWorkflow("crates-package-preflight.yml");
  assert.match(
    preflight,
    /tool: cargo-semver-checks@0[.]50[.]0/u,
  );
  assert.match(preflight, /node scripts\/check-public-crate-baselines[.]mjs/u);
});


test("required Rust check fails unless every validation owner succeeds", () => {
  const rustCi = readWorkflow("rust-ci.yml");
  const aggregate = jobSource(rustCi, "audit");
  assert.match(aggregate, /if: \$\{\{ always\(\) \}\}/u);
  for (const owner of ["rust-checks", "workspace-tests", "package-archives", "semver", "security-mutations",
    "public-crate-msrv", "swift-package", "kotlin-package", "android-target", "ios-target", "production-circuits", "public-artifacts"]) {
    assert.ok(aggregate.includes(`needs.${owner}.result`), owner);
  }
  assert.match(aggregate, /node scripts\/require-ci-results[.]mjs/u);
  for (const lane of ["source", "swift", "android", "ios", "circuits"]) {
    assert.ok(aggregate.includes(`needs.changes.outputs.${lane}`));
  }
});
