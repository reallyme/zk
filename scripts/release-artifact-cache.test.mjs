// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./release-artifact-cache.mjs", import.meta.url));
const sealedArchive = fileURLToPath(new URL(
  "../release-artifacts/modern-v1-bb-6.0.0/mobile-circuit-artifacts-persona-credential-evidence-v1.tar",
  import.meta.url,
));
const swiftArchive = fileURLToPath(new URL(
  "../release-artifacts/modern-v1-bb-6.0.0/swiftpm/ReallyMeZKPlatformFFI.xcframework.zip",
  import.meta.url,
));

test("mobile cache admission rejects extra files while preserving the existing directory", {
  skip: !existsSync(sealedArchive),
}, () => {
  const artifactRoot = mkdtempSync(join(tmpdir(), "reallyme-zk-public-cache-test-"));
  try {
    copyFileSync(sealedArchive, join(artifactRoot, "mobile-circuit-artifacts-persona-credential-evidence-v1.tar"));
    const run = () => spawnSync(process.execPath, [script, "--unpack-mobile-public-artifacts"], {
      encoding: "utf8",
      env: { ...process.env, REALLYME_ZK_LOCAL_ARTIFACT_ROOT: artifactRoot },
    });
    assert.equal(run().status, 0);
    assert.equal(run().status, 0);

    const target = join(artifactRoot, "mobile-demo-artifacts-persona-credential-evidence-v1-candidate");
    const extraDirectory = join(target, "v1", "v1", "verification-vectors");
    mkdirSync(extraDirectory, { recursive: true });
    const extraFile = join(extraDirectory, "unsealed.pb");
    writeFileSync(extraFile, "not part of the sealed archive");
    const rejected = run();
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /differs from the sealed archive/u);

    unlinkSync(extraFile);
    writeFileSync(join(target, "common-credential-root-v1", "poseidon2", "lineage", "program.json"), "changed program");
    const changed = run();
    assert.notEqual(changed.status, 0);
    assert.match(changed.stderr, /differs from the sealed archive/u);
  } finally {
    rmSync(artifactRoot, { force: true, recursive: true });
  }
});

test("Swift cache admission rejects an altered local XCFramework", {
  skip: process.platform !== "darwin" || !existsSync(swiftArchive),
}, () => {
  const artifactRoot = mkdtempSync(join(tmpdir(), "reallyme-zk-swift-cache-test-"));
  try {
    const archiveDirectory = join(artifactRoot, "swiftpm");
    mkdirSync(archiveDirectory);
    copyFileSync(swiftArchive, join(archiveDirectory, "ReallyMeZKPlatformFFI.xcframework.zip"));
    const run = () => spawnSync(process.execPath, [script, "--unpack-swift-xcframework"], {
      encoding: "utf8",
      env: { ...process.env, REALLYME_ZK_LOCAL_ARTIFACT_ROOT: artifactRoot },
    });
    assert.equal(run().status, 0);
    assert.equal(run().status, 0);

    const framework = join(artifactRoot, "apple-platform-ffi", "ReallyMeZKPlatformFFI.xcframework");
    writeFileSync(join(framework, "Info.plist"), "changed metadata");
    const changed = run();
    assert.notEqual(changed.status, 0);
    assert.match(changed.stderr, /differs from the pinned SwiftPM archive/u);
  } finally {
    rmSync(artifactRoot, { force: true, recursive: true });
  }
});

test("upload list includes the pinned Swift archive URL", {
  skip: !existsSync(swiftArchive),
}, () => {
  const result = spawnSync(process.execPath, [script, "--upload-list", "--distribution-only", "--swift-only"], {
    encoding: "utf8",
    env: {
      ...process.env,
      REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL: "https://static.reallyme.net/zk",
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const rows = result.stdout.trimEnd().split("\n");
  assert.equal(rows.length, 2);
  const columns = rows[1].split("\t");
  const digest = columns[2];
  assert.equal(digest.length, 64);
  assert.match(columns[1], new RegExp(`swift/${digest}/`, "u"));
});

test("artifact manifest rejects a stale content-addressed remote path", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "reallyme-zk-cache-manifest-test-"));
  try {
    const temporaryScript = join(temporaryRoot, "release-artifact-cache.mjs");
    copyFileSync(new URL("./static-upload-package.mjs", import.meta.url), join(temporaryRoot, "static-upload-package.mjs"));
    copyFileSync(new URL("./r2-artifact-source.mjs", import.meta.url), join(temporaryRoot, "r2-artifact-source.mjs"));
    const source = readFileSync(script, "utf8").replace(
      /swift\/[a-f0-9]{64}\/ReallyMeZKPlatformFFI[.]xcframework[.]zip/u,
      "swift/0000000000000000000000000000000011111111111111111111111111111111/ReallyMeZKPlatformFFI.xcframework.zip",
    );
    writeFileSync(temporaryScript, source);
    const result = spawnSync(process.execPath, [temporaryScript, "--list"], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /content-addressed remote path does not encode its SHA-256/u);
  } finally {
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
});

test("upload list rejects non-distribution artifacts", () => {
  const result = spawnSync(process.execPath, [script, "--upload-list"], {
    encoding: "utf8",
    env: {
      ...process.env,
      REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL: "https://static.reallyme.net/zk",
    },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /--upload-list and --stage-upload require --distribution-only/u);
});

test("upload list rejects ambiguous or unauthenticated CDN bases", () => {
  for (const baseUrl of [
    "http://static.reallyme.net/zk/",
    "https://user:secret@static.reallyme.net/zk/",
    "https://static.reallyme.net/zk/?v=1",
    "https://static.reallyme.net/zk/#fragment",
    "https://",
  ]) {
    const result = spawnSync(process.execPath, [script, "--upload-list", "--distribution-only", "--swift-only"], {
      encoding: "utf8",
      env: { ...process.env, REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL: baseUrl },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must be an HTTPS URL/u);
  }
});

test("static distribution contains only the six content-addressed runtime objects", () => {
  const result = spawnSync(process.execPath, [script, "--list", "--distribution-only"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const objects = result.stdout.trimEnd().split("\n").slice(1).map((row) => {
    const [, , remotePath, sha256, distribution] = row.split("\t");
    assert.equal(distribution, "yes");
    assert.ok(remotePath.split("/").includes(sha256));
    return remotePath.replace(sha256, "<sha256>");
  });
  assert.deepEqual(objects.sort(), [
    "circuits/<sha256>/mobile-circuits.tar",
    "cli/macos-arm64/<sha256>/reallyme-zk",
    "crs/<sha256>/bn254_g1.dat",
    "crs/<sha256>/bn254_g1.prover",
    "crs/<sha256>/bn254_g2.dat",
    "swift/<sha256>/ReallyMeZKPlatformFFI.xcframework.zip",
  ]);
});

test("mobile artifact selection excludes SDK binaries and unrelated registry artifacts", () => {
  const result = spawnSync(process.execPath, [script, "--list", "--mobile-only"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const paths = result.stdout.trim().split("\n").slice(1).map((row) => row.split("\t")[1]);
  assert.deepEqual(paths.sort(), ["mobile-circuit-artifacts-persona-credential-evidence-v1.tar", "cdn/crs/bn254_g1.prover", "cdn/crs/bn254_g2.dat"].sort());
  const conflicting = spawnSync(process.execPath, [script, "--list", "--mobile-only", "--swift-only"], { encoding: "utf8" });
  assert.notEqual(conflicting.status, 0);
});

test("rejected public downloads report only bounded edge diagnostics", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "reallyme-zk-edge-diagnostics-"));
  try {
    const preload = join(temporaryRoot, "fetch-fixture.mjs");
    const body = "response-body-must-remain-private";
    for (const [ray, expectedRay] of [
      ["0123456789abcdef-MRS", "0123456789abcdef-MRS"],
      ["untrusted-header-must-remain-private", "unavailable"],
    ]) {
      writeFileSync(preload, `globalThis.fetch = async (_url, options) => {
        if (options?.headers?.["User-Agent"] !== "ReallyMe-ZK-Artifact-Cache") {
          process.exit(93);
        }
        return new Response(${JSON.stringify(body)}, { status: 403,
          headers: { "cf-ray": ${JSON.stringify(ray)}, "cf-mitigated": "challenge" } });
      };\n`);
      const result = spawnSync(process.execPath, ["--import", preload, script, "--hydrate", "--mobile-only"], {
        encoding: "utf8",
        env: {
          ...process.env,
          REALLYME_ZK_LOCAL_ARTIFACT_ROOT: join(temporaryRoot, "cache"),
          REALLYME_ZK_ARTIFACT_TRANSPORT: "cdn",
        },
        timeout: 10_000,
      });
      assert.equal(result.status, 1);
      assert.ok(result.stderr.includes(`edge_request=${expectedRay}; challenged=true`));
      assert.ok(!result.stderr.includes(body));
      assert.ok(!result.stderr.includes("untrusted-header-must-remain-private"));
    }
  } finally {
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
});

test("R2 cache hydration fails closed without credentials and never falls back to the CDN", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "reallyme-zk-r2-cache-"));
  try {
    const preload = join(temporaryRoot, "no-network.mjs");
    writeFileSync(preload, "globalThis.fetch = () => { process.exit(93); };\n");
    for (const [transport, endpoint, reason] of [
      ["r2", "https://00000000000000000000000000000000.r2.cloudflarestorage.com", "invalid-r2-credentials"],
      ["r2", "https://private-endpoint-must-not-be-logged.invalid", "invalid-r2-endpoint"],
      ["unknown", "", "unsupported-artifact-transport"],
    ]) {
      const result = spawnSync(process.execPath, ["--import", preload, script, "--hydrate", "--mobile-only"], {
        encoding: "utf8",
        env: {
          ...process.env,
          REALLYME_ZK_LOCAL_ARTIFACT_ROOT: join(temporaryRoot, "cache"),
          REALLYME_ZK_ARTIFACT_TRANSPORT: transport,
          R2_ENDPOINT: endpoint,
          R2_ACCESS_KEY_ID: "",
          R2_SECRET_ACCESS_KEY: "",
        },
        timeout: 10_000,
      });
      assert.equal(result.status, 1);
      assert.equal(result.stderr.trim(), `release artifact cache failed: ${reason}`);
      assert.equal(result.stdout, "");
    }
  } finally {
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
});

test("R2 CLI downloads pass through the pinned cache admission and reject altered bytes", {
  skip: ![
    sealedArchive,
    new URL("../release-artifacts/modern-v1-bb-6.0.0/cdn/crs/bn254_g1.prover", import.meta.url),
    new URL("../release-artifacts/modern-v1-bb-6.0.0/cdn/crs/bn254_g2.dat", import.meta.url),
  ].every(existsSync),
}, () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "reallyme-zk-r2-cli-cache-"));
  try {
    const command = join(temporaryRoot, "aws");
    const sourceRoot = fileURLToPath(new URL("../release-artifacts/modern-v1-bb-6.0.0/", import.meta.url));
    const cache = join(temporaryRoot, "cache");
    const preload = join(temporaryRoot, "no-network.mjs");
    writeFileSync(preload, "globalThis.fetch = () => { process.exit(93); };\n");
    const fixture = `#!${process.execPath}
import { copyFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const args = process.argv.slice(2);
const argument = (name) => args[args.indexOf(name) + 1];
const key = argument("--key");
if (argument("--bucket") !== "static" || !key.startsWith("zk/") ||
    process.env.AWS_ACCESS_KEY_ID !== "fixture-access" ||
    process.env.AWS_SECRET_ACCESS_KEY !== "fixture-secret") process.exit(94);
const paths = {
  "mobile-circuits.tar": "mobile-circuit-artifacts-persona-credential-evidence-v1.tar",
  "bn254_g1.prover": "cdn/crs/bn254_g1.prover",
  "bn254_g2.dat": "cdn/crs/bn254_g2.dat",
};
const path = paths[key.split("/").at(-1)];
if (path === undefined) process.exit(95);
copyFileSync(join(${JSON.stringify(sourceRoot)}, path), args.at(-1));
console.error("private-cli-diagnostic");
`;
    writeFileSync(command, fixture);
    chmodSync(command, 0o755);
    const run = () => spawnSync(process.execPath, ["--import", preload, script, "--hydrate", "--mobile-only"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: temporaryRoot,
        REALLYME_ZK_LOCAL_ARTIFACT_ROOT: cache,
        REALLYME_ZK_ARTIFACT_TRANSPORT: "r2",
        R2_ENDPOINT: "https://00000000000000000000000000000000.r2.cloudflarestorage.com",
        R2_ACCESS_KEY_ID: "fixture-access",
        R2_SECRET_ACCESS_KEY: "fixture-secret",
      },
      timeout: 30_000,
    });
    const accepted = run();
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(accepted.stderr, "");
    assert.match(accepted.stdout, /release artifact cache check passed/u);

    // A successful origin response is insufficient: modified bytes must never
    // replace a digest-admitted artifact, even when downloaded with credentials.
    const archive = join(cache, "mobile-circuit-artifacts-persona-credential-evidence-v1.tar");
    unlinkSync(archive);
    writeFileSync(command, `${fixture}\nwriteFileSync(args.at(-1), "changed bytes");\n`);
    const rejected = run();
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /has SHA-256/u);
    assert.ok(!rejected.stderr.includes("private-cli-diagnostic"));
    assert.ok(!existsSync(archive));
    assert.ok(!existsSync(`${archive}.download`));
  } finally {
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
});
