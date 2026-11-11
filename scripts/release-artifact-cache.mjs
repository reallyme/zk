#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { stageStaticUpload } from "./static-upload-package.mjs";
import { downloadR2Artifact, R2ArtifactError } from "./r2-artifact-source.mjs";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const stackId = "modern-v1-bb-6.0.0";
const defaultArtifactRoot = resolve(repositoryRoot, "release-artifacts", stackId);
const artifactRoot = resolve(process.env.REALLYME_ZK_LOCAL_ARTIFACT_ROOT ?? defaultArtifactRoot);
const defaultArtifactBaseUrl = "https://static.reallyme.net/zk";

const artifacts = [
  {
    path: "swiftpm/ReallyMeZKPlatformFFI.xcframework.zip",
    remotePath: "swift/60505f149fcf345a3c6132478aeed05dbc8ee8a7b245d96a7fedeeee4d27d341/ReallyMeZKPlatformFFI.xcframework.zip",
    sha256: "60505f149fcf345a3c6132478aeed05dbc8ee8a7b245d96a7fedeeee4d27d341",
    distribution: true,
    label: "SwiftPM binary target XCFramework",
  },
  {
    path: "rust-cli/darwin-arm64/reallyme-zk",
    remotePath: "cli/macos-arm64/aabec6a9db4ef63177c48faa7217cbaa87fa8d9ab472af273b4a7904dd3d84bf/reallyme-zk",
    sha256: "aabec6a9db4ef63177c48faa7217cbaa87fa8d9ab472af273b4a7904dd3d84bf",
    distribution: true,
    label: "Rust CLI darwin arm64 binary",
  },
  {
    path: "mobile-circuit-artifacts-persona-credential-evidence-v1.tar",
    remotePath: "circuits/74990876329b137dc0bc073360423d64d08b8f0a50872639c4ed0dbfcffe89a9/mobile-circuits.tar",
    sha256: "74990876329b137dc0bc073360423d64d08b8f0a50872639c4ed0dbfcffe89a9",
    distribution: true,
    label: "Mobile circuit runtime artifact package",
  },
  {
    path: "cdn/crs/bn254_g1.prover",
    remotePath: "crs/0f238856e55722f15a4d64ef0de12b4260e218245590bd3a6c900aee188de8e5/bn254_g1.prover",
    sha256: "0f238856e55722f15a4d64ef0de12b4260e218245590bd3a6c900aee188de8e5",
    distribution: true,
    label: "BN254 prover CRS",
  },
  {
    path: "cdn/crs/bn254_g1.dat",
    remotePath: "crs/ea6069e3563ad79f186d1c0088499309cbdaeb54254346760ffec7fe15ae49cd/bn254_g1.dat",
    sha256: "ea6069e3563ad79f186d1c0088499309cbdaeb54254346760ffec7fe15ae49cd",
    distribution: true,
    label: "BN254 full G1 source CRS",
  },
  {
    path: "cdn/crs/bn254_g2.dat",
    remotePath: "crs/01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f/bn254_g2.dat",
    sha256: "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f",
    distribution: true,
    label: "BN254 verifier G2 CRS",
  },
  {
    path: "android-platform-jni/arm64-v8a/libreallyme_zk_platform_jni.so",
    sha256: "b7f7069cf1a859c5cb9ff27b29bb5dc5b5d04164fc00e8dcbf9dbf255f1c716b",
    distribution: false,
    label: "Android JNI library before AAR packaging",
  },
  {
    path: "android-platform-jni/arm64-v8a/libc++_shared.so",
    sha256: "7466ed097631a564ed6bff0b47768caa76bf03270d2047b5a65c03f497b824df",
    distribution: false,
    label: "Android C++ runtime before AAR packaging",
  },
];

validateArtifactManifest();

const argumentsByName = new Set(process.argv.slice(2));
const supportedArguments = new Set([
  "--check",
  "--distribution-only",
  "--hydrate",
  "--list",
  "--mobile-only",
  "--stage-upload",
  "--swift-only",
  "--unpack-mobile-circuit-artifacts",
  "--unpack-mobile-public-artifacts",
  "--unpack-swift-xcframework",
  "--upload-list",
  "--verify-remote",
]);

for (const argument of argumentsByName) {
  if (!supportedArguments.has(argument)) {
    fail(`unsupported argument ${argument}`);
  }
}

const distributionOnly = argumentsByName.has("--distribution-only");
const swiftOnly = argumentsByName.has("--swift-only");
const mobileOnly = argumentsByName.has("--mobile-only");
if (swiftOnly && mobileOnly) {
  fail("Swift and mobile artifact selections are mutually exclusive");
}
if ((argumentsByName.has("--upload-list") || argumentsByName.has("--stage-upload")) && !distributionOnly) {
  fail("--upload-list and --stage-upload require --distribution-only");
}
const selectedArtifacts = artifacts.filter(
  (artifact) =>
    (!distributionOnly || artifact.distribution) &&
    (!swiftOnly || artifact.path === "swiftpm/ReallyMeZKPlatformFFI.xcframework.zip") &&
    (!mobileOnly || artifact.path === "mobile-circuit-artifacts-persona-credential-evidence-v1.tar" ||
      artifact.path === "cdn/crs/bn254_g1.prover" || artifact.path === "cdn/crs/bn254_g2.dat"),
);

if (argumentsByName.has("--list")) {
  listArtifacts(selectedArtifacts);
}

if (argumentsByName.has("--upload-list")) {
  listUploadArtifacts(selectedArtifacts);
}

if (argumentsByName.has("--stage-upload")) {
  try {
    const manifest = stageStaticUpload({
      rows: uploadArtifactRows(selectedArtifacts),
      artifactRoot,
      outputRoot: join(repositoryRoot, "release-artifacts", "r2-upload"),
    });
    console.log(`Prepared ${manifest.objects.length} static release objects for bucket static`);
  } catch (error) {
    fail(error?.code ?? "static-upload-staging-failed");
  }
}

if (argumentsByName.has("--hydrate")) {
  await hydrateArtifacts(selectedArtifacts);
}

if (argumentsByName.has("--verify-remote")) {
  await verifyRemoteArtifacts(selectedArtifacts);
}

if (argumentsByName.has("--unpack-swift-xcframework")) {
  unpackSwiftXcframework();
}

if (
  argumentsByName.has("--unpack-mobile-circuit-artifacts") ||
  argumentsByName.has("--unpack-mobile-public-artifacts")
) {
  unpackMobilePublicCircuitArtifacts();
}

if (
  argumentsByName.has("--check") ||
  (!argumentsByName.has("--list") &&
    !argumentsByName.has("--hydrate") &&
    !argumentsByName.has("--unpack-mobile-circuit-artifacts") &&
    !argumentsByName.has("--unpack-mobile-public-artifacts") &&
    !argumentsByName.has("--unpack-swift-xcframework") &&
    !argumentsByName.has("--upload-list") &&
    !argumentsByName.has("--stage-upload") &&
    !argumentsByName.has("--verify-remote"))
) {
  checkArtifacts(selectedArtifacts);
}

function listArtifacts(listedArtifacts) {
  console.log("stack\tpath\tremote_path\tsha256\tdistribution\tlabel");
  for (const artifact of listedArtifacts) {
    console.log(
      [
        stackId,
        artifact.path,
        remoteArtifactPath(artifact),
        artifact.sha256,
        artifact.distribution ? "yes" : "no",
        artifact.label,
      ].join("\t"),
    );
  }
}

function listUploadArtifacts(listedArtifacts) {
  const rows = uploadArtifactRows(listedArtifacts);
  console.log("local_absolute_path\tcdn_url\tsha256\tlabel");
  for (const row of rows) {
    console.log(row.join("\t"));
  }
}

function uploadArtifactRows(listedArtifacts) {
  const baseUrl = process.env.REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL ?? defaultArtifactBaseUrl;
  if (typeof baseUrl !== "string" || !URL.canParse(baseUrl)) {
    fail("REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL must be an HTTPS URL for --upload-list");
  }
  const parsedBaseUrl = new URL(baseUrl);
  if (
    parsedBaseUrl.protocol !== "https:" ||
    parsedBaseUrl.username !== "" ||
    parsedBaseUrl.password !== "" ||
    parsedBaseUrl.search !== "" ||
    parsedBaseUrl.hash !== ""
  ) {
    fail("REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL must be an HTTPS URL for --upload-list");
  }
  const rows = [];
  for (const artifact of listedArtifacts) {
    const path = localPath(artifact.path);
    if (!existsSync(path) || !statSync(path).isFile() || sha256File(path) !== artifact.sha256) {
      fail(`missing or changed ${displayPath(path)}`);
    }
    const remotePath = remoteArtifactPath(artifact);
    rows.push([path, artifactUrl(baseUrl, remotePath), artifact.sha256, artifact.label]);
  }
  return rows;
}

async function hydrateArtifacts(hydratedArtifacts) {
  const baseUrl = process.env.REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL ?? defaultArtifactBaseUrl;
  if (typeof baseUrl !== "string" || baseUrl.length === 0) {
    fail("REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL is required for --hydrate");
  }

  for (const artifact of hydratedArtifacts) {
    const outputPath = localPath(artifact.path);
    if (!existsSync(outputPath) || sha256File(outputPath) !== artifact.sha256) {
      await downloadArtifact(baseUrl, artifact, outputPath);
    }
  }
  checkArtifacts(hydratedArtifacts);
}

async function verifyRemoteArtifacts(verifiedArtifacts) {
  const baseUrl = process.env.REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL ?? defaultArtifactBaseUrl;
  if (typeof baseUrl !== "string" || baseUrl.length === 0) {
    fail("REALLYME_ZK_RELEASE_ARTIFACT_BASE_URL is required for --verify-remote");
  }

  const temporaryRoot = mkdtempSync(join(tmpdir(), "reallyme-zk-release-artifacts-"));
  try {
    for (const artifact of verifiedArtifacts) {
      const outputPath = join(temporaryRoot, artifact.path);
      await downloadArtifact(baseUrl, artifact, outputPath);
    }
  } finally {
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
  console.log("release artifact remote verification passed");
}

async function downloadArtifact(baseUrl, artifact, outputPath) {
  const temporaryPath = `${outputPath}.download`;
  mkdirSync(dirname(outputPath), { recursive: true });
  rmSync(temporaryPath, { force: true });

  await downloadFromSource(baseUrl, remoteArtifactPath(artifact), temporaryPath);
  const actual = sha256File(temporaryPath);
  if (actual !== artifact.sha256) {
    rmSync(temporaryPath, { force: true });
    fail(`downloaded ${artifact.path} has SHA-256 ${actual}`);
  }
  renameSync(temporaryPath, outputPath);
}

async function downloadFromSource(baseUrl, remotePath, temporaryPath) {
  const transport = process.env.REALLYME_ZK_ARTIFACT_TRANSPORT ?? "cdn";
  if (transport === "r2") {
    try {
      downloadR2Artifact(remotePath, temporaryPath);
    } catch (error) {
      fail(error instanceof R2ArtifactError ? error.code : "r2-download-failed");
    }
    return;
  }
  if (transport !== "cdn") fail("unsupported-artifact-transport");
  const downloaded = await downloadWithFetch(artifactUrl(baseUrl, remotePath), temporaryPath);
  if (!downloaded) downloadWithCurl(artifactUrl(baseUrl, remotePath), temporaryPath, remotePath);
}

async function downloadWithFetch(url, temporaryPath) {
  let response;
  try {
    response = await fetch(url, {
      headers: {
        "User-Agent": "ReallyMe-ZK-Artifact-Cache",
        Accept: "application/octet-stream",
      },
    });
  } catch {
    return false;
  }
  if (!response.ok || response.body === null) {
    // An edge request identifier permits firewall diagnosis without logging
    // response bodies, cookies, arbitrary headers, or caller network details.
    const suppliedRay = response.headers.get("cf-ray") ?? "";
    const ray = /^[0-9a-f]{16,32}-[A-Z]{3}$/u.test(suppliedRay) ? suppliedRay : "unavailable";
    const challenged = response.headers.get("cf-mitigated") === "challenge";
    fail(`failed to download ${url} (${response.status}); edge_request=${ray}; challenged=${challenged}`);
  }
  await pipeline(Readable.fromWeb(response.body), createWriteStream(temporaryPath));
  return true;
}

function downloadWithCurl(url, temporaryPath, artifactPath) {
  const result = spawnSync(
    "curl",
    ["--fail", "--location", "--show-error", "--silent", "--output", temporaryPath, url],
    {
      cwd: repositoryRoot,
      stdio: "inherit",
    },
  );
  if (result.error !== undefined || result.status !== 0) {
    rmSync(temporaryPath, { force: true });
    fail(`failed to download ${artifactPath}`);
  }
}

function artifactUrl(baseUrl, artifactPath) {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const encodedPath = artifactPath.split("/").map(encodeURIComponent).join("/");
  return new URL(encodedPath, normalizedBase).href;
}

function remoteArtifactPath(artifact) {
  return artifact.remotePath ?? artifact.path;
}

function validateArtifactManifest() {
  for (const artifact of artifacts) {
    if (!artifact.distribution) {
      continue;
    }
    const match = artifact.remotePath?.match(/\/(?:([0-9a-f]{64}))\//u);
    if (match === null || match === undefined || match[1] !== artifact.sha256) {
      fail(`${artifact.path} content-addressed remote path does not encode its SHA-256`);
    }
  }
}

function unpackSwiftXcframework() {
  const archivePath = localPath("swiftpm/ReallyMeZKPlatformFFI.xcframework.zip");
  const outputRoot = localPath("apple-platform-ffi");
  const frameworkPath = join(outputRoot, "ReallyMeZKPlatformFFI.xcframework");
  if (!existsSync(archivePath)) {
    fail("SwiftPM XCFramework archive is missing");
  }
  const actual = sha256File(archivePath);
  const expected = artifactByPath("swiftpm/ReallyMeZKPlatformFFI.xcframework.zip").sha256;
  if (actual !== expected) {
    fail(`SwiftPM XCFramework archive has SHA-256 ${actual}`);
  }
  // The local SwiftPM target takes precedence over the pinned CDN target. A
  // plausible Info.plist alone must never admit a different local binary.
  const temporaryRoot = mkdtempSync(join(artifactRoot, ".swift-framework-"));
  const temporaryFramework = join(temporaryRoot, "ReallyMeZKPlatformFFI.xcframework");
  const result = spawnSync("ditto", ["-x", "-k", archivePath, temporaryRoot], {
    cwd: repositoryRoot,
    stdio: "inherit",
  });
  if (result.error || result.status !== 0) {
    rmSync(temporaryRoot, { force: true, recursive: true });
    fail("ditto failed while unpacking Swift XCFramework");
  }
  if (!existsSync(join(temporaryFramework, "Info.plist"))) {
    rmSync(temporaryRoot, { force: true, recursive: true });
    fail("unpacked Swift XCFramework is missing Info.plist");
  }
  if (existsSync(frameworkPath)) {
    const matches = identicalRegularFileTrees(temporaryFramework, frameworkPath);
    rmSync(temporaryRoot, { force: true, recursive: true });
    if (!matches) {
      fail("existing XCFramework differs from the pinned SwiftPM archive; remove the stale framework before unpacking");
    }
  } else {
    mkdirSync(outputRoot, { recursive: true });
    renameSync(temporaryFramework, frameworkPath);
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
}

function unpackMobilePublicCircuitArtifacts() {
  const archivePath = localPath("mobile-circuit-artifacts-persona-credential-evidence-v1.tar");
  const targetRoot = localPath("mobile-demo-artifacts-persona-credential-evidence-v1-candidate");
  if (!existsSync(archivePath)) {
    fail("mobile circuit artifact archive is missing");
  }
  const actual = sha256File(archivePath);
  const expected = artifactByPath("mobile-circuit-artifacts-persona-credential-evidence-v1.tar").sha256;
  if (actual !== expected) {
    fail(`mobile circuit artifact archive has SHA-256 ${actual}`);
  }
  verifyMobilePublicCircuitArchiveListing(archivePath);
  // Extract into a fresh directory before trusting an existing cache. Checking
  // only index.pb leaves stale or extra files available to artifact consumers.
  const temporaryRoot = mkdtempSync(join(artifactRoot, ".mobile-public-"));
  const result = spawnSync("tar", ["-xf", archivePath, "-C", temporaryRoot], {
    cwd: repositoryRoot,
    stdio: "inherit",
  });
  if (result.error || result.status !== 0) {
    rmSync(temporaryRoot, { force: true, recursive: true });
    fail("tar failed while unpacking mobile circuit artifacts");
  }
  verifyMobilePublicCircuitArtifacts(temporaryRoot);
  if (existsSync(targetRoot)) {
    const matches = identicalRegularFileTrees(temporaryRoot, targetRoot);
    rmSync(temporaryRoot, { force: true, recursive: true });
    if (!matches) {
      fail("existing mobile circuit artifact directory differs from the sealed archive; remove the stale directory before unpacking");
    }
  } else {
    renameSync(temporaryRoot, targetRoot);
  }
  verifyMobilePublicCircuitArtifacts(targetRoot);
}

function identicalRegularFileTrees(expectedRoot, actualRoot) {
  const expected = regularFileTree(expectedRoot);
  const actual = regularFileTree(actualRoot);
  if (expected === null || actual === null || expected.length !== actual.length) {
    return false;
  }
  for (let index = 0; index < expected.length; index += 1) {
    if (expected[index] !== actual[index]) {
      return false;
    }
    if (sha256File(join(expectedRoot, expected[index])) !== sha256File(join(actualRoot, actual[index]))) {
      return false;
    }
  }
  return true;
}

function regularFileTree(root) {
  if (!lstatSync(root).isDirectory()) {
    return null;
  }
  const files = [];
  const directories = [""];
  while (directories.length > 0) {
    const directory = directories.pop();
    const entries = readdirSync(join(root, directory), { withFileTypes: true });
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        directories.push(path);
      } else if (entry.isFile()) {
        files.push(path);
      } else {
        // Symlinks and special files cannot be accepted as release artifacts.
        return null;
      }
    }
  }
  return files.sort();
}

function verifyMobilePublicCircuitArchiveListing(archivePath) {
  const result = spawnSync("tar", ["-tf", archivePath], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  if (result.error) {
    fail("tar failed to start while listing mobile circuit artifacts");
  }
  if (result.status !== 0) {
    fail("tar failed while listing mobile circuit artifacts");
  }
  const entries = result.stdout.trimEnd().split("\n");
  if (entries.length === 0) {
    fail("mobile circuit artifact archive is empty");
  }
  for (const entry of entries) {
    if (
      entry.startsWith("/") ||
      entry.includes("../") ||
      (!entry.startsWith("common-credential-root-v1/") &&
       !entry.startsWith("persona-credential-evidence-v1/") &&
       !entry.startsWith("v1/")) ||
      entry.includes("/vectors/") ||
      entry.includes("/vectors/proving-spec/")
    ) {
      fail("mobile circuit artifact archive contains an unexpected path");
    }
  }
}

function verifyMobilePublicCircuitArtifacts(targetRoot) {
  const indexPath = join(targetRoot, "v1/v1/index.pb");
  if (!existsSync(indexPath)) {
    fail("unpacked mobile public circuit artifacts are missing the release index");
  }
  const expectedIndexSha256 =
    "9260afdb9a3a0133a679af141a310b6aacbf2e814724692ca964d2711ae49ce7";
  const actualIndexSha256 = sha256File(indexPath);
  if (actualIndexSha256 !== expectedIndexSha256) {
    fail(`unpacked mobile public release index has SHA-256 ${actualIndexSha256}`);
  }
}

function checkArtifacts(checkedArtifacts) {
  for (const artifact of checkedArtifacts) {
    const path = localPath(artifact.path);
    if (!existsSync(path) || !statSync(path).isFile()) {
      fail(`missing ${displayPath(path)}`);
    }
    const actual = sha256File(path);
    if (actual !== artifact.sha256) {
      fail(`${displayPath(path)} has SHA-256 ${actual}`);
    }
  }
  console.log("release artifact cache check passed");
}

function artifactByPath(path) {
  const artifact = artifacts.find((candidate) => candidate.path === path);
  if (artifact === undefined) {
    fail(`internal artifact manifest is missing ${path}`);
  }
  return artifact;
}

function localPath(path) {
  return resolve(artifactRoot, path);
}

function displayPath(path) {
  return relative(repositoryRoot, path);
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function fail(reason) {
  console.error(`release artifact cache failed: ${reason}`);
  process.exit(1);
}
