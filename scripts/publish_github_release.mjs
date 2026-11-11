#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const VERSION = /^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}$/u;
const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const REPOSITORY = /^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/u;
const ASSET_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const MAX_ASSETS = 100;
const MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const HASH_BUFFER_BYTES = 1024 * 1024;

export class GitHubReleaseError extends Error {
  constructor(code) {
    super(code);
    this.name = "GitHubReleaseError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new GitHubReleaseError(code);
};
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const isId = (value) => Number.isSafeInteger(value) && value > 0;

export const githubReleaseTag = (version) => {
  if (typeof version !== "string" || version.length > 64 || !VERSION.test(version)) {
    fail("invalid-release-version");
  }
  return `reallyme-zk-v${version}`;
};

const requestGitHub = (method, path, fields = {}, optional = false) => {
  const args = ["api", "--method", method, path];
  for (const [key, value] of Object.entries(fields)) {
    args.push(typeof value === "boolean" ? "--field" : "--raw-field", `${key}=${value}`);
  }
  const result = spawnSync("gh", args, {
    encoding: "utf8", maxBuffer: MAX_RESPONSE_BYTES, timeout: 30_000,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.error !== undefined) fail("github-request-failed");
  let response;
  try { response = JSON.parse(result.stdout); } catch { fail("invalid-github-response"); }
  if (result.status !== 0) {
    // A failed lookup is absence only when GitHub explicitly returns 404.
    // Authentication, transport, and server failures must never admit creation.
    if (optional && isRecord(response) && response.status === "404") return null;
    fail("github-request-failed");
  }
  return response;
};

const uploadGitHub = (repository, tag, path) => {
  const result = spawnSync("gh", ["release", "upload", tag, path, "--repo", repository], {
    timeout: 600_000, stdio: "ignore",
  });
  if (result.error !== undefined || result.status !== 0) fail("github-upload-failed");
};

const inspectAsset = (path) => {
  if (typeof path !== "string" || path.length === 0) fail("invalid-asset-path");
  const absolute = resolve(path);
  const name = basename(absolute);
  if (!ASSET_NAME.test(name)) fail("invalid-asset-name");
  let descriptor;
  try {
    descriptor = openSync(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_ASSET_BYTES) {
      fail("invalid-asset-file");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(HASH_BUFFER_BYTES);
    let total = 0;
    for (;;) {
      const length = readSync(descriptor, buffer, 0, buffer.length, null);
      if (length === 0) break;
      total += length;
      if (!Number.isSafeInteger(total) || total > metadata.size) fail("asset-changed-during-read");
      hash.update(buffer.subarray(0, length));
    }
    if (total !== metadata.size) fail("asset-changed-during-read");
    return { path: absolute, name, size: total, digest: `sha256:${hash.digest("hex")}` };
  } catch (error) {
    if (error instanceof GitHubReleaseError) throw error;
    fail("asset-read-failed");
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { fail("asset-close-failed"); }
    }
  }
};

const parseRelease = (value, tag) => {
  if (value === null) return null;
  if (!isRecord(value) || !isId(value.id) || value.tag_name !== tag ||
      typeof value.name !== "string" || typeof value.draft !== "boolean" ||
      typeof value.immutable !== "boolean" || !Array.isArray(value.assets) ||
      value.assets.length > MAX_ASSETS) fail("invalid-release-response");
  const names = new Set();
  for (const asset of value.assets) {
    if (!isRecord(asset) || !isId(asset.id) || typeof asset.name !== "string" ||
        !ASSET_NAME.test(asset.name) || names.has(asset.name) ||
        !Number.isSafeInteger(asset.size) || asset.size < 1 || asset.size > MAX_ASSET_BYTES ||
        typeof asset.digest !== "string" || !DIGEST.test(asset.digest)) fail("invalid-release-asset");
    names.add(asset.name);
  }
  return value;
};

export function publishGitHubRelease({
  mode, assetPaths = [], swiftVersionAlias = false,
  env = process.env, request = requestGitHub, upload = uploadGitHub,
} = {}) {
  const repository = env.GITHUB_REPOSITORY;
  const sha = env.RELEASE_SHA;
  const tag = githubReleaseTag(env.RELEASE_VERSION);
  if (typeof repository !== "string" || repository.length > 128 || !REPOSITORY.test(repository) ||
      repository.split("/").some((segment) => segment === "." || segment === "..") ||
      typeof sha !== "string" || !SHA.test(sha) || env.GITHUB_SHA !== sha) fail("invalid-release-identity");
  if ((mode !== "prepare" && mode !== "publish") || !Array.isArray(assetPaths) ||
      typeof swiftVersionAlias !== "boolean" || (mode === "prepare" && swiftVersionAlias) ||
      assetPaths.length > MAX_ASSETS || (mode === "prepare" && assetPaths.length !== 0) ||
      (mode === "publish" && assetPaths.length === 0)) fail("invalid-publication-input");
  const assets = assetPaths.map(inspectAsset);
  if (new Set(assets.map((asset) => asset.name)).size !== assets.length) fail("duplicate-asset-name");
  const root = `repos/${repository}`;
  const requireMain = () => {
    const main = request("GET", `${root}/git/ref/heads/main`);
    if (!isRecord(main) || main.ref !== "refs/heads/main" || main.object?.sha !== sha) {
      fail("release-sha-is-not-current-main");
    }
  };
  const requireTag = (value, expectedTag = tag) => {
    if (!isRecord(value) || value.ref !== `refs/tags/${expectedTag}` || !isRecord(value.object) ||
        !SHA.test(value.object.sha ?? "")) fail("invalid-release-tag");
    let target = value.object.sha;
    if (value.object.type === "tag") {
      const commit = request("GET", `${root}/commits/${expectedTag}`);
      if (!isRecord(commit) || typeof commit.sha !== "string" || !SHA.test(commit.sha)) {
        fail("invalid-release-tag");
      }
      target = commit.sha;
    } else if (value.object.type !== "commit") fail("invalid-release-tag");
    if (target !== sha) {
      fail(expectedTag === tag ? "release-tag-target-mismatch" : "swift-version-alias-target-mismatch");
    }
  };
  requireMain();
  // Refuse a second public identity even if an older workflow is still present.
  if (request("GET", `${root}/releases/tags/v${env.RELEASE_VERSION}`, {}, true) !== null) {
    fail("legacy-release-exists");
  }
  const alias = `v${env.RELEASE_VERSION}`;
  if (swiftVersionAlias) {
    const existingAlias = request("GET", `${root}/git/ref/tags/${alias}`, {}, true);
    if (existingAlias !== null) requireTag(existingAlias, alias);
  }
  let tagRef = request("GET", `${root}/git/ref/tags/${tag}`, {}, true);
  if (tagRef !== null) requireTag(tagRef);
  let release = parseRelease(request("GET", `${root}/releases/tags/${tag}`, {}, true), tag);
  if (release !== null && tagRef === null) fail("release-tag-missing");
  const missingAssets = (current) => assets.filter((asset) => {
    const existing = current?.assets.find((candidate) => candidate.name === asset.name);
    if (existing === undefined) return true;
    if (existing.digest !== asset.digest || existing.size !== asset.size) fail("release-asset-conflict");
    return false;
  });
  let missing = missingAssets(release);
  if (release?.immutable && missing.length > 0) fail("immutable-release-missing-assets");
  if ((release?.assets.length ?? 0) + missing.length > MAX_ASSETS) fail("too-many-release-assets");
  if (tagRef === null) {
    tagRef = request("POST", `${root}/git/refs`, { ref: `refs/tags/${tag}`, sha });
    requireTag(tagRef);
  }
  if (release === null) {
    release = parseRelease(request("POST", `${root}/releases`, {
      tag_name: tag, target_commitish: sha, name: tag, draft: true,
      body: `ReallyMe ZK ${env.RELEASE_VERSION}.`,
    }), tag);
    if (release === null || !release.draft) fail("invalid-draft-release");
  }
  if (mode === "prepare") return tag;
  for (const asset of missing) upload(repository, tag, asset.path);
  requireMain();
  requireTag(request("GET", `${root}/git/ref/tags/${tag}`));
  const verified = parseRelease(request("GET", `${root}/releases/tags/${tag}`), tag);
  if (verified === null || verified.id !== release.id) fail("release-identity-changed");
  missing = missingAssets(verified);
  if (missing.length !== 0) fail("release-assets-missing-after-upload");
  // SwiftPM accepts semantic-version tags with an optional v prefix. Keep
  // that compatibility ref separate from the single GitHub release identity.
  if (swiftVersionAlias) {
    const existingAlias = request("GET", `${root}/git/ref/tags/${alias}`, {}, true);
    requireTag(existingAlias ?? request("POST", `${root}/git/refs`, {
      ref: `refs/tags/${alias}`, sha,
    }), alias);
  }
  if (verified.draft || verified.name !== tag) {
    const published = parseRelease(request("PATCH", `${root}/releases/${verified.id}`, {
      draft: false, name: tag,
    }), tag);
    if (published === null || published.id !== release.id || published.draft || published.name !== tag ||
        missingAssets(published).length !== 0) fail("release-publication-not-verified");
  }
  return tag;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const [argument, ...inputs] = process.argv.slice(2);
    const mode = argument === "--prepare" ? "prepare" : argument === "--publish" ? "publish" : undefined;
    const swiftVersionAlias = inputs[0] === "--swift";
    const assetPaths = swiftVersionAlias ? inputs.slice(1) : inputs;
    const tag = publishGitHubRelease({ mode, assetPaths, swiftVersionAlias });
    console.log(`Verified GitHub release: ${tag}`);
  } catch (error) {
    console.error(`GitHub release failed: ${error instanceof GitHubReleaseError ? error.code : "unexpected-failure"}`);
    process.exitCode = 1;
  }
}
