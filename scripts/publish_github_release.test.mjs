#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";

import { GitHubReleaseError, githubReleaseTag, publishGitHubRelease } from "./publish_github_release.mjs";

const SHA = "a".repeat(40);
const TAG = "reallyme-zk-v0.3.1";
const ENV = { GITHUB_REPOSITORY: "reallyme/zk", RELEASE_VERSION: "0.3.1", RELEASE_SHA: SHA, GITHUB_SHA: SHA };
const clone = (value) => structuredClone(value);
const digest = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const rejects = (code) => (error) => error instanceof GitHubReleaseError && error.code === code;

const fixture = (t) => {
  const directory = mkdtempSync(join(tmpdir(), "zk-github-release-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const paths = ["module.crate", "framework.zip"].map((name) => {
    const path = join(directory, name);
    writeFileSync(path, name);
    return path;
  });
  const state = { tag: null, alias: null, release: null, legacy: null, calls: [], uploads: [], main: SHA };
  const request = (method, path, fields = {}) => {
    state.calls.push({ method, path, fields });
    if (method === "GET" && path.endsWith("/git/ref/heads/main")) {
      return { ref: "refs/heads/main", object: { sha: state.main } };
    }
    if (method === "GET" && path.endsWith("/releases/tags/v0.3.1")) return clone(state.legacy);
    if (method === "GET" && path.includes("/releases?")) {
      return [state.release, state.legacy === null ? null : { ...state.legacy, tag_name: "v0.3.1" }]
        .filter((release) => release !== null).map(clone);
    }
    if (method === "GET" && path.endsWith(`/git/ref/tags/${TAG}`)) return clone(state.tag);
    if (method === "GET" && path.endsWith("/git/ref/tags/v0.3.1")) return clone(state.alias);
    if (method === "GET" && path.endsWith(`/releases/tags/${TAG}`)) {
      return state.release?.draft === false ? clone(state.release) : null;
    }
    if (method === "GET" && path.endsWith("/releases/7")) return clone(state.release);
    if (method === "GET" && path.endsWith(`/commits/${TAG}`)) return { sha: SHA };
    if (method === "POST" && path.endsWith("/git/refs")) {
      if (fields.ref === "refs/tags/v0.3.1") {
        assert.equal(state.alias, null);
        state.alias = { ref: fields.ref, object: { sha: fields.sha, type: "commit" } };
        return clone(state.alias);
      }
      assert.equal(state.tag, null);
      state.tag = { ref: fields.ref, object: { sha: fields.sha, type: "commit" } };
      return clone(state.tag);
    }
    if (method === "POST" && path.endsWith("/releases")) {
      assert.equal(state.release, null);
      state.release = { ...fields, id: 7, immutable: false, assets: [] };
      return clone(state.release);
    }
    if (method === "PATCH" && path.endsWith("/releases/7")) {
      Object.assign(state.release, fields);
      return clone(state.release);
    }
    assert.fail(`unexpected request: ${method} ${path}`);
  };
  const upload = (repository, tag, path) => {
    assert.equal(repository, ENV.GITHUB_REPOSITORY);
    assert.equal(tag, TAG);
    const bytes = readFileSync(path);
    state.uploads.push(path);
    state.release.assets.push({ id: state.uploads.length, name: basename(path), size: bytes.length, digest: digest(bytes) });
  };
  const invoke = (overrides = {}) => publishGitHubRelease({
    mode: "publish", assetPaths: paths, env: ENV, request, upload, ...overrides,
  });
  const mutations = () => state.calls.filter((call) => call.method !== "GET");
  return { directory, paths, state, request, upload, invoke, mutations };
};

test("uses one stable canonical name and rejects malformed or nonstable versions", () => {
  assert.equal(githubReleaseTag("0.3.0"), "reallyme-zk-v0.3.0");
  assert.equal(githubReleaseTag("0.3.1"), TAG);
  for (const version of [undefined, 3, "v0.3.1", "0.03.1", "0.3.1-rc.1", "0.3.1/extra", "9".repeat(65)]) {
    assert.throws(() => githubReleaseTag(version), rejects("invalid-release-version"));
  }
});

test("prepares one canonical tag and draft without publishing", (t) => {
  const f = fixture(t);
  assert.equal(f.invoke({ mode: "prepare", assetPaths: [] }), TAG);
  assert.equal(f.state.release.draft, true);
  assert.equal(f.state.release.name, TAG);
  assert.deepEqual(f.state.release.assets, []);
  assert.equal(f.state.tag.object.sha, SHA);
  assert.equal(f.mutations().length, 2);
});

test("two package lanes merge assets into one release and reruns are idempotent", (t) => {
  const f = fixture(t);
  f.invoke({ assetPaths: [f.paths[0]] });
  assert.equal(f.state.release.draft, false);
  f.invoke({ assetPaths: [f.paths[1]], swiftVersionAlias: true });
  assert.equal(f.state.release.assets.length, 2);
  assert.equal(f.state.calls.filter((call) => call.method === "POST" && call.path.endsWith("/releases")).length, 1);
  const before = f.mutations().length;
  f.invoke();
  assert.equal(f.mutations().length, before);
  assert.equal(f.state.uploads.length, 2);
  assert.equal(f.state.alias.object.sha, SHA);
  assert.equal(f.state.alias.ref, "refs/tags/v0.3.1");
});

test("resumes an uploaded draft using its ID when published tag lookup returns 404", (t) => {
  const f = fixture(t);
  f.invoke({ mode: "prepare", assetPaths: [] });
  for (const path of f.paths) f.upload(ENV.GITHUB_REPOSITORY, TAG, path);
  assert.equal(f.request("GET", `repos/reallyme/zk/releases/tags/${TAG}`), null);
  f.state.calls.length = 0;
  assert.equal(f.invoke({ swiftVersionAlias: true }), TAG);
  assert.equal(f.state.release.id, 7);
  assert.equal(f.state.release.draft, false);
  assert.equal(f.state.uploads.length, 2);
  assert.equal(f.state.calls.filter((call) => call.method === "POST" && call.path.endsWith("/releases")).length, 0);
  assert.equal(f.state.calls.some((call) => call.path.includes("/releases/tags/")), false);
  assert.ok(f.state.calls.some((call) => call.method === "GET" && call.path.endsWith("/releases/7")));
});

test("finds an existing draft after a complete first inventory page", (t) => {
  const f = fixture(t);
  f.invoke({ mode: "prepare", assetPaths: [] });
  const visited = [];
  const request = (method, path, ...rest) => {
    if (path.includes("/releases?")) {
      const page = Number(new URL(`https://api.github.com/${path}`).searchParams.get("page"));
      visited.push(page);
      return page === 1 ? Array.from({ length: 25 }, (_, index) => ({ id: index + 100, tag_name: `older-${index}` }))
        : [clone(f.state.release)];
    }
    return f.request(method, path, ...rest);
  };
  assert.equal(f.invoke({ request }), TAG);
  assert.deepEqual(visited, [1, 2]);
  assert.equal(f.state.release.id, 7);
});

test("rejects malformed, duplicate, and incomplete release inventories before mutation", (t) => {
  const f = fixture(t);
  for (const response of [{}, [null], [{ id: 0, tag_name: TAG }], [{ id: 1, tag_name: "x".repeat(257) }]]) {
    assert.throws(() => f.invoke({ request: (method, path, ...rest) => path.includes("/releases?")
      ? response : f.request(method, path, ...rest) }), rejects("invalid-release-inventory"));
  }
  assert.throws(() => f.invoke({ request: (method, path, ...rest) => path.includes("/releases?")
    ? [{ id: 1, tag_name: TAG }, { id: 2, tag_name: TAG }] : f.request(method, path, ...rest) }),
  rejects("duplicate-release-identity"));
  assert.throws(() => f.invoke({ request: (method, path, ...rest) => path.includes("/releases?")
    ? Array.from({ length: 25 }, (_, index) => ({ id: index + 1, tag_name: `${path}-${index}` }))
    : f.request(method, path, ...rest) }), rejects("release-inventory-limit-exceeded"));
  assert.deepEqual(f.mutations(), []);
});

test("Swift aliases never create another release or overwrite an existing version", (t) => {
  const f = fixture(t);
  f.state.alias = { ref: "refs/tags/v0.3.1", object: { type: "commit", sha: "b".repeat(40) } };
  assert.throws(() => f.invoke({ swiftVersionAlias: true }), rejects("swift-version-alias-target-mismatch"));
  assert.deepEqual(f.mutations(), []);
  f.state.alias = null;
  f.invoke({ swiftVersionAlias: true });
  assert.equal(f.state.alias.object.sha, f.state.tag.object.sha);
  assert.equal(f.state.calls.filter((call) => call.method === "POST" && call.path.endsWith("/releases")).length, 1);
});

test("does not overwrite existing release assets or retarget a published version", (t) => {
  const f = fixture(t);
  f.invoke();
  const before = f.mutations().length;
  writeFileSync(f.paths[0], "different reviewed bytes");
  assert.throws(() => f.invoke(), rejects("release-asset-conflict"));
  assert.equal(f.mutations().length, before);
  assert.equal(f.state.uploads.length, 2);
  f.state.tag.object.sha = "b".repeat(40);
  assert.throws(() => f.invoke(), rejects("release-tag-target-mismatch"));
  assert.equal(f.mutations().length, before);
});

test("refuses an existing legacy release instead of creating a second entry", (t) => {
  const f = fixture(t);
  f.state.legacy = { id: 99 };
  assert.throws(() => f.invoke(), rejects("legacy-release-exists"));
  assert.deepEqual(f.mutations(), []);
});

test("rejects wrong source identity and stale main before any mutation", (t) => {
  const f = fixture(t);
  assert.throws(() => f.invoke({ env: { ...ENV, GITHUB_SHA: "b".repeat(40) } }), rejects("invalid-release-identity"));
  assert.throws(() => f.invoke({ env: { ...ENV, GITHUB_REPOSITORY: "../other" } }), rejects("invalid-release-identity"));
  assert.throws(() => f.invoke({ env: { ...ENV, GITHUB_REPOSITORY: "org/.." } }), rejects("invalid-release-identity"));
  f.state.main = "b".repeat(40);
  assert.throws(() => f.invoke(), rejects("release-sha-is-not-current-main"));
  assert.deepEqual(f.mutations(), []);
});

test("rejects missing, empty, duplicate, and symlink assets before mutation", (t) => {
  const f = fixture(t);
  assert.throws(() => f.invoke({ assetPaths: [] }), rejects("invalid-publication-input"));
  assert.throws(() => f.invoke({ assetPaths: [f.paths[0], f.paths[0]] }), rejects("duplicate-asset-name"));
  const empty = join(f.directory, "empty.zip");
  writeFileSync(empty, "");
  const link = join(f.directory, "linked.zip");
  symlinkSync(f.paths[0], link);
  for (const path of [link, join(f.directory, "missing.zip")]) {
    assert.throws(() => f.invoke({ assetPaths: [path] }), rejects("asset-read-failed"));
  }
  assert.throws(() => f.invoke({ assetPaths: [empty] }), rejects("invalid-asset-file"));
  assert.deepEqual(f.mutations(), []);
});

test("supports annotated canonical tags after verifying the resolved commit", (t) => {
  const f = fixture(t);
  f.state.tag = { ref: `refs/tags/${TAG}`, object: { type: "tag", sha: "c".repeat(40) } };
  assert.equal(f.invoke(), TAG);
  assert.equal(f.mutations().filter((call) => call.path.endsWith("/git/refs")).length, 0);
});

test("does not publish a draft when upload admission or current main changes", (t) => {
  const f = fixture(t);
  assert.throws(() => f.invoke({ upload: () => {} }), rejects("release-assets-missing-after-upload"));
  assert.equal(f.state.release.draft, true);
  assert.throws(() => f.invoke({ upload: (...args) => {
    f.upload(...args);
    f.state.main = "b".repeat(40);
  } }), rejects("release-sha-is-not-current-main"));
  assert.equal(f.state.release.draft, true);
});

test("rejects malformed, duplicate, or unpinned remote asset metadata", (t) => {
  const f = fixture(t);
  f.invoke();
  const original = clone(f.state.release);
  for (const mutate of [
    (release) => { release.assets[0].digest = null; },
    (release) => { release.assets[0].size = -1; },
    (release) => { release.assets.push(clone(release.assets[0])); },
    (release) => { release.assets[0].name = "../asset"; },
    (release) => { release.id = 0; },
    (release) => { release.tag_name = "v0.3.1"; },
  ]) {
    f.state.release = clone(original);
    mutate(f.state.release);
    assert.throws(() => f.invoke(), (error) => error instanceof GitHubReleaseError &&
      ["invalid-release-response", "invalid-release-asset", "invalid-release-inventory", "legacy-release-exists"].includes(error.code));
  }
});

test("accepts an unchanged immutable release but rejects missing immutable assets", (t) => {
  const f = fixture(t);
  f.invoke({ assetPaths: [f.paths[0]] });
  f.state.release.immutable = true;
  assert.equal(f.invoke({ assetPaths: [f.paths[0]] }), TAG);
  assert.throws(() => f.invoke(), rejects("immutable-release-missing-assets"));
});

test("transport and authentication failures cannot be mistaken for missing releases", (t) => {
  const f = fixture(t);
  const bin = join(f.directory, "bin");
  mkdirSync(bin);
  const executable = join(bin, "gh");
  writeFileSync(executable, `#!/usr/bin/env node
const path = process.argv[process.argv.indexOf("--method") + 2];
if (path.endsWith("/git/ref/heads/main")) {
  console.log(JSON.stringify({ref:"refs/heads/main", object:{sha:"${SHA}"}}));
} else {
  console.log(JSON.stringify({status:process.env.FAILURE_STATUS}));
  process.exitCode = 1;
}
`);
  chmodSync(executable, 0o700);
  for (const status of ["401", "403", "404", "500", "403:untrusted-context"]) {
    const result = spawnSync(process.execPath, ["scripts/publish_github_release.mjs", "--prepare"], {
      encoding: "utf8", env: { ...process.env, ...ENV, PATH: `${bin}:${process.env.PATH}`, FAILURE_STATUS: status },
    });
    assert.equal(result.status, 1);
    const suffix = /^[1-5][0-9]{2}$/u.test(status) ? `:http-${status}` : "";
    assert.equal(result.stderr, `GitHub release failed: github-request-failed${suffix}\n`);
    assert.equal(result.stdout, "");
  }
});

test("the command-line transport prepares, uploads, verifies, and publishes one release", (t) => {
  const f = fixture(t);
  const bin = join(f.directory, "cli-bin");
  const statePath = join(f.directory, "cli-state.json");
  mkdirSync(bin);
  writeFileSync(statePath, JSON.stringify({ tag: null, alias: null, release: null, creations: 0 }));
  const executable = join(bin, "gh");
  writeFileSync(executable, `#!/usr/bin/env node
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const path = require("node:path");
const args = process.argv.slice(2);
const state = JSON.parse(fs.readFileSync(process.env.RELEASE_TEST_STATE, "utf8"));
const save = () => fs.writeFileSync(process.env.RELEASE_TEST_STATE, JSON.stringify(state));
const respond = (value) => {
  if (value === null) { console.log(JSON.stringify({status:"404"})); process.exitCode = 1; }
  else console.log(JSON.stringify(value));
};
if (args[0] === "release") {
  assert.deepEqual(args.slice(0, 3), ["release", "upload", "${TAG}"]);
  assert.deepEqual(args.slice(4), ["--repo", "reallyme/zk"]);
  const bytes = fs.readFileSync(args[3]);
  state.release.assets.push({id:state.release.assets.length + 1, name:path.basename(args[3]), size:bytes.length,
    digest:"sha256:" + crypto.createHash("sha256").update(bytes).digest("hex")});
  save();
} else {
  assert.deepEqual(args.slice(0, 2), ["api", "--method"]);
  const method = args[2], endpoint = args[3], fields = {};
  for (let i = 4; i < args.length; i += 2) {
    const separator = args[i + 1].indexOf("=");
    const key = args[i + 1].slice(0, separator), value = args[i + 1].slice(separator + 1);
    fields[key] = args[i] === "--field" ? JSON.parse(value) : value;
  }
  if (method === "GET" && endpoint.endsWith("/git/ref/heads/main")) respond({ref:"refs/heads/main",object:{sha:"${SHA}"}});
  else if (method === "GET" && endpoint.includes("/releases?")) respond(state.release === null ? [] : [state.release]);
  else if (method === "GET" && endpoint.endsWith("/releases/tags/v0.3.1")) respond(null);
  else if (method === "GET" && endpoint.endsWith("/git/ref/tags/${TAG}")) respond(state.tag);
  else if (method === "GET" && endpoint.endsWith("/git/ref/tags/v0.3.1")) respond(state.alias);
  else if (method === "GET" && endpoint.endsWith("/releases/tags/${TAG}")) respond(state.release?.draft === false ? state.release : null);
  else if (method === "GET" && endpoint.endsWith("/releases/7")) respond(state.release);
  else if (method === "POST" && endpoint.endsWith("/git/refs")) {
    assert.ok(["refs/tags/${TAG}","refs/tags/v0.3.1"].includes(fields.ref)); assert.equal(fields.sha,"${SHA}");
    const key = fields.ref === "refs/tags/${TAG}" ? "tag" : "alias";
    state[key] = {ref:fields.ref,object:{sha:fields.sha,type:"commit"}}; save(); respond(state[key]);
  } else if (method === "POST" && endpoint.endsWith("/releases")) {
    assert.equal(fields.tag_name,"${TAG}"); assert.equal(fields.name,"${TAG}");
    assert.equal(fields.target_commitish,"${SHA}"); assert.equal(fields.draft,true);
    assert.equal(state.release,null);
    state.creations += 1; state.release = {...fields,id:7,immutable:false,assets:[]}; save(); respond(state.release);
  } else if (method === "PATCH" && endpoint.endsWith("/releases/7")) {
    assert.equal(fields.draft,false); assert.equal(fields.name,"${TAG}");
    Object.assign(state.release,fields); save(); respond(state.release);
  } else assert.fail("unexpected request");
}
`);
  chmodSync(executable, 0o700);
  const env = { ...process.env, ...ENV, PATH: `${bin}:${process.env.PATH}`, RELEASE_TEST_STATE: statePath };
  for (const args of [["--prepare"], ["--publish", "--swift", ...f.paths], ["--publish", "--swift", ...f.paths]]) {
    const result = spawnSync(process.execPath, ["scripts/publish_github_release.mjs", ...args], { encoding: "utf8", env });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `Verified GitHub release: ${TAG}\n`);
  }
  const state = JSON.parse(readFileSync(statePath, "utf8"));
  assert.equal(state.creations, 1);
  assert.equal(state.release.draft, false);
  assert.equal(state.release.assets.length, 2);
  assert.equal(state.alias.object.sha, state.tag.object.sha);
});
