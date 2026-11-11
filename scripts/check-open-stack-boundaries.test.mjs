// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const script = join(repositoryRoot, "scripts", "check-open-stack-boundaries.sh");

test("boundary gate never follows legacy predictable match-file symlinks and cleans up", () => {
  const directory = mkdtempSync(join(tmpdir(), "zk-boundary-policy-test-"));
  try {
    const sentinel = join(directory, "sentinel");
    const legacyPath = join(directory, "reallyme-zk-platform-rust-features.matches");
    writeFileSync(sentinel, "unchanged");
    symlinkSync(sentinel, legacyPath);

    const result = spawnSync(script, [], {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: { ...process.env, TMPDIR: directory },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(sentinel, "utf8"), "unchanged");
    assert.deepEqual(
      readdirSync(directory).sort(),
      ["reallyme-zk-platform-rust-features.matches", "sentinel"],
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("boundary gate fails CI when a required sibling checkout is absent", () => {
  const directory = mkdtempSync(join(tmpdir(), "zk-boundary-required-sibling-"));
  try {
    const reallyme = join(directory, "reallyme");
    const zk = join(reallyme, "zk");
    const scripts = join(zk, "scripts");
    const fakeScript = join(scripts, "check-open-stack-boundaries.sh");
    for (const path of [
      scripts,
      join(zk, "crates", "api", "src"),
      join(zk, "crates", "artifacts"),
      join(zk, "crates", "backend-bb", "src"),
      join(zk, "crates", "proto", "proto"),
      join(zk, "crates", "proto-codec"),
    ]) {
      mkdirSync(path, { recursive: true });
    }
    for (const manifest of [
      join(zk, "Cargo.toml"),
      join(zk, "crates", "api", "Cargo.toml"),
      join(zk, "crates", "artifacts", "Cargo.toml"),
      join(zk, "crates", "proto", "Cargo.toml"),
      join(zk, "crates", "proto-codec", "Cargo.toml"),
    ]) {
      writeFileSync(manifest, "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\n");
    }
    writeFileSync(fakeScript, readFileSync(script, "utf8"));
    chmodSync(fakeScript, 0o700);

    const result = spawnSync(fakeScript, [], {
      cwd: zk,
      encoding: "utf8",
      env: {
        ...process.env,
        CI: "true",
        REALLYME_ZK_REQUIRED_OPEN_STACK_CHECKOUTS: "ssi",
      },
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /error: SSI checkout not found/u);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("boundary gate reports secure temporary-directory creation failure", () => {
  const directory = mkdtempSync(join(tmpdir(), "zk-boundary-mktemp-failure-"));
  try {
    const fakeMktemp = join(directory, "mktemp");
    writeFileSync(fakeMktemp, "#!/bin/sh\nexit 1\n");
    chmodSync(fakeMktemp, 0o700);
    const result = spawnSync(script, [], {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: { ...process.env, PATH: `${directory}:${process.env.PATH ?? ""}` },
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /error: secure temporary directory creation failed/u);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("boundary gate source covers aliased process execution and transitive backend dependencies", () => {
  const source = readFileSync(script, "utf8");
  const workspace = readFileSync(join(repositoryRoot, "Cargo.toml"), "utf8");
  const clippyPolicy = readFileSync(join(repositoryRoot, "clippy.toml"), "utf8");

  assert.match(source, /cargo tree --locked --all-features --edges normal,build/u);
  assert.match(source, /reallyme-zk-api/u);
  assert.match(source, /reallyme-zk-proto-codec/u);
  assert.match(source, /std::process\\s\+as/u);
  assert.match(source, /Command::new/u);
  assert.match(workspace, /disallowed_methods\s*=\s*"deny"/u);
  assert.match(workspace, /disallowed_types\s*=\s*"deny"/u);
  assert.match(clippyPolicy, /std::process::Command::new/u);
  assert.match(clippyPolicy, /std::process::Command/u);
});

test("compiler policy rejects aliased process execution", () => {
  const directory = mkdtempSync(join(tmpdir(), "zk-boundary-clippy-alias-"));
  try {
    mkdirSync(join(directory, "src"), { recursive: true });
    writeFileSync(
      join(directory, "Cargo.toml"),
      [
        "[package]",
        "name = \"reallyme-zk-boundary-alias-fixture\"",
        "version = \"0.0.0\"",
        "edition = \"2021\"",
        "publish = false",
        "",
        "[lints.clippy]",
        "disallowed_methods = \"deny\"",
        "disallowed_types = \"deny\"",
        "",
      ].join("\n"),
    );
    writeFileSync(join(directory, "clippy.toml"), readFileSync(join(repositoryRoot, "clippy.toml")));
    writeFileSync(
      join(directory, "src", "lib.rs"),
      [
        "use std::process as hidden_process;",
        "",
        "pub fn spawn_alias_bypass_fixture() {",
        "    let _command = hidden_process::Command::new(\"true\");",
        "}",
        "",
      ].join("\n"),
    );

    const result = spawnSync(
      "cargo",
      [
        "clippy",
        "--manifest-path",
        join(directory, "Cargo.toml"),
        "--lib",
        "--",
        "-D",
        "warnings",
      ],
      {
        cwd: directory,
        encoding: "utf8",
        env: {
          ...process.env,
          CARGO_TARGET_DIR: join(directory, "target"),
        },
      },
    );

    assert.notEqual(result.status, 0, result.stdout);
    assert.match(result.stderr, /std::process::Command/u);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
