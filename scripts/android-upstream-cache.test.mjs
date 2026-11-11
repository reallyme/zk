// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./build_android_barretenberg_static_archive.sh", import.meta.url));
const digest = (value) => createHash("sha256").update(value).digest("hex");

function fixture(action) {
  const root = mkdtempSync(join(tmpdir(), "zk-android-cache-test-"));
  const output = join(root, "libraries");
  const lock = join(root, "lock.json");
  const bb = Buffer.from("approved archive fixture");
  const companion = Buffer.from("approved companion fixture");
  const identity = {
    size: bb.length, sha256: digest(bb),
    companionStaticLibraries: [{ size: companion.length, sha256: digest(companion) }],
  };
  const writeLock = (value = identity) => writeFileSync(lock, JSON.stringify({
    candidateMatchedPair: { barretenberg: { linkableStaticLibraries: {
      androidArm64: { ...value, linuxSourceBuild: value },
    } } },
  }));
  const run = (args = ["--verify-only"]) => spawnSync("bash", [script, ...args], {
    encoding: "utf8", timeout: 10_000,
    env: {
      ...process.env, TOOLCHAIN_LOCK: lock, OUTPUT_DIR: output,
      ANDROID_NDK_HOME: join(root, "no-ndk"), CMAKE_BIN: "no-compiler-may-run", NINJA_BIN: "no-ninja-may-run",
    },
  });
  try {
    mkdirSync(output);
    writeFileSync(join(output, "libbb-external.a"), bb);
    writeFileSync(join(output, "libdeflate.a"), companion);
    writeLock();
    action({ root, output, run, bb, companion, writeLock, identity });
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
}

test("Android cache verification accepts a complete pinned pair without any build tools", () => {
  fixture(({ run }) => {
    const result = run();
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "");
  });
});

test("Android cache verification rejects truncated and same-size modified archives", () => {
  fixture(({ output, run, bb, companion }) => {
    for (const [name, contents] of [["libbb-external.a", bb], ["libdeflate.a", companion]]) {
      const path = join(output, name);
      for (const changed of [contents.subarray(1), Buffer.alloc(contents.length)]) {
        writeFileSync(path, changed);
        const result = run();
        assert.equal(result.status, 2);
        assert.match(result.stderr, /differs from the toolchain lock/u);
        assert.ok(!result.stderr.includes("no-compiler-may-run"));
      }
      writeFileSync(path, contents);
    }
  });
});

test("Android cache verification rejects missing and symlinked archives", () => {
  fixture(({ root, output, run, bb }) => {
    const archive = join(output, "libbb-external.a");
    rmSync(archive);
    assert.equal(run().status, 2);
    const target = join(root, "outside.a");
    writeFileSync(target, bb);
    symlinkSync(target, archive);
    const result = run();
    assert.equal(result.status, 2);
    assert.match(result.stderr, /not a regular file/u);
  });
});

test("Android cache verification rejects a pair approved by a different pin", () => {
  fixture(({ run, writeLock, identity }) => {
    writeLock({ ...identity, sha256: "0".repeat(64) });
    const result = run();
    assert.equal(result.status, 2);
    assert.match(result.stderr, /SHA-256 differs from the toolchain lock/u);
  });
});

test("Android archive builder rejects unknown cache controls before attempting a build", () => {
  fixture(({ run }) => {
    for (const args of [["--unknown"], ["--verify-only", "extra"]]) {
      const result = run(args);
      assert.equal(result.status, 2);
      assert.match(result.stderr, /unsupported argument/u);
    }
  });
});
