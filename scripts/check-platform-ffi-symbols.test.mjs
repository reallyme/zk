#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

test("Apple archive checks discover llvm-nm in the active Rust toolchain", () => {
  const temporary = mkdtempSync(join(tmpdir(), "zk-apple-symbols-"));
  try {
    const bin = join(temporary, "bin");
    const sysroot = join(temporary, "rust");
    const llvmBin = join(sysroot, "lib/rustlib/fixture-apple-darwin/bin");
    mkdirSync(bin);
    mkdirSync(llvmBin, { recursive: true });
    for (const tool of ["dirname", "grep", "sed", "mktemp", "rm"]) {
      const found = spawnSync("which", [tool], { encoding: "utf8" });
      assert.equal(found.status, 0);
      symlinkSync(found.stdout.trim(), join(bin, tool));
    }
    const executable = (path, script) => {
      writeFileSync(path, `#!/bin/sh\n${script}\n`);
      chmodSync(path, 0o700);
    };
    executable(join(bin, "rustc"), 'case "$1" in --print) printf "%s\\n" "$FIXTURE_SYSROOT";; -vV) printf "host: fixture-apple-darwin\\n";; esac');
    executable(join(bin, "nm"), 'printf "private external _reallyme_bbapi_call\\nprivate external _reallyme_bbapi_free\\n"');
    const symbols = ["context_create", "context_create_with_crs_files", "dispatch",
      "context_destroy", "buffer_destroy", "encode_failure_response"]
      .map((name) => `_reallyme_zk_platform_${name}`).join("\\n");
    executable(join(llvmBin, "llvm-nm"), `printf '${symbols}\\n'`);
    const archive = join(temporary, "libfixture.a");
    writeFileSync(archive, Buffer.from([0]));
    const result = spawnSync("/bin/bash", ["scripts/check-platform-ffi-symbols.sh", "apple", archive], {
      encoding: "utf8",
      env: { ...process.env, PATH: bin, LLVM_NM: "", FIXTURE_SYSROOT: sysroot },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /symbol check passed for apple/u);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("large unresolved-symbol lists cannot hide a forbidden JNI backend symbol", () => {
  const temporary = mkdtempSync(join(tmpdir(), "zk-jni-symbols-"));
  try {
    const archive = join(temporary, "libjni.so");
    const readelf = join(temporary, "readelf");
    writeFileSync(archive, Buffer.from([0]));
    const symbols = [
      "1: 0 0 FUNC GLOBAL DEFAULT UND _ZN2bbForbidden",
      ...Array.from({ length: 20_000 }, (_value, index) =>
        `${index + 2}: 0 0 FUNC GLOBAL DEFAULT UND harmless_${index}`),
      "20002: 0 0 FUNC GLOBAL DEFAULT 1 Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextCreate",
      "20003: 0 0 FUNC GLOBAL DEFAULT 1 Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextCreateWithCrsFiles",
      "20004: 0 0 FUNC GLOBAL DEFAULT 1 Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeDispatch",
      "20005: 0 0 FUNC GLOBAL DEFAULT 1 Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextDestroy",
    ].join("\n");
    writeFileSync(readelf, `#!/bin/sh\ncat <<'SYMBOLS'\n${symbols}\nSYMBOLS\n`);
    chmodSync(readelf, 0o700);
    const result = spawnSync("bash", ["scripts/check-platform-ffi-symbols.sh", "android-jni", archive], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, LLVM_READELF: readelf },
    });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /unresolved internal Barretenberg symbols/u);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("Android visibility checks discover the NDK inspector without host LLVM", () => {
  const temporary = mkdtempSync(join(tmpdir(), "zk-android-symbols-"));
  try {
    const bin = join(temporary, "bin");
    const ndk = join(temporary, "ndk");
    const host = process.platform === "darwin" ? "darwin-x86_64" : "linux-x86_64";
    const inspector = join(ndk, "toolchains/llvm/prebuilt", host, "bin/llvm-readelf");
    mkdirSync(bin);
    mkdirSync(dirname(inspector), { recursive: true });
    for (const tool of ["dirname", "grep", "mktemp", "rm", "uname"]) {
      const found = spawnSync("which", [tool], { encoding: "utf8" });
      assert.equal(found.status, 0);
      symlinkSync(found.stdout.trim(), join(bin, tool));
    }
    const symbols = ["context_create", "context_create_with_crs_files", "dispatch",
      "context_destroy", "buffer_destroy", "encode_failure_response"]
      .map((name) => `1: 0 0 FUNC GLOBAL DEFAULT 1 reallyme_zk_platform_${name}`)
      .concat(["1: 0 0 FUNC GLOBAL HIDDEN 1 reallyme_bbapi_call",
        "1: 0 0 FUNC GLOBAL HIDDEN 1 reallyme_bbapi_free"]).join("\n");
    const writeInspector = (output) => {
      writeFileSync(inspector, `#!/bin/sh\nprintf '%s\\n' '${output}'\n`);
      chmodSync(inspector, 0o700);
    };
    writeInspector(symbols);
    const archive = join(temporary, "libfixture.a");
    writeFileSync(archive, Buffer.from([0]));
    const run = (variable) => spawnSync("/bin/bash", ["scripts/check-platform-ffi-symbols.sh", "android", archive], {
      encoding: "utf8",
      env: { ...process.env, PATH: bin, LLVM_READELF: "", ANDROID_NDK_HOME: "",
        ANDROID_NDK_ROOT: "", ANDROID_NDK_LATEST_HOME: "", [variable]: ndk },
    });
    for (const variable of ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "ANDROID_NDK_LATEST_HOME"]) {
      const result = run(variable);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /symbol check passed for android/u);
    }
    writeInspector(symbols.replace("HIDDEN 1 reallyme_bbapi_call", "DEFAULT 1 reallyme_bbapi_call"));
    const rejected = run("ANDROID_NDK_HOME");
    assert.equal(rejected.status, 2);
    assert.match(rejected.stderr, /raw bbapi call symbol is not hidden/u);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
