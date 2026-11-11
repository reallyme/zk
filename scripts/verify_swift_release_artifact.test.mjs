#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./verify_swift_release_artifact.mjs", import.meta.url));
const requiredSymbols = [
  "reallyme_zk_platform_context_create",
  "reallyme_zk_platform_context_create_with_crs_files",
  "reallyme_zk_platform_dispatch",
  "reallyme_zk_platform_context_destroy",
  "reallyme_zk_platform_buffer_destroy",
  "reallyme_zk_platform_encode_failure_response",
];

const writeExecutable = (path, source) => {
  writeFileSync(path, source, { mode: 0o700 });
  chmodSync(path, 0o700);
};

const writeFixture = (root, { bound = true, forgedSidecar = false, omitSymbol = false, undefinedSymbol = false } = {}) => {
  const payload = join(root, "payload");
  const framework = join(payload, "ReallyMeZKPlatformFFI.xcframework");
  const slices = ["macos-arm64", "ios-arm64", "ios-arm64-simulator"];
  mkdirSync(framework, { recursive: true });
  writeFileSync(join(framework, "Info.plist"), "fixture\n");
  for (const slice of slices) {
    const headers = join(framework, slice, "Headers");
    mkdirSync(headers, { recursive: true });
    writeFileSync(join(headers, "reallyme_zk_platform_abi.h"), "/* fixture */\n");
    writeFileSync(join(headers, "module.modulemap"), "module Fixture {}\n");
    writeFileSync(join(framework, slice, "libreallyme_zk_platform_ffi.a"), `fixture ${slice}\n`);
  }

  const archive = join(root, "ReallyMeZKPlatformFFI.xcframework.zip");
  execFileSync("zip", ["-X", "-q", "-r", archive, "ReallyMeZKPlatformFFI.xcframework"], {
    cwd: payload,
    stdio: "pipe",
  });
  const checksum = createHash("sha256").update(readFileSync(archive)).digest("hex");
  const sidecar = join(root, "ReallyMeZKPlatformFFI.xcframework.checksum");
  writeFileSync(sidecar, `${forgedSidecar ? "0".repeat(64) : checksum}\n`);

  const manifest = join(root, "Package.swift");
  writeFileSync(
    manifest,
    `let ffiArtifactChecksum = "${checksum}"
let ffiArtifactVersion = "0.2.0"
let ffiArtifactLocalPathOverride = ""
.binaryTarget(
  name: "ReallyMeZKPlatformFFI",
  url: "https://static.reallyme.net/zk/swift/\\(ffiArtifactChecksum)/ReallyMeZKPlatformFFI.xcframework.zip",
  checksum: ${bound ? "ffiArtifactChecksum" : `"${checksum}"`}
)
`,
  );

  const tools = join(root, "tools");
  const rustTargetLibrary = join(root, "rust-toolchain", "lib", "rustlib", "fixture", "lib");
  const llvmBin = join(root, "rust-toolchain", "lib", "rustlib", "fixture", "bin");
  mkdirSync(tools, { recursive: true });
  mkdirSync(rustTargetLibrary, { recursive: true });
  mkdirSync(llvmBin, { recursive: true });
  writeExecutable(
    join(tools, "swift"),
    "#!/bin/sh\nset -eu\n[ \"$1\" = package ]\n[ \"$2\" = compute-checksum ]\nshasum -a 256 \"$3\" | cut -d ' ' -f 1\n",
  );
  writeExecutable(join(tools, "rustc"), `#!/bin/sh\nprintf '%s\\n' '${rustTargetLibrary}'\n`);
  const symbols = omitSymbol ? requiredSymbols.slice(1) : requiredSymbols;
  writeExecutable(
    join(llvmBin, "llvm-nm"),
    `#!/bin/sh\nprintf '%s\\n' ${symbols
      .map((symbol, index) => `'00000000 ${undefinedSymbol && index === 0 ? "U" : "T"} _${symbol}'`)
      .join(" ")}\n`,
  );
  return {
    archive,
    env: { ...process.env, PATH: `${tools}${delimiter}${process.env.PATH ?? ""}` },
    manifest,
    sidecar,
  };
};

const runVerifier = (fixture) =>
  execFileSync(
    process.execPath,
    [script, fixture.archive, fixture.sidecar, fixture.manifest, "0.2.0"],
    { env: fixture.env, stdio: "pipe" },
  );

test("accepts a checksum-bound archive with every required slice and ABI symbol", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-zk-swift-release-"));
  try {
    assert.doesNotThrow(() => runVerifier(writeFixture(root)));
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("recomputes the archive bytes and rejects a forged checksum sidecar", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-zk-swift-release-"));
  try {
    assert.throws(() => runVerifier(writeFixture(root, { forgedSidecar: true })));
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects a manifest that does not consume its checksum binding", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-zk-swift-release-"));
  try {
    assert.throws(() => runVerifier(writeFixture(root, { bound: false })));
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects an archive whose native slices omit a required ABI symbol", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-zk-swift-release-"));
  try {
    assert.throws(() => runVerifier(writeFixture(root, { omitSymbol: true })));
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects undefined ABI references and cleans up extracted slices on failure", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-zk-swift-release-"));
  try {
    const fixture = writeFixture(root, { undefinedSymbol: true });
    const scratch = join(root, "scratch");
    mkdirSync(scratch);
    fixture.env.TMPDIR = scratch;
    fixture.env.TMP = scratch;
    fixture.env.TEMP = scratch;
    assert.throws(() => runVerifier(fixture));
    assert.deepEqual(readdirSync(scratch), []);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
