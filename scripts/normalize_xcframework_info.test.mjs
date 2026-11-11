// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

function fixture(run) {
  const root = mkdtempSync(join(tmpdir(), "xcframework-metadata-"));
  const path = join(root, "Info.plist");
  const normalize = () => spawnSync("python3", ["scripts/normalize_xcframework_info.py", path], { encoding: "utf8" });
  try { run({ root, path, normalize }); } finally { rmSync(root, { recursive: true, force: true }); }
}
function metadata(identifiers) {
  const libraries = identifiers.map((identifier) => `<dict><key>LibraryIdentifier</key><string>${identifier}</string><key>LibraryPath</key><string>library.a</string></dict>`).join("");
  return `<?xml version="1.0"?><plist version="1.0"><dict><key>AvailableLibraries</key><array>${libraries}</array><key>XCFrameworkFormatVersion</key><string>1.0</string></dict></plist>`;
}

test("every Xcode slice order produces the same canonical bytes", () => {
  fixture(({ path, normalize }) => {
    let canonical;
    for (const order of [
      ["macos-arm64", "ios-arm64", "ios-arm64-simulator"],
      ["ios-arm64-simulator", "macos-arm64", "ios-arm64"],
      ["ios-arm64", "ios-arm64-simulator", "macos-arm64"],
    ]) {
      writeFileSync(path, metadata(order));
      const result = normalize();
      assert.equal(result.status, 0, result.stderr);
      const bytes = readFileSync(path);
      canonical ??= bytes;
      assert.deepEqual(bytes, canonical);
      assert.equal(normalize().status, 0);
      assert.deepEqual(readFileSync(path), canonical);
    }
  });
});

test("malformed, missing, duplicate, and unsupported slices preserve the input on failure", () => {
  fixture(({ path, normalize }) => {
    for (const input of ["invalid", '<?xml version="1.0"?><plist><dict>', metadata([]), metadata(["macos-arm64", "ios-arm64", "ios-arm64"]), metadata(["macos-arm64", "ios-arm64", "unknown"])]) {
      writeFileSync(path, input);
      assert.equal(normalize().status, 1);
      assert.equal(readFileSync(path, "utf8"), input);
    }
  });
});

test("normalization rejects a metadata symlink", () => {
  fixture(({ root, path, normalize }) => {
    const target = join(root, "target.plist");
    writeFileSync(target, metadata(["macos-arm64", "ios-arm64", "ios-arm64-simulator"]));
    symlinkSync(target, path);
    assert.equal(normalize().status, 1);
  });
});


test("Swift ZIP packaging produces identical bytes across host timezones", () => {
  fixture(({ root }) => {
    const framework = join(root, "ReallyMeZKPlatformFFI.xcframework");
    mkdirSync(framework);
    writeFileSync(join(framework, "Info.plist"), "fixed metadata");
    const source = readFileSync("scripts/build_swift_xcframework.sh", "utf8");
    const start = source.indexOf('(\n  cd "${PACKAGE_DIR}"');
    const end = source.indexOf('\nswift package compute-checksum', start);
    assert.ok(start >= 0 && end > start);
    const packaging = source.slice(start, end);
    let canonical;
    for (const timezone of ["Europe/Malta", "UTC", "Pacific/Honolulu"]) {
      const archive = join(root, "ReallyMeZKPlatformFFI.xcframework.zip");
      rmSync(archive, { force: true });
      const result = spawnSync("bash", ["-c", packaging], {
        encoding: "utf8",
        env: { ...process.env, PACKAGE_DIR: root, TZ: timezone },
      });
      assert.equal(result.status, 0, result.stderr);
      const bytes = readFileSync(archive);
      canonical ??= bytes;
      assert.deepEqual(bytes, canonical);
    }
  });
});
