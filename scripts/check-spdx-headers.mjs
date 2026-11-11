#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { extname } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const COPYRIGHT =
  "SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved";
const NOIR_COPYRIGHT =
  "SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved";
const LICENSE = "SPDX-License-Identifier: MIT OR Apache-2.0";
const FIX_ARGUMENT = "--fix";
const supportedArguments = new Set([FIX_ARGUMENT]);
const suppliedArguments = process.argv.slice(2);

for (const argument of suppliedArguments) {
  if (!supportedArguments.has(argument)) {
    console.error(`SPDX check failed: unsupported argument ${argument}`);
    process.exit(2);
  }
}

if (new Set(suppliedArguments).size !== suppliedArguments.length) {
  console.error("SPDX check failed: duplicate arguments are not allowed");
  process.exit(2);
}

const fix = suppliedArguments.includes(FIX_ARGUMENT);
const tracked = spawnSync("git", ["ls-files", "-z"], {
  encoding: "utf8",
  maxBuffer: 16 * 1024 * 1024,
});
if (tracked.status !== 0 || tracked.error !== undefined) {
  console.error("SPDX check failed: unable to enumerate tracked files");
  process.exit(1);
}

const lineCommentExtensions = new Set([
  ".cc",
  ".cpp",
  ".h",
  ".hpp",
  ".java",
  ".kt",
  ".kts",
  ".mjs",
  ".proto",
  ".rs",
  ".swift",
  ".ts",
]);
const hashCommentExtensions = new Set([
  ".py",
  ".sh",
  ".toml",
  ".vector",
  ".yaml",
  ".yml",
]);
const excludedPrefixes = [
  "circuits/vendor/",
  "crates/proto/src/generated/",
  "gen/java/zk/",
  "gen/kotlin/zk/",
  "packages/swift/Sources/Generated/ReallyMeZkProtoGenerated/",
  "scripts/release-readiness/",
];

function headerFor(path) {
  if (lineCommentExtensions.has(extname(path))) {
    return `// ${COPYRIGHT}\n//\n// ${LICENSE}\n\n`;
  }
  if (path.endsWith(".nr")) {
    // Nargo rejects non-ASCII characters even inside comments.
    return `// ${NOIR_COPYRIGHT}\n//\n// ${LICENSE}\n\n`;
  }
  if (hashCommentExtensions.has(extname(path)) || path.endsWith("/.gitignore") || path === ".gitignore") {
    return `# ${COPYRIGHT}\n#\n# ${LICENSE}\n\n`;
  }
  return undefined;
}

function insertHeader(text, header) {
  if (!text.startsWith("#!")) {
    return `${header}${text}`;
  }
  const newline = text.indexOf("\n");
  if (newline === -1) {
    return `${text}\n${header}`;
  }
  return `${text.slice(0, newline + 1)}${header}${text.slice(newline + 1)}`;
}

const missing = [];
const trackedFiles = tracked.stdout.split("\0").filter((path) => path.length > 0);
for (const path of trackedFiles) {
  if (excludedPrefixes.some((prefix) => path.startsWith(prefix))) {
    continue;
  }
  const text = readFileSync(path, "utf8");
  if (path.endsWith(".md") || path.endsWith(".txt")) {
    if (text.includes("SPDX-FileCopyrightText:") || text.includes("SPDX-License-Identifier:")) {
      console.error(`SPDX check failed: ${path} must not carry an SPDX header`);
      process.exit(1);
    }
    continue;
  }
  const header = headerFor(path);
  if (header === undefined) {
    continue;
  }
  const expectedCopyright = path.endsWith(".nr") ? NOIR_COPYRIGHT : COPYRIGHT;
  if (text.includes(expectedCopyright) && text.includes(LICENSE)) {
    continue;
  }
  missing.push(path);
  if (fix) {
    const normalizedText =
      path.endsWith(".nr") && text.includes(COPYRIGHT)
        ? text.replace(COPYRIGHT, NOIR_COPYRIGHT)
        : insertHeader(text, header);
    writeFileSync(path, normalizedText, "utf8");
  }
}

if (missing.length > 0 && !fix) {
  for (const path of missing) {
    console.error(`SPDX check failed: ${path} is missing the required header`);
  }
  process.exit(1);
}

if (fix) {
  console.log(`added SPDX headers to ${missing.length} tracked files`);
} else {
  console.log("SPDX header check passed");
}
