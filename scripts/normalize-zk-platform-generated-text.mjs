#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFile, readdir, writeFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..");
const generatedRoots = [
  "gen/java/zk",
  "gen/kotlin/zk",
  "packages/swift/Sources/Generated/ReallyMeZkProtoGenerated",
];
const textExtensions = new Set([".java", ".kt", ".swift"]);

async function normalizeDirectory(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      await normalizeDirectory(path);
      continue;
    }
    if (!entry.isFile() || !textExtensions.has(extname(entry.name))) {
      continue;
    }

    const source = await readFile(path, "utf8");
    const normalized = `${source
      .replaceAll("\r\n", "\n")
      .replaceAll(
        "SPDX-License-Identifier: Apache-2.0",
        "SPDX-License-Identifier: MIT OR Apache-2.0",
      )
      .split("\n")
      .map((line) => line.replace(/[\t ]+$/u, ""))
      .join("\n")
      .trimEnd()}\n`;
    if (normalized !== source) {
      await writeFile(path, normalized, "utf8");
    }
  }
}

for (const relativeRoot of generatedRoots) {
  await normalizeDirectory(join(repoRoot, relativeRoot));
}
