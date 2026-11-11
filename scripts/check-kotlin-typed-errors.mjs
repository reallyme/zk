#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE_LIMIT_BYTES = 1_048_576;
const DOMAIN_EXCEPTION_PATH =
  "packages/kotlin/src/main/kotlin/me/really/zk/ReallyMeZkProvider.kt";
const GENERIC_ERROR_CONSTRUCTOR =
  /\b(?:Exception|RuntimeException|IllegalArgumentException|IllegalStateException|ZkProviderExceptionBase)[ \t\n]*\(/gu;
const GENERIC_ERROR_ALIAS =
  /\btypealias[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(?:(?:kotlin|java\.lang)\.)?(Exception|RuntimeException|IllegalArgumentException|IllegalStateException)\b/gu;
const GENERIC_ERROR_IMPORT_ALIAS =
  /^[ \t]*import[ \t]+(?:(?:kotlin|java\.lang)\.)?(?:Exception|RuntimeException|IllegalArgumentException|IllegalStateException)[ \t]+as[ \t]+[A-Za-z_][A-Za-z0-9_]*/gmu;

// Keep offsets stable so a rejected constructor can be reported without
// printing source text, which may include private fixture values.
function scrubNonCode(source) {
  let output = "";
  let state = "code";
  let blockDepth = 0;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (state === "code") {
      if (character === "/" && next === "/") {
        output += "  ";
        index += 1;
        state = "line-comment";
      } else if (character === "/" && next === "*") {
        output += "  ";
        index += 1;
        blockDepth = 1;
        state = "block-comment";
      } else if (source.startsWith('"""', index)) {
        output += "   ";
        index += 2;
        state = "raw-string";
      } else if (character === '"' || character === "'") {
        output += " ";
        state = character === '"' ? "string" : "character";
      } else {
        output += character;
      }
      continue;
    }
    if (state === "line-comment") {
      output += character === "\n" ? "\n" : " ";
      if (character === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (character === "/" && next === "*") {
        output += "  ";
        index += 1;
        blockDepth += 1;
      } else if (character === "*" && next === "/") {
        output += "  ";
        index += 1;
        blockDepth -= 1;
        if (blockDepth === 0) state = "code";
      } else {
        output += character === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (state === "raw-string") {
      if (source.startsWith('"""', index)) {
        output += "   ";
        index += 2;
        state = "code";
      } else {
        output += character === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (character === "\\" && next !== undefined) {
      output += next === "\n" ? " \n" : "  ";
      index += 1;
    } else {
      output += character === "\n" ? "\n" : " ";
      if ((state === "string" && character === '"') ||
          (state === "character" && character === "'")) {
        state = "code";
      }
    }
  }
  return output;
}

function isReviewedDomainExceptionSuperclass(source, path, offset) {
  if (path !== DOMAIN_EXCEPTION_PATH) return false;
  const declaration = "class ReallyMeZkProviderException";
  const start = source.lastIndexOf(declaration, offset);
  if (start < 0) return false;
  const prefix = source.slice(start, offset);
  return /^class ReallyMeZkProviderException\s*\([^{};]*\)\s*:\s*$/u.test(prefix);
}

export function firstGenericKotlinError(source, path) {
  const code = scrubNonCode(source);
  if (path === DOMAIN_EXCEPTION_PATH &&
      !/^private typealias ZkProviderExceptionBase = Exception$/mu.test(code)) {
    return 1;
  }
  for (const match of code.matchAll(GENERIC_ERROR_ALIAS)) {
    if (path === DOMAIN_EXCEPTION_PATH &&
        match[1] === "ZkProviderExceptionBase" &&
        match[2] === "Exception") continue;
    return code.slice(0, match.index).split("\n").length;
  }
  for (const match of code.matchAll(GENERIC_ERROR_IMPORT_ALIAS)) {
    return code.slice(0, match.index).split("\n").length;
  }
  GENERIC_ERROR_CONSTRUCTOR.lastIndex = 0;
  for (const match of code.matchAll(GENERIC_ERROR_CONSTRUCTOR)) {
    if (isReviewedDomainExceptionSuperclass(code, path, match.index)) continue;
    return code.slice(0, match.index).split("\n").length;
  }
  return null;
}

function main() {
  const listing = spawnSync(
    "git",
    ["ls-files", "-co", "--exclude-standard", "-z", "--", "packages/kotlin"],
    { encoding: "utf8" },
  );
  if (listing.status !== 0 || listing.error) {
    console.error("Kotlin typed-error check could not enumerate source files");
    process.exitCode = 1;
    return;
  }
  const paths = listing.stdout.split("\0").filter((path) =>
    path.endsWith(".kt") &&
    /\/src\/(?:main|commonMain|androidMain)\//u.test(path),
  );
  for (const path of paths) {
    const source = readFileSync(path, "utf8");
    if (Buffer.byteLength(source, "utf8") > SOURCE_LIMIT_BYTES) {
      console.error(`Kotlin typed-error check rejected oversized source: ${path}`);
      process.exitCode = 1;
      return;
    }
    const line = firstGenericKotlinError(source, path);
    if (line !== null) {
      console.error(`Kotlin typed-error check rejected generic constructor: ${path}:${line}`);
      process.exitCode = 1;
      return;
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
