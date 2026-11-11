#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { lstatSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const MAX_SOURCE_BYTES = 512 * 1024;
const MAX_SOURCE_FILES = 512;
const SECURITY_REGRESSION_PREFIX = "circuits/security-regressions/";

export class NoirSecurityProfileError extends Error {
  constructor(code) {
    super(code);
    this.name = "NoirSecurityProfileError";
    this.code = code;
  }
}

function replaceWithSpace(character) {
  return character === "\n" || character === "\r" ? character : " ";
}

export function stripCommentsAndStrings(source) {
  let result = "";
  let index = 0;
  let blockDepth = 0;
  let state = "code";

  while (index < source.length) {
    const character = source[index];
    const next = source[index + 1];

    if (state === "code") {
      if (character === "/" && next === "/") {
        result += "  ";
        index += 2;
        state = "line-comment";
        continue;
      }
      if (character === "/" && next === "*") {
        result += "  ";
        index += 2;
        blockDepth = 1;
        state = "block-comment";
        continue;
      }
      if (character === '"') {
        result += " ";
        index += 1;
        state = "string";
        continue;
      }
      result += character;
      index += 1;
      continue;
    }

    if (state === "line-comment") {
      result += replaceWithSpace(character);
      index += 1;
      if (character === "\n") {
        state = "code";
      }
      continue;
    }

    if (state === "block-comment") {
      if (character === "/" && next === "*") {
        result += "  ";
        index += 2;
        blockDepth += 1;
        continue;
      }
      if (character === "*" && next === "/") {
        result += "  ";
        index += 2;
        blockDepth -= 1;
        if (blockDepth === 0) {
          state = "code";
        }
        continue;
      }
      result += replaceWithSpace(character);
      index += 1;
      continue;
    }

    if (state === "string") {
      if (character === "\\") {
        result += " ";
        index += 1;
        if (index < source.length) {
          result += replaceWithSpace(source[index]);
          index += 1;
        }
        continue;
      }
      result += replaceWithSpace(character);
      index += 1;
      if (character === '"') {
        state = "code";
      }
    }
  }

  if (state === "block-comment") {
    throw new NoirSecurityProfileError("unterminated-block-comment");
  }
  if (state === "string") {
    throw new NoirSecurityProfileError("unterminated-string");
  }
  return result;
}

const forbiddenPatterns = [
  ["unconstrained-function", /\bunconstrained\b/u],
  ["while-loop", /\bwhile\b/u],
  ["signed-integer", /\bi(?:8|16|32|64|128)\b/u],
  ["u128-integer", /\bu128\b/u],
  [
    "dynamic-slice-type",
    /(?:[:>-]\s*|\btype\b[^=\n;]{1,256}=\s*)\[[^\]\n;]+\]/u,
  ],
  ["dynamic-slice-operation", /\.(?:as_slice|as_array|push_back|push_front|pop_back|pop_front|insert|remove)\b/u],
  ["foreign-call", /\b(?:foreign_call|oracle)\b/u],
  ["dynamic-hasher", /\bstd::hash::Hasher\b/u],
  ["embedded-curve-operation", /\b(?:embedded_curve(?:_[a-z0-9]+)?|multi_scalar_mul|msm)\b/u],
  ["aes-black-box", /\baes(?:128(?:_[a-z0-9]+)?|_encrypt|_decrypt)\b/u],
  ["first-class-mutable-reference", /&\s*mut\s+(?!self\b)/u],
];

function closingParenthesis(source, openIndex) {
  let depth = 0;
  for (let index = openIndex; index < source.length; index += 1) {
    if (source[index] === "(") {
      depth += 1;
    } else if (source[index] === ")") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return -1;
}

function hasOnlyDirectAssertedEcdsaCalls(source) {
  // Import aliases and boolean expressions can turn a verification call into
  // dead or bypassable evidence. Require the reviewed direct-call form.
  if (
    /\buse\s+[^;\n]*\becdsa_secp256(?:k1|r1)[^;\n]*\bas\b/u.test(source) ||
    /\bverify_signature\b(?!\s*\()/u.test(source)
  ) {
    return false;
  }

  const calls = [...source.matchAll(/\b(?:[A-Za-z_][A-Za-z0-9_]*::)*verify_signature\s*\(/gu)];
  for (const call of calls) {
    const fullCall = call[0];
    if (!/^ecdsa_secp256(?:k1|r1)::verify_signature\s*\($/u.test(fullCall)) {
      return false;
    }
    const prefix = source.slice(0, call.index);
    if (!/\bassert\s*\(\s*$/u.test(prefix)) {
      return false;
    }
    const openIndex = call.index + fullCall.length - 1;
    const closeIndex = closingParenthesis(source, openIndex);
    if (closeIndex < 0 || !/^\s*[,)]/u.test(source.slice(closeIndex + 1))) {
      return false;
    }
  }
  return true;
}

export function inspectNoirSource(source) {
  const stripped = stripCommentsAndStrings(source);
  const violations = [];
  for (const [code, pattern] of forbiddenPatterns) {
    if (pattern.test(stripped)) {
      violations.push(code);
    }
  }

  if (!hasOnlyDirectAssertedEcdsaCalls(stripped)) {
    violations.push("unasserted-ecdsa-verification");
  }
  return violations;
}

function fail(code) {
  console.error(`Noir security profile check failed: ${code}`);
  process.exit(1);
}

function noirSources() {
  const listed = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "circuits"], {
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
  });
  if (listed.status !== 0 || listed.error !== undefined) {
    fail("source-enumeration-failed");
  }
  return [...new Set(listed.stdout
    .split("\0")
    .filter(
      (path) =>
        path.endsWith(".nr") && !path.startsWith(SECURITY_REGRESSION_PREFIX),
    ))]
    .sort();
}

function main() {
  const sources = noirSources();
  if (sources.length === 0 || sources.length > MAX_SOURCE_FILES) {
    fail("source-count-out-of-range");
  }

  const failures = [];
  for (const path of sources) {
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      failures.push(`${path}:unsupported-file-type`);
      continue;
    }
    if (metadata.size > MAX_SOURCE_BYTES) {
      failures.push(`${path}:source-too-large`);
      continue;
    }
    try {
      for (const violation of inspectNoirSource(readFileSync(path, "utf8"))) {
        failures.push(`${path}:${violation}`);
      }
    } catch (error) {
      if (error instanceof NoirSecurityProfileError) {
        failures.push(`${path}:${error.code}`);
        continue;
      }
      throw error;
    }
  }

  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(`Noir security profile violation: ${failure}`);
    }
    process.exit(1);
  }
  console.log(`Noir security profile passed for ${sources.length} source files`);
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main();
}
