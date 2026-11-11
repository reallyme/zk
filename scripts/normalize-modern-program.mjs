// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const maximumArtifactBytes = 32 * 1024 * 1024;

/** Normalize source metadata with the release process's pinned modern profile. */
export function normalizeModernProgram(program) {
  if (!Buffer.isBuffer(program) || program.length === 0 ||
      program.length > maximumArtifactBytes) {
    return null;
  }
  const result = spawnSync(
    "cargo",
    ["run", "--quiet", "--locked", "-p", "reallyme-zk-release-process",
      "--bin", "normalize-modern-program"],
    {
      cwd: root,
      input: program,
      maxBuffer: maximumArtifactBytes,
    },
  );
  if (result.error !== undefined || result.status !== 0 ||
      !Buffer.isBuffer(result.stdout) || result.stdout.length === 0 ||
      result.stdout.length > maximumArtifactBytes) {
    return null;
  }
  return result.stdout;
}
