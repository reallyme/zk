// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));

test("taxonomy ledger generation cannot write a stale tracked default", () => {
  const result = spawnSync("ruby", ["scripts/generate_taxonomy_conformance_ledger.rb"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 2);
  assert.match(
    result.stderr,
    /--output is required; conformance evidence must be generated outside the tracked tree/u,
  );
});

test("taxonomy ledger generation rejects an explicit in-repository output", () => {
  const result = spawnSync(
    "ruby",
    [
      "scripts/generate_taxonomy_conformance_ledger.rb",
      "--output",
      "conformance/taxonomy/conformance-ledger-evidence.json",
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--output must be outside the repository tree/u);
});
