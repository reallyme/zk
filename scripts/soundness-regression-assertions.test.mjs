// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const assertions = fileURLToPath(new URL("./soundness-regression-assertions.sh", import.meta.url));
const rejection = "Proof verification failed\nFailed to verify the generated proof!\n";

function withDirectory(run) {
  const directory = mkdtempSync(join(tmpdir(), "soundness-assertions-"));
  try {
    return run(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function invokeRejection({ status = 1, message = rejection, artifact = "" } = {}) {
  return withDirectory((directory) => {
    const backend = join(directory, "bb");
    writeFileSync(backend, `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
if (args[0] !== "prove" || !args.includes("-c") || !args.includes("-o")) process.exit(3);
const output = args[args.indexOf("-o") + 1];
const artifact = ${JSON.stringify(artifact)};
if (artifact) {
  fs.mkdirSync(output, { recursive: true });
  fs.writeFileSync(require("node:path").join(output, artifact), "invalid");
}
process.stderr.write(${JSON.stringify(message)});
process.exit(${status});
`, { mode: 0o755 });
    return spawnSync("bash", ["-c", `
set -euo pipefail
source "$1"
fail() { exit 2; }
run_bb_prove_rejects rejection "$2/output" -b fixture -w witness -k key
`, "soundness-test", assertions, directory], {
      env: { ...process.env, BB: backend, LOG_DIR: directory, BB_CRS_DIR: directory },
      encoding: "utf8",
    });
  });
}

test("tampered witnesses require the pinned proof verification rejection", () => {
  const result = invokeRejection();
  assert.equal(result.status, 0, result.stderr);
});

test("success, crashes, and unrelated backend errors cannot satisfy the negative test", () => {
  for (const input of [
    { status: 0 },
    { status: 137 },
    { message: "CRS unavailable\n" },
    { message: "Failed to verify the generated proof!\n" },
    { message: "Proof verification failed\n" },
  ]) {
    assert.notEqual(invokeRejection(input).status, 0);
  }
});

test("a rejected prover must not leave either proof artifact", () => {
  for (const artifact of ["proof", "public_inputs"]) {
    assert.notEqual(invokeRejection({ artifact }).status, 0);
  }
});

function invokeMutation(source, target) {
  return spawnSync("bash", ["-c", `
set -euo pipefail
source "$1"
fail() { exit 2; }
mutate_proof_bytes "$2" "$3"
`, "soundness-test", assertions, source, target], { encoding: "utf8" });
}

test("proof mutation changes one field byte while retaining the complete framing", () => {
  withDirectory((directory) => {
    const source = join(directory, "proof");
    const target = join(directory, "mutated-proof");
    const original = Buffer.alloc(96, 7);
    writeFileSync(source, original);
    const result = invokeMutation(source, target);
    assert.equal(result.status, 0, result.stderr);
    const mutated = readFileSync(target);
    assert.equal(mutated.length, original.length);
    assert.deepEqual([...mutated.keys()].filter((index) => mutated[index] !== original[index]), [63]);
    assert.deepEqual(readFileSync(source), original);
  });
});

test("empty, unaligned, oversized, and absent proof inputs fail mutation", () => {
  withDirectory((directory) => {
    const source = join(directory, "proof");
    const target = join(directory, "mutated-proof");
    for (const length of [0, 31, 33, 1024 * 1024 + 32]) {
      writeFileSync(source, Buffer.alloc(length));
      assert.notEqual(invokeMutation(source, target).status, 0);
    }
    rmSync(source);
    assert.notEqual(invokeMutation(source, target).status, 0);
  });
});
