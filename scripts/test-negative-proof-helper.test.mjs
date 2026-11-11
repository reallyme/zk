// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("negative proof helper rejects an always-failing verifier before accepting negative cases", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-zk-negative-proof-test."));
  const fakeBin = join(root, "bin");
  const circuit = join(root, "circuit");
  const proofDir = join(circuit, "target", "proof");
  const vkDir = join(circuit, "target", "vk");
  mkdirSync(fakeBin, { recursive: true });
  mkdirSync(proofDir, { recursive: true });
  mkdirSync(vkDir, { recursive: true });

  writeFileSync(
    join(fakeBin, "bb"),
    "#!/usr/bin/env bash\nprintf '%s\\n' 'simulated verifier outage' >&2\nexit 1\n",
    { mode: 0o755 },
  );
  writeFileSync(join(proofDir, "proof"), Buffer.alloc(96, 1));
  writeFileSync(join(proofDir, "public_inputs"), Buffer.alloc(32, 2));
  writeFileSync(join(vkDir, "vk"), Buffer.alloc(64, 3));

  const result = spawnSync("bash", ["circuits/test-negative-proof.sh", circuit], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
    },
    encoding: "utf8",
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /baseline verifier failed/u);
  assert.match(result.stderr, /simulated verifier outage/u);
});

test("negative proof helper does not count verifier infrastructure failures as proof rejection", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-zk-negative-proof-infra-test."));
  const fakeBin = join(root, "bin");
  const circuit = join(root, "circuit");
  const proofDir = join(circuit, "target", "proof");
  const vkDir = join(circuit, "target", "vk");
  const callCount = join(root, "bb-call-count");
  mkdirSync(fakeBin, { recursive: true });
  mkdirSync(proofDir, { recursive: true });
  mkdirSync(vkDir, { recursive: true });

  writeFileSync(
    join(fakeBin, "bb"),
    `#!/usr/bin/env bash
count=0
if [[ -f "${callCount}" ]]; then
  count="$(cat "${callCount}")"
fi
count="$((count + 1))"
printf '%s' "$count" > "${callCount}"
if [[ "$count" -eq 1 ]]; then
  exit 0
fi
printf '%s\\n' 'failed to open verifier input: No such file or directory' >&2
exit 1
`,
    { mode: 0o755 },
  );
  writeFileSync(join(proofDir, "proof"), Buffer.alloc(96, 1));
  writeFileSync(join(proofDir, "public_inputs"), Buffer.alloc(32, 2));
  writeFileSync(join(vkDir, "vk"), Buffer.alloc(64, 3));

  const result = spawnSync("bash", ["circuits/test-negative-proof.sh", circuit], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
    },
    encoding: "utf8",
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /verifier infrastructure failed/u);
  assert.match(result.stderr, /No such file or directory/u);
});

test("negative proof helper requires reviewed invalid-proof rejection for same-shape crypto negatives", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-zk-negative-proof-outage-test."));
  const fakeBin = join(root, "bin");
  const circuit = join(root, "circuit");
  const proofDir = join(circuit, "target", "proof");
  const vkDir = join(circuit, "target", "vk");
  const callCount = join(root, "bb-call-count");
  mkdirSync(fakeBin, { recursive: true });
  mkdirSync(proofDir, { recursive: true });
  mkdirSync(vkDir, { recursive: true });

  writeFileSync(
    join(fakeBin, "bb"),
    `#!/usr/bin/env bash
count=0
if [[ -f "${callCount}" ]]; then
  count="$(cat "${callCount}")"
fi
count="$((count + 1))"
printf '%s' "$count" > "${callCount}"
if [[ "$count" -eq 1 ]]; then
  exit 0
fi
printf '%s\\n' 'simulated verifier outage' >&2
exit 1
`,
    { mode: 0o755 },
  );
  writeFileSync(join(proofDir, "proof"), Buffer.alloc(96, 1));
  writeFileSync(join(proofDir, "public_inputs"), Buffer.alloc(32, 2));
  writeFileSync(join(vkDir, "vk"), Buffer.alloc(64, 3));

  const result = spawnSync("bash", ["circuits/test-negative-proof.sh", circuit], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
    },
    encoding: "utf8",
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /without a reviewed invalid-proof rejection/u);
  assert.match(result.stderr, /simulated verifier outage/u);
});
