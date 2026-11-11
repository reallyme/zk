// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("poseidon2 crypto contract uses the published crates.io package", () => {
  const script = readFileSync("scripts/check-poseidon2-crypto-contract.sh", "utf8");
  const manifest = readFileSync("Cargo.toml", "utf8");
  const cryptoVersion = manifest.match(/crypto-core = \{ package = "reallyme-crypto-core", version = "=([0-9]+[.][0-9]+[.][0-9]+)"/u)?.[1];

  assert.ok(cryptoVersion, "workspace crypto version must be pinned");

  assert.match(script, /crypto_poseidon2_package="reallyme-crypto-poseidon2"/u);
  assert.ok(script.includes(`crypto_poseidon2_version="${cryptoVersion}"`));
  assert.ok(script.includes(`require_contains "\${contract_root}/Cargo.lock" 'version = "${cryptoVersion}"'`));
  assert.match(script, /version = "=\$\{crypto_poseidon2_version\}"/u);
  assert.match(script, /cargo generate-lockfile/u);
  assert.match(script, /cargo run[\s\S]*--locked/u);
  assert.match(script, /source = "registry\+https:\/\/github[.]com\/rust-lang\/crates[.]io-index"/u);
  assert.doesNotMatch(script, /REALLYME_CRYPTO_REPO/u);
  assert.doesNotMatch(script, /sibling checkout/u);
});
