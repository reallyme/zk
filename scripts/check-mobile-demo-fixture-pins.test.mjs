// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";

const root = new URL("../", import.meta.url);
const swift = "packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo/";
const kotlin = "packages/kotlin/demo-android/src/main/kotlin/me/really/zk/demo/android/";
const source = (path) => readFileSync(new URL(path, root), "utf8");
const digest = (path) => createHash("sha256").update(readFileSync(new URL(path, root))).digest("hex");

test("both demo verifier policies agree with the session and issuer in every shipped flow", () => {
  const swiftPolicy = source("packages/swift/Sources/ReallyMeZKDemoSupport/DemoVerifierPolicy.swift");
  const kotlinPolicy = source("packages/kotlin/demo-shared/src/main/kotlin/me/really/zk/demo/shared/ReallyMeZkDemoVerifierPolicy.kt");
  const fields = [
    ["challenge", "NonceHash", "NONCE_HASH", "session"],
    ["audience_hash", "AudienceHash", "AUDIENCE_HASH", "session"],
    ["transaction_data_hash", "TransactionDataHash", "TRANSACTION_DATA_HASH", "session"],
    ["pk_issuer_x", "IssuerX", "ISSUER_X", "credential_envelope"],
    ["pk_issuer_y", "IssuerY", "ISSUER_Y", "credential_envelope"],
  ];
  for (const [field, swiftName, kotlinName, stage] of fields) {
    const swiftPin = swiftPolicy.match(new RegExp(`verifier${swiftName}: \\[UInt8\\] = \\[([^\\]]+)\\]`, "u"));
    const kotlinPin = kotlinPolicy.match(new RegExp(`REVIEWED_${kotlinName}_BASE64 = "([^"]+)"`, "u"));
    assert.ok(swiftPin && kotlinPin, field);
    const swiftBytes = swiftPin[1].split(",").map((byte) => byte.trim()).filter(Boolean).map(Number);
    const kotlinBytes = [...Buffer.from(kotlinPin[1], "base64")];
    assert.equal(swiftBytes.length, 32, field);
    assert.deepEqual(swiftBytes, kotlinBytes, field);
    for (const lane of ["sha256", "poseidon2"]) {
      for (const family of ["credential_subject_claim_v1", "private_persona_claim_v1"]) {
        const fixture = JSON.parse(source(`vectors/demo-flow-inputs/v1/${lane}_flow_${family}_${stage}_inputs.json`));
        assert.deepEqual(fixture[field], swiftBytes, `${lane}/${family}: ${field}`);
      }
    }
  }
});

// These are independent app admission boundaries. A regenerated fixture must
// update both platforms; otherwise an app compiles but rejects its own assets.
for (const [manifest, consumers] of [
  ["vectors/common-credential-root-stage-requests-v1.sha256.tsv", [
    [`${swift}ReallyMeZKDemoCommonCredentialRootRunner.swift`, "expectedStageManifestSha256"],
    [`${kotlin}AndroidDemoCommonCredentialRootAssets.kt`, "COMMON_CREDENTIAL_ROOT_STAGE_MANIFEST_SHA256"],
  ]],
  ["vectors/persona-credential-evidence-mobile-requests-v1/sha256.tsv", [
    [`${swift}ReallyMeZKDemoPersonaCredentialEvidenceRunner.swift`, "expectedManifestSha256"],
    [`${kotlin}AndroidDemoPersonaCredentialEvidenceAssets.kt`, "PERSONA_CREDENTIAL_EVIDENCE_MANIFEST_SHA256"],
  ]],
]) {
  for (const [path, constant] of consumers) {
    test(`${path} admits the current ${manifest}`, () => {
      const match = source(path).match(new RegExp(`${constant}\\s*=\\s*"([0-9a-f]{64})"`, "u"));
      assert.equal(match?.[1], digest(manifest));
    });
  }
}

const fixtureRoot = "vectors/common-credential-root-mobile-fixtures-v1/";
for (const name of readdirSync(new URL(fixtureRoot, root)).filter((name) => name.endsWith(".pb"))) {
  for (const path of [
    `${swift}ReallyMeZKDemoCommonCredentialRootRunner.swift`,
    `${kotlin}AndroidDemoCommonCredentialRootAssets.kt`,
    "scripts/stage-demo-mobile-assets.mjs",
  ]) {
    test(`${path} binds ${name} to its current bytes`, () => {
      const text = source(path);
      const offset = text.indexOf(name.replace(/\.pb$/u, ""));
      assert.ok(offset >= 0);
      assert.ok(text.slice(offset, offset + 240).includes(digest(fixtureRoot + name)));
    });
  }
}
