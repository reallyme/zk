// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, writeFileSync } from 'node:fs';

const artifactPath = process.argv[2];
const offsetText = process.argv[3] ?? '64';
if (artifactPath === undefined || artifactPath.length === 0) {
  console.error('usage: test-negative-proof.mjs ARTIFACT_PATH [MUTATION_OFFSET]');
  process.exit(1);
}

const offset = Number.parseInt(offsetText, 10);
if (!Number.isSafeInteger(offset) || offset < 0) {
  console.error('error: mutation offset must be a non-negative safe integer');
  process.exit(1);
}

const artifact = readFileSync(artifactPath);
if (artifact.length <= offset) {
  console.error('error: artifact is too short to mutate safely');
  process.exit(1);
}

artifact[offset] ^= 0x01;
writeFileSync(artifactPath, artifact);
