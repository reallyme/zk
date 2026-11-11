// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

for (const name of ["manifest", "capabilities"]) {
  const source = readFileSync(new URL(
    `../crates/proto/proto/reallyme/zk/v1/${name}.proto`, import.meta.url,
  ), "utf8").replace(/\/\/[^\n]*/gu, "");

  test(`${name}.proto has no retired-code reservations`, () => {
    assert.doesNotMatch(source, /\breserved\b/u);
  });

  for (const [ , enumName, body] of source.matchAll(/enum\s+(\w+)\s*\{([^}]+)\}/gu)) {
    // Error reason values are a shared cross-stack contract, independent of
    // the ZK transport's own declaration order.
    if (enumName === "ZkErrorReason") continue;
    test(`${enumName} assigns consecutive codes in declaration order`, () => {
      const values = [...body.matchAll(/\b\w+\s*=\s*(\d+)\s*;/gu)]
        .map((match) => Number(match[1]));
      assert.ok(values.length > 0);
      assert.deepEqual(values, Array.from({ length: values.length }, (_, index) => index));
    });
  }
}

const manifest = readFileSync(new URL(
  "../crates/proto/proto/reallyme/zk/v1/manifest.proto", import.meta.url,
), "utf8").replace(/\/\/[^\n]*/gu, "");
for (const [, name, body] of manifest.matchAll(/message\s+(\w+)\s*\{([\s\S]*?)^\}/gmu)) {
  test(`${name} has consecutive active field tags`, () => {
    const values = [...body.matchAll(/\b\w+\s*=\s*(\d+)\s*;/gu)]
      .map((match) => Number(match[1])).sort((left, right) => left - right);
    assert.deepEqual(values, Array.from({ length: values.length }, (_, index) => index + 1));
  });
}
for (const name of [
  "ZkProofPackage", "ZkCommonCredentialRootRawProofPackage",
  "ZkCommonCredentialRootStageProveOperation", "ZkProviderOperationResponse",
]) {
  test(`${name} places its oneof after consecutive metadata fields`, () => {
    const body = manifest.match(new RegExp(`message ${name} \\{([\\s\\S]*?)^\\}`, "mu"))?.[1];
    assert.ok(body !== undefined);
    const values = [...body.matchAll(/\b\w+\s*=\s*(\d+)\s*;/gu)]
      .map((match) => Number(match[1]));
    assert.deepEqual(values, Array.from({ length: values.length }, (_, index) => index + 1));
    // Buffa writes ordinary fields before oneofs; keeping the declaration and
    // tag order aligned also gives SwiftProtobuf and Java the same wire order.
    const afterOneof = body.slice(body.indexOf("oneof "));
    assert.match(afterOneof, /\}\s*$/u);
    assert.doesNotMatch(afterOneof, /\}\s*\w/u);
  });
}
