// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { createPackageDiagnosticReporter } from "./package-diagnostics.mjs";

const codec = "reallyme-zk-proto-codec";
const backend = "reallyme-zk-backend-bb";
const omitted = (name, path = `tests/${name}.rs`) =>
  `warning: ignoring test \`${name}\` as \`${path}\` is not included in the published package\n`;
const pkg = (name, targets = ["bindings", "vectors"]) => ({
  name,
  manifest_path: resolve("crates", name, "Cargo.toml"),
  targets: targets.map((target) => ({
    name: target,
    kind: ["test"],
    src_path: resolve("crates", name, "tests", `${target}.rs`),
  })),
});

test("only intentional omissions become one informational notice per package", () => {
  const report = createPackageDiagnosticReporter([pkg(codec), pkg(backend)]);
  const first = report(omitted("bindings") + omitted("vectors"), codec);
  assert.equal(first, `note: ${codec}: 2 repository-only integration-test targets are excluded from the crate archive; workspace test targets are unchanged.\n`);
  assert.equal(report(omitted("bindings"), codec), "");
  assert.match(report(omitted("bindings"), backend), /note: reallyme-zk-backend-bb/u);
});

test("workspace package headings identify omissions including colored Cargo output", () => {
  const report = createPackageDiagnosticReporter([pkg(codec), pkg(backend)]);
  const heading = `\u001b[1m\u001b[32m   Packaging\u001b[0m ${codec} v0.3.2 (/workspace/codec)\n`;
  const warning = omitted("bindings").replace("warning:", "\u001b[33mwarning:\u001b[0m");
  const output = report(heading + warning + `   Packaging ${backend} v0.3.2 (/workspace/backend)\n` + omitted("bindings"));
  assert.ok(output.startsWith(heading));
  assert.equal(output.match(/note:/gu).length, 2);
  assert.doesNotMatch(output, /warning:/u);
});

test("unexpected warnings, errors, and unmatched target identities remain byte-for-byte visible", () => {
  const report = createPackageDiagnosticReporter([pkg(codec)]);
  for (const output of [
    "warning: a new dependency warning\nerror: verification failed\n",
    omitted("unknown"),
    omitted("bindings", "tests/other.rs"),
    omitted("bindings", "examples/bindings.rs"),
    omitted("bindings").replace("ignoring test", "ignoring example"),
    omitted("bindings").replace("package\n", "package: unexpected reason\n"),
  ]) {
    assert.equal(report(output, codec), output);
  }
});

test("an omission cannot be attributed to another or an unapproved package", () => {
  for (const name of [undefined, backend, "reallyme-zk-proto", "unreviewed-crate"]) {
    const report = createPackageDiagnosticReporter([pkg(codec), pkg("reallyme-zk-proto")]);
    assert.equal(report(omitted("bindings"), name), omitted("bindings"));
  }
  const report = createPackageDiagnosticReporter([pkg(codec)]);
  const output = "   Packaging unrelated v1.0.0 (/workspace/unrelated)\n" + omitted("bindings");
  assert.equal(report(output, codec), output);
});

test("missing or malformed metadata never conceals diagnostics", () => {
  for (const metadata of [null, {}, [], [null], [{ name: codec }],
    [{ ...pkg(codec), targets: null }],
    [{ ...pkg(codec), targets: [null, { name: "bindings", kind: ["lib"], src_path: "/tests/bindings.rs" }] }],
    [{ ...pkg(codec), targets: [{ name: "bindings", kind: ["test"], src_path: resolve("elsewhere/bindings.rs") }] }],
  ]) {
    const report = createPackageDiagnosticReporter(metadata);
    assert.equal(report(omitted("bindings"), codec), omitted("bindings"));
  }
});

test("CRLF diagnostics normalize while unrelated output preserves its line endings", () => {
  const report = createPackageDiagnosticReporter([pkg(codec)]);
  const suffix = "warning: retained\r\nerror: retained\r\n";
  const output = report(omitted("bindings").replace("\n", "\r\n") + suffix, codec);
  assert.ok(output.endsWith(suffix));
  assert.match(output, /^note:/u);
});
