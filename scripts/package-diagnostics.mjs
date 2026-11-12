// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { dirname, relative, sep } from "node:path";
import { stripVTControlCharacters } from "node:util";
import { REPOSITORY_TEST_PACKAGES } from "./package-inventory-policy.mjs";

const OMITTED_TEST = /^warning: ignoring test `([A-Za-z0-9_-]+)` as `(tests\/[A-Za-z0-9_./-]+\.rs)` is not included in the published package$/u;
const PACKAGE_HEADER = /^\s*Packaging ([a-z0-9][a-z0-9_-]*) v\S+ /u;

/** Report intentional repository-only suites without concealing other diagnostics. */
export function createPackageDiagnosticReporter(packages) {
  const suites = new Map();
  for (const pkg of Array.isArray(packages) ? packages : []) {
    if (!REPOSITORY_TEST_PACKAGES.includes(pkg?.name) ||
        typeof pkg.manifest_path !== "string" || !Array.isArray(pkg.targets)) continue;
    const tests = new Set();
    for (const target of pkg.targets) {
      if (!Array.isArray(target?.kind) || !target.kind.includes("test") ||
          typeof target.name !== "string" || typeof target.src_path !== "string") continue;
      const path = relative(dirname(pkg.manifest_path), target.src_path).split(sep).join("/");
      if (path.startsWith("tests/")) tests.add(`${target.name}\0${path}`);
    }
    suites.set(pkg.name, tests);
  }
  const reported = new Set();
  return (output, packageName) => {
    let currentPackage = packageName;
    return output.split(/(?<=\n)/u).map((line) => {
      const plain = stripVTControlCharacters(line).replace(/\r?\n$/u, "");
      const header = PACKAGE_HEADER.exec(plain);
      if (header !== null) currentPackage = header[1];
      const omitted = OMITTED_TEST.exec(plain);
      const tests = suites.get(currentPackage);
      if (omitted === null || tests === undefined || !tests.has(`${omitted[1]}\0${omitted[2]}`)) {
        return line;
      }
      // Cargo reports the same omission during packaging and publication. Only
      // targets confirmed by Cargo metadata and our package policy qualify.
      if (reported.has(currentPackage)) return "";
      reported.add(currentPackage);
      return `note: ${currentPackage}: ${tests.size} repository-only integration-test targets are excluded from the crate archive; workspace test targets are unchanged.\n`;
    }).join("");
  };
}
