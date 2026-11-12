// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { PUBLIC_CRATE_NAMES } from "./public-crates.mjs";

export class PublicPackageBoundaryError extends Error {
  constructor(code) {
    super(code);
    this.name = "PublicPackageBoundaryError";
    this.code = code;
  }
}

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const PRIVATE_IMPLEMENTATIONS = new Set(["reallyme-zk-noir-witness-core", "reallyme-zk-platform-ffi"]);

// Optional runtime dependencies still enter a registry package and its feature
// graph. The public boundary must hold with every feature enabled, not just by
// hiding unpublished implementation crates behind disabled default features.
export function validatePublicPackageBoundary(packages) {
  if (!Array.isArray(packages) || packages.length > 256) {
    throw new PublicPackageBoundaryError("invalid-package-metadata");
  }
  for (const pkg of packages) {
    if (!isRecord(pkg) || typeof pkg.name !== "string" || !Array.isArray(pkg.dependencies)) {
      throw new PublicPackageBoundaryError("invalid-package-metadata");
    }
  }
  const workspaceNames = new Set(packages.map((pkg) => pkg.name));
  const publicNames = new Set(PUBLIC_CRATE_NAMES);
  for (const pkg of packages) {
    if (!publicNames.has(pkg.name)) continue;
    if (!Array.isArray(pkg.dependencies)) throw new PublicPackageBoundaryError("invalid-package-metadata");
    for (const dependency of pkg.dependencies) {
      if (!isRecord(dependency) || typeof dependency.name !== "string" ||
          (dependency.package !== undefined && typeof dependency.package !== "string") ||
          ![null, "dev", "build"].includes(dependency.kind) ||
          (dependency.source !== null && typeof dependency.source !== "string")) {
        throw new PublicPackageBoundaryError("invalid-package-metadata");
      }
      const name = dependency.package ?? dependency.name;
      if (dependency.kind === "dev") {
        if (PRIVATE_IMPLEMENTATIONS.has(name) &&
            (dependency.source !== null || typeof dependency.path !== "string" || dependency.req !== "*")) {
          throw new PublicPackageBoundaryError("private-development-dependency-must-be-omitted");
        }
        continue;
      }
      if (PRIVATE_IMPLEMENTATIONS.has(name) || (workspaceNames.has(name) && !publicNames.has(name))) {
        throw new PublicPackageBoundaryError("unpublished-runtime-dependency");
      }
      if (typeof dependency.source === "string" && dependency.source.startsWith("git+")) {
        throw new PublicPackageBoundaryError("git-runtime-dependency");
      }
    }
  }
}
