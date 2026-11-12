// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// This order covers runtime and build dependencies. Workspace-only development
// dependencies are excluded from publication and cannot invert the release order.
export const PUBLIC_CRATES = Object.freeze([
  Object.freeze({ name: "reallyme-zk-api", manifest: "crates/api/Cargo.toml", firstVersion: null }),
  Object.freeze({ name: "reallyme-zk-artifacts", manifest: "crates/artifacts/Cargo.toml", firstVersion: "0.3.0" }),
  Object.freeze({ name: "reallyme-zk-proto", manifest: "crates/proto/Cargo.toml", firstVersion: "0.3.0" }),
  Object.freeze({ name: "reallyme-zk-proto-codec", manifest: "crates/proto-codec/Cargo.toml", firstVersion: "0.3.1" }),
  Object.freeze({ name: "reallyme-zk-backend-bb", manifest: "crates/backend-bb/Cargo.toml", firstVersion: "0.3.1" }),
]);

export const PUBLIC_CRATE_NAMES = Object.freeze(PUBLIC_CRATES.map((crate) => crate.name));
