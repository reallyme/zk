#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  NoirSecurityProfileError,
  inspectNoirSource,
  stripCommentsAndStrings,
} from "./check-noir-security-profile.mjs";

test("accepts the reviewed fixed-array profile", () => {
  const source = `
    fn absorb(&mut self, values: [Field; 4]) {
      for index in 0..4 { self.state[index] += values[index]; }
    }
    fn main(signature: [u8; 64], x: [u8; 32], y: [u8; 32], hash: [u8; 32]) {
      assert(ecdsa_secp256r1::verify_signature(x, y, signature, hash), "invalid");
    }
  `;
  assert.deepEqual(inspectNoirSource(source), []);
});

test("rejects advisory-affected language and black-box families", () => {
  const cases = new Map([
    ["unconstrained fn derive() {}", "unconstrained-function"],
    ["fn main() { while true {} }", "while-loop"],
    ["fn main(value: i32) {}", "signed-integer"],
    ["fn main(value: u128) {}", "u128-integer"],
    ["fn main(value: [Field]) {}", "dynamic-slice-type"],
    ["type Values = [Field];", "dynamic-slice-type"],
    ["fn main(value: [Field; 1]) { value.push_back(1); }", "dynamic-slice-operation"],
    ["fn main() { oracle(); }", "foreign-call"],
    ["use std::hash::Hasher;", "dynamic-hasher"],
    ["fn main() { embedded_curve_add(); }", "embedded-curve-operation"],
    ["fn main() { aes128_encrypt(); }", "aes-black-box"],
    ["fn main(value: &mut Field) {}", "first-class-mutable-reference"],
  ]);
  for (const [source, expected] of cases) {
    assert.ok(inspectNoirSource(source).includes(expected), expected);
  }
});

test("requires every ECDSA verification result to be asserted directly", () => {
  assert.deepEqual(
    inspectNoirSource(
      "fn main() { let valid = ecdsa_secp256k1::verify_signature(x, y, signature, hash); }",
    ),
    ["unasserted-ecdsa-verification"],
  );
  for (const source of [
    "use std::ecdsa_secp256r1 as signature; fn main() { assert(signature::verify_signature(x, y, s, h)); }",
    "use std::ecdsa_secp256r1::verify_signature as verify; fn main() { assert(verify(x, y, s, h)); }",
    "use std::ecdsa_secp256r1::{verify_signature as verify}; fn main() { assert(verify(x, y, s, h)); }",
    "fn main() { let verify = ecdsa_secp256r1::verify_signature; assert(verify(x, y, s, h)); }",
    "fn main() { assert(ecdsa_secp256r1::verify_signature(x, y, s, h) || bypass); }",
    "fn main() { assert(ecdsa_secp256r1::verify_signature(x, y, s, h) == bypass); }",
  ]) {
    assert.ok(inspectNoirSource(source).includes("unasserted-ecdsa-verification"));
  }
});

test("does not treat comments or strings as executable syntax", () => {
  const source = `
    // unconstrained fn ignored() {}
    fn main(value: [Field; 1]) {
      assert(value[0] == 1, "while u128 push_back");
      /* fn ignored(other: [Field]) {} */
    }
  `;
  assert.deepEqual(inspectNoirSource(source), []);
});

test("supports nested block comments and rejects unterminated lexical input", () => {
  const nestedComment = "/* outer /* inner */ done */fn main() {}";
  const stripped = stripCommentsAndStrings(nestedComment);
  assert.equal(stripped.length, nestedComment.length);
  assert.ok(stripped.endsWith("fn main() {}"));
  assert.throws(
    () => stripCommentsAndStrings("/* incomplete"),
    (error) =>
      error instanceof NoirSecurityProfileError && error.code === "unterminated-block-comment",
  );
  assert.throws(
    () => stripCommentsAndStrings('fn main() { "incomplete }'),
    (error) =>
      error instanceof NoirSecurityProfileError && error.code === "unterminated-string",
  );
});
