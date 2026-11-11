// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ReallyMeZkBbjsErrorReason,
  createReallyMeZkBbjsVerifier,
  dynamicBbjsLoader,
  loadReallyMeZkBbjsRuntime,
  verifyReallyMeZkBbjsProof,
} from "../src/index.mjs";

const FIELD_ONE = `0x${"00".repeat(31)}01`;
const FIELD_TWO = `0x${"00".repeat(31)}02`;
const BN254_FR_MODULUS_HEX =
  "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
const LARGEST_CANONICAL_FIELD =
  "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
const PRODUCTION_OPTIONS = { verifierTarget: "evm" };
const ACIR_BYTECODE = "encoded-acir";
const ARTIFACT_PIN = Object.freeze({
  acirBytecodeSha256: "01d7b2d592f51c867990ba3b4dea2dbb4a779b837a795024ad6d8dcb38a81996",
  publicInputCount: 2,
});

function proofBytes(length = 64) {
  return new Uint8Array(length).fill(7);
}

function validProofData() {
  return Object.freeze({
    proof: proofBytes(),
    publicInputs: Object.freeze([FIELD_ONE, FIELD_TWO]),
  });
}

class FakeBarretenberg {
  static instances = [];
  static failNew = false;

  static async new(options) {
    if (FakeBarretenberg.failNew) {
      throw new globalThis.Error("backend unavailable");
    }
    const api = new FakeBarretenberg(options);
    FakeBarretenberg.instances.push(api);
    return api;
  }

  constructor(options) {
    this.options = options;
    this.destroyed = false;
  }

  async destroy() {
    this.destroyed = true;
  }
}

class FakeUltraHonkBackend {
  static instances = [];

  constructor(acirBytecode, api) {
    this.acirBytecode = acirBytecode;
    this.api = api;
    this.receivedWitness = undefined;
    this.receivedProof = undefined;
    this.proveOptions = undefined;
    this.verifyOptions = undefined;
    FakeUltraHonkBackend.instances.push(this);
  }

  async generateProof(witness, options) {
    this.receivedWitness = witness;
    this.proveOptions = options;
    return validProofData();
  }

  async verifyProof(proofData, options) {
    this.receivedProof = proofData.proof;
    this.verifyOptions = options;
    return proofData.publicInputs.length === 2 && proofData.proof.byteLength === 64;
  }
}

function fakeModule(backend = FakeUltraHonkBackend, barretenberg = FakeBarretenberg) {
  return async () => Object.freeze({ UltraHonkBackend: backend, Barretenberg: barretenberg });
}

function resetFakes() {
  FakeBarretenberg.instances.length = 0;
  FakeBarretenberg.failNew = false;
  FakeUltraHonkBackend.instances.length = 0;
}

test("runtime loads lazily and binds one Barretenberg instance per circuit", async () => {
  resetFakes();
  let loadCount = 0;
  const runtime = await loadReallyMeZkBbjsRuntime({
    loadBbjs: async () => {
      loadCount += 1;
      return Object.freeze({
        UltraHonkBackend: FakeUltraHonkBackend,
        Barretenberg: FakeBarretenberg,
      });
    },
    threads: 1,
    wasmPath: "/bb.wasm",
  });

  assert.equal(runtime.success, true);
  assert.equal(loadCount, 1);

  const backend = runtime.value.createUltraHonkBackend(ACIR_BYTECODE, ARTIFACT_PIN);
  assert.equal(backend.success, true);
  assert.equal(FakeBarretenberg.instances.length, 0);

  const [first, second] = await Promise.all([
    backend.value.verifyProof(validProofData()),
    backend.value.verifyProof(validProofData()),
  ]);
  assert.deepEqual(first, { success: true, value: true });
  assert.deepEqual(second, { success: true, value: true });
  assert.equal(FakeBarretenberg.instances.length, 1);
  assert.deepEqual(FakeBarretenberg.instances[0].options, { threads: 1, wasmPath: "/bb.wasm" });
  assert.equal(FakeUltraHonkBackend.instances.length, 1);
  assert.equal(FakeUltraHonkBackend.instances[0].acirBytecode, "encoded-acir");
  assert.equal(FakeUltraHonkBackend.instances[0].api, FakeBarretenberg.instances[0]);
});

test("generateProof consumes and clears caller witness bytes", async () => {
  resetFakes();
  const runtime = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule() });
  assert.equal(runtime.success, true);
  const backend = runtime.value.createUltraHonkBackend(ACIR_BYTECODE, ARTIFACT_PIN);
  assert.equal(backend.success, true);

  const witness = new Uint8Array([1, 2, 3, 4]);
  const result = await backend.value.generateProof(witness);

  assert.equal(result.success, true);
  assert.deepEqual([...witness], [0, 0, 0, 0]);
  assert.deepEqual([...FakeUltraHonkBackend.instances[0].receivedWitness], [0, 0, 0, 0]);
  assert.deepEqual(result.value.publicInputs, [FIELD_ONE, FIELD_TWO]);
  assert.equal(result.value.proof.byteLength, 64);
});

test("proving and verification always use the Keccak zero-knowledge suite", async () => {
  resetFakes();
  const runtime = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule() });
  assert.equal(runtime.success, true);
  const backend = runtime.value.createUltraHonkBackend(ACIR_BYTECODE, ARTIFACT_PIN);
  assert.equal(backend.success, true);

  // Caller-supplied suite options are not part of the contract and are ignored.
  const proved = await backend.value.generateProof(new Uint8Array([1]), {
    verifierTarget: "evm-no-zk",
  });
  const verified = await backend.value.verifyProof(validProofData(), { keccak: true });

  assert.equal(proved.success, true);
  assert.deepEqual(verified, { success: true, value: true });
  assert.deepEqual(FakeUltraHonkBackend.instances[0].proveOptions, PRODUCTION_OPTIONS);
  assert.deepEqual(FakeUltraHonkBackend.instances[0].verifyOptions, PRODUCTION_OPTIONS);
});

test("verifyProof delegates using a cleared backend proof copy", async () => {
  resetFakes();
  const runtime = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule() });
  assert.equal(runtime.success, true);
  const backend = runtime.value.createUltraHonkBackend(ACIR_BYTECODE, ARTIFACT_PIN);
  assert.equal(backend.success, true);

  const proofData = validProofData();
  const result = await backend.value.verifyProof(proofData);

  assert.deepEqual(result, { success: true, value: true });
  assert.equal(proofData.proof[0], 7);
  assert.equal(FakeUltraHonkBackend.instances[0].receivedProof.byteLength, 64);
  assert.equal(
    FakeUltraHonkBackend.instances[0].receivedProof.every((byte) => byte === 0),
    true,
  );
});

test("malformed, oversized, and non-canonical proof data fail before the backend", async () => {
  resetFakes();
  const runtime = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule(), maxProofBytes: 64 });
  assert.equal(runtime.success, true);
  const backend = runtime.value.createUltraHonkBackend(ACIR_BYTECODE, ARTIFACT_PIN);
  assert.equal(backend.success, true);

  const invalid = { success: false, reason: ReallyMeZkBbjsErrorReason.InvalidProofData };
  for (const proofData of [
    undefined,
    { proof: new Uint8Array(0), publicInputs: [FIELD_ONE, FIELD_TWO] },
    { proof: proofBytes(33), publicInputs: [FIELD_ONE, FIELD_TWO] },
    { proof: proofBytes(), publicInputs: "0x01" },
    { proof: proofBytes(), publicInputs: [FIELD_ONE, ""] },
    { proof: proofBytes(), publicInputs: [FIELD_ONE, "0x01"] },
    { proof: proofBytes(), publicInputs: [FIELD_ONE, `0x${"zz".repeat(32)}`] },
    { proof: proofBytes(), publicInputs: [FIELD_ONE, `${FIELD_ONE}00`] },
    { proof: proofBytes(), publicInputs: [FIELD_ONE, BN254_FR_MODULUS_HEX] },
    { proof: proofBytes(), publicInputs: [FIELD_ONE, `0x${"ff".repeat(32)}`] },
    { proof: proofBytes(), publicInputs: [FIELD_ONE, 1] },
    // The count is pinned: one too few and one too many are both rejected.
    { proof: proofBytes(), publicInputs: [FIELD_ONE] },
    { proof: proofBytes(), publicInputs: [FIELD_ONE, FIELD_TWO, FIELD_ONE] },
    { proof: proofBytes(), publicInputs: [] },
  ]) {
    assert.deepEqual(await backend.value.verifyProof(proofData), invalid);
  }
  assert.deepEqual(
    await backend.value.verifyProof({
      proof: proofBytes(96),
      publicInputs: [FIELD_ONE, FIELD_TWO],
    }),
    { success: false, reason: ReallyMeZkBbjsErrorReason.OversizedProof },
  );
  // Validation fails before any Barretenberg instance is created.
  assert.equal(FakeBarretenberg.instances.length, 0);

  const boundary = await backend.value.verifyProof({
    proof: proofBytes(),
    publicInputs: [LARGEST_CANONICAL_FIELD, FIELD_ONE.slice(2)],
  });
  assert.deepEqual(boundary, { success: true, value: true });
});

test("a backend proof with malformed public inputs is not returned", async () => {
  resetFakes();
  class MalformedProver extends FakeUltraHonkBackend {
    async generateProof() {
      return { proof: proofBytes(), publicInputs: [FIELD_ONE, "0x01"] };
    }
  }
  const runtime = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule(MalformedProver) });
  assert.equal(runtime.success, true);
  const backend = runtime.value.createUltraHonkBackend(ACIR_BYTECODE, ARTIFACT_PIN);
  assert.equal(backend.success, true);

  assert.deepEqual(await backend.value.generateProof(new Uint8Array([1])), {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.InvalidProofData,
  });
});

test("bytecode is authenticated against the artifact pin before the backend opens", async () => {
  resetFakes();
  const runtime = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule() });
  assert.equal(runtime.success, true);

  const invalidPin = { success: false, reason: ReallyMeZkBbjsErrorReason.InvalidArtifactPin };
  for (const pin of [
    undefined,
    {},
    { publicInputCount: 2 },
    { acirBytecodeSha256: ARTIFACT_PIN.acirBytecodeSha256 },
    { acirBytecodeSha256: "abc", publicInputCount: 2 },
    { acirBytecodeSha256: ARTIFACT_PIN.acirBytecodeSha256.toUpperCase(), publicInputCount: 2 },
    { acirBytecodeSha256: `0x${ARTIFACT_PIN.acirBytecodeSha256}`, publicInputCount: 2 },
    { acirBytecodeSha256: ARTIFACT_PIN.acirBytecodeSha256, publicInputCount: -1 },
    { acirBytecodeSha256: ARTIFACT_PIN.acirBytecodeSha256, publicInputCount: 1.5 },
    { acirBytecodeSha256: ARTIFACT_PIN.acirBytecodeSha256, publicInputCount: 4097 },
  ]) {
    assert.deepEqual(runtime.value.createUltraHonkBackend(ACIR_BYTECODE, pin), invalidPin);
  }

  const mismatch = { success: false, reason: ReallyMeZkBbjsErrorReason.ArtifactMismatch };
  const substituted = runtime.value.createUltraHonkBackend("other-acir", ARTIFACT_PIN);
  assert.equal(substituted.success, true);
  assert.deepEqual(await substituted.value.verifyProof(validProofData()), mismatch);
  const witness = new Uint8Array([1, 2]);
  assert.deepEqual(await substituted.value.generateProof(witness), mismatch);
  assert.deepEqual([...witness], [0, 0]);
  // A substituted circuit never reaches Barretenberg.
  assert.equal(FakeBarretenberg.instances.length, 0);
  assert.equal(FakeUltraHonkBackend.instances.length, 0);

  const oneShot = await verifyReallyMeZkBbjsProof({
    loadBbjs: fakeModule(),
    acirBytecode: "other-acir",
    ...ARTIFACT_PIN,
    proofData: validProofData(),
  });
  assert.deepEqual(oneShot, mismatch);
  const unpinned = await createReallyMeZkBbjsVerifier({
    loadBbjs: fakeModule(),
    acirBytecode: ACIR_BYTECODE,
  });
  assert.deepEqual(unpinned, invalidPin);
});

test("witness input is validated and cleared on rejection", async () => {
  resetFakes();
  const runtime = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule(), maxWitnessBytes: 2 });
  assert.equal(runtime.success, true);
  const backend = runtime.value.createUltraHonkBackend(ACIR_BYTECODE, ARTIFACT_PIN);
  assert.equal(backend.success, true);

  assert.deepEqual(await backend.value.generateProof(new Uint8Array(0)), {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.InvalidWitness,
  });
  const oversized = new Uint8Array([1, 2, 3]);
  assert.deepEqual(await backend.value.generateProof(oversized), {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.OversizedWitness,
  });
  assert.deepEqual([...oversized], [0, 0, 0]);
  assert.equal(FakeBarretenberg.instances.length, 0);
});

test("backend failures are typed and never read as verification", async () => {
  resetFakes();
  class ThrowingBackend extends FakeUltraHonkBackend {
    async verifyProof() {
      throw new globalThis.Error("backend detail must not escape");
    }
  }
  const runtime = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule(ThrowingBackend) });
  assert.equal(runtime.success, true);
  const backend = runtime.value.createUltraHonkBackend(ACIR_BYTECODE, ARTIFACT_PIN);
  assert.equal(backend.success, true);
  assert.deepEqual(await backend.value.verifyProof(validProofData()), {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.BackendFailure,
  });

  resetFakes();
  FakeBarretenberg.failNew = true;
  const unavailable = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule() });
  assert.equal(unavailable.success, true);
  const closed = unavailable.value.createUltraHonkBackend(ACIR_BYTECODE, ARTIFACT_PIN);
  assert.equal(closed.success, true);
  const witness = new Uint8Array([5, 6]);
  assert.deepEqual(await closed.value.generateProof(witness), {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.BackendFailure,
  });
  assert.deepEqual([...witness], [0, 0]);
  assert.deepEqual(await closed.value.verifyProof(validProofData()), {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.BackendFailure,
  });
});

test("destroy releases the Barretenberg instance and ends backend use", async () => {
  resetFakes();
  const runtime = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule() });
  assert.equal(runtime.success, true);
  const backend = runtime.value.createUltraHonkBackend(ACIR_BYTECODE, ARTIFACT_PIN);
  assert.equal(backend.success, true);

  assert.deepEqual(await backend.value.verifyProof(validProofData()), {
    success: true,
    value: true,
  });
  assert.deepEqual(await backend.value.destroy(), { success: true, value: undefined });
  assert.equal(FakeBarretenberg.instances[0].destroyed, true);
  assert.deepEqual(await backend.value.verifyProof(validProofData()), {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.BackendFailure,
  });
  assert.deepEqual(await backend.value.destroy(), { success: true, value: undefined });
  assert.equal(FakeBarretenberg.instances.length, 1);
});

test("createReallyMeZkBbjsVerifier exposes a verifier-shaped SDK facade", async () => {
  resetFakes();
  const verifier = await createReallyMeZkBbjsVerifier({
    loadBbjs: fakeModule(),
    acirBytecode: ACIR_BYTECODE,
    ...ARTIFACT_PIN,
  });
  assert.equal(verifier.success, true);

  const result = await verifier.value.verify(validProofData());
  assert.deepEqual(result, { success: true, value: true });

  const destroyResult = await verifier.value.destroy();
  assert.deepEqual(destroyResult, { success: true, value: undefined });
  assert.equal(FakeBarretenberg.instances[0].destroyed, true);
});

test("createReallyMeZkBbjsVerifier rejects missing artifact bytecode", async () => {
  const verifier = await createReallyMeZkBbjsVerifier({ loadBbjs: fakeModule() });
  assert.deepEqual(verifier, {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.InvalidAcirBytecode,
  });
});

test("verifyReallyMeZkBbjsProof verifies and destroys a one-shot backend", async () => {
  resetFakes();
  const result = await verifyReallyMeZkBbjsProof({
    loadBbjs: fakeModule(),
    acirBytecode: ACIR_BYTECODE,
    ...ARTIFACT_PIN,
    proofData: validProofData(),
    verifyOptions: { verifierTarget: "evm-no-zk" },
  });

  assert.deepEqual(result, { success: true, value: true });
  assert.equal(FakeBarretenberg.instances[0].destroyed, true);
  assert.deepEqual(FakeUltraHonkBackend.instances[0].verifyOptions, PRODUCTION_OPTIONS);
});

test("verifyReallyMeZkBbjsProof keeps proof rejection primary over destroy failure", async () => {
  resetFakes();
  class RejectingBackend extends FakeUltraHonkBackend {
    async verifyProof() {
      return false;
    }
  }
  class FailingDestroy extends FakeBarretenberg {
    static async new(options) {
      return new FailingDestroy(options);
    }

    async destroy() {
      throw new globalThis.Error("destroy failed");
    }
  }

  const rejected = await verifyReallyMeZkBbjsProof({
    loadBbjs: fakeModule(RejectingBackend, FailingDestroy),
    acirBytecode: ACIR_BYTECODE,
    ...ARTIFACT_PIN,
    proofData: validProofData(),
  });
  assert.deepEqual(rejected, {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.InvalidProof,
  });

  const accepted = await verifyReallyMeZkBbjsProof({
    loadBbjs: fakeModule(FakeUltraHonkBackend, FailingDestroy),
    acirBytecode: ACIR_BYTECODE,
    ...ARTIFACT_PIN,
    proofData: validProofData(),
  });
  assert.deepEqual(accepted, {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.DestroyFailed,
  });
});

test("invalid loaders and modules fail closed", async () => {
  const missingLoader = await loadReallyMeZkBbjsRuntime({});
  assert.deepEqual(missingLoader, {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.InvalidLoader,
  });

  const unsupported = { success: false, reason: ReallyMeZkBbjsErrorReason.UnsupportedModule };
  for (const moduleValue of [
    {},
    { UltraHonkBackend: FakeUltraHonkBackend },
    { Barretenberg: FakeBarretenberg },
    { UltraHonkBackend: FakeUltraHonkBackend, Barretenberg: class {} },
  ]) {
    const result = await loadReallyMeZkBbjsRuntime({
      loadBbjs: async () => Object.freeze(moduleValue),
    });
    assert.deepEqual(result, unsupported);
  }

  const untypedLoaderError = await loadReallyMeZkBbjsRuntime({
    loadBbjs: async () => Object.freeze({ success: false, reason: "raw-backend-text" }),
  });
  assert.deepEqual(untypedLoaderError, {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.ModuleUnavailable,
  });
});

test("invalid runtime options fail closed and limits cannot exceed their ceilings", async () => {
  const invalidLimit = { success: false, reason: ReallyMeZkBbjsErrorReason.InvalidLimit };
  for (const limits of [
    { maxWitnessBytes: 0 },
    { maxWitnessBytes: 4 * 1024 * 1024 + 1 },
    { maxProofBytes: 256 * 1024 + 1 },
    { maxAcirBytecodeChars: 64 * 1024 * 1024 + 1 },
    { maxProofBytes: 1.5 },
  ]) {
    const result = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule(), ...limits });
    assert.deepEqual(result, invalidLimit);
  }
  const atCeiling = await loadReallyMeZkBbjsRuntime({
    loadBbjs: fakeModule(),
    maxWitnessBytes: 4 * 1024 * 1024,
    maxProofBytes: 256 * 1024,
    maxAcirBytecodeChars: 64 * 1024 * 1024,
  });
  assert.equal(atCeiling.success, true);

  const invalidWasmPath = await loadReallyMeZkBbjsRuntime({
    loadBbjs: fakeModule(),
    wasmPath: "",
  });
  assert.deepEqual(invalidWasmPath, {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.InvalidBackendOptions,
  });

  const invalidThreads = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule(), threads: 0 });
  assert.deepEqual(invalidThreads, {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.InvalidThreadCount,
  });

  const runtime = await loadReallyMeZkBbjsRuntime({ loadBbjs: fakeModule(), maxAcirBytecodeChars: 4 });
  assert.equal(runtime.success, true);
  assert.deepEqual(runtime.value.createUltraHonkBackend("too-long"), {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.OversizedAcirBytecode,
  });
});

test("dynamicBbjsLoader reports module load failure without throwing", async () => {
  const result = await dynamicBbjsLoader("@reallyme/missing-bbjs-test-package")();
  assert.deepEqual(result, {
    success: false,
    reason: ReallyMeZkBbjsErrorReason.ModuleUnavailable,
  });
});
