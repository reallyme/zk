// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const DEFAULT_BBJS_PACKAGE = "@aztec-foundation/bb.js";
// Ceilings match the native ReallyMe ZK lane. Callers may lower a limit but
// cannot raise one above the bound the linked Barretenberg provider accepts.
const MAX_ACIR_BYTECODE_CHARS = 64 * 1024 * 1024;
const MAX_WITNESS_BYTES = 4 * 1024 * 1024;
const MAX_PROOF_BYTES = 256 * 1024;
const MAX_PUBLIC_INPUTS = 4096;
const MAX_THREADS = 32;
const FIELD_BYTES = 32;
const FIELD_HEX_DIGITS = FIELD_BYTES * 2;
const FIELD_HEX_PATTERN = /^(?:0x)?[0-9a-fA-F]{64}$/u;
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/u;
// BN254 scalar field modulus. A public input at or above it would alias a
// smaller canonical value inside the backend.
const BN254_FR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
// The only suite this adapter proves or verifies: UltraHonk with the Keccak
// transcript, zero-knowledge masking, and no IPA accumulation. In bb.js 6.0.0
// that is the `evm` verifier target; with no target bb.js selects Poseidon2.
const PRODUCTION_BACKEND_OPTIONS = Object.freeze({ verifierTarget: "evm" });

export const REALLYME_ZK_BBJS_PROVIDER_VERSION = "0.1.0";

export const ReallyMeZkBbjsErrorReason = Object.freeze({
  ArtifactMismatch: "artifact_mismatch",
  BackendFailure: "backend_failure",
  DestroyFailed: "destroy_failed",
  InvalidAcirBytecode: "invalid_acir_bytecode",
  InvalidArtifactPin: "invalid_artifact_pin",
  InvalidBackendOptions: "invalid_backend_options",
  InvalidLimit: "invalid_limit",
  InvalidLoader: "invalid_loader",
  InvalidProof: "invalid_proof",
  InvalidProofData: "invalid_proof_data",
  InvalidThreadCount: "invalid_thread_count",
  InvalidWitness: "invalid_witness",
  ModuleUnavailable: "module_unavailable",
  OversizedAcirBytecode: "oversized_acir_bytecode",
  OversizedProof: "oversized_proof",
  OversizedWitness: "oversized_witness",
  UnsupportedModule: "unsupported_module",
});
const KNOWN_ERROR_REASONS = new Set(Object.values(ReallyMeZkBbjsErrorReason));

export function dynamicBbjsLoader(specifier = DEFAULT_BBJS_PACKAGE) {
  if (typeof specifier !== "string" || specifier.length === 0) {
    return async () => errorResult(ReallyMeZkBbjsErrorReason.InvalidLoader);
  }
  return async () => {
    try {
      return successResult(await import(specifier));
    } catch {
      return errorResult(ReallyMeZkBbjsErrorReason.ModuleUnavailable);
    }
  };
}

export async function loadReallyMeZkBbjsRuntime(options) {
  if (!isObject(options) || typeof options.loadBbjs !== "function") {
    return errorResult(ReallyMeZkBbjsErrorReason.InvalidLoader);
  }
  const threadCount = normalizeThreadCount(options.threads);
  if (!threadCount.success) {
    return threadCount;
  }
  const limits = normalizeLimits(options);
  if (!limits.success) {
    return limits;
  }
  const wasmPath = normalizeOptionalPath(options.wasmPath);
  if (!wasmPath.success) {
    return wasmPath;
  }
  const loaded = await loadModule(options.loadBbjs);
  if (!loaded.success) {
    return loaded;
  }
  const moduleValue = loaded.value;
  if (
    !isObject(moduleValue) ||
    typeof moduleValue.UltraHonkBackend !== "function" ||
    typeof moduleValue.Barretenberg !== "function" ||
    typeof moduleValue.Barretenberg.new !== "function"
  ) {
    return errorResult(ReallyMeZkBbjsErrorReason.UnsupportedModule);
  }
  return successResult(
    new ReallyMeZkBbjsRuntime(moduleValue.UltraHonkBackend, moduleValue.Barretenberg, {
      limits: limits.value,
      threads: threadCount.value,
      wasmPath: wasmPath.value,
    }),
  );
}

export async function createReallyMeZkBbjsVerifier(options) {
  if (!isObject(options)) {
    return errorResult(ReallyMeZkBbjsErrorReason.InvalidBackendOptions);
  }
  const runtime = await loadReallyMeZkBbjsRuntime(options);
  if (!runtime.success) {
    return runtime;
  }
  const backend = runtime.value.createUltraHonkBackend(options.acirBytecode, {
    acirBytecodeSha256: options.acirBytecodeSha256,
    publicInputCount: options.publicInputCount,
  });
  if (!backend.success) {
    return backend;
  }
  return successResult(new ReallyMeZkBbjsVerifier(backend.value));
}

export async function verifyReallyMeZkBbjsProof(options) {
  if (!isObject(options)) {
    return errorResult(ReallyMeZkBbjsErrorReason.InvalidBackendOptions);
  }
  const verifier = await createReallyMeZkBbjsVerifier(options);
  if (!verifier.success) {
    return verifier;
  }

  const verification = await verifier.value.verify(options.proofData);
  const destroyResult = await verifier.value.destroy();
  // A rejected proof is a failure result and stays primary over cleanup errors.
  if (!verification.success) {
    return verification;
  }
  if (!destroyResult.success) {
    return destroyResult;
  }
  return verification;
}

class ReallyMeZkBbjsRuntime {
  #UltraHonkBackend;
  #Barretenberg;
  #options;

  constructor(UltraHonkBackend, Barretenberg, options) {
    this.#UltraHonkBackend = UltraHonkBackend;
    this.#Barretenberg = Barretenberg;
    this.#options = Object.freeze({
      limits: options.limits,
      threads: options.threads,
      wasmPath: options.wasmPath,
    });
    Object.freeze(this);
  }

  createUltraHonkBackend(acirBytecode, artifactPin) {
    if (typeof acirBytecode !== "string" || acirBytecode.length === 0) {
      return errorResult(ReallyMeZkBbjsErrorReason.InvalidAcirBytecode);
    }
    if (acirBytecode.length > this.#options.limits.maxAcirBytecodeChars) {
      return errorResult(ReallyMeZkBbjsErrorReason.OversizedAcirBytecode);
    }
    // The verification key is derived from this bytecode, so the caller must
    // state which bytecode and which public-input layout it expects.
    if (
      !isObject(artifactPin) ||
      typeof artifactPin.acirBytecodeSha256 !== "string" ||
      !SHA256_HEX_PATTERN.test(artifactPin.acirBytecodeSha256) ||
      !Number.isSafeInteger(artifactPin.publicInputCount) ||
      artifactPin.publicInputCount < 0 ||
      artifactPin.publicInputCount > MAX_PUBLIC_INPUTS
    ) {
      return errorResult(ReallyMeZkBbjsErrorReason.InvalidArtifactPin);
    }
    const apiOptions = {};
    if (this.#options.threads !== undefined) {
      apiOptions.threads = this.#options.threads;
    }
    if (this.#options.wasmPath !== undefined) {
      apiOptions.wasmPath = this.#options.wasmPath;
    }
    return successResult(
      new ReallyMeZkBbjsUltraHonkBackend(
        this.#UltraHonkBackend,
        this.#Barretenberg,
        acirBytecode,
        Object.freeze({
          acirBytecodeSha256: artifactPin.acirBytecodeSha256,
          publicInputCount: artifactPin.publicInputCount,
        }),
        Object.freeze(apiOptions),
        this.#options.limits,
      ),
    );
  }
}

class ReallyMeZkBbjsVerifier {
  #backend;

  constructor(backend) {
    this.#backend = backend;
    Object.freeze(this);
  }

  async verify(proofData) {
    return await this.#backend.verifyProof(proofData);
  }

  async destroy() {
    return await this.#backend.destroy();
  }
}

// One circuit bound to one Barretenberg instance. The instance is created on
// first use and released by `destroy()`, which also ends the backend's use.
class ReallyMeZkBbjsUltraHonkBackend {
  #UltraHonkBackend;
  #Barretenberg;
  #acirBytecode;
  #artifactPin;
  #apiOptions;
  #limits;
  #state;

  constructor(UltraHonkBackend, Barretenberg, acirBytecode, artifactPin, apiOptions, limits) {
    this.#UltraHonkBackend = UltraHonkBackend;
    this.#Barretenberg = Barretenberg;
    this.#acirBytecode = acirBytecode;
    this.#artifactPin = artifactPin;
    this.#apiOptions = apiOptions;
    this.#limits = limits;
    this.#state = { api: undefined, opening: undefined, destroyed: false };
    Object.freeze(this);
  }

  // Concurrent first calls share one opening so a circuit never holds two
  // Barretenberg instances.
  async #backend() {
    const state = this.#state;
    if (state.destroyed) {
      return errorResult(ReallyMeZkBbjsErrorReason.BackendFailure);
    }
    if (state.opening === undefined) {
      state.opening = this.#open();
    }
    return await state.opening;
  }

  async #open() {
    const state = this.#state;
    // Authenticate the bytecode before any Barretenberg instance sees it.
    const digest = await sha256Hex(this.#acirBytecode);
    if (!digest.success) {
      state.opening = undefined;
      return digest;
    }
    if (digest.value !== this.#artifactPin.acirBytecodeSha256) {
      return errorResult(ReallyMeZkBbjsErrorReason.ArtifactMismatch);
    }
    let api;
    try {
      api = await this.#Barretenberg.new(this.#apiOptions);
    } catch {
      state.opening = undefined;
      return errorResult(ReallyMeZkBbjsErrorReason.BackendFailure);
    }
    try {
      const backend = new this.#UltraHonkBackend(this.#acirBytecode, api);
      state.api = api;
      return successResult(backend);
    } catch {
      state.opening = undefined;
      await destroyApi(api);
      return errorResult(ReallyMeZkBbjsErrorReason.BackendFailure);
    }
  }

  async generateProof(compressedWitness) {
    if (!(compressedWitness instanceof Uint8Array) || compressedWitness.byteLength === 0) {
      return errorResult(ReallyMeZkBbjsErrorReason.InvalidWitness);
    }
    if (compressedWitness.byteLength > this.#limits.maxWitnessBytes) {
      compressedWitness.fill(0);
      return errorResult(ReallyMeZkBbjsErrorReason.OversizedWitness);
    }

    const witnessForBackend = new Uint8Array(compressedWitness);
    compressedWitness.fill(0);
    try {
      const backend = await this.#backend();
      if (!backend.success) {
        return backend;
      }
      const proofData = await backend.value.generateProof(
        witnessForBackend,
        PRODUCTION_BACKEND_OPTIONS,
      );
      return validateProofData(
        proofData,
        this.#limits.maxProofBytes,
        this.#artifactPin.publicInputCount,
      );
    } catch {
      return errorResult(ReallyMeZkBbjsErrorReason.BackendFailure);
    } finally {
      witnessForBackend.fill(0);
    }
  }

  async verifyProof(proofData) {
    const validated = validateProofData(
      proofData,
      this.#limits.maxProofBytes,
      this.#artifactPin.publicInputCount,
    );
    if (!validated.success) {
      return validated;
    }

    const proofForBackend = new Uint8Array(validated.value.proof);
    try {
      const backend = await this.#backend();
      if (!backend.success) {
        return backend;
      }
      const verified = await backend.value.verifyProof(
        Object.freeze({
          proof: proofForBackend,
          publicInputs: validated.value.publicInputs,
        }),
        PRODUCTION_BACKEND_OPTIONS,
      );
      // Rejection is a typed failure, so `success` alone never admits a proof.
      if (verified !== true) {
        return errorResult(ReallyMeZkBbjsErrorReason.InvalidProof);
      }
      return successResult(true);
    } catch {
      return errorResult(ReallyMeZkBbjsErrorReason.BackendFailure);
    } finally {
      proofForBackend.fill(0);
    }
  }

  async destroy() {
    const state = this.#state;
    state.destroyed = true;
    if (state.opening !== undefined) {
      await state.opening;
    }
    const api = state.api;
    state.api = undefined;
    state.opening = undefined;
    if (api === undefined) {
      return successResult(undefined);
    }
    return await destroyApi(api);
  }
}

async function destroyApi(api) {
  if (!isObject(api) || typeof api.destroy !== "function") {
    return errorResult(ReallyMeZkBbjsErrorReason.DestroyFailed);
  }
  try {
    await api.destroy();
    return successResult(undefined);
  } catch {
    return errorResult(ReallyMeZkBbjsErrorReason.DestroyFailed);
  }
}

async function loadModule(loader) {
  let loaded;
  try {
    loaded = await loader();
  } catch {
    return errorResult(ReallyMeZkBbjsErrorReason.ModuleUnavailable);
  }
  if (isProviderResult(loaded)) {
    return normalizeProviderResult(loaded);
  }
  return successResult(loaded);
}

function normalizeProviderResult(result) {
  if (result.success === true && Object.hasOwn(result, "value")) {
    return successResult(result.value);
  }
  if (
    result.success === false &&
    typeof result.reason === "string" &&
    KNOWN_ERROR_REASONS.has(result.reason)
  ) {
    return errorResult(result.reason);
  }
  return errorResult(ReallyMeZkBbjsErrorReason.ModuleUnavailable);
}

// SHA-256 over the UTF-8 bytes of the bytecode string, as lowercase hex.
async function sha256Hex(text) {
  const subtle = globalThis.crypto?.subtle;
  if (!isObject(subtle) || typeof subtle.digest !== "function") {
    return errorResult(ReallyMeZkBbjsErrorReason.BackendFailure);
  }
  try {
    const digest = new Uint8Array(await subtle.digest("SHA-256", new TextEncoder().encode(text)));
    let hex = "";
    for (const byte of digest) {
      hex += byte.toString(16).padStart(2, "0");
    }
    return successResult(hex);
  } catch {
    return errorResult(ReallyMeZkBbjsErrorReason.BackendFailure);
  }
}

function validateProofData(proofData, maxProofBytes, publicInputCount) {
  if (!isObject(proofData) || !(proofData.proof instanceof Uint8Array)) {
    return errorResult(ReallyMeZkBbjsErrorReason.InvalidProofData);
  }
  if (proofData.proof.byteLength === 0 || proofData.proof.byteLength % FIELD_BYTES !== 0) {
    return errorResult(ReallyMeZkBbjsErrorReason.InvalidProofData);
  }
  if (proofData.proof.byteLength > maxProofBytes) {
    return errorResult(ReallyMeZkBbjsErrorReason.OversizedProof);
  }
  if (
    !Array.isArray(proofData.publicInputs) ||
    proofData.publicInputs.length !== publicInputCount
  ) {
    return errorResult(ReallyMeZkBbjsErrorReason.InvalidProofData);
  }
  for (const publicInput of proofData.publicInputs) {
    if (!isCanonicalFieldHex(publicInput)) {
      return errorResult(ReallyMeZkBbjsErrorReason.InvalidProofData);
    }
  }
  return successResult(
    Object.freeze({
      proof: new Uint8Array(proofData.proof),
      publicInputs: Object.freeze([...proofData.publicInputs]),
    }),
  );
}

// A public input is exactly one 32-byte big-endian field element below the
// BN254 scalar modulus, so each value has a single accepted encoding.
function isCanonicalFieldHex(value) {
  if (typeof value !== "string" || !FIELD_HEX_PATTERN.test(value)) {
    return false;
  }
  const digits = value.slice(value.length - FIELD_HEX_DIGITS);
  return BigInt(`0x${digits}`) < BN254_FR_MODULUS;
}

function normalizeThreadCount(threads) {
  if (threads === undefined) {
    return successResult(undefined);
  }
  if (!Number.isSafeInteger(threads) || threads < 1 || threads > MAX_THREADS) {
    return errorResult(ReallyMeZkBbjsErrorReason.InvalidThreadCount);
  }
  return successResult(threads);
}

function normalizeLimits(options) {
  const maxAcirBytecodeChars = normalizeOptionalPositiveSafeInteger(
    options.maxAcirBytecodeChars,
    MAX_ACIR_BYTECODE_CHARS,
  );
  if (!maxAcirBytecodeChars.success) {
    return maxAcirBytecodeChars;
  }
  const maxProofBytes = normalizeOptionalPositiveSafeInteger(
    options.maxProofBytes,
    MAX_PROOF_BYTES,
  );
  if (!maxProofBytes.success) {
    return maxProofBytes;
  }
  const maxWitnessBytes = normalizeOptionalPositiveSafeInteger(
    options.maxWitnessBytes,
    MAX_WITNESS_BYTES,
  );
  if (!maxWitnessBytes.success) {
    return maxWitnessBytes;
  }
  return successResult(
    Object.freeze({
      maxAcirBytecodeChars: maxAcirBytecodeChars.value,
      maxProofBytes: maxProofBytes.value,
      maxWitnessBytes: maxWitnessBytes.value,
    }),
  );
}

function normalizeOptionalPositiveSafeInteger(value, ceiling) {
  if (value === undefined) {
    return successResult(ceiling);
  }
  if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) {
    return errorResult(ReallyMeZkBbjsErrorReason.InvalidLimit);
  }
  return successResult(value);
}

function normalizeOptionalPath(value) {
  if (value === undefined) {
    return successResult(undefined);
  }
  if (typeof value !== "string" || value.length === 0) {
    return errorResult(ReallyMeZkBbjsErrorReason.InvalidBackendOptions);
  }
  return successResult(value);
}

function successResult(value) {
  return Object.freeze({ success: true, value });
}

function errorResult(reason) {
  return Object.freeze({ success: false, reason });
}

function isProviderResult(value) {
  return isObject(value) && typeof value.success === "boolean";
}

function isObject(value) {
  return typeof value === "object" && value !== null;
}
