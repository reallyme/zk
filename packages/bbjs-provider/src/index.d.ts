// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

export declare const REALLYME_ZK_BBJS_PROVIDER_VERSION: "0.1.0";

export declare const ReallyMeZkBbjsErrorReason: Readonly<{
  ArtifactMismatch: "artifact_mismatch";
  BackendFailure: "backend_failure";
  DestroyFailed: "destroy_failed";
  InvalidAcirBytecode: "invalid_acir_bytecode";
  InvalidArtifactPin: "invalid_artifact_pin";
  InvalidBackendOptions: "invalid_backend_options";
  InvalidLimit: "invalid_limit";
  InvalidLoader: "invalid_loader";
  InvalidProof: "invalid_proof";
  InvalidProofData: "invalid_proof_data";
  InvalidThreadCount: "invalid_thread_count";
  InvalidWitness: "invalid_witness";
  ModuleUnavailable: "module_unavailable";
  OversizedAcirBytecode: "oversized_acir_bytecode";
  OversizedProof: "oversized_proof";
  OversizedWitness: "oversized_witness";
  UnsupportedModule: "unsupported_module";
}>;

export type ReallyMeZkBbjsErrorReason =
  (typeof ReallyMeZkBbjsErrorReason)[keyof typeof ReallyMeZkBbjsErrorReason];

export type ReallyMeZkBbjsResult<T> =
  | Readonly<{ success: true; value: T }>
  | Readonly<{ success: false; reason: ReallyMeZkBbjsErrorReason }>;

/**
 * `proof` is a whole number of 32-byte field elements. Each public input is
 * exactly 64 hexadecimal digits, optionally `0x`-prefixed, encoding a value
 * below the BN254 scalar field modulus.
 */
export type ReallyMeZkBbjsProofData = Readonly<{
  proof: Uint8Array;
  publicInputs: ReadonlyArray<string>;
}>;

export type ReallyMeZkBbjsLoader = () => Promise<
  unknown | ReallyMeZkBbjsResult<unknown>
>;

/**
 * Each limit may be lowered below its built-in ceiling. A value above the
 * ceiling is rejected with `invalid_limit`.
 */
export type ReallyMeZkBbjsRuntimeOptions = Readonly<{
  loadBbjs: ReallyMeZkBbjsLoader;
  threads?: number;
  wasmPath?: string;
  maxAcirBytecodeChars?: number;
  maxProofBytes?: number;
  maxWitnessBytes?: number;
}>;

/**
 * Identifies the circuit the caller expects.
 *
 * `acirBytecodeSha256` is the lowercase hexadecimal SHA-256 of the UTF-8 bytes
 * of the bytecode string, taken from a release manifest the caller trusts.
 * `publicInputCount` is the exact number of public inputs of that circuit.
 * Bytecode with another digest fails with `artifact_mismatch` before it
 * reaches `bb.js`; proof data with another count is rejected.
 */
export type ReallyMeZkBbjsArtifactPin = Readonly<{
  acirBytecodeSha256: string;
  publicInputCount: number;
}>;

export type ReallyMeZkBbjsVerifierOptions = ReallyMeZkBbjsRuntimeOptions &
  ReallyMeZkBbjsArtifactPin &
  Readonly<{
    acirBytecode: string;
  }>;

export type ReallyMeZkBbjsVerifyProofOptions = ReallyMeZkBbjsVerifierOptions &
  Readonly<{
    proofData: ReallyMeZkBbjsProofData;
  }>;

/**
 * One circuit on one Barretenberg instance.
 *
 * Proving and verification always use UltraHonk with the Keccak transcript,
 * zero-knowledge masking, and no IPA accumulation. The suite is not
 * selectable. A rejected proof is a failure with reason `invalid_proof`.
 * `destroy()` releases the Barretenberg instance and ends use of the backend.
 */
export type ReallyMeZkBbjsUltraHonkBackend = Readonly<{
  generateProof(
    compressedWitness: Uint8Array,
  ): Promise<ReallyMeZkBbjsResult<ReallyMeZkBbjsProofData>>;
  verifyProof(proofData: ReallyMeZkBbjsProofData): Promise<ReallyMeZkBbjsResult<true>>;
  destroy(): Promise<ReallyMeZkBbjsResult<void>>;
}>;

/** Single-proof backend evidence; does not establish credential acceptance or consume a session. */
export type ReallyMeZkBbjsVerifier = Readonly<{
  verify(proofData: ReallyMeZkBbjsProofData): Promise<ReallyMeZkBbjsResult<true>>;
  destroy(): Promise<ReallyMeZkBbjsResult<void>>;
}>;

export type ReallyMeZkBbjsRuntime = Readonly<{
  createUltraHonkBackend(
    acirBytecode: string,
    artifactPin: ReallyMeZkBbjsArtifactPin,
  ): ReallyMeZkBbjsResult<ReallyMeZkBbjsUltraHonkBackend>;
}>;

export declare function dynamicBbjsLoader(specifier?: string): ReallyMeZkBbjsLoader;

export declare function createReallyMeZkBbjsVerifier(
  options: ReallyMeZkBbjsVerifierOptions,
): Promise<ReallyMeZkBbjsResult<ReallyMeZkBbjsVerifier>>;

/** Verify one proof only. Credential validity, current status, and session consumption require a complete verifier. */
export declare function verifyReallyMeZkBbjsProof(
  options: ReallyMeZkBbjsVerifyProofOptions,
): Promise<ReallyMeZkBbjsResult<true>>;

export declare function loadReallyMeZkBbjsRuntime(
  options: ReallyMeZkBbjsRuntimeOptions,
): Promise<ReallyMeZkBbjsResult<ReallyMeZkBbjsRuntime>>;
