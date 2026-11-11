# ReallyMe ZK bb.js Provider

This package is the optional ReallyMe adapter for Aztec Barretenberg `bb.js`.
It is not part of the default Identity or ZK bundle. Applications that need
browser or Node proving install and load `@aztec-foundation/bb.js` explicitly,
then pass that runtime into this package.

The supported peer runtime is pinned to
`@aztec-foundation/bb.js@6.0.0`. Applications may inject a
different loader only after running the ReallyMe ZK provider vectors against
that exact runtime.

The package provides these UltraHonk operations:

- `dynamicBbjsLoader()` creates a lazy loader for the peer runtime;
- `loadReallyMeZkBbjsRuntime()` validates that the loaded module provides the
  expected `Barretenberg` factory and `UltraHonkBackend` constructor;
- `createReallyMeZkBbjsVerifier()` creates an SDK-compatible verifier for one
  caller-supplied ACIR artifact without registering circuits in JavaScript;
- `verifyReallyMeZkBbjsProof()` verifies one proof and destroys the backend;
- `createUltraHonkBackend()` binds a single ACIR bytecode blob. The backend
  opens its own Barretenberg instance on first use and releases it in
  `destroy()`;
- `generateProof()` consumes and clears the caller's witness buffer before
  dispatching to `bb.js`;
- `verifyProof()` delegates proof verification and returns a typed result. A
  rejected proof is a failure with reason `invalid_proof`; `success` is true
  only for a proof the backend accepted.

## Proof suite

Every proof is generated and verified with UltraHonk, the Keccak transcript,
zero-knowledge masking, and no IPA accumulation. This is the same suite as the
native linked provider, selected through the `bb.js` `evm` verifier target.
The suite is fixed: the adapter accepts no transcript, masking, or recursion
option, and it never uses the `bb.js` default, which is a different transcript.

## Input bounds

The adapter rejects input before it reaches `bb.js` when:

- the compressed witness exceeds 4 MiB, the proof exceeds 256 KiB, or the ACIR
  bytecode string exceeds 64 MiB of characters. A caller may lower these
  limits but cannot raise them;
- the proof is not a whole number of 32-byte field elements;
- a public input is not exactly 64 hexadecimal digits, optionally prefixed
  with `0x`, or encodes a value at or above the BN254 scalar field modulus.

Proof data returned by `generateProof()` passes the same checks.

## Artifact selection

`bb.js` derives the verification key from the ACIR bytecode it is given, so
every backend and verifier requires an artifact pin:

- `acirBytecodeSha256`: the lowercase hexadecimal SHA-256 of the UTF-8 bytes
  of the bytecode string;
- `publicInputCount`: the exact number of public inputs of that circuit.

The adapter hashes the bytecode before any Barretenberg instance is created
and fails with `artifact_mismatch` when the digest differs. Proof data whose
public-input count differs from the pin is rejected. The SDK takes both values
from the ReallyMe release manifest it has authenticated; this package does not
choose circuits and holds no manifest of its own. The meaning of each public
input remains the caller's check against the circuit's public-input layout.

## Witness memory

The adapter overwrites the caller's witness buffer and its own copy on every
path. It cannot clear the copies `bb.js` makes: the decompressed witness, the
copy placed in WebAssembly linear memory, and any copy sent to a worker. Those
remain until the runtime reuses or releases that memory. Call `destroy()` when
proving is finished, and run proving in a dedicated worker or page that is
discarded afterwards when witness lifetime matters.

Identity and application SDKs remain responsible for decoding canonical
`ZkProviderOperationRequest` bytes, selecting the circuit artifact, and mapping
typed ReallyMe errors. This package does not create a second circuit registry
and does not replace the native linked Barretenberg package used by Swift,
Kotlin, and verifier services.

A successful single-proof result is backend evidence only. It does not
establish credential acceptance, current status, or single-use session handling.
Use a complete credential verifier with trusted issuer/status policy and
atomic session consumption. SHA-256 is the preferred credential hash lane;
the credential hash lane does not change the proof suite.

Load browser proving on a dedicated ZK page or in a worker where supported.
Multi-threaded `bb.js` needs cross-origin isolation in browsers, so production
apps should set the required COOP/COEP headers only on the proving page when
that is compatible with the rest of the application.
