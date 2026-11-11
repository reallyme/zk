# Barretenberg backend

This crate adapts a linked Barretenberg implementation and validates its
artifacts. Its `native` feature includes the C++ shim and
`NativeBarretenbergBackend`; the reviewed static library is supplied as an
explicit build input. Applications inject the concrete backend without
exposing backend types to identity, OpenID4VP, or wallet-core.

The crate provides:

- `BarretenbergArtifactResolver`: the required resolver for hash-pinned ACIR
  bytecode and verification-key artifacts.
- `BarretenbergArtifactStore`: the byte-loading hook for bundled mobile assets,
  local cache entries, or service-managed artifact storage. It returns
  kind-specific `ArtifactBytes`, never an unconstrained raw vector, and must
  enforce declared content length before allocation or streaming reads.
- `NativeFilesystemArtifactStore`: the native backend's bounded reader for a
  sealed package tree. It requires an explicit absolute root, derives all
  descendants from typed coordinates, rejects symlinked directories and
  files, checks metadata before and after each read, and stops at the
  artifact-kind limit before bytes enter digest verification.
- `ManifestBackedArtifactResolver`: the resolver that binds a
  caller-authenticated `ProductionBundleManifest` trust root to an artifact
  store. Constructing a manifest does not authenticate it; callers derive it
  from a reviewed release index or an equivalent authenticated configuration.
- `BbStageArtifacts`: bytecode, verification key, and manifest metadata after
  SHA-256 validation.
- `LinkedBarretenbergBackend`: the platform/service binding point for proving
  and verifying one production stage. Every implementation advertises one
  exact `ZkProofSuite`; there is no implicit backend default.
- `BbStageProveResponse`: an opaque, bounded proof response. Its
  constructors validate both reported buffer lengths before copying, validate
  the exact compact public-input ABI, and redact proof/public-input bytes from
  diagnostics.
- `BarretenbergPublicInputCodec`: the checked conversion between flattened
  32-byte big-endian Barretenberg field elements and the compiler-pinned
  compact provider ABI. It also normalizes separate iOS results and complete
  Android proof buffers into the same stage response.
- `NativeBarretenbergBackend`: the `native` backend that constructs typed
  BBAPI `CircuitProve` and `CircuitVerify` commands, invokes the linked
  ReallyMe BBAPI C++ shim through direct C symbols, validates the exact
  response schemas, and discards opaque upstream error text.
- `BarretenbergBundleProvider`: the stable adapter that proves and verifies a
  four-stage `ZkClaimProofBundle` over the artifact resolver and linked backend.

Individual stage verification is useful for diagnostics. Verifying the complete
bundle establishes the claim statement by checking the issuer-signed
credential root and the commitments that join all four stages.

Native production builds must link the reviewed BBAPI shim archive and the
exact Barretenberg v6.0.0 `libbb-external.a` explicitly:

```sh
REALLYME_BARRETENBERG_LIB_DIR=/path/to/barretenberg/v6.0.0/lib \
cargo build -p reallyme-zk-backend-bb --features native
```

The crate does not discover backend symbols at runtime.

With the explicit `dev-cli` feature, the unpublished
`check-public-inputs` audit binary reads one absolute, non-symlinked backend
public-input file under an exact typed hash, bundle kind, and stage. It
requires the compiler-derived byte length, decodes every canonical field, and
re-encodes byte-for-byte. It does not prove, verify, discover providers, or
enter runtime packages.

The adapter requires an exact `ZkCircuitRef`, a single hash lane per bundle,
session-binding equality at the API boundary, and typed `ZkErrorReason` values.
It resolves artifacts and checks their size, kind, and digest before each
backend call. Linked implementations must also check bindings in
stage public inputs before returning success.

The approved production suite is Barretenberg UltraHonk with a Keccak
transcript, zero-knowledge masking enabled, and IPA accumulation disabled.
Explicit compatibility suites may select Keccak or Poseidon2 transcripts and
masked or unmasked proving only where the linked implementation advertises the
exact combination. Proofs, manifests, requests, and provider results retain
that suite explicitly. The adapter compares them before invoking the backend
and fails with `UnsupportedProofSuite` on any mismatch or unsupported
combination; it never downgrades masking or changes transcript hash.

The adapter also compares each proof's `ZkArtifactManifestDigest` with the
manifest resolved for its exact stage. A stale or substituted manifest fails
with `ArtifactMismatch` before the linked verifier runs, even when the circuit
reference, proof suite, and artifact payload digests are otherwise valid.

Runtime features:

- `native`: compiles the native filesystem artifact store and the direct-linked
  prover/verifier backend. The shim and Barretenberg static archives remain
  explicit build inputs rather than repository-vendored binaries.
- `wasm`: compiles the platform-neutral backend contract for downstream WASM
  integration; Identity owns WebAssembly composition, with an optional
  `packages/bbjs-provider` adapter in this repository for the external runtime.
- `dev-cli`: local circuit iteration only.

The `bb` CLI shell-out path is allowed only behind a dev-only feature for
circuit iteration. It must not be enabled in SDKs, services, or apps.
