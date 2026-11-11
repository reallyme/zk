# Provider compatibility

Applications must explicitly select a provider for proof generation and
verification. Each provider must support the requested circuit, credential hash algorithm,
proof suite, and artifact identity without modification.

If a provider is unavailable or incompatible, the operation must fail.
Runtimes must never select a backend implicitly or silently substitute a
different proof suite.

A circuit or proof suite appearing in the API does not guarantee provider
support. Support depends on the provider version, available circuit artifacts,
and target platform.

Providers supporting `common_credential_root_v1` must verify all nine proofs
and the relationships between them.

## Production requirements

A provider may be used in production only if it meets all of these requirements:

- Implements the complete four-stage `ZkClaimProofBundle` contract.
- Uses the exact `barretenberg_ultra_honk_keccak_zk_no_ipa` proof suite.
- Resolves every proof stage using a hash-pinned artifact manifest.
- Validates the exact public-input ABI and binds proofs to the active session.
- Verifies the complete proof bundle. Verifying one stage does not establish
  the guarantees of the entire bundle.
- Enforces trusted-issuer and presentation-expiry policies at verification.
  Verifiers requiring credential revocation status must reject the four-stage
  v1 bundle: it does not contain a stable issuer-status reference. Credential
  acceptance additionally requires the joined issuer-status proof and an
  authenticated current issuer feed.
- Returns typed errors without backend diagnostics, proofs, witnesses, public
  inputs, or identity information.
- Passes all retained positive and negative conformance tests for every
  supported bundle kind, presentation mode, and credential hash algorithm.

## Proof suites

The provider contract defines four UltraHonk configurations without IPA
accumulation:

| Transcript | Witness masking | Status |
| --- | --- | --- |
| Keccak | Enabled | Required for production |
| Keccak | Disabled | Diagnostics only; does not provide witness privacy |
| Poseidon2 | Enabled | Requires explicit provider support and successful conformance testing |
| Poseidon2 | Disabled | Diagnostics only; does not provide witness privacy |

The circuit credential hash algorithm (`ZkCredentialHashAlgorithm`) and proof transcript hash are
independent settings. Adapters must preserve both values and select artifacts
using the complete `ZkProofSuite` configuration.

An unmasked proof may establish the validity of a statement, but it does not
protect the witness. Unmasked proofs must never satisfy policies that invoke
`require_zero_knowledge()`.

Platform APIs may expose transcript selection and witness masking as separate
options. They must combine those options into one exact `ZkProofSuite` before
passing the request to a provider. For example, an iOS adapter must not silently
convert a Poseidon2 configuration with zero-knowledge masking into an unmasked
Poseidon2 configuration.

Providers must return `UnsupportedProofSuite` for unsupported suites. A suite
must pass conformance testing before a provider advertises support for it.

The wire-format enum may define more proof suites than a provider implements.
An enum value, a working sample application, or a successful local build does
not establish production support.

## Responsibilities

This repository defines and maintains:

- Rust provider contracts.
- Canonical protobuf messages.
- Artifact validation.
- Conformance vectors.
- The internal Barretenberg adapter boundary.
- First-party Swift and Kotlin provider packages.

Application SDKs expose the public identity APIs, integrate these components,
and manage TypeScript/WebAssembly packaging and service integration.

Platform adapters may use different implementations, provided they preserve
the protocol's buffer limits, ownership rules, canonical requests and
responses, error contracts, proof bundles, and artifact identities.

Witness material must be held in a short-lived, zeroizing owner. It must never
enter JSON serialization, logging, or telemetry. Transfers into unmanaged
memory require an explicit destruction mechanism.

## Conformance

A provider may advertise production support only after its distributed package
has passed the shared proof conformance tests. These tests must cover the
proving and verification operations it supports, including successful results
and rejection of:

- Tampered proofs.
- Incorrect nonces.
- Incorrect audiences.
- Stale artifacts.
- Mismatched credential hash algorithms.
- Missing proof stages.
- Duplicate proof stages.
- Unsupported circuits.
- Incorrect transaction-data bindings.

Passing compilation checks or protobuf tests alone does not demonstrate that
a provider can correctly generate or verify proofs for its advertised capabilities.
