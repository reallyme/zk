# Protobuf

The ZK message definitions are in
[`../crates/proto/proto/reallyme/zk/v1/manifest.proto`](../crates/proto/proto/reallyme/zk/v1/manifest.proto).
The transport-neutral service declaration is separate in
[`../crates/proto/proto/reallyme/zk/v1/zk_service.proto`](../crates/proto/proto/reallyme/zk/v1/zk_service.proto).

Use these protobuf definitions for artifact manifests, vector metadata,
durable service configuration, and Connect-style provider interfaces. Ordinary
identity, OpenID4VP, policy, and wallet-core Rust code should use
`reallyme-zk-api` types directly.

JSON at ZK boundaries must be generated from these protobuf/Buffa models or
from explicit typed protocol models. Do not maintain a parallel hand-written
JSON schema for the same provider, artifact, or proof-bundle messages.

The schema distinguishes circuit semantics from exact source identity:

- `ZkCircuitId` is the stable semantic registry key consumed by policy and
  proof-format logic.
- `ZkCircuitRef` is the exact imported source circuit selected for artifacts,
  vectors, and providers: credential hash algorithm, VC family, stage, and circuit version.
- `ZkClaimProofBundleKind` and `ZkClaimProofBundle` define the four-stage request-bound
  claim evidence returned by platform providers. Credential validity and current
  status require the separate status-qualified contract:
  `ZkStatusQualifiedClaimProofBundleVerifyOperation` carries the joined bundle
  with the verifier's authenticated current issuer status list and its
  `expected_issuer` credential issuer key, and
  `ZkStatusQualifiedClaimProofBundleVerification` is its distinct result.
- `ZkCircuitStage` identifies an exact source program. A proof slot identifies a
  position in a composed proof set; the selected-claim slot can use a public or
  private source stage. These concepts must not share an enum name.
- `ZkCredentialHashAlgorithm` selects credential commitment hashing independently
  of the proof suite's transcript hash.
- `ZkP256PublicKey` carries neutral public coordinates. Its enclosing field names
  the role; Rust domain boundaries distinguish issuer, persona, attestation, and
  status-authority keys.
- `ZkIssuerStatusPurpose` is the shared revocation/suspension vocabulary. Default
  and unknown enum values are rejected before witness conversion.
- `may_be_correlated` describes a capability and its privacy limit. It does not
  grant permission or promise unlinkability.

## Generated bindings

| Language | Bindings |
| --- | --- |
| Rust | `reallyme-zk-proto` with the `generated` feature |
| Swift | generated from the canonical schemas for `packages/swift`; checked-in output belongs under `gen/swift` |
| Kotlin/Android | generated from the canonical schemas for `packages/kotlin`; checked-in output belongs under `gen/kotlin` |
| TypeScript/WASM | generated and packaged by downstream consumer SDKs from the canonical schemas and fixtures |

Protobuf wire compatibility is the supported contract for these schemas.
The Buffa-generated Rust structs are transport bindings, and their public
fields include generator-owned types and unknown-field storage. Adding a
wire-compatible protobuf field can therefore require a Rust source change in
code that constructs those structs directly. Consumers should generate from
the schema and convert at the boundary; the generated Rust struct layout is
not a stable domain API. Changes to the published Rust package follow Cargo
versioning separately from protobuf wire compatibility.

## Transport Adapters

The message schema does not declare RPC services. `zk_service.proto` declares
the transport-neutral operation service separately. Connect or HTTP handlers
are downstream adapters: they accept `ZkProviderOperationRequest`, call an
injected provider, and return `ZkProviderOperationResponse` with a typed result
or `ZkError`. Connect-generated code cannot enter the message crate.

## Public Error Surface

`reallyme.zk.v1.ZkErrorReason` defines stable reason codes for public ZK errors.

`reallyme-zk-api::ZkError` stores a structured `ZkErrorKind` and normalizes it
to a stable top-level `ZkErrorReason`. Boundary adapters that emit the identity
common envelope must set `IdentityStackError.domain` to
`IDENTITY_STACK_ERROR_DOMAIN_ZK` and `IdentityStackError.reason_code` to
`ZkError::reason_code()`. `correlation_id` is optional and must remain non-PII.
The application or protocol layer that owns a cross-stack envelope performs
that mapping. ZK does not import identity protobufs.

The generated `reallyme.zk.v1.ZkError` message carries the same shape: a stable
top-level `reason` plus a granular `detail` oneof for circuit, input, proof,
bundle, binding, artifact, backend, or transport failures. The top-level reason
and the detail must match. Mismatches, protobuf defaults, missing detail, and
unknown open-enum values fail closed before leaving the adapter.

`reallyme-zk-proto-codec` owns explicit conversion helpers between generated
Buffa error enums/messages and Rust domain errors. Do not hand-maintain parallel
error maps in OpenID4VP, wallet, SDK, or service code.

Private implementation errors may remain Rust-native only when they never cross
a crate, RPC, FFI, package, storage, audit-log, telemetry, vector, or SDK
boundary and are normalized into `ZkErrorReason` before leaving the component.
Backend exception text, witness bytes, proof bytes, public inputs, raw buffers,
PII, and secrets must never be embedded in public errors.

Public identity service APIs and generated Connect adapters belong in
`reallyme/identity` or a dedicated runtime package.

Every proof package and artifact-backed provider request requires an exact
`ZkCircuitRef`. A semantic identifier alone is insufficient for proving or
verification. Format adapters may begin from a `ZkCircuitId`, but
must resolve it to a supported circuit reference and exact manifest before
constructing the provider request.

Proving, verification, and artifact-lookup operations also require an exact
`ZkProofSuite`. Verification requires the caller's expected suite to match the
suite carried by the proof. The value fixes transcript hash, witness-masking
mode, and accumulation policy; an unspecified, unknown, or mismatched value is
rejected before backend dispatch. The circuit reference's SHA-256/Poseidon2
credential hash algorithm is independent from the proof suite's Keccak/Poseidon2 transcript
choice.

Production provider adapters should return `ZkClaimProofBundle` for complete
platform proofs. The single-proof `ZkProofPackage` remains available for
low-level stage testing, vectors, and backend diagnostics.

`ZkClaimProofBundleProveOperation.witness_bundle` contains exactly four ordered
`ZkWitness` values. Every witness is a provider-generated serialized stack
pinned to the exact stage `ZkCircuitRef` and the closed
`ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1` representation; the strict codec
rejects missing or unknown encodings as well as missing, extra, reordered,
cross-bundle-kind, and cross-hash stacks.

`ZkRetainedClaimProofBundleProveOperation` proves the same four stages using native
handles. Its `ZkRetainedClaimProofBundleWitness` carries ordered opaque witness handles
from one provider context, so Swift and Kotlin do not serialize private witness
stacks back across the ABI. The native owner validates the entire handle set
before taking it. Once dispatch transfers ownership, a backend or response
failure may consume the handles; callers must generate a new set before
retrying. Both operations return the same complete `ZkClaimProofBundle` contract.

Handlers must treat `ZkWitness.encoded` and the containing `ZkClaimProofBundleWitness` as
secret input. Do not log request bodies, witness bytes, proof bytes, public
inputs, backend exception text, or raw artifact contents.

Executable adapters must decode `ZkProviderOperationRequest` through
`reallyme-zk-proto-codec::operation`. That boundary applies named binary and
JSON size limits, recursion and materialized-element budgets, rejects binary
unknown fields, converts every selected operation to domain types, and rejects
secret-bearing proving operations before ProtoJSON deserialization. Generated
message constructors and generic Buffa decode helpers are not executable
provider boundaries by themselves.

`reallyme-zk-proto-codec` is unpublished. The published
`reallyme-zk-proto` crate therefore supplies schemas and generated types,
not a standalone validator for untrusted provider operations. A
consumer outside this repository must supply an equivalently reviewed
validator before accepting those operations.

The strict ProtoJSON decoder accepts a canonical subset of
the proto3 JSON mapping. It rejects alternate field spellings, numeric enum
values, noncanonical base64, and other equivalent encodings when they do not
round-trip byte-for-byte through the canonical encoder. It must not be
advertised as a general-purpose proto3 JSON decoder.

The public sealed ProtoJSON helper independently enforces the same transport
policy for `ZkProviderOperationRequest`; direct generic encode or decode cannot
admit a proving variant. `ZkProvingVectorSet` has no public ProtoJSON
implementation because its transitive proving operations are binary-only.

## Boundary Rule

Convert at API, storage, and message boundaries:

```text
protobuf manifest/provider message -> reallyme-zk-api request/type -> backend
backend result -> reallyme-zk-api type -> protobuf response
```

Do not pass generated protobuf types through core policy or proof-format logic.
Those layers depend on `reallyme-zk-api`, not on generated transport crates.

## Generate

From the repository root:

```sh
buf lint
buf generate
node scripts/harden-zk-generated.mjs
cargo fmt --package reallyme-zk-proto
node scripts/harden-zk-generated.mjs --check-idempotent
```

The generation config follows the ReallyMe convention:

- Buffa Rust message and view types are emitted under
  `crates/proto/src/generated/buffa`.
- `reallyme-zk-proto` exposes generated Rust behind its `generated` feature.
- `reallyme-zk-proto-codec` exposes validated conversion helpers from generated
  Buffa messages into `reallyme-zk-api` and `reallyme-zk-artifacts` types.
  Provider adapters should use these helpers instead of duplicating enum,
  digest, proof-bundle, or optional-field conversion.
- Cross-stack error-envelope adapters belong to the application or protocol
  layer that owns that envelope; this repository exports stable numeric domain
  and reason codes without importing sibling protobuf packages.
- Swift and Kotlin/Android generated output is produced from the canonical
  schemas for this repository's first-party platform packages and, when
  checked in, lives only in the designated generated directories.
- TypeScript/WASM and any Connect runtime output are generated and packaged by
  downstream consumer SDKs or runtime packages.

This repository expects `protoc-gen-buffa` and
`protoc-gen-buffa-packaging` `0.9.2`.

Do not publish or consume freshly generated output before the hardening pass.
`node scripts/harden-zk-generated.mjs --check-idempotent` and the pinned
release-readiness generated-output check enforce this sequence.

## Identity and version compatibility

`ZkArtifactManifestDigest` is SHA-256 of a canonical binary protobuf manifest.
`ZkArtifactSetIdentity` is a separately domain-separated digest of exact circuit,
source, bytecode, and verification-key pins. Proof envelopes preserve the
construction with an `artifact_identity` oneof. Equal digest bytes with different
identity variants must never compare as the same artifact identity. Common-root
private sessions may reuse a claim-bundle manifest; other exact-source stages
use their reviewed artifact-set identity.

`ZkCircuitRef.circuit_revision` is the sole source-circuit revision authority.
The duplicate outer circuit-version fields have been removed.
`ZkClaimProofBundle.format_version` identifies its
composition envelope independently of the circuit revision. Crate/package
release versions and compiler/backend versions describe their own artifacts.

The 0.3.0 transport contract uses consecutive enum codes in declaration order,
without compatibility aliases or retired-code reservations. `ZkErrorReason`
retains the shared cross-stack error reason codes.

Proof envelopes, common-root stage inputs and provider responses place ordinary
metadata fields before their `oneof` alternatives, with increasing field tags.
This keeps Buffa, SwiftProtobuf and protobuf Java serialization in the same
canonical order. Swift and Kotlin fixture tests compare their encoded requests
byte for byte with the native fixtures. Native admission continues to reject
noncanonical encodings.

The terminology migration is a coordinated pre-1.0 compatibility change.
Generated type, enum, field, and operation names change source APIs and
ProtoJSON. Retiring duplicate version fields and replacing the legacy textual
bundle version changes binary envelopes too: strict decoders reject legacy
encodings. Rebuild provider packages, regenerate synthetic fixtures and artifact
manifests, and produce a newly sealed release/index before distribution. Existing
signed releases remain immutable. Circuit proof bytes, circuit identifiers,
public-input layouts, and transcript domains are not changed by these renames.

The schemas own transport contracts. Generated files must be regenerated and
hardened rather than edited, and SDKs must not define parallel wire messages or
registries. `reallyme-zk-api` owns circuit semantics and narrow Rust domain
projections without depending on protobuf; `reallyme-zk-proto-codec` owns the
validated conversions between those boundaries.
