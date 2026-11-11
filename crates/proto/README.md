# reallyme-zk-proto

`reallyme-zk-proto` provides protobuf schemas and generated messages for artifact
manifests, provider operations, and ZK test-vector metadata.

The schema carries the full `ZkProofSuite` on artifact manifests, proof
packages, bundles, and verification results. The approved value fixes
UltraHonk, Keccak, ZK enabled, and IPA disabled. The suite is the sole proof-policy input.

`ZkProofPackage.artifact_identity` must select a manifest digest or a derived
artifact-set identity. The domain codec retains both the construction and its
digest in `ZkProof`. These identities are required integrity metadata: equal
digest bytes with different constructions are not interchangeable, and the
identity must not be dropped after length validation.

`ZkWitness` carries an explicit `ZkWitnessEncoding`. The only admitted v1 value
is `NOIR_WITNESS_STACK_V1`, identifying the serialized stack produced after
`reallyme-zk-noir-witness-core` validates the exact circuit ABI and typed inputs.
Unspecified and unknown values fail closed in the executable codec.

The crate is organized as follows:

- generated Buffa Rust code lives under `src/generated/buffa`,
- generated code is exposed only with the `generated` feature,
- validated domain conversions live in the separate `reallyme-zk-proto-codec`
  crate,
- checked-in schemas live under `proto/reallyme/zk/v1`,
- `capabilities.proto` owns disclosure, predicate, binding and guarantee vocabulary;
  `manifest.proto` imports it for artifact and provider contracts,
- protobuf and ProtoJSON compatibility fixtures ship under `tests/fixtures`
  for downstream identity generation and conformance,
- transport-neutral service declarations live in the separate
  `zk_service.proto`; generated service runtimes remain adapter-owned.

Core policy, OpenID4VP, and wallet flows should not use generated protobuf
types internally. They convert at their boundary and then operate on
`reallyme-zk-api` types.

The generated boundary supports uncompressed Buffa/protobuf bytes and Buffa
ProtoJSON. Concrete HTTP/Connect adapters live in SDKs, apps, and services.
Compression belongs at the transport or package layer. Use the shared identity
Brotli implementation rather than adding a separate ZK compressor.

Generated message decoding alone does not validate an executable provider
operation. The bounded, canonical operation decoder lives in the unpublished
`reallyme-zk-proto-codec` crate. Consumers of this published schema package
must not pass untrusted generated messages directly to a provider; they need
an equivalently reviewed validator.

The protobuf wire schema is the interoperability contract. Buffa-generated
Rust fields and unknown-field storage are exposed transport bindings, not a
stable domain model. A wire-compatible schema addition may change the Rust
struct API; use the protobuf schema for cross-language compatibility and
convert generated messages into domain types at the boundary.

This crate contains messages only and does not depend on the semantic API,
artifacts, backends, identity-common, or transport code. Cross-stack error
envelopes are constructed by the responsible application or protocol layer from
the stable ZK domain and reason codes.

## Capability contract

Disclosure and predicates are independent fields in `ZkCircuitCapabilities`.
The current canonical circuit registry advertises no predicates. The Rust
codec rejects unsupported claims of capability, including known predicate
values unsupported by the selected circuit.

Swift and Kotlin boundary codecs validate the generated capability vocabulary.
That validation alone authenticates no manifest and grants no circuit capability.
The Rust registry remains the authority for supported circuit semantics.

The 0.3.0 schema uses consecutive enum values and active message field tags in
logical declaration order.
Obsolete entries and compatibility aliases are absent. Shared `ZkErrorReason`
values retain their cross-stack reason-code mappings. Generated consumers and
binary fixtures must use the same schema snapshot.

Swift generated names retain their `Reallyme_Zk_V1_` prefix. Java/Kotlin
capability bindings are under `reallyme.zk.v1.Capabilities`; provider and proof
messages remain under `reallyme.zk.v1.Manifest`.
