# Platform Binding Contract

This repository defines the canonical `reallyme.zk.v1` messages, the separate
transport-neutral service declaration, generated Buffa/Rust messages, strict
Rust codec mappings, circuit semantics, artifacts, and backend contracts.

This repository provides first-party Swift and Kotlin provider packages under
`packages/swift` and `packages/kotlin`. Their manifests, generated protobuf
bindings, provider APIs, and native transports use the shared schemas, Rust
types, artifact formats, and provider contracts. They must not duplicate
protocol messages, circuit registries, proof suites, artifact formats, or errors.

Platform protobuf types for Swift and Kotlin are generated from the versioned
schemas and validated against the public fixtures in
`crates/proto/tests/fixtures/protobuf` and
`crates/proto/tests/fixtures/protojson`. Checked-in generated platform code
belongs in an explicit package-local generated path and is never mixed with
authored package adapters. TypeScript, WebAssembly composition, and public
identity SDKs may use the canonical package, but they must not
redefine the operation or error DTOs. This repository emits no standalone
ReallyMe `.wasm` binary. The optional `packages/bbjs-provider` package is a
lazy adapter over the external Aztec `bb.js` runtime and does not define
another DTO layer, circuit registry, or provider-operation codec.

Connect adapters are also downstream runtime code. The service schema may be
used to generate a dedicated adapter package, but Connect dependencies and
generated Connect code cannot enter `reallyme-zk-proto` or the strict codec
crate. Missing platform providers fail closed with the canonical typed error.

Platform bindings must preserve the exact `ZkProofSuite` selected by the
caller. They may report that a linked backend does not implement a suite, but
must not change transcript hash or disable ZK masking to make a request run.
The `bb.js` adapter implements only the production suite and passes that
selection to `bb.js` itself; it exposes no option that selects another.
Production packages use only the Noir and Barretenberg versions pinned by the
toolchain lock and artifact manifests. Legacy beta.9 artifacts,
Barretenberg 0.87 libraries, and raw upstream `bbapi` payloads are not admitted
by a production platform package.

The canonical exchange ABI is layered inside `crates/proto-codec`, above the
strict protobuf codec and below platform package adapters. Platform callers
pass bounded canonical `ZkProviderOperationRequest` bytes and receive bounded
canonical `ZkProviderOperationResponse` bytes plus numeric ReallyMe status
codes. `reallyme_zk_platform_encode_failure_response` is the shared
failure-response constructor for Swift, Kotlin/JNI, and other provider
wrappers; it binds every response to the SHA-256 of the exact request bytes and
returns only typed `ZkErrorReason` values. Returned buffers are opaque and must
be released exactly once with `reallyme_zk_platform_buffer_destroy`, which
zeroizes the owned allocation before freeing it.

The numeric platform ABI includes an internal-panic status for builds where
Rust unwinding is enabled and a panic can be contained before crossing C.
Shipped mobile artifacts use the reviewed `mobile-release` Cargo profile,
which inherits the release optimization profile but enables `panic = "unwind"`
at the platform FFI boundary. Workspace `release` builds still use
`panic = "abort"` and remain fail-stop. C++ Barretenberg exceptions are a
separate backend boundary and must still be caught before crossing the
ReallyMe C ABI.

`crates/platform-ffi` is the native provider adapter above the protobuf codec
and linked Barretenberg backend. It exports
`reallyme_zk_platform_context_create`,
`reallyme_zk_platform_dispatch`, and
`reallyme_zk_platform_context_destroy`. Context creation accepts only an
absolute artifact root, a canonical `ZkReleaseIndex`, the out-of-band approved
release-index SHA-256 digest, a repository-pinned CRS mode, and CRS bytes whose
lengths and SHA-256 identities match the toolchain lock. The platform context
rejects a substituted index before decoding, checks the index toolchain and
capability-registry digest against the repository registry, and opens artifact
manifests through descriptor-relative no-follow path traversal. Dispatch admits
only canonical provider operations; raw Barretenberg BBAPI MessagePack remains
an internal Rust-to-C++ transport and must not be called by Swift, Kotlin,
Java, or app code.

## Native package boundaries

The Apple package binds its platform ABI header through a Clang module map.
The Android JNI library includes `libc++_shared.so` and applies
`packages/kotlin/native/jni/reallyme_zk_platform_jni.map`. Its app-facing
exports are limited to
`Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextCreate`,
`Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextCreateWithCrsFiles`,
`Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeDispatch`, and
`Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextDestroy`.
Raw platform ABI and BBAPI symbols remain hidden from that library.

The default Android package uses the production `native` build.
`claim_bundle_4` diagnostic libraries have separate outputs and cannot
replace production package bytes or make that source stage a production
capability. Apple and Android package gates check the recorded source
closure and binary hashes, so a changed source tree cannot reuse stale
native artifacts. Before publishing, test installation from an external project
and run device proof tests against the distributed native binaries.

The reviewed native builders are
`scripts/build_apple_platform_ffi_xcframework.sh`,
`scripts/build_android_platform_ffi_static.sh`, and
`scripts/build_android_platform_jni.sh`. The
[platform build guide](platform-builds.md) records their invocation, output
paths, example-project setup, and diagnostic build selection.

The backend provider generates and verifies proofs. Native dispatch supports
stage artifact-manifest lookup, typed witness
generation, diagnostic stage proving and verification, and complete four-stage
bundle proving and verification. The retained-handle bundle operation accepts
four ordered witness handles produced in the same native context. It validates
the complete handle set before consuming it and does not return private witness
bytes to Swift or Kotlin. After dispatch transfers ownership, proving or
response-encoding failure may still consume the handles. Four-stage bundle
verification establishes claim evidence with trusted-issuer, active-session,
and expiry policy. Credential acceptance additionally requires the joined
issuer-validity/status proof and an authenticated current issuer feed; the
Swift and Kotlin `verifyPresentationBoundClaimBundle` APIs return only
presentation-bound claim evidence. Their result cannot stand in for
status-qualified credential verification. The protobuf `verify_claim_proof_bundle`
operation and its report are transport contracts and carry no acceptance capability.

The `verify_status_qualified_claim_proof_bundle` operation is the platform
boundary for credential acceptance. Its request carries the four claim proofs,
the issuer validity and current-status proof, the active session binding, the
trusted issuer keys, the verifier clock, and the verifier's current issuer
status list: root, length, list identifier, URL hash, and purpose. The native
provider has no network access and no issuer trust store, so the verifier
application authenticates that status list first, including its signature,
issuer, freshness, and rollback floor. The provider rejects a request whose
status list is absent, default-valued, or incomplete. It verifies all five
proofs, requires the status proof to share the claim bundle's issuer,
presentation expiry, and request-scoped credential binding, and requires the
status proof's root, length, list identifier, URL hash, and purpose to equal
the supplied list. A status proof that points at a different list or purpose
fails with a binding mismatch.

The request also names `expected_issuer`: the credential issuer for which the
application authenticated the supplied list. It must be trusted and equal the
issuer proven by the claim bundle. A delegated status-list signer does not
replace this credential issuer key. Matching list identifiers alone cannot
authorize reuse of one issuer's status feed for another issuer.

Its result is a separate message and a separate Swift and Kotlin type from the
four-proof report. An adapter accepts it only when it reports five verified
proofs, the production suite, the requested status purpose, and a statement
equal to the one decoded from the bundle it sent. A four-proof report returned
for this operation is rejected. The result covers one status purpose at the
supplied verifier clock and does not consume the session.
An individual stage is insufficient. For example, an envelope-stage result alone does not authenticate a
credential. The four-stage claim check requires the root-stage issuer signature
and the bundle's cross-stage commitment checks.

Each context retains at most 16 stage witnesses. Capacity exhaustion returns
the typed `ResourceExhausted` reason without evicting another live handle;
releasing a handle makes capacity available again. A caller that abandons a
presentation must release its handles. Destroying the context drops any
remaining retained witness owners, subject to the upstream memory limits in
the memory ownership guide. Concurrent native dispatch on one context is
single-flight and reports ABI `DISPATCH_BUSY` (with typed
`BackendUnavailable` as the underlying reason) to concurrent callers. Swift
maps this to `alreadyRunning` and Kotlin to `PROVIDER_BUSY`. The caller can
retry after the in-flight operation returns. Callers must not infer that a
rejected concurrent request ran.

The platform APIs apply a 1 MiB per-stage witness limit to
bound mobile memory, while the Rust operation codec allows up to 4 MiB. The
Android JNI request boundary is narrower than the Rust operation envelope.
The size-contract check enforces these limits across Rust, Swift, Kotlin, and
JNI, so changing any of them requires review. All 20 request-bound witness
fixtures are below the 1 MiB platform limit. Mobile fixture tests cover the
common-credential-root stages separately.
Any circuit exceeding the limit requires a reviewed platform-limit and
memory budget update before it can be advertised as mobile supported.

Sensitive witness inputs remain binary-only at executable boundaries. Every
stage witness must be produced by this repository's typed witness owner and
must carry the canonical `NoirWitnessStackV1` encoding discriminator; missing,
unknown, or locally invented representations fail before backend dispatch.
Identity and other consumers construct typed requests through the canonical
package without duplicating the field registry in ZK messages.

The [platform build guide](platform-builds.md#poseidon2-fixture-parity)
records the pinned Poseidon2 fixture encoding and cross-repository hash
parity check. Production off-circuit hashing belongs in
`reallyme-crypto-poseidon2`; this repository owns the circuit constraints
and proving boundary.

Every platform implementation must enforce the same protobuf size, recursion,
unknown-field, oneof, canonical-encoding, and ownership rules before dispatch,
and must zeroize owned witness, proof, public-input, and session-binding bytes
as soon as practical.

## API discovery and verification state

Rust contracts are grouped under `circuits`, `capabilities`, `proofs`,
`claim_bundle`, `common_root`, `persona_evidence`, `issuer_status`, `keys`,
`artifacts` and `errors`. Descriptive type names remain intact; for example,
`reallyme_zk_api::claim_bundle::ZkClaimProofBundle`.

Swift keeps the `ReallyMeZKKit` module and descriptive public type names.
Its source and documentation group core types, claim bundles, common-root
composition and persona evidence by domain. Kotlin uses `me.really.zk.circuits`,
`me.really.zk.claimbundle`, `me.really.zk.commonroot` and
`me.really.zk.personaevidence` for the corresponding models. Shared provider
interfaces remain under `me.really.zk`.

The capability schema is separate from the provider schema and remains in the
same protobuf package. Java/Kotlin capability types are generated beneath
`Capabilities`; Swift retains the fully qualified generated type names.
Neither SDK maintains a separate circuit capability registry.

A bundle or stage proof can exist before verification. A verification result
or verified value establishes only its documented checks. Persona evidence
verification is followed by live holder authentication and durable replay
acceptance at the presentation boundary. A proof usability window is distinct
from the issuer-signed credential validity interval.
