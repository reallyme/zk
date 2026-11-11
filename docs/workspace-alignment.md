# Architecture and package ownership

`reallyme/zk` provides the zero-knowledge contracts and providers used by the
ReallyMe Identity stack. Circuits, artifact manifests, semantic capabilities,
provider traits, proof bundles, protobuf schemas, and backend adapters are
versioned together. Identity, OpenID, wallet, and SDK users link a proving
stack only when they enable ZK support.

## Ownership Boundary

`reallyme/identity` provides the application SDK packages:

- crates.io: `reallyme-identity`
- npm: `@reallyme/identity`
- Swift package/product: `ReallyMeIdentity` or `ReallyMe`
- Kotlin/Maven: `me.really:identity`

This repository must not publish those packages or define their FFI, JNI,
wasm-bindgen, or TypeScript API. It exposes typed Rust provider
contracts, generated Buffa models, and first-party Swift and Kotlin provider
packages. These adapt the ZK protocol for each platform; Identity provides the
application-facing identity APIs.

## Layering

The shared Rust API for the stack is `reallyme-zk-api`. Identity
policy, OpenID4VP formats and verifier code, and wallet presentation flows may
use that crate for circuit identifiers, capabilities, typed errors, and
injected prover/verifier traits.

Those layers must not depend on `reallyme-zk-backend-bb`, Barretenberg, ACIR,
Nargo, artifact caches, packaging code, or generated transport models.
Identity, the application, or the verifier service injects the concrete provider.

## Proto, JSON, Connect, And Buffa

Protobuf is the durable ZK provider and artifact contract. Buf owns linting and
generation. Buffa-generated Rust models and views are the preferred native
message boundary for manifests, provider services, fixtures, and adapter tests.

The separate service schema is transport-neutral. Connect-generated runtimes
remain outside this repository and translate generated protobuf messages into
`reallyme-zk-api` or `reallyme-zk-artifacts` domain types before calling core
logic. JSON must pass through the sealed, bounded Buffa ProtoJSON codec. Do not
create a second hand-maintained JSON schema for the same ZK messages.

## Compression

Large protobuf or JSON payloads must use the shared identity compression API
(`reallyme-compression-brotli` / `reallyme::compression::brotli`) at the
transport or envelope layer, with bounded decompression and typed errors.

## Runtime Packaging

Rust backend features select runtimes such as `native`, `wasm`,
and `dev-cli`. Rust crates must not add cargo features named `swift` or
`kotlin`; platform provider selection belongs in the Swift and Kotlin package
packages and in the SDK integration layer.

Production native proving and verification require an injected linked-library
Barretenberg binding. This repository supplies the adapter contract and owns
first-party Swift and Kotlin provider packages over reviewed mobile bindings.
The `bb` CLI is used only by release tooling and local circuit-iteration
scripts.

The Rust `wasm` feature supports ReallyMe Identity's combined WebAssembly build.
It does not create a separate package: this repository must
not expose `wasm-bindgen` or produce a Rust `cdylib` or standalone `.wasm`
binary. The exception is the optional `packages/bbjs-provider` adapter, which
does not compile ReallyMe Rust to WebAssembly and does not bundle Barretenberg;
it validates and lazy-loads the external Aztec `bb.js` runtime for applications
that explicitly enable browser or Node proving. Identity owns the single
application-facing WebAssembly module, TypeScript API, optional features, and
loading policy.

## Single-Binary Rule

A consumer app should include one ReallyMe native binary or one ReallyMe WASM
module at the highest layer it uses. `identity` composes identity, OpenID4VCI,
OpenID4VP, wallet, crypto, JOSE/COSE, and optional ZK support through Cargo and
package dependencies. Lower-layer ZK code must cross the boundary as owned bytes
and typed results, never shared handles or shared runtime memory.
