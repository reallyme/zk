# Package distribution

ReallyMe ZK provides Rust protocol contracts, native Swift and Kotlin provider
packages, and an optional JavaScript adapter. Each integration uses the same
circuit registry, proof suites, and artifact identities.

## Package boundaries

The Swift and Kotlin providers live in `packages/swift` and `packages/kotlin`.
They use this repository's schemas, circuit registry, artifacts, and provider
contracts. The optional `packages/bbjs-provider` package adapts the external
Aztec `bb.js` runtime for browsers and Node. It does not define a separate circuit
registry, protobuf message set, proof suite, or operation codec.

Application SDKs live outside this repository: `reallyme-identity`,
`@reallyme/identity`, Swift `ReallyMeIdentity` or `ReallyMe`, and Kotlin/Maven
`me.really:identity`. They can integrate these providers but must preserve the
shared ZK messages, circuit registry, proof suites, artifact formats, and errors.

## Native

Production native proving and verification use linked Barretenberg bindings via
the `backend-bb` lane. The production backend must not invoke `Command::new("bb")`.
Shelling out to the `bb` CLI is reserved for a dev-only circuit-iteration
feature and must not be enabled in shipping SDKs, services, or apps.

## WebAssembly

The Rust `wasm` feature and `wasm32-unknown-unknown` check keep ZK code compatible
with ReallyMe Identity's combined WebAssembly build. This
repository does not expose a `wasm-bindgen` API, produce a `cdylib` or standalone
ReallyMe `.wasm` binary. The optional `packages/bbjs-provider` npm package
loads `@aztec-foundation/bb.js` only when an application enables browser or
Node proving.

`reallyme/identity` owns the single combined WebAssembly module and TypeScript
facade. It decides whether ZK support is included and how it is loaded. When the
provider is absent, ZK operations fail closed with a typed unsupported
error.

The default Identity bundle does not include `bb.js`.
Applications that enable browser proving must install the pinned peer runtime
and provide the cross-origin isolation required for multi-threaded WebAssembly
where that mode is used.

## Mobile

The Swift and Kotlin packages wrap the mobile Barretenberg bindings. They
provide native packaging and example applications while using the shared
protobuf protocol and Rust provider contracts.

Provider selection belongs in platform glue and SDK composition, not Rust cargo
features. Rust crates must not add `swift` or `kotlin` features.

The mobile example bundles a BN254 CRS prefix from the Aztec Ignition ceremony.
The source and packaged prefixes and the G2 point have pinned byte counts and
SHA-256 digests in `circuits/toolchain-lock.json`; packaging verifies the bytes
against those pins. See [CRS provenance](docs/provenance/toolchain-artifact-provenance.md#common-reference-string)
for the ceremony source and distribution hashes.
