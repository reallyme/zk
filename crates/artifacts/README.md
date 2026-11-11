# Artifacts

This crate validates artifact manifests and their hash-pinned contents for ZK
providers.

Each manifest binds:

- a production `ZkClaimProofBundleKind`,
- a production `ZkClaimProofBundleStage`,
- an exact source `ZkCircuitRef`,
- the exact `ZkProofSuite`,
- ACIR bytecode hash,
- verification-key hash,
- capability-registry hash,
- positive and negative vector-set hashes.

Changes to circuit source, artifact hashes, and capability semantics must be
committed together.

Manifest construction retains any closed `ZkProofSuite` represented by the API,
so compatibility packages cannot be confused with production packages. Sealed
production release indexes still require `ZkProofSuite::PRODUCTION`:
Barretenberg UltraHonk, Keccak transcript, zero-knowledge enabled, and IPA
accumulation disabled. A provider must advertise the manifest's identical suite
before artifact bytes can reach proving or verification. Unknown and
unspecified suite values return `UnsupportedProofSuite`; the provider must not
fall back to another suite or infer one from backend settings.

`ArtifactManifestPin` keeps the selected suite and the canonical manifest
SHA-256 together. For protobuf-delivered manifests, the hash covers the exact
deterministic binary encoding before fields move into domain owners. Static
package manifests must ship the same precomputed value. Proof verification
compares this identity with the resolved stage manifest before backend use.

Release tooling constructs a `ProductionArtifactManifestDraft`, then passes it
to `reallyme-zk-proto-codec::artifact::seal_artifact_manifest`. The sealing
boundary produces the canonical protobuf owner and the runtime domain manifest
together, after computing their shared SHA-256 identity. The public manifest
constructors check structure and capability consistency; they do not establish
the provenance of caller-supplied hashes or bytes. Runtime providers must load
artifacts through sealed package validation and compare the reviewed
manifest identity before accepting a proof or preparing a proving key.

Adapters handle fetching, caching, and package-specific resource loading.
iOS, Kotlin/Android, WebAssembly, and service providers use the same manifest
checks before proving or verifying.

`ArtifactKind` defines independent ACIR bytecode and verification-key limits.
Adapters validate declared lengths before allocation, return only bounded
`ArtifactBytes`, and promote those bytes to `VerifiedArtifactBytes` only after
the manifest-pinned SHA-256 digest succeeds. Debug output reports kind and
length but never raw artifact payloads.

`ArtifactPackageLayout` is the single owner of the versioned, content-addressed
on-disk package coordinates used by both release tooling and runtime adapters.
Paths are derived only from the closed hash-strategy, bundle-kind, and
production-stage enums plus the canonical manifest SHA-256. Multiple releases
can therefore retain different immutable packages for the same semantic stage.
Release code must not maintain a parallel layout registry, and runtime code
must not accept caller-supplied package-relative paths.
