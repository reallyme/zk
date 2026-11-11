# ReallyMe ZK Artifact Package

This unpublished crate builds and verifies deterministic ZK artifact packages.
It contains release tooling, not a runtime provider, and never invokes Nargo
or Barretenberg.

Each package is rooted at
`artifacts/v1/{hash}/{profile}/{stage}/{manifest-sha256}/` and contains:

- `program.json`: the exact bounded ACIR program consumed by Barretenberg;
- `verification-key.bin`: the exact bounded verification key;
- `vectors/proving-spec-*.pb`: canonical pre-manifest proving-vector protobuf
  files in strict lexical order;
- `manifest.pb`: the canonical `ZkArtifactManifest`, written last as the package
  commit marker.

The builder hashes a normalized, ordered Noir source-file set, the program,
verification key, capability registry, and each path-bound vector file. The
registry input is a typed canonical protobuf generated from the
`reallyme-zk-api` circuit registry. Caller-supplied registry bytes are rejected.
The builder then uses
`reallyme-zk-proto-codec` to seal those values into one canonical manifest
identity. Package generation uses create-new semantics and never overwrites an
existing package. Verification bounds every file before allocation and compares
the complete expected package byte-for-byte. A `.pb` suffix alone is not
sufficient: every supplied vector file must first pass the strict canonical
proving-vector codec. In-memory package payloads read during verification and
owned vector copies are zeroized so synthetic witness bytes do not remain in
ordinary heap buffers.

Release generation should construct bundle vectors through
`CanonicalBundleVectorFile`. That owner accepts only a validated
`BundleProvingVectorInput`, retains canonical protobuf bytes in zeroizing
storage, and yields a short-lived borrowed package file. Package construction
also compares every decoded vector's bundle kind, hash lane, and exact proof suite
with the package coordinates, so a valid vector from another artifact lane
cannot be hashed into the manifest. Compatibility packages remain explicitly
suite-bound; only release-index assembly is restricted to the approved
production suite.

Verification vectors containing proofs cannot be stored in this
manifest-hashed directory: each proof already contains the manifest digest.
The release index pins those vectors instead, avoiding a circular hash dependency.

Release-index assembly checks the package contents as well as metadata. It decodes
all 24 canonical stage manifests and six proof-bearing verification-vector
sets, checks their exact order, toolchain, suite, capability-registry identity,
manifest pins, vector counts, and SHA-256 values, and only then emits canonical
`ZkReleaseIndex` bytes. Both decoded proof owners and the canonical proof-vector
bytes required for persistence are zeroizing and are never exposed through
debug formatting. The index SHA-256 is returned separately for publication or
signing.

`SealedArtifactPackage` and `SealedRelease` validate existing packages.
They reopen canonical manifests from pinned releases, bound all
filesystem reads, recompute program, verification-key, path-bound proving
vector, and post-manifest vector identities, and reject missing, additional,
tampered, oversized, or symlinked entries before returning public metadata.
Release workflows use `check-sealed-release` to run these checks without
modifying the package.

One sealed release is rooted at `artifacts/v1/{release-version}/`. Its six
post-manifest vector sets use paths derived only from closed hash and bundle-kind enums:
`verification-vectors/{hash}/{profile}.pb`. Release creation refuses existing
destinations, syncs every vector payload first, and writes `index.pb` last as
the readiness marker. Verification rejects missing, additional, tampered,
oversized, or symlinked entries and compares the expected release byte-for-byte.
Release versions `.`, `..`, `sha256`, and `poseidon2` are rejected before they
can become filesystem components, preventing collision with package-format and
hash-lane directories.

Promotion is a separate create-new operation. `promote-sealed-release` first
requires `STAGING_ROOT ARTIFACT_ROOT RELEASE_VERSION EXPECTED_INDEX_SHA256`,
admits an exact closed source tree with no unreferenced sibling files or
directories, and matches the canonical index to that independently reviewed
digest before its first destination write. It then copies or exactly revalidates immutable
content-addressed stage packages, creates the release-version directory, and
writes `index.pb` last. File commits use a same-directory synced temporary file
and an atomic hard link, so an existing destination is never replaced. On a
handled failure, promotion removes only the newly created release-version
directory. Immutable content-addressed packages remain available for exact
reuse or inspection.

`quarantine-incomplete-release ARTIFACT_ROOT RELEASE_VERSION` recovers an
incomplete release directory left by interruption or process termination. It
must run only after the promotion process has stopped. It
refuses any release directory containing an `index.pb` entry, including a
symlink or malformed marker, and moves only an uncommitted directory to
`.incomplete-releases/v1/{release-version}/release`. The quarantine slot is
create-new and existing evidence is never replaced. No file is deleted, so an
operator can inspect or archive the preserved partial bytes before deliberately
removing them outside this tool. A fresh promotion can then recreate the
original version directory without reusing uncommitted state.

An interrupted immutable-package copy is recovered with the public
`quarantine_incomplete_artifact_package` API and its exact `ReleaseArtifactPin`.
The function refuses any package containing a `manifest.pb` entry and moves
manifest-less bytes, without deletion or overwrite, under
`.incomplete-artifact-packages/` using the package's typed relative path. A
promotion retry can then recreate the original content-addressed package while
the partial bytes remain available as audit evidence.

`check-release-index-attestation ARTIFACT_ROOT RELEASE_VERSION INDEX_SHA256`
validates a release before signing. It verifies one complete sealed release and
requires the canonical `index.pb` digest to equal the reviewed lowercase SHA-256
argument. The reusable release workflow runs this tool before requesting a
GitHub artifact attestation, so the signed subject transitively binds all
manifest-pinned programs, verification keys, source identities, capability
registries, proving vectors, and proof-bearing verification vectors.

Tool invocation and exact Nargo/Barretenberg version discovery belong in a
separate release-process adapter. This crate accepts only a validated
`ArtifactToolchain`, keeping command execution out of the package integrity
boundary.
