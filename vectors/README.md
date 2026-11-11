# Vectors

This directory documents the positive and negative proof vectors and contains
the non-secret provider-boundary fixture. The sealed-release process generates
and validates cryptographic proof vectors; the provider-boundary fixture
contains no proofs.

Two vector layers avoid circular hash dependencies:

- pre-manifest `ZkProvingVectorSet` protobuf files contain valid synthetic
  proving operations, typed mutation recipes, and deterministic expected proof
  shapes. Stage manifests hash these files before they are sealed;
- post-manifest verification vectors contain concrete proofs carrying the
  sealed manifest identity. They cannot be hashed by that same manifest and
  are instead encoded as canonical `ZkVerificationVectorSet` values and pinned
  by `ZkReleaseIndex`.

Do not place a concrete proof carrying `artifact_manifest_sha256` inside a
manifest-hashed vector set. Doing so creates an impossible circular hash.
ProtoJSON is disabled for proving vector sets because they contain
synthetic witness bytes.

Pre-manifest files are accepted only through the strict
`reallyme-zk-proto-codec::vector` boundary. The codec enforces deterministic
binary encoding, bounded decoding, matching format, bundle kind, hash, and suite,
contiguous numbering, proving-only operations, complete expected shapes, and
typed mutation/error agreement. Mutation execution returns through the same
operation decoder used by runtime adapters; a conformance harness must compare
the resulting domain error or proof shape rather than backend exception text.
Canonical bundle sets derive empty and oversized witness, unsupported
transaction-data, missing-stage, reordered-stage, and cross-circuit-witness
cases from the same valid four-stack base operation. This prevents negative
fixtures from bypassing the exact-witness constructor while still exercising
the untrusted protobuf boundary.
Release-generated bundle vectors enter artifact packages through the
zeroizing `CanonicalBundleVectorFile` owner. Every package rechecks the decoded
vector bundle kind, hash lane, and proof suite against its own typed coordinates;
canonical bytes from another lane are rejected rather than merely rehashed.

Post-manifest sets contain the four ordered `ZkReleaseArtifactPin` values for
their bundle kind and hash lane. Each case begins with a valid concrete verification
operation; a closed `ZkVerificationVectorMutation` produces negative cases.
The release index binds the complete 24-manifest matrix and the digest and
count of every verification-vector set. The index never embeds its own digest.

`reallyme-zk-proto-codec::verification_vector` is the acceptance boundary for
these files. It validates deterministic binary encoding, all four manifest
pins, exact proof identities, verification-only operations, expected response
kind, and mutation/error compatibility. Tampered proof bytes and stale
manifest identities remain structurally valid operations so the conformance
harness can require the injected provider to reject them; malformed inputs and
binding mismatches fail during canonical preflight.

## Provider Boundary Vector

`provider-boundary-v1.vector` is a non-secret fixture for cross-language wire compatibility.
It pins the canonical protobuf bytes for an empty artifact-manifest lookup and
the corresponding typed backend-unavailable response. Rust, TypeScript, Swift,
and Kotlin generate both messages from their bindings and compare the resulting
bytes to this one file. It is not a proof vector and contains no witness, proof,
public input, identifier, or other user-controlled value.

Changes limited to this fixture use focused platform CI. They do not start the
workspace circuit/proof matrix because no circuit, ABI, proof suite, or artifact
is involved.

## Common-credential-root derivation reference

`common-credential-root-v1-derivation.tsv` contains two synthetic relationship contexts
under one synthetic root. It pins the canonical context hash and HKDF-SHA-256
lineage value for each issuer. It is a cryptographic interoperability reference,
not a proof vector or an artifact admission record. Proof artifacts use the
production matrix and sealed-release admission rules above.

`common-credential-root-v1-sha-commitments.tsv` and
`common-credential-root-v1-poseidon2-commitments.tsv` pin the ZK claim transcript for the
same two relationships in each hash lane: the reserved lineage leaf at slot
zero, one selected claim leaf, and their Merkle root. SSI's ordinary claim
commitment uses a different transcript, so an SSI ZK credential profile must
match these bytes explicitly. The vectors contain synthetic claim data and no
issuer key.

## Public-input compatibility lock

`modern-transaction-bound-public-inputs-v1.tsv` preserves the byte length and
SHA-256 of the public inputs emitted for all 20 request-bound v1
circuit fixtures. Public inputs are not witnesses or private material. Keeping
only their digests avoids retaining proving artifacts while providing a
byte-for-byte compatibility reference for the circuit tests.

The lock was generated with the pinned Noir 1.0.0/Barretenberg 6.0.0 pair
after the nonce, audience, and transaction-data fields were bound into every v1
stage. The modern circuit gate recomputes the output length and digest for
every run. A circuit that still proves and verifies but changes its public-input
encoding therefore fails the compatibility check.

## Production Matrix

Every release candidate must include vectors for each production bundle kind:

- `credential_subject_claim_v1`
- `private_persona_claim_v1`

Each bundle kind needs vectors for every production stage:

- `session`
- `credential_envelope`
- `credential_root`
- `claim`

Vectors are backend-specific but contract-compatible. iOS, Android/Kotlin,
WASM, and service providers must all verify the shared vector set for the same
`ZkCircuitRef` and artifact manifest version.

## Required Cases

Each combination of production bundle kind, stage, and hash lane needs:

- valid proofs for each supported disclosure mode,
- invalid proofs with tampered proof bytes,
- invalid proofs with wrong nonce, audience, and transaction-data binding,
- invalid proofs with stale artifact hashes,
- invalid proofs for unsupported circuit identifiers,
- invalid proof bundles with duplicate, missing, and wrong stages,
- invalid proof bundles with mixed hash lanes,
- invalid artifact manifests with bytecode and verification-key digest
  mismatches,
- maximum-size accepted public-input and proof fixtures.

## Release Rule

No provider is production-compatible until it can prove or verify the relevant
positive vectors and reject every negative vector with a typed `ZkErrorReason`.
Provider failures must not expose witness bytes, proof bytes, public inputs,
backend exception text, filesystem paths, or raw artifact contents.
