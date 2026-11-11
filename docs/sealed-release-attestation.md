# Sealed Release Attestation

> Release maintainer reference for artifact validation and signing.

Proof generation and package attestation are separate release operations. The
24-stage proof matrix is generated once through the pinned release-process
adapter and assembled into the canonical 103-file sealed tree. Attestation uses
those same bytes; it must not regenerate proofs when transferring them into CI.

## Candidate Asset

The reviewed sealed tree is transferred as an uncompressed POSIX ustar archive
whose root contains only `v1/`. For release `0.3.0`, the exact asset and
candidate tag are:

```text
reallyme-zk-sealed-release-0.3.0.tar
zk-candidate-v0.3.0
```

Create the archive from the admitted sealed root, not from an intermediate
proof matrix or staging directory:

```sh
tar --format=ustar -cf reallyme-zk-sealed-release-0.3.0.tar \
  -C /absolute/path/to/admitted-sealed-root v1
shasum -a 256 reallyme-zk-sealed-release-0.3.0.tar
```

The candidate GitHub release must target the exact lowercase 40-character
current-main commit and remain a draft or prerelease. Its asset digest and the
canonical `index.pb` digest are reviewed separately before dispatching
`sealed-release-package-attestation.yml`.

Before using this workflow for a release, retain a controlled dry run showing
that the repository-scoped `contents: read` token can read the
private draft release metadata and download the exact asset. A public release
is not an acceptable workaround. If draft visibility or asset download fails
under the workflow token, stop the release until the repository permissions
are corrected and independently reviewed.

## Ingress Boundary

The workflow queries the candidate through the authenticated GitHub Releases
API. It checks the tag, source commit, asset name, and GitHub-reported SHA-256
against the expected values and rejects assets larger than 128 MiB. It hashes
the download again and compares digests using a timing-safe comparison.

The repository-owned ustar reader does not shell out to `tar` or `unzip`. It
accepts only regular files and directories, validates every header checksum,
requires the two-block terminator, rejects nonzero trailing bytes, and bounds:

- archive size to 128 MiB;
- extracted content to 96 MiB;
- each file to 32 MiB; and
- entry count to 512.

Absolute paths, `..`, duplicate paths, links, devices, GNU extensions, PAX
extensions, paths outside the exact release/hash roots, and an existing output
root fail closed. Files are written create-new through `O_NOFOLLOW`, synchronized,
and never replace prior content.

After extraction, the workflow requires exactly 103 files. The Rust
`SealedRelease` validation tool reopens all 103 files,
recomputes every manifest, program, verification-key, proving-vector,
verification-vector, and release-index relationship, and requires the reviewed
canonical index digest. The attestation gate also requires the reviewed modern
toolchain versions, compares the index capability-registry digest with the
current registry, and recomputes each packaged circuit's normalized Noir
source digest from the exact release commit. Only then is the release uploaded
as a same-run Actions artifact.

## Protected Attestation

The producer invokes `sealed-release-attestation.yml` in the same workflow run.
Its validation job runs without signing credentials, downloads the same-run
artifact, and repeats the package, toolchain, registry, and source checks. A
separate job protected by the
`sealed-release-attestation` environment downloads the admitted index, checks
its exact reviewed SHA-256, and issues the Sigstore/SLSA attestation. The
protected job has only read access plus `attestations: write` and
`id-token: write`; it does not compile repository code. It does not publish
packages, mutate the candidate release, promote an
artifact tree, or regenerate the 24-proof matrix. Platform retained-proof and
browser conformance consume the attested index in `reallyme/identity`.

A successful local proof run, archive digest alone, GitHub asset digest alone,
or reusable workflow definition without this reviewed caller is not release
attestation evidence.
