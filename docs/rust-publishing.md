# Rust Publishing

> Release maintainer reference for crates.io publication.

The approved public Rust crates cover contracts, artifact validation, strict
protobuf conversion, and the injectable Barretenberg backend. Witness execution
and the platform ABI implementation remain private native implementation crates.
Conformance harnesses, release assembly, and external-tool runners also remain
unpublished. Publishing the backend does not enable it by default or make it an
identity or policy dependency.

## Public crates

The crates.io package set contains exactly five crates, in publication order:

| Package | Public role |
| --- | --- |
| `reallyme-zk-api` | Proof-system-independent circuit semantics, capabilities, typed proof owners, and injected prover/verifier traits. |
| `reallyme-zk-artifacts` | Bounded artifact owners and hash-pinned manifest validation over `reallyme-zk-api`. |
| `reallyme-zk-proto` | Canonical versioned protobuf schema and hardened generated Rust message bindings. |
| `reallyme-zk-proto-codec` | Strict validation and conversion between protobuf and domain contracts. |
| `reallyme-zk-backend-bb` | Injectable backend contract and optional linked native Barretenberg implementation. |

`reallyme-zk-proto` is a schema and generated-message package. Its generic
decode methods do not validate executable provider operations. The bounded
validator is in the published
`reallyme-zk-proto-codec` crate; external consumers need an equivalent
reviewed validator before dispatching untrusted operations.

`reallyme-zk-api` and `reallyme-zk-proto` are independent leaf packages.
`reallyme-zk-artifacts` is released only after the matching
`reallyme-zk-api` version is visible from crates.io. All five approved packages
now share version `0.3.2`, including the codec's optional SSI `0.6.2` stack-error
adapter. Automated preflight and release require all five manifests to agree.

## Public API compatibility policy

The serialized protobuf wire contract is the stable cross-language boundary.
Generated Rust message structs and enums are public only so consumers can
encode and decode that contract; their concrete field layout is not an
extension point. Adding a protobuf field or enum value can make generated Rust
matching non-exhaustive in practice, so such a change requires an explicit
lockstep version decision and may not be released as an unnoticed patch.

Every version change is checked against the latest non-yanked crates.io
release with pinned `cargo-semver-checks`. A reported breaking change blocks
the release unless the public crate set receives the corresponding semver
version change and the change is recorded in `CHANGELOG.md`. Hand-written
domain types expose constructors and accessors as their supported boundary;
consumers must not rely on generated implementation details.

Each public manifest uses an include allowlist, carries its README, inherits the
workspace's dual-license declaration, declares a compatible version for
every local path dependency, and packages the source material needed to audit
its contract. `reallyme-zk-proto` owns the canonical schema set under
`proto/reallyme/zk/v1`: `capabilities.proto`, `manifest.proto` and
`zk_service.proto`. The manifest imports the shared capability contract; the
repository root does not retain a second schema copy.

## Unpublished crates

The following crates retain `publish = false`:

- `reallyme-zk-noir-witness-core`: pinned Noir ABI, artifact parsing, and ACVM
  witness execution. Its upstream compiler dependencies are not on crates.io.
- `reallyme-zk-platform-ffi`: native ABI composition; the `native` feature enables
  its optional witness-core and backend dependencies. Without that feature,
  native operations return typed unsupported results.
- `reallyme-zk-conformance`: repository and provider certification tooling.
- `reallyme-zk-artifact-package`: sealed-release construction and promotion
  tooling rather than an application dependency.
- `reallyme-zk-release-process` and `reallyme-zk-release-assembly`: pinned
  Nargo/Barretenberg execution and release orchestration.

Swift and Kotlin packages have separate builds and tests. The Android example
is an application, not an AAR release. ZK's `wasm`
feature is checked for downstream composition but does not create a
standalone ReallyMe WebAssembly package. The optional `packages/bbjs-provider`
package is a JavaScript adapter around the external Aztec `bb.js` runtime, not
a Rust package or a default SDK dependency. Publishing a Rust
contract crate does not authorize platform-provider publication. The pinned
Noir 1.0.0 and Barretenberg 6.0.0 toolchain has passed its compatibility tests.
Swift and Kotlin packages require their own conformance tests and publication
approval.
Android CI reuses the pinned Barretenberg and libdeflate archives from a GitHub
build cache keyed by the toolchain lock and upstream build scripts. Every
restored pair must match the reviewed byte counts and SHA-256 digests. A cache
miss builds those upstream libraries once from the pinned source; no Cloudflare
upload is required. Relevant source changes still build and test the current
Rust platform FFI and JNI package. The Android job also checks the source
workspace without native Barretenberg.

Repository development, package preflight, and publication use the pinned Rust
1.99.0 toolchain. The public manifests declare `rust-version = "1.99"`. A
separate CI job checks exactly the five approved public crates at that minimum
supported version.

## Inspection And Release Order

The package inspector derives the publication order from Cargo
metadata and fails on an external path dependency, stale local version,
dependency cycle, missing include allowlist, or package-construction
failure:

```sh
node scripts/publish-crates-in-order.mjs inspect --allow-dirty
```

Ordinary CI runs the same inspection without `--allow-dirty`. Inspection may
read the crates.io index and fetch locked dependencies; it compiles extracted
archives offline and performs credential-free publication dry-runs without
uploading packages. The explicit package preflight validates the current `main`
commit and all five public manifest versions, scans Git history, audits locked
dependencies, checks the public protobuf baseline and Rust API compatibility,
and compiles normalized crate archives with all features. It runs bounded
crates.io dry-runs and attests the exact package bytes:

```sh
node scripts/publish-crates-in-order.mjs preflight
```

Package preflight runs independently of Rust CI, protobuf CI, and fuzzing.
It does not wait for those workflows or require their run IDs. Source tests,
security mutations, mobile validation, and circuit checks remain in Rust CI;
manual Rust CI selects every validation lane and runs one production proof pass.
Fuzz smoke runs cover Rust and fuzz inputs and the existing native SDK
qualification inputs. Scheduled and manually dispatched fuzz campaigns retain
their longer runs.

During a first release, an expected lookup failure is accepted only when the
missing package is an earlier crate in the derived release order. No upload
occurs in inspect or preflight mode. Each Cargo command has a fixed five-minute
execution ceiling so registry availability cannot stall the workflow
indefinitely.

Before package inspection, preflight queries the crates.io API for every public
crate. Only an HTTP 404 is classified as first publication; timeouts, transport
errors, non-404 failures, and malformed registry responses block the release.
Once a crate has a published version, the requested version may not regress and
every version advance runs pinned `cargo-semver-checks` 0.50.0 against the exact
latest non-yanked release with all features. A same-version result is accepted
only when recovering a partial publication: the credentialed publisher downloads
that published archive and requires byte-identical SHA-256 before continuing.

Credentialed publication uses the same dependency order:

```sh
node scripts/publish-crates-in-order.mjs publish
```

Run this command only in the release workflow for an attested commit at the
current tip of `main`, after the exact-version
package preflight succeeds. Newly published dependencies are retried only for
bounded crates.io index propagation; all other failures stop the release.

In GitHub Actions, run **Crates Package Preflight** first. The version field is
prefilled with the current public Rust release version and checked against all
five crate manifests.
The workflow binds that version to the current `main` commit, scans complete Git
history, audits every tracked lockfile, runs the pinned release-readiness
repository policy gate, and produces the
normalized crate archives without registry credentials. It uploads the exact
archives plus a manifest containing each filename, size, and SHA-256 digest.
GitHub artifact attestations cryptographically bind both the manifest and the
archives to the preflight workflow and source commit.

Then run **Crates.io Release** from that same current `main` commit. Before any
credentialed work, the release workflow verifies the GitHub provenance, exact
first-attempt preflight run, current `main` identity, manifest, and all five
reviewed archives. After approval in the protected `crates-io` environment, it
creates or verifies the immutable `reallyme-zk-v<version>` tag and a draft
GitHub release. The protected publication job reverifies the reviewed bytes before requesting the
`CARGO_REGISTRY_TOKEN`; each just-created Cargo archive must be byte-identical
to the reviewed preflight archive before it can be uploaded. Normalized crate
compilation and dry-run publication remain the responsibility of the
credential-free preflight and are not repeated with the token in scope.

Publication maintains an atomic machine-readable ledger across retries and
recovery from partial publication. After every successful upload—or byte-identical
already-published result—the workflow downloads the crates.io archive and
verifies its SHA-256. Only after all crates are verified does the final job
attach the reviewed archives, preflight manifest, and publication ledger to the
draft release and make it public.

Keep `main` at the certified source commit until publication and finalization
finish. The release jobs recheck current-main identity; moving it during a
partial publication prevents the existing recovery path from resuming.

## Deployment Prerequisites

Workflow source alone cannot confirm that GitHub environments are protected.
Before a release is authorized, an authenticated settings audit must confirm
that both `crates-io` and `sealed-release-attestation`:

- allow deployments only from the protected `main` branch;
- require an independent reviewer and prevent self-approval;
- expose publication or signing credentials only as environment secrets; and
- do not grant those secrets to the unprotected evidence-verification jobs.

The release record must retain the environment API response and a controlled
unauthorized `workflow_dispatch` run showing that the protected job remains in
the waiting state and receives no secret. Missing or unverifiable settings are
a release blocker. The workflow definition cannot substitute for checking the
deployed settings.

The same authenticated settings audit must record the crates.io owner set,
multi-factor-authentication policy, and the publishing credential's scope. A
single-person owner set or a long-lived token without independently reviewed
rotation and recovery controls blocks publication. Existing package identities
require Trusted Publishing. Initial publication requires the protected
environment, a short-lived release window, and a retained credential audit;
those controls alone do not establish registry-account security.

Rust CI checks the pinned Noir and Barretenberg pair using archive and
executable hashes from `circuits/toolchain-lock.json`, a hash-checked full-prover
CRS, the 20-circuit request-bound proving matrix, the fourteen common-credential-root
stage circuits and their nine-proof composition, the twelve persona-credential-evidence
stage circuits, and the soundness-regression
fixtures. It also checks advisory ancestry against the pinned Noir source
revision. This evidence supports the lock's `promoted` status, but promotion
does not authorize package publication.


## Continuous integration coverage

Rust CI has separate source-policy, normalized-package, semver, security-mutation,
and workspace-test jobs. The workspace matrix runs default, native, and all-feature
configurations with the same locked, bounded nextest runner. The required Rust
check fails if any selected matrix lane or validation job fails or is skipped.
Deliberately excluded platform and circuit jobs may be skipped only when the
changed-file classifier excludes them; manual release qualification selects all
jobs. Shared Rust, circuit, registry, fixture, toolchain and workflow changes
select full coverage. CI evidence and lane-selection policy changes retain
source validation without rebuilding unchanged native providers or proofs;
manual release qualification still selects every lane. Provider
vector tests run in this matrix rather than rebuilding them in another workflow.

Protobuf CI owns schema linting, the pinned wire descriptor, and generated Rust,
Swift, and Kotlin freshness. Fuzz CI compiles its complete target set once, executes
every target against the committed corpus on affected pull requests and pushes,
and reuses those executables in five-minute scheduled target jobs. Production and
fuzz dependency graphs have separate strict, locked audits. Mutation checks require
a nonempty target selection and isolate build directories between workers.

Manual release-qualification runs are not cancelled by unrelated pushes. Package
preflight validates and attests the exact package sources; the credentialed publisher
consumes the attested archives and verifies uploaded registry bytes without
repeating the workspace tests. Noir soundness, linked proving, cross-verification,
mobile targets, and SDK packages remain additional ZK-specific gates.


## Manual 0.3.2 publication

All five public Rust packages are prepared at `0.3.2`. From the clean commit,
publish in this order and wait for each version to become visible in the registry
before continuing:

```sh
cargo publish --locked --registry crates-io -p reallyme-zk-api
cargo publish --locked --registry crates-io -p reallyme-zk-artifacts
cargo publish --locked --registry crates-io -p reallyme-zk-proto
cargo publish --locked --registry crates-io -p reallyme-zk-proto-codec
cargo publish --locked --registry crates-io -p reallyme-zk-backend-bb
```

Cargo verifies each package before uploading. Backend's integration-test codec
dependency requires codec to be visible in the registry. Its private
witness test harness is omitted from the published manifest. Native package
validation additionally uses `--all-features` and the already approved library
specified by `REALLYME_BARRETENBERG_LIB_DIR`; no upstream library rebuild is
required.

## Public and native dependency boundary

The publishable API, artifacts, proto, codec, and backend packages do not depend
on witness-core or platform-ffi at runtime or build time, including optional
features. Backend integration tests may use private workspace crates as
versionless development dependencies; Cargo removes those dependencies from
the registry manifest. Package checks compile the extracted archives with all
features and admit the backend's bundled toolchain lock before native linking.
No native libraries or circuit binaries are included in these crate archives.
