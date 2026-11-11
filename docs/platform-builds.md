# Platform builds and fixtures

Build the native Swift and Android providers with the pinned Barretenberg
libraries and the scripts in this guide. The
[platform binding contract](platform-binding-contract.md) defines the ABI,
ownership, artifact validation, and provider requirements.
The paths below are defaults. The build scripts accept
`REALLYME_ZK_LOCAL_ARTIFACT_ROOT` to select another output root.

## Apple native package

`scripts/build_apple_platform_ffi_xcframework.sh` builds arm64 iOS,
iOS-simulator, and macOS static slices. It requires the caller-supplied,
toolchain-pinned Barretenberg archive directories and packages the platform
ABI header with a Clang module map. The output is:

```text
build/native/apple-platform-ffi/ReallyMeZKPlatformFFI.xcframework
```

The root Swift package provides `ReallyMeZKKit` and
`ReallyMeZKPlatformNative`. The latter supplies the C bridge and links the
XCFramework as a binary target. The example app and its hosted tests link one
dynamic `ReallyMeZKDemoBundle` so overlapping Swift and generated Protobuf
modules load from one image.

The XCFramework has an arm64 simulator slice. Select an arm64
simulator or set `ARCHS=arm64` for a generic iOS Simulator build. Xcode can
still compile Swift package targets for x86_64 on a generic destination;
those targets cannot link the arm64-only binary. The Xcode example has no
development team, provisioning profile, or signing identity. Device builds
use the consumer's signing configuration.

## Android native package

`scripts/build_android_barretenberg_static_archive.sh` builds the Android
arm64 Barretenberg archive from the pinned Aztec packages 6.0.0 source with
the pinned Android NDK, CMake, Ninja, generated protocol constants, and
dependency revisions. It rejects a non-Android libc++ ABI namespace and
requires the final archive and its separately built libdeflate companion to
match the hashes in `circuits/toolchain-lock.json`.

`scripts/build_android_platform_ffi_static.sh` builds the Android arm64
static library and header, with metadata recording the mobile Cargo profile:

```text
build/native/android-platform-ffi/arm64-v8a
```

`scripts/build_android_platform_jni.sh` links that library into:

```text
build/native/android-platform-jni/arm64-v8a/libreallyme_zk_platform_jni.so
```

The JNI build copies `libc++_shared.so` and applies
`packages/kotlin/native/jni/reallyme_zk_platform_jni.map`. Kotlin's Android
library module packages the JNI libraries into an AAR; the example app
depends on that module.

The default Android package uses the production `native` build. To exercise
the opt-in `claim_bundle_4` source diagnostic, build its native library with
`scripts/build-android-claim-bundle4-diagnostic-native.sh` and the locked
Android Barretenberg archive directory in `ANDROID_ARM64_BB_LIB_DIR`.
Then select `-PreallymeZkAndroidNativePackageMode=diagnostic-exact-source`
in Gradle. Diagnostic outputs are kept separate:

```text
build/native/android-platform-ffi-diagnostic
build/native/android-platform-jni-diagnostic
```

The build scripts reject a diagnostic library in the production output. The
diagnostic Gradle mode checks its build metadata and bytes; it does not
change the production package hash or admit `claim_bundle_4` as a
production stage.

## Build provenance

XCFramework and JNI files are generated build outputs. The Apple
package records hashes for the Rust source files and each binary slice, and rejects a stale
XCFramework. Both native builds remap build-host Rust paths before packaging
and reject outputs that retain the builder's home path. The Android JNI build
records the Rust/JNI source closure and
binary hashes; the Android library checks that metadata before assembling
the AAR. A binary hash alone cannot reveal a source change after the binary
was built.

Before publishing, test installation from an external project and run device
proof tests against the distributed native binaries.

## Runtime distribution

Public runtime artifacts use `https://static.reallyme.net/zk/`. The R2 bucket
is named `static`; its object keys start with `zk/`. The Swift binary target
uses a checksum-pinned ZIP from this host. GitHub release assets may mirror
that ZIP.

The object layout is:

```text
zk/swift/<sha256>/ReallyMeZKPlatformFFI.xcframework.zip
zk/circuits/<sha256>/mobile-circuits.tar
zk/cli/macos-arm64/<sha256>/reallyme-zk
zk/crs/<sha256>/bn254_g1.prover
zk/crs/<sha256>/bn254_g1.dat
zk/crs/<sha256>/bn254_g2.dat
```

Each hash directory contains one complete SHA-256 digest. The three CRS files
have independent identities and need no per-SDK duplicates. Keep this
hierarchy and never overwrite released bytes.

### Maven Central

Add `mavenCentral()` to your Gradle dependency repositories. Declare
`implementation("me.really:zk:0.3.1")` for Kotlin/JVM or
`implementation("me.really:zk-android:0.3.1")` for Android. The Android
artifact includes the Kotlin API as a dependency. The JVM and Android
publications resolve their protobuf modules from Maven Central at the same
version.

To prepare a release for manual upload, build the local Android provider and
run `./scripts/maven-central-bundle.local.sh --unsigned` from the repository
root. This step uses the installed Android SDK and the pinned NDK.

Load `MAVEN_SIGNING_KEY_ID` and `MAVEN_SIGNING_PASSWORD` for the ReallyMe
GPG signing key and sign the prepared files:

```sh
./scripts/maven-central-bundle.local.sh
```

The signing step verifies the prepared files and writes
`build/maven/out/reallyme-maven-central-0.3.1.zip` for manual
upload in the Central Portal.

### Local output layout and R2 upload

Generated outputs have one layout under `build/`:

| Directory | Contents |
| --- | --- |
| `build/r2/` | Exact R2 object tree, with `zk/` at its root |
| `build/maven/` | Maven publication staging and signed release bundles |
| `build/native/` | Native build inputs, libraries, and extracted runtime resources |
| `build/swift/` | Swift build metadata and checksum used by release verification |
| `build/cli/` | CLI build metadata |

`scripts/release-artifact-manifest.mjs` defines the runtime artifact identities
and resolves their canonical paths. Builds and downloads place distribution
files directly in `build/r2/zk/{swift,circuits,cli,crs}/`. The mirror includes the
Swift archives required by published SDK versions.

Verify the complete inventory and remove obsolete local keys or stray files:

```sh
node scripts/release-artifact-cache.mjs --stage-upload --distribution-only
```

The command validates every required payload before removing extra entries.
`build/r2/` contains only bucket objects. Upload its contents into the root of
bucket `static`, retaining the `zk/` prefix. When the dashboard is open at
`static / zk`, the corresponding local directory is `build/r2/zk/`.
For a Swift-only update, upload the single newly pinned ZIP under
`build/r2/zk/swift/<sha256>/`. Existing circuit, CLI, CRS, and published Swift
objects retain their bytes and keys.

Check the mirror without changing it:

```sh
node scripts/release-artifact-cache.mjs --check --distribution-only
```

Set `Content-Type` to `application/zip` for ZIP archives, `application/x-tar`
for circuit archives, and `application/octet-stream` for other payloads. Immutable successful responses
use `Cache-Control: public, max-age=31536000, immutable`. Configure the custom
domain's cache rule to cover every artifact extension and allow cross-origin
`GET` and `HEAD` for browser consumers. Preserve byte-range requests for binary
downloads.

In the `reallyme.net` zone, create a Cloudflare Cache Rule with this expression:

```text
(http.host eq "static.reallyme.net" and starts_with(http.request.uri.path, "/zk/"))
```

Use these settings:

| Setting | Value |
| --- | --- |
| Cache eligibility | Eligible for cache |
| Edge TTL | Ignore cache-control header and use a TTL of one year |
| Status code TTL: 200–299 | One year |
| Status code TTL: 300–599 | Do not store |
| Browser TTL | Respect origin |

The edge override also covers uploads that lack HTTP cache metadata. Set the
object metadata from the manifest to enable the intended browser caching.
Publish changed content under a new hash so cached URLs always identify the
same bytes.

R2 Standard includes a monthly Class B allowance. Edge cache hits avoid R2
reads; cache misses can consume that allowance or incur read charges. R2
egress is free for both cases. A long TTL controls freshness, not retention:
Cloudflare can evict an object early and fetch it from R2 on a later request.
Smart Tiered Cache can reduce those origin reads across edge locations.
See Cloudflare's [Cache Rule settings](https://developers.cloudflare.com/cache/how-to/cache-rules/settings/),
[R2 cache integration](https://developers.cloudflare.com/cache/interaction-cloudflare-products/r2/),
[cache retention](https://developers.cloudflare.com/cache/concepts/retention-vs-freshness/),
and [R2 pricing](https://developers.cloudflare.com/r2/pricing/).

Check repeated full `GET` requests for `CF-Cache-Status: HIT`. A first request
at an edge location can report `MISS`; `DYNAMIC` means the response is not
being admitted to cache. Browser refresh controls and request cache directives
can affect this check, so use ordinary requests without cache-busting queries.

Public URL verification is an optional diagnostic after uploading:

```sh
node scripts/release-artifact-cache.mjs --verify-remote --distribution-only
```

CI can retrieve its pinned circuit and CRS inputs directly from the R2 S3 API
without depending on the public hostname's browser challenge settings. Use R2
credentials with **Object Read Only** permission scoped to the `static` bucket.
Store the following values as GitHub Actions repository secrets:

| Secret | Value |
| --- | --- |
| `R2_ENDPOINT` | The bucket's S3 API endpoint from the R2 dashboard |
| `R2_ACCESS_KEY_ID` | The R2 access key ID |
| `R2_SECRET_ACCESS_KEY` | The matching secret access key |

The copied endpoint may include the `/static` bucket suffix; the downloader
normalizes it before passing the bucket separately to the AWS CLI.

Pass those secrets only to the download step, set
`REALLYME_ZK_ARTIFACT_TRANSPORT=r2`, and run:

```sh
node scripts/release-artifact-cache.mjs --hydrate --mobile-only
```

This transport reads objects under `zk/` in the `static` bucket. It requires
AWS CLI v2 and uses region `auto`. Optional temporary credentials also accept
`R2_SESSION_TOKEN`. Credentials are never command arguments or log output.
Downloaded files must match the same pinned SHA-256 digests before admission;
an R2 error does not fall back to anonymous downloads. The default transport
remains the public static hostname for local use.
See Cloudflare's [R2 authentication](https://developers.cloudflare.com/r2/api/tokens/)
and [AWS CLI configuration](https://developers.cloudflare.com/r2/examples/aws/aws-cli/).

The published circuit archive contains the sealed runtime index, manifests,
compiled programs, verification keys, and source lock. It contains no proving
vectors or witness inputs. Public CRS files are separate, hash-pinned objects.
Raw static libraries, unpacked frameworks, JNI staging files, demo inputs,
private witnesses, and build directories are not upload objects.

The browser provider is the optional `@reallyme/zk-bbjs-provider` JavaScript
adapter, which loads `@aztec-foundation/bb.js` lazily. This repository currently
ships no separate ReallyMe WASM binary in the static artifact inventory.

## Poseidon2 fixture parity

Poseidon2 circuit fixtures use Noir's byte-bounded encoding. Each input
byte becomes a BN254 field element in the `0..255` range. The declared
length is passed to the vendored `Poseidon2::hash(fields, len)` API; the
sponge derives its IV from that length. The output field element is encoded
as 32 big-endian bytes.

The `poseidon2-bounded-fixture` binary calls the pinned Noir/ACIR
permutation to regenerate reference fixtures. It is not the
production off-circuit hashing API. That API belongs to the published
`reallyme-crypto-poseidon2` crate with fixed parameters and
cross-repository vectors. `scripts/check-poseidon2-crypto-contract.sh`
pins version `0.3.17`, runs its `hash_bytes` implementation, and
compares reviewed vectors with those reference fixtures. This repository owns
the in-circuit constraints and Barretenberg proving boundary.

## Public mobile artifact validation

Mobile circuit packs contain programs, verification keys, manifests, source
locks and a release index. They exclude private proof-bearing test vectors.
`check-mobile-runtime` validates their canonical capability registry, pinned
contents and exact file tree. Asset staging runs this check before copying
resources into either example app.

`check-sealed-release` remains the complete release check and requires its
verification vectors. Runtime integrity validation does not replace proof
verification or complete release validation.
