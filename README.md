<div align="center">

# ReallyMe ZK

**Zero-knowledge credential proofs for the ReallyMe Identity stack**

[![Rust CI](https://github.com/reallyme/zk/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/zk/actions/workflows/rust-ci.yml)
[![Fuzz](https://github.com/reallyme/zk/actions/workflows/fuzz.yml/badge.svg)](https://github.com/reallyme/zk/actions/workflows/fuzz.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.99-475569)](Cargo.toml)
[![Maven Central](https://img.shields.io/maven-central/v/me.really/zk?label=Maven%20Central)](https://central.sonatype.com/artifact/me.really/zk)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

[Identity](https://github.com/reallyme/identity) · [SSI](https://github.com/reallyme/ssi) · [OpenID4VCI](https://github.com/reallyme/openid4vci) · [OpenID4VP](https://github.com/reallyme/openid4vp) · [Wallet](https://github.com/reallyme/wallet) · **ZK**

</div>

ReallyMe ZK enables credential holders to prove issuer-authenticated claims and
demonstrate their authorization to present them without revealing the
credential’s subject key.

It provides zero-knowledge circuits, typed Rust contracts, artifact validation,
and proof provider interfaces.

> **Looking for the ReallyMe SDK?** Start with
> [ReallyMe Identity](https://github.com/reallyme/identity), the
> application-facing SDK for issuers, verifiers, wallets, and identity-enabled apps.

Use this repository to integrate a provider, implement a verifier, or inspect
the proof contracts.

## Capabilities

| Circuit family | What it proves |
| --- | --- |
| `credential_subject_claim_v1` | A selected issuer-authenticated claim and control of the hidden credential subject key. |
| `private_persona_claim_v1` | A selected issuer-authenticated claim and the subject's authorization of a hidden persona controlled by the presenter. |
| `persona_credential_evidence_v1` | A selected issuer-authenticated claim and current credential status, presented with a fresh signature from a public persona or one-time holder key. |
| `common_credential_root_v1` | Selected claims from two credentials, authorized for one persona, with lineage from the same ReallyMe-assured private root. |

A persona allows a credential holder to present claims without revealing the
subject key associated with the original credential. Private personas keep
their keys hidden, while public personas use reusable keys. Presentations can
also use one-time holder keys to reduce linkability.

These mechanisms improve privacy but do not guarantee anonymity. Disclosed
claims, information known to issuers, and network metadata may still allow
presentations to be linked. Similarly, proving that two credentials share a
common assured root does not necessarily mean their issuers verified the same
individual.

For more information, see the [credential privacy guide](docs/persona-credential-privacy.md)
and [circuit reference](circuits/README.md).

## Quick start: build and test

With the pinned Rust 1.99.0 toolchain, build and test the public Rust contracts:

```sh
cargo test --locked -p reallyme-zk-api -p reallyme-zk-proto -p reallyme-zk-artifacts
```

For proof generation and verification, see the [iOS example](packages/swift/Examples/ReallyMeZKDemo)
and [Android example](packages/kotlin/demo-android). Both use synthetic credential
fixtures and require the pinned native libraries, CRS, and circuit artifacts.
Follow [platform builds](docs/platform-builds.md) to prepare those dependencies.

## Architecture

ReallyMe ZK provides the proof layer in the [ReallyMe stack](https://github.com/reallyme/ssi#architecture).
Arrows show composition, not Cargo dependencies.

```text
                           Applications
                                │
                                ▼
                       ReallyMe Identity
                 application SDKs and composition
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
       OpenID4VCI          OpenID4VP              Wallet
         issuance       presentation/session   state · consent
            │               /       \          lifecycle · audit
            │              /         \
            └─────────────▼           ▼
                          SSI      ReallyMe ZK
                identity and credential   circuits and proof
                      semantics           infrastructure
                       /      \               /
                    JOSE      COSE            /
                       \       │             /
                        └──────┴────────────┘
                               ▼
                        reallyme/crypto
```

Identity provides the application SDKs. SSI owns credential semantics; ZK owns
circuits, proofs, and providers. OpenID4VP binds presentations to requests.

## Noir and Barretenberg

Circuits are written in [Noir](https://github.com/noir-lang/noir), a language
for zero-knowledge proofs. [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/next/barretenberg)
provides UltraHonk proving and verification. Native providers link the backend
directly; the optional JavaScript adapter uses Aztec's `bb.js` runtime.

This release pins **[Noir 1.0.0](https://github.com/noir-lang/noir/releases/tag/v1.0.0)**
and **[Barretenberg 6.0.0](https://github.com/AztecProtocol/aztec-packages/releases/tag/v6.0.0)**.
The configured suite uses a Keccak transcript, zero-knowledge masking, and no
IPA accumulation. SHA-256 and Poseidon2 circuit lanes select the credential
hash independently of that transcript. **SHA-256 is the preferred credential
hash lane** and the mobile SDK default. Poseidon2 remains available for
integrations that explicitly select and validate that lane.

The [toolchain lock](circuits/toolchain-lock.json) pins the build inputs and
their hashes. See [provenance](docs/provenance/toolchain-artifact-provenance.md)
for the upstream sources and CRS.

## Integration

| Package | Purpose |
| --- | --- |
| [`reallyme-zk-api`](crates/api) | Circuit registry, bounded proof owners, typed errors, and injected provider traits. |
| [`reallyme-zk-artifacts`](crates/artifacts) | Bounded artifacts and hash-pinned manifest validation. |
| [`reallyme-zk-proto`](crates/proto) | Canonical schemas and generated messages; untrusted operations require a validated boundary. |
| [Swift](packages/swift) and [Kotlin](packages/kotlin) | Native provider packages over linked Barretenberg bindings. |
| [bb.js provider](packages/bbjs-provider) | Optional browser and Node adapter over an explicitly installed runtime. |

Providers are injected explicitly. Missing providers, unsupported circuits,
suite mismatches, and incompatible artifacts fail closed with typed errors.
The backend, strict protobuf codec, and release tooling are unpublished Rust
crates. Generated protobuf decoding alone does not validate provider requests.

### Verification and OpenID4VP

Credential acceptance requires issuer-signed validity and current status as
well as proof verification. Four-proof presentation evidence has a distinct
result and statement type; it cannot produce a `ZkVerifiedClaimStatement`.

A request-bound claim bundle has four linked stages:

```text
session → credential envelope → credential root → selected claim
```

| Verification path | Checks |
| --- | --- |
| `verify_presentation_bound_claim_bundle_with` | Four claim proofs, issuer signatures under a caller-trusted key, presentation expiry, and session bindings. Does not check credential validity dates or current status. |
| `verify_status_qualified_claim_proof_bundle_with` | The four claim proofs plus issuer-signed validity and a fifth status proof against an authenticated current feed. |
| Persona credential evidence | Five proofs, current issuer status, and a live holder signature. |
| Common-credential-root | Nine proofs, their joins, trusted issuers, root assurance, and current status. |

The [OpenID4VP adapter](docs/openid4vp-presentation-binding.md) maps verified
requests to nonce, audience, and transaction-data bindings and applies claim
policy. Multiple accepted bundles remain independent claims unless Identity
checks their shared persona. Proofs bind the nonce, audience, transaction data,
and presentation expiry to the active request, preventing reuse under different
bindings. Single-use acceptance additionally requires the verifier to atomically
consume its session in durable state before granting access. Status verification
does not consume a session. The decode-only Digital Credentials API runtime
does not authorize responses.

See the [0.3.0 integration migration guide](docs/verification-migration-0.3.0.md)
for Rust, Swift, and Kotlin API names and acceptance requirements.

## Compatibility

ReallyMe ZK is pre-1.0. The public Rust crates share one version. Circuit
semantics, protobuf contracts, artifact identities, and conformance vectors
form one compatibility set.

Use matching circuit artifacts and provider versions. A circuit listed in the
API is not necessarily supported by every provider. See
[provider compatibility](PROVIDER_POLICY.md) for supported suites and required
verification checks.

## Security

**Audit status:** Not independently audited.

Repository-owned witness buffers use zeroizing owners. Noir, Barretenberg,
and managed runtimes can retain additional copies outside that guarantee.
See the [memory model](docs/security-memory-model.md) for ownership boundaries
and deployment controls. Report vulnerabilities privately under
[SECURITY.md](SECURITY.md).

## Documentation

- [Circuit inventory](circuits/README.md) and [API reference](crates/api/README.md)
- [Credential privacy](docs/persona-credential-privacy.md) and [common-root presentations](docs/common-credential-root-persona-presentations.md)
- [Common-root proof contract](docs/common-credential-root-v1-proof-contract.md)
- [OpenID4VP binding](docs/openid4vp-presentation-binding.md) and [stack integration](docs/open-stack-integration.md)
- [Protobuf](docs/protobuf.md), [platform ABI](docs/platform-binding-contract.md), and [package distribution](PACKAGING.md)
- [Conformance](conformance/README.md) and [fuzzing](fuzz/README.md)
- Maintainers: [Rust publishing](docs/rust-publishing.md) and [release attestation](docs/sealed-release-attestation.md)

## Contributing

See [contribution guidance](CONTRIBUTING.md) for checks and compatibility requirements.
Report security issues privately through [SECURITY.md](SECURITY.md).

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party components retain their own licenses and notices.

## Copyright and Trademarks

Copyright © 2026 by ReallyMe Technologies Limited.

ReallyMe® is a registered trademark of ReallyMe Technologies Limited.
