# reallyme-zk-api

`reallyme-zk-api` provides shared Rust types and traits for working with
ReallyMe ZK proofs without linking a proving or verification backend.

Identity, OpenID4VP, wallet, policy, SDK, and service crates use it to identify
ZK presentations, inspect what they prove, hold bounded proof bytes, and call
injected providers without depending on Noir, Barretenberg, protobuf codecs,
FFI bindings, or platform packages.

> **Pre-1.0:** this crate contains no proving backend. Check your provider's
> supported circuits, artifacts, and platform versions before using it.

## Public API organization

Public types retain their descriptive names and are imported from domain modules:

| Module | Responsibility |
| --- | --- |
| `circuits` | Circuit identifiers, families, source stages, revisions and credential hash algorithms |
| `capabilities` | Subject/persona binding, disclosure modes, predicates and semantic guarantees |
| `proofs` | Proof bytes, secret witnesses, public inputs, session bindings and proof suites |
| `claim_bundle` | Four-stage claim proof bundles, status-qualified composition and verification results |
| `common_root` | Common-root commitments, lineage, joins, assurance and composed proofs |
| `persona_evidence` | Persona credential evidence, proof windows and replay contracts |
| `issuer_status` | Issuer status feeds, authority contracts and credential-status proofs |
| `keys` | Public keys distinguished by their protocol role |
| `artifacts` | Manifest digests and artifact-set identities |
| `errors` | Typed errors and stable cross-stack reason mappings |

```rust
use reallyme_zk_api::{
    claim_bundle::{ZkClaimProofBundle, ZkPresentationBoundClaimBundleVerifier},
    circuits::{ZkCircuitFamily, ZkCredentialHashAlgorithm},
    errors::ZkError,
};
```

The crate root exposes these modules. It does not duplicate their types under
older import paths. A descriptive name remains meaningful after import, in
IDE results, and across the protobuf, Swift and Kotlin boundaries.

### Capability semantics

`ZkDisclosureMode` distinguishes `Hidden` and `Reveal`. `ZkPredicateType`
describes comparisons independently: `GreaterThanOrEqual`, `LessThanOrEqual`
and `Range`. Enum vocabulary alone does not establish circuit support.

Every current circuit advertises an empty `predicate_types` list. Claim stages
advertise `Reveal`; stages with no selected claim advertise no disclosure mode.
A manifest that claims an unsupported predicate fails canonical admission.

Current presentations may be correlated through disclosed values, issuer
knowledge or other observable context. The capability contract makes no
unconditional presentation-unlinkability guarantee. Hiding the subject or
persona key is not a promise that presentations cannot be correlated.

A `Proof` is cryptographic evidence awaiting the required verification.
`Verification` describes a verification result. A `Verified` value has passed
its documented checks; it establishes no additional protocol acceptance steps.
In particular, verified persona credential evidence still requires live holder
authentication, active-request checks and durable replay handling.

## Persona credential evidence API

The `ZkPersonaCredentialEvidence*` types model complete credential evidence
and its independently verified stages:

| Purpose | Canonical Rust API |
| --- | --- |
| One exact proof and its stage public inputs | `ZkPersonaCredentialEvidenceStageProof` |
| Exact source-circuit stage | `ZkPersonaCredentialEvidenceSourceStage` |
| Backend boundary for verifying stage proofs | `ZkPersonaCredentialEvidenceStageVerifier` |
| Verifier policy and the five required stages | `ZkPersonaCredentialEvidenceVerifyRequest` |
| Credential evidence verified before live holder authentication | `ZkVerifiedPersonaCredentialEvidence` |
| Half-open interval in which the evidence may be presented | `ZkPersonaCredentialEvidenceValidityWindow` |
| Inputs to the token-specific credential join | `ZkPersonaCredentialEvidenceBindingInputs` |

Protobuf, Swift and Kotlin retain the descriptive domain names. Rust source
stages distinguish the public and private claim circuits; protobuf proof slots
identify the five positions in the evidence presentation, including its single
selected-claim slot.

## Integration boundary

The API supports several integrations:

- wallet code needs to request proofs;
- OpenID4VP needs to bind proofs to active verifier requests;
- Identity needs a small API that integrates into application SDKs; and
- verifier services need typed evidence without depending on mobile or circuit
  tooling.

`reallyme-zk-api` supplies the types shared by those integrations:
identifiers, capability metadata, bounded proof and witness types, request
types, verifier traits, and typed errors.

It does not choose credentials, generate witnesses, compile circuits, validate
protobuf transport messages, or decide issuer trust.

Concrete proving and verification backends are supplied by applications,
platform SDKs, verifier services, or conformance harnesses.

> **Fail closed:** if a ZK presentation is received and no compatible verifier
> has been injected, the caller must reject it.

## Proofs

The circuit identifiers describe what each proof establishes:

| Need | `ZkCircuitId` |
| --- | --- |
| Present one issuer-authenticated fact and prove control of the hidden subject key | `rm-zk-credential-subject-claim-v1` |
| Present through a hidden persona | `rm-zk-private-persona-claim-v1` |
| Present through a reusable public persona or a one-time private key using prepared evidence | `rm-zk-persona-credential-evidence-v1` |
| Prove common assured-root provenance for two exact credentials | `rm-zk-common-credential-root-v1` |

`ZkCircuitId` identifies the statement a verified proof establishes. Use it in
policy and presentation formats.

`ZkCircuitRef` identifies an exact circuit artifact for provider lookup and
dispatch. It specifies the hash lane, family, stage, and source revision.

The circuit-ref registry at source revision `1` contains 46 exact refs:

- 20 request-bound credential refs across the direct and private persona families;
- 14 common-credential-root refs, including its public presenting-persona session; and
- 12 persona-credential-evidence refs across the public and private selected-claim stages.

Retired pre-v1 aliases are rejected.

## Verification

Accept a presentation only after verifying its complete proof set and the
relationships between its stages.

Stage verification is useful for diagnostics, but production acceptance
requires the verifier to check all of the following together:

- proof bytes and public inputs;
- artifact identity;
- active request binding;
- issuer policy;
- stage ordering; and
- cross-stage joins.

### Verification terminology

A **claim proof bundle** contains the four request-bound claim proofs. Its
verification establishes the selected claim and session bindings; it does not
establish issuer-signed validity or current credential status. A
**status-qualified claim proof bundle** additionally authenticates those facts.

**Persona credential evidence** is the five-proof credential/status context.
`ZkVerifiedPersonaCredentialEvidence` is an intermediate result; it does not
establish possession of the live presenting key or consume a verifier nonce.
An **accepted presentation** additionally passes the active request, holder
signature, policy, and durable replay checks at the complete protocol boundary.

### Request-bound claims

The credential-subject-claim and private-persona request-bound bundles use
`ZkPresentationBoundClaimBundleVerifier` and `verify_presentation_bound_claim_bundle_with` for four-stage claim evidence.

A successful four-stage bundle proves that the selected claim belongs to the
authenticated credential commitment and is bound to the active request. The private-persona
bundle also proves subject-to-persona authorization and session binding.
It does not establish issuer-signed credential validity or current status.
`prove_status_qualified_claim_proof_bundle_with` joins that bundle to the fifth,
issuer-credential-status proof. For credential acceptance,
`verify_status_qualified_claim_proof_bundle_with` verifies all five proofs, joins the
issuer-signed validity and hidden status index to the same credential, and
checks an independently authenticated current issuer-status feed at the
verifier's clock. The status authority must enforce a durable rollback floor.
Its `ZkVerifiedClaimStatement` is distinct from the basic operation's
`ZkPresentationBoundClaimStatement`; acceptance APIs must require the qualified
result or statement. Neither result consumes a session nonce. The protocol
must atomically consume the active session before granting access.

SHA-256 is the preferred credential hash lane; Poseidon2 is an explicit
interoperability choice. See the [0.3.0 migration guide](../../docs/verification-migration-0.3.0.md).

### Persona credential evidence presentations

`persona_credential_evidence_v1` authenticates four credential-evidence proofs and a
refreshable current-status proof. The stages share one credential binding,
holder key, token nonce, and proof window. The verifier additionally checks an
authenticated current issuer-status feed and a fresh signature over the
canonical request transcript. Public persona evidence can be reused within
its proof window; private persona evidence uses a reserved one-time token key.

### Common-credential-root bundles

`common_credential_root_v1` uses `ZkCommonCredentialRootVerifier` to verify nine
proofs:

- root attestation;
- active root status;
- two credential lineages;
- two selected claims;
- one persona-session proof; and
- two issuer credential-status proofs.

The verifier supplies trusted issuer keys, status snapshots, rollback floors,
the active session, and evaluation time.

### Request binding

All presentations bind proofs to the verifier nonce, audience, and transaction-data
hash.

Requests without transaction data bind a reserved absence value. That reserved
value cannot be supplied as real transaction data.

## Boundaries

Other components handle the following responsibilities:

| Owned elsewhere | Boundary |
| --- | --- |
| Circuit source and artifact construction | `reallyme/zk` circuit and release tooling |
| Protobuf schemas and generated messages | `reallyme-zk-proto` |
| Strict provider-operation transport validation | private codec and validation layers |
| Proving and verification implementation | platform packages, services, or conformance providers |
| Credential selection, disclosure intent, issuer trust, and request policy | Identity, OpenID4VP, wallet, and application policy |

Applications can use these API contracts without acquiring backend dependencies.

Unsupported proof systems, suites, circuits, and artifact manifests fail closed
with typed errors.

## Suites and features

`ZkProofSuite::PRODUCTION` identifies the reviewed production suite:

- Barretenberg UltraHonk;
- Keccak transcript;
- zero-knowledge masking enabled; and
- IPA accumulation disabled.

The API also represents compatibility suites. Providers must explicitly support
or reject each requested suite; an enum value alone does not establish support.

The default feature set is empty.

The `native` and `wasm` features enable the cryptographic providers used by
helper APIs that verify signatures, Poseidon2 commitments, or common-credential-root
holder-assurance material.

## Errors

`ZkError` carries a structured `ZkErrorKind` and exposes a stable
`ZkErrorReason` through `reason_code()`.

The reason-code vocabulary is aligned with the protobuf contract, but
`reallyme-zk-api` does not depend on generated protobuf bindings. Transport
codecs can map reason codes into shared SDK, FFI, RPC, or telemetry envelopes
without pulling transport code into policy crates.
