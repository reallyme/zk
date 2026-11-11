# ``ReallyMeZKKit``

Backend-independent requests, domain models and injected providers for ReallyMe ZK.

## Overview

Select the circuit family and credential hash algorithm, then inject a provider
for the supported platform. Provider and protobuf decoding failures remain typed.
A stage proof establishes only its verified circuit statement; complete
presentation acceptance also checks stage joins, trust policy and live binding.

Disclosure and predicates are separate in the generated capability contract.
Current circuits advertise no predicates. Vocabulary validation by the Swift
codec does not authenticate a manifest or establish circuit support; the
canonical Rust registry owns those decisions.

## Verification levels

Claim proof bundles can be verified at two levels. The result types are
unrelated, so a result from one level cannot be passed where the other is
required.

**Presentation-bound verification.** `verifyPresentationBoundClaimBundle`
checks the four claim proofs and returns
`ReallyMeZKPresentationBoundClaimBundleVerification`. It establishes the
trusted issuer, the presentation expiry, and the binding to the active request.
It does not establish that the credential is issuer-signed and valid, or that
it is current. Use it for diagnostics and for flows that need request-bound
evidence without granting access.

**Status-qualified verification.** `verifyStatusQualifiedClaimBundle` checks
the four claim proofs together with the issuer credential-status proof against
the verifier's current issuer status list, and returns
`ReallyMeZKStatusQualifiedClaimBundleVerification`. It additionally establishes
issuer-signed credential validity and current status for the reported status
purpose. This is the only claim bundle result that may be used for credential
acceptance.

The provider has no network access and no trust store. Before building a
`ReallyMeZKStatusQualifiedClaimBundleVerifyRequest`, the verifier application
authenticates the issuer status list, including its signature, issuer,
freshness, and rollback floor, and supplies the list root, length, identifier,
URL hash, and purpose. These values must never come from the holder's
presentation.

Neither level consumes the session. The verifier must atomically accept the
active session exactly once before granting access.

## Topics

### Credential acceptance

- ``ReallyMeZKStatusQualifiedClaimBundleVerifier``
- ``ReallyMeZKStatusQualifiedClaimBundleVerifyRequest``
- ``ReallyMeZKStatusQualifiedClaimBundleVerification``

### Circuit selection

- ``ZKCredentialHashAlgorithm``
- ``ZKClaimProofBundleKind``
- ``ZKClaimProofBundleStage``

### Claim proof bundles

- ``ReallyMeZKClaimProofBundleProveRequest``
- ``ReallyMeZKClaimProofBundleVerifyRequest``
- ``ZKClaimProofBundleMetrics``

### Common credential root

- ``ZKCommonCredentialRootPersonaMode``
- ``ReallyMeZKCommonCredentialRootVerifyRequest``
- ``ReallyMeZKCommonCredentialRootPresentationProveRequest``
- ``ReallyMeZKCommonCredentialRootPresentationProof``
- ``ReallyMeZKVerifiedCommonCredentialRoot``

### Persona credential evidence

- ``ReallyMeZKPersonaCredentialEvidenceStageProveRequest``

### Provider integration

- ``ReallyMeZKProvider``
- ``ReallyMeZKError``


`verifyPresentationBoundClaimBundle` returns
`ReallyMeZKPresentationBoundClaimBundleVerification`. This four-proof result
establishes the claim's trusted issuer, presentation expiry, and active request
binding. Credential acceptance requires joined issuer-signed validity and
current status at the complete verifier boundary. It also requires atomic
single-use session consumption before access is granted. Native transport
reports and individual stage results are not acceptance capabilities.

SHA-256 is the preferred credential hash lane and the default for claim bundle
proving. Poseidon2 is available through explicit selection with matching
artifacts and provider support.
