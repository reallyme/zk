# Verification integration for 0.3.0

Release 0.3.0 distinguishes presentation-bound claim evidence from credential
validity and current-status verification. These changes apply before the initial
release. There are no deprecated aliases or version changes.

## Rust

Update four-proof integrations to these names:

| Previous API | 0.3.0 API |
| --- | --- |
| `verify_claim_proof_bundle_with` | `verify_presentation_bound_claim_bundle_with` |
| `ZkClaimProofBundleVerifier` | `ZkPresentationBoundClaimBundleVerifier` |
| `verify_claim_proof_bundle_evidence` | `verify_presentation_bound_claim_bundle_evidence` |
| `ZkClaimProofBundleVerifyRequest` | `ZkPresentationBoundClaimBundleVerifyRequest` |
| `ZkClaimProofBundleVerification` | `ZkPresentationBoundClaimBundleVerification` |

The basic result's `statement()` now returns
`&ZkPresentationBoundClaimStatement`. It establishes the selected claim, trusted
issuer, presentation expiry, and nonce/audience/transaction bindings. It carries
no assertion of issuer-signed credential validity or current status.

Credential acceptance must require
`ZkStatusQualifiedClaimProofBundleVerification` or its
`&ZkVerifiedClaimStatement`. Only
`verify_status_qualified_claim_proof_bundle_with` constructs that stronger
statement, after verifying all five proofs, their shared credential binding,
signed validity, and the independently authenticated current issuer status feed.
There is no public conversion from basic evidence or decoded transport data.
The former runtime `require_issuer_signed_validity` and
`require_credential_status` checks are removed from basic evidence: require the
stronger type in the accepting function's signature instead.

```rust
use reallyme_zk_api::claim_bundle::{
    ZkStatusQualifiedClaimProofBundleVerification, ZkVerifiedClaimStatement,
};

fn credential_claim(
    verified: &ZkStatusQualifiedClaimProofBundleVerification,
) -> &ZkVerifiedClaimStatement {
    verified.statement()
}
```

This capability establishes validity at the supplied verifier clock and status
under the selected status purpose. Application claim policy and single-use
session acceptance remain required. Do not cache it as indefinitely current.

Other presentation families retain their own complete verification boundaries.
Prepared persona evidence alone still requires live holder authentication and
durable nonce consumption. Common-root proof verification still requires the
protocol's authenticated request, trust/status policy, and session handling.
Do not promote either family's intermediate results into a generic acceptance
capability solely because proof verification succeeded.

## Swift and Kotlin

Use `verifyPresentationBoundClaimBundle` in place of `verifyClaimProofBundle`.
The verifier protocols, requests, and results now have explicit scope:

| SDK | Verifier | Request | Result |
| --- | --- | --- | --- |
| Swift | `ReallyMeZKPresentationBoundClaimBundleVerifier` | `ReallyMeZKPresentationBoundClaimBundleVerifyRequest` | `ReallyMeZKPresentationBoundClaimBundleVerification` |
| Kotlin | `ReallyMeZkPresentationBoundClaimBundleVerifier` | `ZkPresentationBoundClaimBundleVerifyRequest` | `ZkPresentationBoundClaimBundleVerification` |

The corresponding unsupported verifier implementations follow the same naming.
Bundle proving APIs retain their names. The basic verification result remains
presentation evidence; it must not authorize credential acceptance.

Credential acceptance uses the status-qualified verifier:

| SDK | Verifier | Request | Result |
| --- | --- | --- | --- |
| Swift | `ReallyMeZKStatusQualifiedClaimBundleVerifier` | `ReallyMeZKStatusQualifiedClaimBundleVerifyRequest` | `ReallyMeZKStatusQualifiedClaimBundleVerification` |
| Kotlin | `ReallyMeZkStatusQualifiedClaimBundleVerifier` | `ZkStatusQualifiedClaimBundleVerifyRequest` | `ZkStatusQualifiedClaimBundleVerification` |

`verifyStatusQualifiedClaimBundle` sends the four claim proofs and the issuer
validity and current-status proof with the active session binding, trusted
issuer keys, verifier clock, and the verifier's current issuer status list.
The application must authenticate that status list before building the
request: its signature, issuer, freshness, and rollback floor. Set
`expectedIssuer` to the credential issuer whose status list was authenticated;
this remains the credential issuer when the list uses a delegated signer. The
key must be trusted and match the issuer established by the proofs. The native
provider checks the proofs against the list it is given and cannot detect a
stale or forged one. The result type has no public constructor and no
conversion from the four-proof result. It covers one status purpose at the
supplied verifier clock and does not consume the session, so the application
still accepts the active session exactly once in durable storage before
granting access. Missing support must fail closed.
The sample runners verify synthetic fixture bundles and do not consume live
verifier sessions.

Identity's Rust `ZkVerifier` façade uses `verify_presentation_bound_bundle` and
`verify_presentation_bound_bundle_with_suite` for basic evidence; its
`verify_status_qualified_bundle` remains the credential-verification boundary.
Identity's Swift and Kotlin façades likewise use
`verifyPresentationBoundClaimBundle` and explicitly named presentation-bound
outcome types. TypeScript uses `identity.zk.verifyPresentationBoundClaimBundle`,
`verifyZkPresentationBoundClaimBundleV1`,
`ZkPresentationBoundClaimBundleVerificationOptions`, and
`ZkPresentationBoundClaimBundleVerificationOutcome`.

Protobuf operation/report names and binary encodings are unchanged. Reports are
transport data, not domain verification capabilities. The bb.js adapter likewise
returns single-proof backend evidence and does not perform credential acceptance.

## Hash selection and replay protection

SHA-256 is the preferred credential hash lane and the mobile bundle-proving
default. Retain Poseidon2 support for explicitly selected integrations with
matching commitments, artifacts, and provider conformance. This choice is
independent of the production UltraHonk Keccak transcript. Do not reinterpret an
existing Poseidon2 credential as SHA-256 or silently fall back between lanes.

The proof binds the nonce, audience, transaction data, and presentation expiry
to the active verifier request. Reuse with different bindings is rejected.
Status-qualified verification additionally rejects credentials lacking valid,
current issuer evidence; it does not record nonce use.

For single-use acceptance, the protocol must:

1. Obtain the outstanding session and bindings from authenticated verifier state.
2. Verify the complete credential evidence and requested claim policy.
3. Atomically transition the same unexpired session from outstanding to accepted
   in durable shared state, rejecting reuse, concurrent losers, and store failure.
4. Grant access only after that transition succeeds.

Keep session consumption separate from revocation/status-list rollback state.
Repeated cryptographic verification under identical inputs can succeed; only the
session transition establishes single use. See the
[OpenID4VP binding contract](openid4vp-presentation-binding.md).
