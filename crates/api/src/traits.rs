// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    claim_bundle::{
        ZkClaimProofBundle, ZkClaimProofBundleProveRequest,
        ZkPresentationBoundClaimBundleVerification, ZkPresentationBoundClaimBundleVerifyRequest,
        ZkPresentationBoundClaimStatement,
    },
    errors::ZkError,
    proofs::{ZkProof, ZkProveRequest},
};

/// Proof-system-agnostic prover boundary.
///
/// Wallet and SDK flows receive this trait object from the application layer.
/// They must not construct or depend on concrete backend types.
pub trait ZkProver: Send + Sync {
    /// Produces a proof for the supplied request.
    fn prove(&self, request: ZkProveRequest<'_>) -> Result<ZkProof, ZkError>;
}

/// Production bundle prover boundary.
///
/// This is the mobile-shaped provider contract used by identity and
/// wallet flows. Concrete implementations may use linked Barretenberg,
/// platform witness generators, lazy WASM modules, or remote service
/// isolation, but callers see only the stable proof bundle.
pub trait ZkClaimProofBundleProver: Send + Sync {
    /// Produces a complete four-stage production proof bundle.
    fn prove_claim_proof_bundle(
        &self,
        request: ZkClaimProofBundleProveRequest<'_>,
    ) -> Result<ZkClaimProofBundle, ZkError>;
}

/// Verifier boundary for presentation-bound four-proof claim evidence.
///
/// Success does not establish issuer-signed credential validity or current
/// status. Credential acceptance requires status-qualified verification.
///
/// OpenID4VP and service verifiers inject this trait when they accept the
/// staged production format. Absence of this verifier must fail closed before
/// any ZK presentation is accepted. Individual stage verification is only
/// diagnostic; in particular, a standalone credential-envelope proof does not
/// authenticate a claim without the complete bundle/root equality checks.
pub trait ZkPresentationBoundClaimBundleVerifier: Send + Sync {
    /// Verifies every stage and policy input. Success is evidence consumed by
    /// the API-owned minting function.
    fn verify_presentation_bound_claim_bundle_evidence(
        &self,
        request: ZkPresentationBoundClaimBundleVerifyRequest<'_>,
    ) -> Result<(), ZkError>;
}

/// Verify four claim proofs and mint presentation-bound evidence only.
///
/// This checks the request's issuer, binding, and presentation-time policy.
/// It does not establish credential validity/current status or consume a nonce.
/// Use `verify_status_qualified_claim_proof_bundle_with` for credential evidence
/// eligible for acceptance, then atomically consume the protocol session.
pub fn verify_presentation_bound_claim_bundle_with(
    verifier: &dyn ZkPresentationBoundClaimBundleVerifier,
    request: ZkPresentationBoundClaimBundleVerifyRequest<'_>,
) -> Result<ZkPresentationBoundClaimBundleVerification, ZkError> {
    let statement = request.bundle().decode_claimed_statement()?;
    let session_link_commitment = request.bundle().session_link_commitment()?;
    verifier.verify_presentation_bound_claim_bundle_evidence(request)?;
    let verified_stage_count = u8::try_from(request.bundle().stage_proofs().len())
        .map_err(|_| ZkError::new(crate::errors::ZkErrorReason::LengthOverflow))?;
    Ok(ZkPresentationBoundClaimBundleVerification::from_verified(
        request.bundle().bundle_kind(),
        verified_stage_count,
        request.expected_proof_suite(),
        ZkPresentationBoundClaimStatement::from_claimed(statement, session_link_commitment),
    ))
}
