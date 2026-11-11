// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Four-stage claim proof composition, request-bound status, and verification results.

pub use crate::bundle::{
    ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimProofBundleProveRequest,
    ZkClaimProofBundleStage, ZkClaimProofBundleStageProof, ZkClaimProofBundleWitness,
    ZkCompatibilitySuiteAcknowledgement,
};
pub use crate::claim_proof_bundle_verification::{
    ZkClaimedStatement, ZkPresentationBoundClaimBundleVerification,
    ZkPresentationBoundClaimBundleVerifyRequest, ZkPresentationBoundClaimStatement,
    MAX_PRESENTATION_LIFETIME_SECONDS, MAX_TRUSTED_ISSUERS,
};
pub use crate::credential_status_verification::{
    prove_status_qualified_claim_proof_bundle_with,
    verify_status_qualified_claim_proof_bundle_with, ZkStatusQualifiedClaimProofBundle,
    ZkStatusQualifiedClaimProofBundleVerification, ZkStatusQualifiedClaimProofBundleVerifyRequest,
    ZkVerifiedClaimStatement, MAX_REQUEST_BOUND_STATUS_PROOF_AGE_SECONDS,
};
pub use crate::traits::{
    verify_presentation_bound_claim_bundle_with, ZkClaimProofBundleProver,
    ZkPresentationBoundClaimBundleVerifier,
};
