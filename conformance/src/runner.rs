// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provider-independent execution of canonical ZK verification vectors.

use reallyme_zk_api::{
    claim_bundle::{
        verify_presentation_bound_claim_bundle_with, ZkPresentationBoundClaimBundleVerification,
        ZkPresentationBoundClaimBundleVerifier, ZkPresentationBoundClaimBundleVerifyRequest,
    },
    errors::ZkErrorReason,
};
use reallyme_zk_proto_codec::{
    operation::ZkProviderOperation,
    result::ZkClaimProofBundleVerificationReport,
    verification_vector::{
        decode_verification_vector_set, ExpectedVerificationOutcome, VerificationVector,
        VerificationVectorMutation,
    },
};

use crate::{ConformanceError, ConformanceErrorReason};

/// Counts from one completely successful verification-vector set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationConformanceSummary {
    /// Total canonical cases executed.
    pub total_cases: u32,
    /// Structurally valid cases dispatched to the injected verifier.
    pub provider_cases: u32,
    /// Structurally valid cases rejected by public verifier policy before backend use.
    pub policy_rejections: u32,
    /// Invalid cases rejected at the canonical operation boundary.
    pub boundary_rejections: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedCase<'a> {
    Bundle(&'a ZkClaimProofBundleVerificationReport),
    Error(ZkErrorReason),
    Unsupported,
}

/// Executes one canonical release vector set against an injected bundle verifier.
///
/// The function succeeds only when every case produces the exact result or
/// stable typed error encoded by the release vector. It never catches backend
/// text, selects a fallback provider, or weakens a provider failure.
pub fn run_claim_proof_bundle_verification_vectors<V: ZkPresentationBoundClaimBundleVerifier>(
    bytes: &[u8],
    verifier: &V,
) -> Result<VerificationConformanceSummary, ConformanceError> {
    let vector_set = decode_verification_vector_set(bytes).map_err(|error| {
        ConformanceError::new(ConformanceErrorReason::InvalidVectorSet(error.reason()))
    })?;
    if !has_complete_mutation_catalog(
        vector_set
            .vectors()
            .iter()
            .map(VerificationVector::mutation),
    ) {
        return Err(ConformanceError::new(
            ConformanceErrorReason::IncompleteVectorSet,
        ));
    }
    let mut total_cases = 0_u32;
    let mut provider_cases = 0_u32;
    let mut policy_rejections = 0_u32;
    let mut boundary_rejections = 0_u32;

    for vector in vector_set.into_vectors() {
        let expected = expected_case(&vector);
        match (expected, vector.execute()) {
            (ExpectedCase::Error(expected_reason), Err(error)) => {
                require_error(expected_reason, error.reason())?;
                boundary_rejections = checked_increment(boundary_rejections)?;
            }
            (
                ExpectedCase::Error(expected_reason),
                Ok(ZkProviderOperation::VerifyClaimProofBundle {
                    claim_proof_bundle,
                    expected_proof_suite,
                    expected_binding,
                    trusted_issuers,
                    verification_time_unix,
                }),
            ) => {
                let request = match ZkPresentationBoundClaimBundleVerifyRequest::try_new(
                    &claim_proof_bundle,
                    expected_proof_suite,
                    expected_binding,
                    &trusted_issuers,
                    verification_time_unix,
                ) {
                    Ok(request) => request,
                    Err(error) => {
                        require_error(expected_reason, error.reason())?;
                        policy_rejections = checked_increment(policy_rejections)?;
                        total_cases = checked_increment(total_cases)?;
                        continue;
                    }
                };
                provider_cases = checked_increment(provider_cases)?;
                match verify_presentation_bound_claim_bundle_with(verifier, request) {
                    Ok(_) => {
                        return Err(ConformanceError::new(
                            ConformanceErrorReason::UnexpectedSuccess,
                        ));
                    }
                    Err(error) => require_error(expected_reason, error.reason())?,
                }
            }
            (
                ExpectedCase::Bundle(expected_verification),
                Ok(ZkProviderOperation::VerifyClaimProofBundle {
                    claim_proof_bundle,
                    expected_proof_suite,
                    expected_binding,
                    trusted_issuers,
                    verification_time_unix,
                }),
            ) => {
                provider_cases = checked_increment(provider_cases)?;
                let request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
                    &claim_proof_bundle,
                    expected_proof_suite,
                    expected_binding,
                    &trusted_issuers,
                    verification_time_unix,
                )
                .map_err(|error| {
                    ConformanceError::new(ConformanceErrorReason::UnexpectedFailure(error.reason()))
                })?;
                let actual = verify_presentation_bound_claim_bundle_with(verifier, request)
                    .map_err(|error| {
                        ConformanceError::new(ConformanceErrorReason::UnexpectedFailure(
                            error.reason(),
                        ))
                    })?;
                if !verification_matches_report(&actual, expected_verification) {
                    return Err(ConformanceError::new(
                        ConformanceErrorReason::VerificationMismatch,
                    ));
                }
            }
            (ExpectedCase::Bundle(_), Err(error)) => {
                return Err(ConformanceError::new(
                    ConformanceErrorReason::UnexpectedFailure(error.reason()),
                ));
            }
            (ExpectedCase::Unsupported, _) | (_, Ok(_)) => {
                return Err(ConformanceError::new(
                    ConformanceErrorReason::UnsupportedOperation,
                ));
            }
        }
        total_cases = checked_increment(total_cases)?;
    }

    Ok(VerificationConformanceSummary {
        total_cases,
        provider_cases,
        policy_rejections,
        boundary_rejections,
    })
}

fn has_complete_mutation_catalog<I>(mutations: I) -> bool
where
    I: IntoIterator<Item = VerificationVectorMutation>,
{
    let mut actual = mutations.into_iter();
    for expected in VerificationVectorMutation::BUNDLE_CONFORMANCE {
        if actual.next() != Some(*expected) {
            return false;
        }
    }
    actual.next().is_none()
}

fn verification_matches_report(
    actual: &ZkPresentationBoundClaimBundleVerification,
    expected: &ZkClaimProofBundleVerificationReport,
) -> bool {
    actual.bundle_kind() == expected.bundle_kind
        && actual.verified_stage_count() == expected.verified_stage_count
        && actual.proof_suite() == expected.proof_suite
        && actual.statement().issuer() == expected.statement.issuer()
        && actual.statement().persona() == expected.statement.persona()
        && actual.statement().credential_binding() == expected.statement.credential_binding()
        && actual.statement().claim_name_hash() == expected.statement.claim_name_hash()
        && actual.statement().claim_value() == expected.statement.claim_value()
        && actual.statement().session_link_commitment() == expected.session_link_commitment
        && actual.statement().presentation_expiry_unix()
            == expected.statement.presentation_expiry_unix()
}

const fn expected_case(vector: &VerificationVector) -> ExpectedCase<'_> {
    match vector.expected_outcome() {
        ExpectedVerificationOutcome::Bundle(verification) => ExpectedCase::Bundle(verification),
        ExpectedVerificationOutcome::Error(error) => ExpectedCase::Error(error.reason()),
        ExpectedVerificationOutcome::Stage(_) => ExpectedCase::Unsupported,
    }
}

fn require_error(expected: ZkErrorReason, actual: ZkErrorReason) -> Result<(), ConformanceError> {
    if expected != actual {
        return Err(ConformanceError::new(
            ConformanceErrorReason::ErrorMismatch { expected, actual },
        ));
    }
    Ok(())
}

fn checked_increment(value: u32) -> Result<u32, ConformanceError> {
    value.checked_add(1).ok_or(ConformanceError::new(
        ConformanceErrorReason::LengthOverflow,
    ))
}

#[cfg(test)]
mod tests;
