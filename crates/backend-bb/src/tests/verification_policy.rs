// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    binding, bundle_with_hashes, bundle_with_hashes_and_binding, production_manifest, provider,
    trusted_issuer, validate_presentation_expiry, verify_presentation_bound_claim_bundle_with,
    AcceptingBackend, BarretenbergBundleProvider, ManifestBackedArtifactResolver,
    VerificationOnlyStore, ZkClaimProofBundleKind, ZkCredentialHashAlgorithm, ZkError,
    ZkErrorReason, ZkPresentationBoundClaimBundleVerifyRequest, ZkProofSuite,
};

#[test]
fn presentation_expiry_boundaries_are_closed_and_exact() -> Result<(), ZkError> {
    let now = 1_000_u64;
    let maximum = now
        .checked_add(reallyme_zk_api::claim_bundle::MAX_PRESENTATION_LIFETIME_SECONDS)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let too_far = maximum
        .checked_add(1)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;

    assert!(matches!(
        validate_presentation_expiry(now, now),
        Err(error) if error.reason() == ZkErrorReason::PresentationExpired
    ));
    assert!(matches!(
        validate_presentation_expiry(now, 0),
        Err(error) if error.reason() == ZkErrorReason::PresentationExpired
    ));
    assert!(validate_presentation_expiry(now.saturating_add(1), now).is_ok());
    assert!(validate_presentation_expiry(maximum, now).is_ok());
    assert!(matches!(
        validate_presentation_expiry(too_far, now),
        Err(error) if error.reason() == ZkErrorReason::PresentationExpiryTooFar
    ));
    Ok(())
}

#[test]
fn verification_only_resolver_never_loads_bytecode() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let resolver = ManifestBackedArtifactResolver::from_configured_trust_root(
        production_manifest(bundle_kind, credential_hash_algorithm)?,
        VerificationOnlyStore,
    );
    let provider = BarretenbergBundleProvider::new(AcceptingBackend::all_suites(), resolver);
    let bundle = bundle_with_hashes(
        bundle_kind,
        &[
            Some(credential_hash_algorithm),
            Some(credential_hash_algorithm),
            Some(credential_hash_algorithm),
            Some(credential_hash_algorithm),
        ],
    )?;

    let verification = verify_presentation_bound_claim_bundle_with(
        &provider,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &bundle,
            ZkProofSuite::PRODUCTION,
            binding(7),
            &[trusted_issuer()],
            41,
        )?,
    )?;

    assert_eq!(verification.bundle_kind(), bundle_kind);
    Ok(())
}

#[test]
fn independently_verified_different_session_links_fail_comparison() -> Result<(), ZkError> {
    let provider = provider();
    let hashes = [
        Some(ZkCredentialHashAlgorithm::Sha256),
        Some(ZkCredentialHashAlgorithm::Sha256),
        Some(ZkCredentialHashAlgorithm::Sha256),
        Some(ZkCredentialHashAlgorithm::Sha256),
    ];
    let left_bundle = bundle_with_hashes_and_binding(
        ZkClaimProofBundleKind::PrivatePersonaClaimV1,
        &hashes,
        binding(7),
    )?;
    let right_bundle = bundle_with_hashes_and_binding(
        ZkClaimProofBundleKind::PrivatePersonaClaimV1,
        &hashes,
        binding(8),
    )?;
    let left = verify_presentation_bound_claim_bundle_with(
        &provider,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &left_bundle,
            ZkProofSuite::PRODUCTION,
            binding(7),
            &[trusted_issuer()],
            41,
        )?,
    )?;
    let right = verify_presentation_bound_claim_bundle_with(
        &provider,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &right_bundle,
            ZkProofSuite::PRODUCTION,
            binding(8),
            &[trusted_issuer()],
            41,
        )?,
    )?;

    let error = left
        .statement()
        .require_same_session_link(right.statement())
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}
