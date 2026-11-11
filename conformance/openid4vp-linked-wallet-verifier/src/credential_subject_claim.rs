// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A real credential-subject-claim proof must join the same issuer-signed status statement
//! as the persona bundle_kind, without borrowing the persona's session witness.

use std::path::Path;

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{
        prove_status_qualified_claim_proof_bundle_with,
        verify_status_qualified_claim_proof_bundle_with, ZkClaimProofBundleKind,
        ZkPresentationBoundClaimBundleVerifyRequest, ZkStatusQualifiedClaimProofBundleVerifyRequest,
    },
    errors::ZkErrorReason,
    issuer_status::ZkIssuerStatusPurpose,
    proofs::ZkProofSuite,
};
use reallyme_zk_backend_bb::{BarretenbergBundleProvider, NativeBarretenbergBackend};

use crate::{
    artifacts::{load_production_stages, StageResolver},
    constants::QUERY_A,
    direct_post::status_floor_store,
    error::HarnessError,
    fixture::CredentialFixture,
    openid::{expect_zk_reason, openid_session_binding},
    status_qualified::{
        issuer_credential_status_witness, signed_status_list, signed_status_list_with_revocation,
        status_source, FixtureStatusSignatureVerifier,
    },
    witness::witness_bundle_from_tomls,
};

pub(crate) fn verify_credential_subject_claim_status(
    root: &Path,
    fixture_root: &Path,
    release_root: &Path,
    release_index: &[u8],
) -> Result<(), HarnessError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let stages = load_production_stages(root, credential_hash_algorithm, bundle_kind)?;
    let fixture = CredentialFixture::try_new(&fixture_root.join("direct"), QUERY_A)?;
    let binding = openid_session_binding();
    let witness = witness_bundle_from_tomls(
        bundle_kind,
        credential_hash_algorithm,
        stages.as_slice(),
        &fixture,
        binding,
    )?;
    let resolver = StageResolver::try_new(bundle_kind, credential_hash_algorithm, stages)?
        .with_common_credential_root_release(release_root, release_index)?;
    // The CRS is process-global and was initialized by the enclosing host.
    let backend = NativeBarretenbergBackend::try_new()?;
    let provider = BarretenbergBundleProvider::new(backend, resolver);
    let status_witness =
        issuer_credential_status_witness(&provider, &fixture, credential_hash_algorithm, binding)?;
    let qualified = prove_status_qualified_claim_proof_bundle_with(
        &provider,
        &provider,
        bundle_kind,
        credential_hash_algorithm,
        &witness,
        &status_witness,
        binding,
    )?;
    let now = fixture.issuer_status()?.verification_time_unix;
    let signer = FixtureStatusSignatureVerifier::new()?;
    let current_list = signed_status_list(&fixture)?;
    let current_sources = [status_source(&current_list, &signer, fixture.issuer_key)];
    let (store, _directory) = status_floor_store()?;
    let authority = reallyme_identity_openid4vp_product_store::ZkPersonaCredentialEvidenceSignedStatusAuthority::new(
        store.as_ref(),
        &current_sources,
    );
    let trusted_issuers = [fixture.issuer_key];
    let request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        qualified.claim_proof_bundle(),
        ZkProofSuite::PRODUCTION,
        binding,
        &trusted_issuers,
        now,
    )?;
    let request = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
        request,
        qualified.issuer_credential_status(),
        &authority,
        ZkIssuerStatusPurpose::Revocation,
    )?;
    let verified = verify_status_qualified_claim_proof_bundle_with(&provider, &provider, request)?;
    if verified.bundle_kind() != bundle_kind {
        return Err(HarnessError::InvalidLength);
    }

    let revoked_list = signed_status_list_with_revocation(&fixture, true)?;
    let revoked_sources = [status_source(&revoked_list, &signer, fixture.issuer_key)];
    let (revoked_store, _directory) = status_floor_store()?;
    let revoked_authority =
        reallyme_identity_openid4vp_product_store::ZkPersonaCredentialEvidenceSignedStatusAuthority::new(
            revoked_store.as_ref(),
            &revoked_sources,
        );
    let revoked_request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        qualified.claim_proof_bundle(),
        ZkProofSuite::PRODUCTION,
        binding,
        &trusted_issuers,
        now,
    )?;
    let revoked_request = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
        revoked_request,
        qualified.issuer_credential_status(),
        &revoked_authority,
        ZkIssuerStatusPurpose::Revocation,
    )?;
    expect_zk_reason(
        verify_status_qualified_claim_proof_bundle_with(&provider, &provider, revoked_request)
            .map(|_| ()),
        ZkErrorReason::BindingMismatch,
    )
}
