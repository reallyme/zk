// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs,
    path::{Path, PathBuf},
};

use reallyme_identity::zk::ZkPersonaVerifier;
use reallyme_openid4vp_verifier::SessionRecord;
use reallyme_openid4vp_wallet::{
    WalletAuthorizationRequest, WalletCommonCredentialRootPresentation,
    WalletCommonCredentialRootProof,
};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        ZkCommonCredentialRootAttestationTrustPolicy, ZkCommonCredentialRootClaimExpectation,
        ZkCommonCredentialRootJoinPolicy, ZkCommonCredentialRootPersonaMode,
        ZkCommonCredentialRootProof, ZkCommonCredentialRootRawPublicInputs,
        ZkCommonCredentialRootVerifyRequest, ZkVerifiedRootStatusSnapshot,
    },
    proofs::{ZkProofBytes, ZkProofSuite, ZkSessionBinding},
};
use reallyme_zk_backend_bb::{BarretenbergBundleProvider, NativeBarretenbergBackend};
use reallyme_zk_proto_codec::{
    common_credential_root::ZkCommonCredentialRootRawProofPackage,
    result::ZkProviderOperationResult,
};

use super::model::{
    common_credential_root_release_root, CommonCredentialRootFixture,
    HarnessCommonCredentialRootPresentation, HarnessCommonCredentialRootProof,
    PlatformContextGuard,
};
use crate::{
    artifacts::StageResolver,
    common_credential_root_issuance::{
        issue_and_transport_into_stage_requests,
        issue_verified_selected_records_for_stage_requests,
        selected_record_presentation_request_from_verified_records,
        trusted_common_credential_root_source_from_verified_stage_requests,
        SelectedRecordPresentationClock,
    },
    common_credential_root_stage_builder::{
        common_credential_root_stage_requests_for_verified,
        common_credential_root_stage_requests_for_verified_profile,
    },
    direct_post::DIRECT_POST_CLIENT_ID,
    error::HarnessError,
};

mod dispatch;
mod request;
mod selected_signature;

pub(super) use self::request::{
    request_for_common_credential_root_fixture, request_for_common_credential_root_fixture_at,
    request_for_common_credential_root_fixture_profile,
};

use self::{
    dispatch::{
        common_credential_root_presentation_expiry, dispatch_success,
        prove_common_credential_root_presentation,
    },
    selected_signature::expect_selected_issuer_signature_substitutions_reject,
};

pub(super) fn verify_common_credential_root_direct(
    provider: &BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>,
    fixture: &CommonCredentialRootFixture,
    presentation: &HarnessCommonCredentialRootPresentation,
    session: &SessionRecord,
) -> Result<(), HarnessError> {
    verify_common_credential_root_direct_profile(
        provider,
        fixture,
        presentation,
        session,
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCredentialHashAlgorithm::Sha256,
    )
}

pub(super) fn verify_common_credential_root_direct_profile(
    provider: &BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>,
    fixture: &CommonCredentialRootFixture,
    presentation: &HarnessCommonCredentialRootPresentation,
    session: &SessionRecord,
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<(), HarnessError> {
    let verification_time_unix = fixture.verification_time()?;
    let proofs = api_common_credential_root_proofs(presentation.proofs(), persona_mode)?;
    let request = common_credential_root_direct_verify_request(
        fixture,
        presentation,
        session,
        &proofs,
        persona_mode,
        credential_hash_algorithm,
    )?;
    let trusted_status = fixture.verified_status_snapshot(verification_time_unix)?;
    ZkPersonaVerifier::new(provider).verify_common_root(
        request,
        trusted_status,
        verification_time_unix,
    )?;
    Ok(())
}

pub(super) fn common_credential_root_direct_session_expiry_unix(
    fixture: &CommonCredentialRootFixture,
    presentation: &HarnessCommonCredentialRootPresentation,
    session: &SessionRecord,
) -> Result<u64, HarnessError> {
    let proofs = api_common_credential_root_proofs(
        presentation.proofs(),
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
    )?;
    let request = common_credential_root_direct_verify_request(
        fixture,
        presentation,
        session,
        &proofs,
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCredentialHashAlgorithm::Sha256,
    )?;
    Ok(request.session_expiry_unix()?)
}

fn common_credential_root_direct_verify_request<'a>(
    fixture: &'a CommonCredentialRootFixture,
    presentation: &HarnessCommonCredentialRootPresentation,
    session: &SessionRecord,
    proofs: &'a [ZkCommonCredentialRootProof],
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<ZkCommonCredentialRootVerifyRequest<'a>, HarnessError> {
    let binding = presentation.session_binding();
    let verification_time_unix = fixture.verification_time()?;
    let issuer_status = fixture
        .verification_policy(&presentation.issuer_status_lists, verification_time_unix)?
        .issuer_status_expectations(verification_time_unix)?;
    Ok(ZkCommonCredentialRootVerifyRequest::try_new(
        persona_mode,
        credential_hash_algorithm,
        ZkProofSuite::PRODUCTION,
        binding,
        proofs,
        ZkCommonCredentialRootJoinPolicy {
            challenge: binding.nonce_hash,
            audience_hash: binding.audience_hash,
            transaction_data_hash: binding.transaction_data_public_input(),
            request_time_unix: session.binding.request_time_unix,
            status_validation_time_unix: verification_time_unix,
            status_validation_max_age_seconds: 120,
            attestation_signer: fixture.attestation_signer,
            assurance_policy_id: fixture.assurance_policy_id,
            status_root: fixture.status_root,
            claims: [
                ZkCommonCredentialRootClaimExpectation {
                    issuer: fixture.first_claim.issuer,
                    claim_name_hash: fixture.first_claim.claim_name_hash,
                    value: fixture.first_claim.value.as_slice(),
                },
                ZkCommonCredentialRootClaimExpectation {
                    issuer: fixture.second_claim.issuer,
                    claim_name_hash: fixture.second_claim.claim_name_hash,
                    value: fixture.second_claim.value.as_slice(),
                },
            ],
            issuer_status,
            persona_mode,
        },
    )?)
}

fn api_common_credential_root_proofs(
    proofs: &[HarnessCommonCredentialRootProof],
    persona_mode: ZkCommonCredentialRootPersonaMode,
) -> Result<Vec<ZkCommonCredentialRootProof>, HarnessError> {
    let mut api_proofs = Vec::new();
    api_proofs
        .try_reserve_exact(proofs.len())
        .map_err(|_| HarnessError::InvalidLength)?;
    for proof in proofs {
        let public_inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
            proof.public_inputs().circuit_ref(),
            proof.public_inputs().as_bytes().to_vec(),
        )?;
        let proof_bytes = ZkProofBytes::try_copy_from_slice(proof.proof_bytes().as_bytes())?;
        api_proofs.push(ZkCommonCredentialRootProof::try_from_parts(
            persona_mode,
            proof.slot(),
            ZkProofSuite::PRODUCTION,
            proof.artifact_identity(),
            proof_bytes,
            public_inputs,
        )?);
    }
    Ok(api_proofs)
}

pub(crate) fn common_credential_root_release_paths() -> Result<(PathBuf, Vec<u8>), HarnessError> {
    let root = common_credential_root_release_root()?;
    let release_index = fs::read(root.join("release-index.pb"))?;
    Ok((root.join("artifacts"), release_index))
}

fn direct_post_session_binding_from_verified(
    verified: &impl WalletAuthorizationRequest,
) -> ZkSessionBinding {
    let binding = reallyme_openid4vp_formats::build_zk_presentation_binding(
        &verified.request().nonce,
        DIRECT_POST_CLIENT_ID,
        None,
    );
    ZkSessionBinding {
        nonce_hash: binding.nonce_hash,
        audience_hash: binding.audience_hash,
        transaction_data_hash: None,
    }
}

pub(super) fn prove_common_credential_root_for_verified(
    context: &PlatformContextGuard,
    stage_request_root: &Path,
    verified: &impl WalletAuthorizationRequest,
    attestation_trust: ZkCommonCredentialRootAttestationTrustPolicy,
    trusted_status: ZkVerifiedRootStatusSnapshot,
    verification_time_unix: u64,
) -> Result<
    (
        Vec<ZkCommonCredentialRootRawProofPackage>,
        ZkSessionBinding,
        [reallyme_credential_status::StatusList; 2],
    ),
    HarnessError,
> {
    let binding = direct_post_session_binding_from_verified(verified);
    let mut requests =
        common_credential_root_stage_requests_for_verified(stage_request_root, binding)?;
    let trusted_source = trusted_common_credential_root_source_from_verified_stage_requests(
        &requests,
        attestation_trust,
        trusted_status,
        verification_time_unix,
    )?;
    let issuer_status_lists = issue_and_transport_into_stage_requests(
        &mut requests,
        &trusted_source,
        verification_time_unix,
    )?;
    let presentation = prove_common_credential_root_presentation(context, &requests)?;
    let (_, _, _, presentation_binding, proofs) = presentation.into_parts();
    if presentation_binding != binding {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    Ok((proofs, binding, issuer_status_lists))
}

pub(super) fn prove_selected_record_common_credential_root_for_verified(
    context: &PlatformContextGuard,
    stage_request_root: &Path,
    verified: &impl WalletAuthorizationRequest,
    attestation_trust: ZkCommonCredentialRootAttestationTrustPolicy,
    trusted_status: ZkVerifiedRootStatusSnapshot,
    verification_time_unix: u64,
) -> Result<
    (
        Vec<ZkCommonCredentialRootRawProofPackage>,
        ZkSessionBinding,
        [reallyme_credential_status::StatusList; 2],
    ),
    HarnessError,
> {
    prove_selected_record_common_credential_root_for_verified_profile(
        context,
        stage_request_root,
        verified,
        attestation_trust,
        trusted_status,
        verification_time_unix,
        CommonCredentialRootProfileLane {
            persona_mode: ZkCommonCredentialRootPersonaMode::PrivatePersona,
            credential_hash_algorithm: ZkCredentialHashAlgorithm::Sha256,
        },
    )
}

pub(super) struct CommonCredentialRootProfileLane {
    pub(super) persona_mode: ZkCommonCredentialRootPersonaMode,
    pub(super) credential_hash_algorithm: ZkCredentialHashAlgorithm,
}

pub(super) fn prove_selected_record_common_credential_root_for_verified_profile(
    context: &PlatformContextGuard,
    stage_request_root: &Path,
    verified: &impl WalletAuthorizationRequest,
    attestation_trust: ZkCommonCredentialRootAttestationTrustPolicy,
    trusted_status: ZkVerifiedRootStatusSnapshot,
    verification_time_unix: u64,
    lane: CommonCredentialRootProfileLane,
) -> Result<
    (
        Vec<ZkCommonCredentialRootRawProofPackage>,
        ZkSessionBinding,
        [reallyme_credential_status::StatusList; 2],
    ),
    HarnessError,
> {
    let CommonCredentialRootProfileLane {
        persona_mode,
        credential_hash_algorithm,
    } = lane;
    let binding = direct_post_session_binding_from_verified(verified);
    let requests = common_credential_root_stage_requests_for_verified_profile(
        stage_request_root,
        binding,
        credential_hash_algorithm,
        persona_mode,
    )?;
    let trusted_source = trusted_common_credential_root_source_from_verified_stage_requests(
        &requests,
        attestation_trust,
        trusted_status,
        verification_time_unix,
    )?;
    let request_time_unix = verified.request().iat.ok_or(HarnessError::MissingField)?;
    let presentation_expiry_unix = common_credential_root_presentation_expiry(&requests)?;
    let selected =
        issue_verified_selected_records_for_stage_requests(&requests, request_time_unix)?;
    let (request, issuer_status_lists) =
        selected_record_presentation_request_from_verified_records(
            selected,
            &trusted_source,
            trusted_status,
            binding,
            SelectedRecordPresentationClock {
                request_time_unix,
                status_validation_time_unix: verification_time_unix,
                presentation_expiry_unix,
            },
            persona_mode,
            credential_hash_algorithm,
        )?;
    if credential_hash_algorithm == ZkCredentialHashAlgorithm::Poseidon2 {
        expect_selected_issuer_signature_substitutions_reject(context, request.request())?;
    }
    let result = dispatch_success(context, request)?;
    let presentation = match result {
        ZkProviderOperationResult::CommonCredentialRootPresentation(presentation) => *presentation,
        _ => return Err(HarnessError::InvalidPresentationAccepted),
    };
    let (_, _, _, presentation_binding, proofs) = presentation.into_parts();
    if presentation_binding != binding {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    Ok((proofs, binding, issuer_status_lists))
}
