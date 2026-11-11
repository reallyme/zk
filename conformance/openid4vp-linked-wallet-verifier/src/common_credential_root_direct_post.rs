// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{path::Path, sync::Arc};

use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_verifier::{
    diagnose_authorization_response_with_options, HolderBindingVerifier, ResponseValidationOptions,
    VerifierErrorReason, ZkHolderBindingVerifier, ZkVerificationRequirements,
};
use reallyme_openid4vp_wallet::{
    prepare_zk_presentation_from_common_credential_root, WalletCommonCredentialRootProof,
    WalletInvocationContext,
};
use reallyme_zk_api::{
    common_root::ZkCommonCredentialRootAttestationTrustPolicy, errors::ZkErrorReason,
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_backend_bb::{BarretenbergBundleProvider, NativeBarretenbergBackend};
use serde_json::json;

use crate::{
    artifacts::StageResolver,
    common_credential_root_stage_builder::common_credential_root_stage_requests_for_verified,
    constants::COMMON_CREDENTIAL_ROOT_QUERY,
    direct_post::{authorization_response, direct_post_body, session_record, verified_request},
    error::{HarnessError, HarnessPhase},
    openid::expect_verifier_reason,
};

mod active_binding;
mod flow;
mod model;
mod policy_rejection;
mod runtime_acceptance;
mod selected_record_matrix;
mod trust_policy;

pub(crate) use self::active_binding::{write_active_binding, SECOND_REQUEST_NONCE};
pub(crate) use self::flow::common_credential_root_release_paths;
pub(crate) use self::model::CommonCredentialRootFixture;
use self::{
    flow::{
        common_credential_root_direct_session_expiry_unix,
        prove_common_credential_root_for_verified,
        prove_selected_record_common_credential_root_for_verified,
        request_for_common_credential_root_fixture, verify_common_credential_root_direct,
    },
    model::{
        session_with_wrong_query, zk_common_credential_root,
        HarnessCommonCredentialRootPresentation, PlatformContextGuard,
    },
    runtime_acceptance::{
        expect_invalid_runtime_presentations, expect_runtime_accepts_once, RuntimeAcceptance,
    },
    selected_record_matrix::{
        expect_distinct_credential_bindings, expect_selected_record_profile_matrix,
    },
    trust_policy::expect_common_credential_root_trust_policy_rejections,
};

const RELEASE_INDEX_SHA256_HEX: &str =
    "9260afdb9a3a0133a679af141a310b6aacbf2e814724692ca964d2711ae49ce7";
const VERIFIER_CRS_G2_BYTES: usize = 128;
const COMMON_CREDENTIAL_ROOT_LANE: &str = "sha256";
const COMMON_CREDENTIAL_ROOT_RELEASE_ROOT: &str = "build/native/ios-demo-resources/zk_demo";
pub(crate) fn expect_common_credential_root_direct_post_accepts_once(
    provider: Arc<BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>>,
    stage_request_root: &Path,
    second_stage_request_root: &Path,
    _verification_time_unix: u64,
    trusted_issuers: &[ZkIssuerPublicKey],
) -> Result<(), HarnessError> {
    let query_id = QueryId::parse(COMMON_CREDENTIAL_ROOT_QUERY)?;
    let fixture = Arc::new(CommonCredentialRootFixture::read()?);
    let verification_time_unix = fixture.verification_time()?;
    let request = request_for_common_credential_root_fixture(&query_id, Some(&fixture))?;
    let verified = verified_request(request.clone(), verification_time_unix)?;
    let context = PlatformContextGuard::create()?;
    let trusted_status = fixture.verified_status_snapshot(verification_time_unix)?;
    let attestation_trust = ZkCommonCredentialRootAttestationTrustPolicy {
        signer: fixture.attestation_signer,
        assurance_policy_id: fixture.assurance_policy_id,
    };
    let (proofs, binding, issuer_status_lists) = prove_common_credential_root_for_verified(
        &context,
        stage_request_root,
        &verified,
        attestation_trust,
        trusted_status,
        verification_time_unix,
    )?;
    let mut stale_session_binding = binding;
    stale_session_binding.nonce_hash[0] ^= 1;
    if !matches!(
        common_credential_root_stage_requests_for_verified(
            stage_request_root,
            stale_session_binding
        ),
        Err(HarnessError::InvalidPresentationAccepted)
    ) {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let mut presentation =
        HarnessCommonCredentialRootPresentation::try_new(proofs, binding, issuer_status_lists)?;
    let invocation = WalletInvocationContext::ProtocolTransport;
    let value = prepare_zk_presentation_from_common_credential_root(
        &verified,
        &invocation,
        &query_id,
        &presentation,
    )?;
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        provider.as_ref(),
        trusted_issuers,
        ZkVerificationRequirements {
            issuer_signed_validity: true,
            credential_status: true,
        },
        provider.as_ref(),
        fixture.verification_policy(&presentation.issuer_status_lists, verification_time_unix)?,
    );
    let session = session_record(request.clone(), verification_time_unix)?;
    verify_common_credential_root_direct(provider.as_ref(), &fixture, &presentation, &session)
        .map_err(|_| {
            HarnessError::Phase(HarnessPhase::CommonCredentialRootInitialDirectVerification)
        })?;
    let (fresh_proofs, fresh_binding, fresh_status_lists) =
        prove_common_credential_root_for_verified(
            &context,
            stage_request_root,
            &verified,
            attestation_trust,
            trusted_status,
            verification_time_unix,
        )?;
    if fresh_binding != binding {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let mut fresh_presentation = HarnessCommonCredentialRootPresentation::try_new(
        fresh_proofs,
        fresh_binding,
        fresh_status_lists,
    )?;
    if fresh_presentation.proofs[0].public_inputs().as_bytes()
        == presentation.proofs[0].public_inputs().as_bytes()
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    verify_common_credential_root_direct(
        provider.as_ref(),
        &fixture,
        &fresh_presentation,
        &session,
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootFreshDirectVerification))?;
    let (selected_proofs, selected_binding, selected_status_lists) =
        prove_selected_record_common_credential_root_for_verified(
            &context,
            stage_request_root,
            &verified,
            attestation_trust,
            trusted_status,
            verification_time_unix,
        )?;
    if selected_binding != binding {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let mut selected_presentation = HarnessCommonCredentialRootPresentation::try_new(
        selected_proofs,
        selected_binding,
        selected_status_lists,
    )?;
    let selected_expiry = common_credential_root_direct_session_expiry_unix(
        &fixture,
        &selected_presentation,
        &session,
    )
    .map_err(|_| {
        HarnessError::Phase(HarnessPhase::CommonCredentialRootSelectedSessionExpiryDecode)
    })?;
    if selected_expiry <= verification_time_unix
        || selected_expiry <= session.binding.request_time_unix
    {
        return Err(HarnessError::Phase(
            HarnessPhase::CommonCredentialRootSelectedSessionExpiryDecode,
        ));
    }
    verify_common_credential_root_direct(
        provider.as_ref(),
        &fixture,
        &selected_presentation,
        &session,
    )
    .map_err(|_| {
        HarnessError::Phase(HarnessPhase::CommonCredentialRootSelectedDirectVerification)
    })?;
    let selected_value = prepare_zk_presentation_from_common_credential_root(
        &verified,
        &invocation,
        &query_id,
        &selected_presentation,
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootSelectedVpValue))?;
    let selected_diagnosed = diagnose_authorization_response_with_options(
        &session,
        &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, selected_value.clone())])?,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootSelectedVpResponse))?;
    if zk_common_credential_root(selected_diagnosed.verified_presentations())
        .map_err(|_| {
            HarnessError::Phase(HarnessPhase::CommonCredentialRootSelectedVerifiedExtraction)
        })?
        .verified_proof_count()
        != 9
    {
        return Err(HarnessError::InvalidLength);
    }
    let mut wrong_selected_session = session.clone();
    wrong_selected_session.binding.nonce =
        "wrong-selected-common-credential-root-direct-post-nonce-v1".to_owned();
    let selected_wrong_session = diagnose_authorization_response_with_options(
        &wrong_selected_session,
        &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, selected_value)])?,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .map_err(HarnessError::from);
    expect_verifier_reason(
        selected_wrong_session,
        VerifierErrorReason::InvalidZkPresentation,
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootSelectedWrongSession))?;
    expect_selected_record_profile_matrix(
        provider.as_ref(),
        &context,
        stage_request_root,
        &fixture,
        &query_id,
        &invocation,
        &verifier,
        attestation_trust,
        trusted_status,
        verification_time_unix,
    )?;
    let (left, right) = selected_presentation.proofs.split_at_mut(3);
    std::mem::swap(&mut left[2], &mut right[0]);
    match verify_common_credential_root_direct(
        provider.as_ref(),
        &fixture,
        &selected_presentation,
        &session,
    ) {
        Err(HarnessError::Zk(error))
            if matches!(
                error.reason(),
                ZkErrorReason::BindingMismatch
                    | ZkErrorReason::MissingStage
                    | ZkErrorReason::StageMismatch
            ) => {}
        _ => {
            return Err(HarnessError::Phase(
                HarnessPhase::CommonCredentialRootSelectedSwappedSlots,
            ))
        }
    }
    // Each proof remains individually valid after this swap. The verifier
    // must reject their combined public joins because the two presentations
    // used different private salts.
    std::mem::swap(
        &mut fresh_presentation.proofs[2],
        &mut presentation.proofs[2],
    );
    let mixed = verify_common_credential_root_direct(
        provider.as_ref(),
        &fixture,
        &fresh_presentation,
        &session,
    );
    std::mem::swap(
        &mut fresh_presentation.proofs[2],
        &mut presentation.proofs[2],
    );
    match mixed {
        Err(HarnessError::Zk(error)) if error.reason() == ZkErrorReason::BindingMismatch => {}
        _ => {
            return Err(HarnessError::Phase(
                HarnessPhase::CommonCredentialRootMixedSaltRejection,
            ))
        }
    }
    let diagnosed = diagnose_authorization_response_with_options(
        &session,
        &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, value.clone())])?,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootFreshVpResponse))?;
    let common_credential_root = zk_common_credential_root(diagnosed.verified_presentations())
        .map_err(|_| {
            HarnessError::Phase(HarnessPhase::CommonCredentialRootFreshVerifiedExtraction)
        })?;
    if common_credential_root.verified_proof_count() != 9 {
        return Err(HarnessError::InvalidLength);
    }

    expect_common_credential_root_trust_policy_rejections(
        provider.as_ref(),
        trusted_issuers,
        &fixture,
        &presentation,
        &session,
        &value,
        verification_time_unix,
    )?;

    let mut wrong_persona_session = session.clone();
    let query = wrong_persona_session
        .dcql_query
        .credentials
        .first_mut()
        .ok_or(HarnessError::MissingField)?;
    query.meta.insert(
        "profile".to_owned(),
        json!("common_credential_root_v1_public_persona"),
    );
    let wrong_persona = diagnose_authorization_response_with_options(
        &wrong_persona_session,
        &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, value.clone())])?,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .map_err(HarnessError::from);
    expect_verifier_reason(wrong_persona, VerifierErrorReason::InvalidZkPresentation)
        .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootWrongPersonaPolicy))?;

    // A second verified wallet request has a different nonce and its own
    // holder-signed session witness. The first request's valid proof bundle
    // must be rejected by the second session, and vice versa.
    let mut second_request = request.clone();
    second_request.nonce = SECOND_REQUEST_NONCE.to_owned();
    let second_verified = verified_request(second_request.clone(), verification_time_unix)?;
    let (second_proofs, second_binding, second_status_lists) =
        prove_common_credential_root_for_verified(
            &context,
            second_stage_request_root,
            &second_verified,
            attestation_trust,
            trusted_status,
            verification_time_unix,
        )
        .map_err(|_| {
            HarnessError::Phase(HarnessPhase::CommonCredentialRootSecondPresentationProof)
        })?;
    if second_binding == binding {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let second_presentation = HarnessCommonCredentialRootPresentation::try_new(
        second_proofs,
        second_binding,
        second_status_lists,
    )?;
    expect_distinct_credential_bindings(&presentation, &second_presentation)?;
    let second_session = session_record(second_request.clone(), verification_time_unix)?;
    let second_expiry = common_credential_root_direct_session_expiry_unix(
        &fixture,
        &second_presentation,
        &second_session,
    )
    .map_err(|_| {
        HarnessError::Phase(HarnessPhase::CommonCredentialRootSecondSessionExpiryDecode)
    })?;
    if second_expiry <= verification_time_unix
        || second_expiry <= second_session.binding.request_time_unix
    {
        return Err(HarnessError::Phase(
            HarnessPhase::CommonCredentialRootSecondSessionExpiryDecode,
        ));
    }
    let second_value = prepare_zk_presentation_from_common_credential_root(
        &second_verified,
        &invocation,
        &query_id,
        &second_presentation,
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootSecondVpValue))?;
    verify_common_credential_root_direct(
        provider.as_ref(),
        &fixture,
        &second_presentation,
        &second_session,
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootSecondDirectVerification))?;
    let second_diagnosed = diagnose_authorization_response_with_options(
        &second_session,
        &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, second_value.clone())])?,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootSecondVpResponse))?;
    if zk_common_credential_root(second_diagnosed.verified_presentations())
        .map_err(|_| {
            HarnessError::Phase(HarnessPhase::CommonCredentialRootSecondVerifiedExtraction)
        })?
        .verified_proof_count()
        != 9
    {
        return Err(HarnessError::InvalidLength);
    }
    let first_in_second = diagnose_authorization_response_with_options(
        &second_session,
        &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, value.clone())])?,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .map_err(HarnessError::from);
    expect_verifier_reason(first_in_second, VerifierErrorReason::InvalidZkPresentation)
        .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootFirstInSecondSession))?;
    let second_in_first = diagnose_authorization_response_with_options(
        &session,
        &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, second_value.clone())])?,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .map_err(HarnessError::from);
    expect_verifier_reason(second_in_first, VerifierErrorReason::InvalidZkPresentation)
        .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootSecondInFirstSession))?;

    let runtime_verifier: Arc<dyn HolderBindingVerifier> = Arc::new(
        crate::runtime::OwnedCommonCredentialRootZkHolderBindingVerifier {
            provider: provider.clone(),
            trusted_issuers: trusted_issuers.to_vec(),
            requirements: ZkVerificationRequirements {
                issuer_signed_validity: true,
                credential_status: true,
            },
            fixture: Arc::clone(&fixture),
            issuer_status_lists: presentation.issuer_status_lists,
            policy_build_time_unix: verification_time_unix,
        },
    );
    let body = direct_post_body([(COMMON_CREDENTIAL_ROOT_QUERY, value.clone())])
        .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootBodyEncoding))?;
    let second_body = direct_post_body([(COMMON_CREDENTIAL_ROOT_QUERY, second_value)])
        .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootBodyEncoding))?;
    expect_runtime_accepts_once(
        second_request,
        second_session,
        runtime_verifier.clone(),
        second_body,
        verification_time_unix,
        RuntimeAcceptance::Second,
    )?;
    expect_invalid_runtime_presentations(
        runtime_verifier.clone(),
        &session,
        &value,
        &body,
        verification_time_unix,
    )?;
    let wrong = diagnose_authorization_response_with_options(
        &session_with_wrong_query(request.clone(), verification_time_unix)?,
        &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, value.clone())])?,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .map_err(HarnessError::from);
    expect_verifier_reason(wrong, VerifierErrorReason::InvalidZkPresentation)
        .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootWrongQuery))?;

    expect_runtime_accepts_once(
        request,
        session,
        runtime_verifier,
        body,
        verification_time_unix,
        RuntimeAcceptance::Initial,
    )?;
    Ok(())
}
