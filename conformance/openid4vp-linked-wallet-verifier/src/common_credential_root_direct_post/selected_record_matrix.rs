// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_verifier::{
    diagnose_authorization_response_with_options, ResponseValidationOptions, VerifierErrorReason,
    ZkHolderBindingVerifier,
};
use reallyme_openid4vp_wallet::{
    prepare_zk_presentation_from_common_credential_root, WalletCommonCredentialRootProof,
    WalletInvocationContext,
};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        ZkCommonCredentialRootAttestationTrustPolicy, ZkCommonCredentialRootPersonaMode,
        ZkVerifiedRootStatusSnapshot,
    },
};
use reallyme_zk_backend_bb::{BarretenbergBundleProvider, NativeBarretenbergBackend};

use crate::{
    artifacts::StageResolver,
    constants::COMMON_CREDENTIAL_ROOT_QUERY,
    direct_post::{authorization_response, session_record, verified_request},
    error::{HarnessError, HarnessPhase},
    openid::expect_verifier_reason,
};

use super::{
    flow::{
        prove_selected_record_common_credential_root_for_verified_profile,
        request_for_common_credential_root_fixture_profile,
        verify_common_credential_root_direct_profile, CommonCredentialRootProfileLane,
    },
    model::{
        zk_common_credential_root, CommonCredentialRootFixture,
        HarnessCommonCredentialRootPresentation, PlatformContextGuard,
    },
};

#[allow(clippy::too_many_arguments)]
pub(super) fn expect_selected_record_profile_matrix(
    provider: &BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>,
    context: &PlatformContextGuard,
    stage_request_root: &Path,
    fixture: &CommonCredentialRootFixture,
    query_id: &QueryId,
    invocation: &WalletInvocationContext,
    verifier: &ZkHolderBindingVerifier<'_>,
    attestation_trust: ZkCommonCredentialRootAttestationTrustPolicy,
    trusted_status: ZkVerifiedRootStatusSnapshot,
    verification_time_unix: u64,
) -> Result<(), HarnessError> {
    for (persona_mode, credential_hash_algorithm) in [
        (
            ZkCommonCredentialRootPersonaMode::PublicPersona,
            ZkCredentialHashAlgorithm::Sha256,
        ),
        (
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            ZkCredentialHashAlgorithm::Poseidon2,
        ),
        (
            ZkCommonCredentialRootPersonaMode::PublicPersona,
            ZkCredentialHashAlgorithm::Poseidon2,
        ),
    ] {
        let request = request_for_common_credential_root_fixture_profile(
            query_id,
            Some(fixture),
            persona_mode,
            credential_hash_algorithm,
        )?;
        let verified = verified_request(request.clone(), verification_time_unix)?;
        let (proofs, binding, status_lists) =
            prove_selected_record_common_credential_root_for_verified_profile(
                context,
                stage_request_root,
                &verified,
                attestation_trust,
                trusted_status,
                verification_time_unix,
                CommonCredentialRootProfileLane {
                    persona_mode,
                    credential_hash_algorithm,
                },
            )?;
        let presentation = HarnessCommonCredentialRootPresentation::try_new_profile(
            persona_mode,
            credential_hash_algorithm,
            proofs,
            binding,
            status_lists,
        )?;
        let session = session_record(request.clone(), verification_time_unix)?;
        verify_common_credential_root_direct_profile(
            provider,
            fixture,
            &presentation,
            &session,
            persona_mode,
            credential_hash_algorithm,
        )
        .map_err(|_| {
            HarnessError::Phase(
                HarnessPhase::CommonCredentialRootSelectedProfileMatrixDirectVerification,
            )
        })?;
        let value = prepare_zk_presentation_from_common_credential_root(
            &verified,
            invocation,
            query_id,
            &presentation,
        )
        .map_err(|_| {
            HarnessError::Phase(HarnessPhase::CommonCredentialRootSelectedProfileMatrixVpValue)
        })?;
        let diagnosed = diagnose_authorization_response_with_options(
            &session,
            &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, value.clone())])?,
            verification_time_unix,
            ResponseValidationOptions {
                holder_binding_verifier: Some(verifier),
            },
        )
        .map_err(|_| {
            HarnessError::Phase(HarnessPhase::CommonCredentialRootSelectedProfileMatrixVpResponse)
        })?;
        if zk_common_credential_root(diagnosed.verified_presentations())
            .map_err(|_| {
                HarnessError::Phase(
                    HarnessPhase::CommonCredentialRootSelectedProfileMatrixVpResponse,
                )
            })?
            .verified_proof_count()
            != 9
        {
            return Err(HarnessError::InvalidLength);
        }

        let wrong_profile_request = request_for_common_credential_root_fixture_profile(
            query_id,
            Some(fixture),
            alternate_profile(persona_mode)?,
            credential_hash_algorithm,
        )?;
        let wrong_profile_session = session_record(wrong_profile_request, verification_time_unix)?;
        let wrong_profile = diagnose_authorization_response_with_options(
            &wrong_profile_session,
            &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, value.clone())])?,
            verification_time_unix,
            ResponseValidationOptions {
                holder_binding_verifier: Some(verifier),
            },
        )
        .map_err(HarnessError::from);
        expect_verifier_reason(wrong_profile, VerifierErrorReason::InvalidZkPresentation).map_err(
            |_| {
                HarnessError::Phase(
                    HarnessPhase::CommonCredentialRootSelectedProfileMatrixWrongProfile,
                )
            },
        )?;

        let wrong_hash_request = request_for_common_credential_root_fixture_profile(
            query_id,
            Some(fixture),
            persona_mode,
            alternate_credential_hash_algorithm(credential_hash_algorithm)?,
        )?;
        let wrong_hash_session = session_record(wrong_hash_request, verification_time_unix)?;
        let wrong_hash = diagnose_authorization_response_with_options(
            &wrong_hash_session,
            &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, value)])?,
            verification_time_unix,
            ResponseValidationOptions {
                holder_binding_verifier: Some(verifier),
            },
        )
        .map_err(HarnessError::from);
        expect_verifier_reason(wrong_hash, VerifierErrorReason::InvalidZkPresentation).map_err(
            |_| {
                HarnessError::Phase(
                    HarnessPhase::CommonCredentialRootSelectedProfileMatrixWrongHash,
                )
            },
        )?;
    }
    Ok(())
}

fn alternate_profile(
    persona_mode: ZkCommonCredentialRootPersonaMode,
) -> Result<ZkCommonCredentialRootPersonaMode, HarnessError> {
    match persona_mode {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => {
            Ok(ZkCommonCredentialRootPersonaMode::PublicPersona)
        }
        ZkCommonCredentialRootPersonaMode::PublicPersona => {
            Ok(ZkCommonCredentialRootPersonaMode::PrivatePersona)
        }
    }
}

fn alternate_credential_hash_algorithm(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<ZkCredentialHashAlgorithm, HarnessError> {
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => Ok(ZkCredentialHashAlgorithm::Poseidon2),
        ZkCredentialHashAlgorithm::Poseidon2 => Ok(ZkCredentialHashAlgorithm::Sha256),
        _ => Err(HarnessError::InvalidPresentationAccepted),
    }
}

pub(super) fn expect_distinct_credential_bindings(
    presentation: &super::model::HarnessCommonCredentialRootPresentation,
    second_presentation: &super::model::HarnessCommonCredentialRootPresentation,
) -> Result<(), HarnessError> {
    // Both presentations reuse the issued credentials. Their public joins
    // must change with the verifier request so the credential binding cannot
    // become a cross-session correlation handle.
    const LINEAGE_CREDENTIAL_BINDING_FIELD: usize = 193;
    const PUBLIC_INPUT_FIELD_BYTES: usize = 32;
    let start = LINEAGE_CREDENTIAL_BINDING_FIELD
        .checked_mul(PUBLIC_INPUT_FIELD_BYTES)
        .ok_or(HarnessError::InvalidLength)?;
    let end = start
        .checked_add(PUBLIC_INPUT_FIELD_BYTES)
        .ok_or(HarnessError::InvalidLength)?;
    for slot in [2_usize, 3_usize] {
        let first = presentation
            .proofs
            .get(slot)
            .ok_or(HarnessError::InvalidLength)?
            .public_inputs()
            .as_bytes();
        let second = second_presentation
            .proofs
            .get(slot)
            .ok_or(HarnessError::InvalidLength)?
            .public_inputs()
            .as_bytes();
        if first.get(start..end).ok_or(HarnessError::InvalidLength)?
            == second.get(start..end).ok_or(HarnessError::InvalidLength)?
        {
            return Err(HarnessError::InvalidPresentationAccepted);
        }
    }
    Ok(())
}
