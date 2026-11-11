// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub(crate) use demo_fixture_types::TestError;
use demo_fixture_types::{CrsMode, DemoPaths, DemoProfile, DemoStage, PlatformContextGuard};
use reallyme_zk_api::{circuits::{ZkCircuitRef}, claim_bundle::{ZkClaimProofBundle, ZkClaimProofBundleStage, ZkClaimProofBundleStageProof, MAX_PRESENTATION_LIFETIME_SECONDS}, common_root::{ZkCommonCredentialRootProofSlot}, errors::{ZkErrorReason}, keys::{ZkIssuerPublicKey}, proofs::{ZkProof, ZkSessionBinding, ABSENT_TRANSACTION_DATA_HASH}};
use reallyme_zk_platform_ffi::reallyme_zk_platform_dispatch;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::{
    common_credential_root::common_credential_root_raw_proof_package_to_proto,
    platform_abi::{reallyme_zk_platform_buffer_destroy, REALLYME_ZK_PLATFORM_STATUS_OK},
    proof::encode_exact_proof,
    result::{decode_operation_response, ZkProviderOperationOutcome, ZkProviderOperationResult},
};
use std::{env, fs, path::PathBuf};
use toml::Value as TomlValue;

const COMMON_CREDENTIAL_ROOT_FIXTURE_ROOT_ENV: &str =
    "REALLYME_ZK_COMMON_CREDENTIAL_ROOT_FIXTURE_ROOT";
const COMMON_CREDENTIAL_ROOT_STAGE_REQUEST_ROOT_ENV: &str =
    "REALLYME_ZK_COMMON_CREDENTIAL_ROOT_STAGE_REQUEST_ROOT";

pub(crate) fn run_demo_stage_fixtures_dispatch_witness_release_prove_and_verify_through_platform_provider(
) -> Result<(), TestError> {
    let Some(paths) = DemoPaths::discover()? else {
        return Ok(());
    };
    let context = PlatformContextGuard::create(&paths, CrsMode::FullProver)?;

    for profile in DemoProfile::ALL {
        let mut stage_proofs = Vec::new();
        stage_proofs
            .try_reserve_exact(DemoStage::ALL.len())
            .map_err(|_| TestError::Domain(ZkErrorReason::ResourceExhausted))?;
        let mut session_binding = None;
        for stage in DemoStage::ALL {
            exercise_release_path(&context, &paths, profile, stage).map_err(|cause| {
                TestError::Fixture {
                    bundle_kind: profile.fixture_name,
                    stage: stage.fixture_name,
                    operation: "release",
                    cause: Box::new(cause),
                }
            })?;
            let stage_result = exercise_prove_and_verify_path(&context, &paths, profile, stage)
                .map_err(|cause| TestError::Fixture {
                    bundle_kind: profile.fixture_name,
                    stage: stage.fixture_name,
                    operation: "prove_verify",
                    cause: Box::new(cause),
                })?;
            require_consistent_binding(&mut session_binding, stage_result.session_binding)?;
            stage_proofs.push(stage_result.stage_proof);
        }
        let session_binding = session_binding.ok_or(TestError::UnexpectedResponse)?;
        let diagnostic_bundle = ZkClaimProofBundle::try_from_stage_proofs(
            profile.domain_profile(),
            session_binding,
            stage_proofs,
        )
        .map_err(|error| TestError::Domain(error.reason()))?;
        exercise_claim_proof_bundle_verify_path(
            &context,
            profile,
            session_binding,
            diagnostic_bundle,
        )
        .map_err(|cause| TestError::Fixture {
            bundle_kind: profile.fixture_name,
            stage: "bundle",
            operation: "verify_claim_proof_bundle",
            cause: Box::new(cause),
        })?;
        let retained_claim_proof_bundle = exercise_retained_claim_proof_bundle_prove_path(
            &context, &paths, profile,
        )
        .map_err(|cause| TestError::Fixture {
            bundle_kind: profile.fixture_name,
            stage: "bundle",
            operation: "prove_retained_claim_proof_bundle",
            cause: Box::new(cause),
        })?;
        exercise_claim_proof_bundle_verify_path(
            &context,
            profile,
            retained_claim_proof_bundle.session_binding,
            retained_claim_proof_bundle.claim_proof_bundle,
        )
        .map_err(|cause| TestError::Fixture {
            bundle_kind: profile.fixture_name,
            stage: "bundle",
            operation: "verify_retained_claim_proof_bundle",
            cause: Box::new(cause),
        })?;
    }

    Ok(())
}

pub(crate) fn run_mobile_package_verifies_both_hashes_and_persona_modes() -> Result<(), TestError> {
    let Some(paths) = DemoPaths::discover()? else {
        return Ok(());
    };
    let context = PlatformContextGuard::create(&paths, CrsMode::FullProver)?;
    let fixture_root = common_credential_root_mobile_fixture_root()?;
    let mut verified_count = 0_u8;

    for lane in ["sha256", "poseidon2"] {
        for mode in ["private", "public"] {
            let request = read_provider_request(
                fixture_root.join(format!("common-credential-root-{lane}-{mode}.pb")),
            )?;
            let result = dispatch_success(&context, request.clone()).map_err(|cause| {
                TestError::Fixture {
                    bundle_kind: mode,
                    stage: lane,
                    operation: "verify_mobile_common_credential_root_fixture",
                    cause: Box::new(cause),
                }
            })?;
            match result {
                ZkProviderOperationResult::CommonCredentialRootVerification(report) => {
                    let expected_count =
                        u8::try_from(ZkCommonCredentialRootProofSlot::ALL.len())
                            .map_err(|_| TestError::Domain(ZkErrorReason::LengthOverflow))?;
                    if report.verified_proof_count != expected_count {
                        return Err(TestError::UnexpectedResponse);
                    }
                    verified_count = verified_count
                        .checked_add(1)
                        .ok_or(TestError::Domain(ZkErrorReason::LengthOverflow))?;
                }
                _ => return Err(TestError::UnexpectedResponse),
            }
            assert_claim_proof_bundle_verify_failure(
                &context,
                tamper_common_credential_root_proof(request.clone())?,
                ZkErrorReason::InvalidProof,
            )?;
            assert_claim_proof_bundle_verify_failure(
                &context,
                tamper_common_credential_root_challenge(request)?,
                ZkErrorReason::BindingMismatch,
            )?;
        }
    }

    if verified_count == 4 {
        Ok(())
    } else {
        Err(TestError::UnexpectedResponse)
    }
}

pub(crate) fn run_mobile_package_proves_every_common_credential_root_stage() -> Result<(), TestError>
{
    let Some(paths) = DemoPaths::discover()? else {
        return Ok(());
    };
    let context = PlatformContextGuard::create(&paths, CrsMode::FullProver)?;
    let request_root = common_credential_root_stage_request_root()?;
    let mut proof_count = 0_u8;

    for lane in ["sha256", "poseidon2"] {
        for mode in ["private", "public"] {
            let mut proofs = Vec::new();
            proofs
                .try_reserve_exact(ZkCommonCredentialRootProofSlot::ALL.len())
                .map_err(|_| TestError::Domain(ZkErrorReason::ResourceExhausted))?;
            for slot in 0_u8..9 {
                let request =
                    read_provider_request(request_root.join(format!("{lane}-{mode}-{slot}.pb")))?;
                let result = dispatch_success(&context, request).map_err(|cause| {
                    TestError::CommonCredentialRootStageFixture {
                        lane,
                        mode,
                        slot,
                        operation: "prove_common_credential_root_stage",
                        cause: Box::new(cause),
                    }
                })?;
                match result {
                    ZkProviderOperationResult::CommonCredentialRootStageProof(proof) => {
                        if proof.proof_bytes().as_bytes().is_empty()
                            || proof.public_inputs().as_bytes().is_empty()
                        {
                            return Err(TestError::UnexpectedResponse);
                        }
                        proof_count = proof_count
                            .checked_add(1)
                            .ok_or(TestError::Domain(ZkErrorReason::LengthOverflow))?;
                        proofs.push(proof);
                    }
                    _ => return Err(TestError::UnexpectedResponse),
                }
            }
            exercise_generated_common_credential_root_verify_path(&context, lane, mode, proofs)
                .map_err(|cause| TestError::Fixture {
                    bundle_kind: mode,
                    stage: lane,
                    operation: "verify_generated_common_credential_root",
                    cause: Box::new(cause),
                })?;
        }
    }

    let expected_count = ZkCommonCredentialRootProofSlot::ALL
        .len()
        .checked_mul(4)
        .and_then(|count| u8::try_from(count).ok())
        .ok_or(TestError::Domain(ZkErrorReason::LengthOverflow))?;
    if proof_count == expected_count {
        Ok(())
    } else {
        Err(TestError::UnexpectedResponse)
    }
}

fn exercise_release_path(
    context: &PlatformContextGuard,
    paths: &DemoPaths,
    profile: DemoProfile,
    stage: DemoStage,
) -> Result<(), TestError> {
    let witness = stage_witness(context, paths, profile, stage)?;
    let result = dispatch_success(context, release_request(&witness.witness_handle))?;
    match result {
        ZkProviderOperationResult::StageWitnessRelease(report) => {
            if report.circuit_ref == witness.witness_handle.circuit_ref {
                Ok(())
            } else {
                Err(TestError::UnexpectedResponse)
            }
        }
        _ => Err(TestError::UnexpectedResponse),
    }
}

struct StageProofOutcome {
    stage_proof: ZkClaimProofBundleStageProof,
    session_binding: ZkSessionBinding,
}

fn exercise_prove_and_verify_path(
    context: &PlatformContextGuard,
    paths: &DemoPaths,
    profile: DemoProfile,
    stage: DemoStage,
) -> Result<StageProofOutcome, TestError> {
    let witness = stage_witness(context, paths, profile, stage)?;
    let result = dispatch_success(context, prove_request(&witness))?;
    let proof = match result {
        ZkProviderOperationResult::StageProof(proof) => proof,
        _ => return Err(TestError::UnexpectedResponse),
    };

    let result = dispatch_success(context, verify_request(&proof, witness.session_binding)?)?;
    match result {
        ZkProviderOperationResult::StageVerification(report) => {
            if report.circuit_ref == Some(witness.witness_handle.circuit_ref) {
                Ok(StageProofOutcome {
                    stage_proof: ZkClaimProofBundleStageProof::try_from_parts(
                        profile.domain_profile(),
                        stage.production_stage,
                        proof,
                    )
                    .map_err(|error| TestError::Domain(error.reason()))?,
                    session_binding: witness.session_binding,
                })
            } else {
                Err(TestError::UnexpectedResponse)
            }
        }
        _ => Err(TestError::UnexpectedResponse),
    }
}

struct BundleProofOutcome {
    claim_proof_bundle: ZkClaimProofBundle,
    session_binding: ZkSessionBinding,
}

fn exercise_retained_claim_proof_bundle_prove_path(
    context: &PlatformContextGuard,
    paths: &DemoPaths,
    profile: DemoProfile,
) -> Result<BundleProofOutcome, TestError> {
    let mut witness_handles = Vec::new();
    witness_handles
        .try_reserve_exact(DemoStage::ALL.len())
        .map_err(|_| TestError::Domain(ZkErrorReason::ResourceExhausted))?;
    let mut session_binding = None;
    for stage in DemoStage::ALL {
        let witness = stage_witness(context, paths, profile, stage)?;
        require_consistent_binding(&mut session_binding, witness.session_binding)?;
        witness_handles.push(witness.witness_handle);
    }
    let session_binding = session_binding.ok_or(TestError::UnexpectedResponse)?;
    let result = dispatch_success(
        context,
        prove_retained_claim_proof_bundle_request(profile, session_binding, &witness_handles),
    )?;
    match result {
        ZkProviderOperationResult::ClaimProofBundle(claim_proof_bundle) => {
            if claim_proof_bundle.bundle_kind() == profile.domain_profile()
                && claim_proof_bundle.session_binding() == session_binding
            {
                Ok(BundleProofOutcome {
                    claim_proof_bundle,
                    session_binding,
                })
            } else {
                Err(TestError::UnexpectedResponse)
            }
        }
        _ => Err(TestError::UnexpectedResponse),
    }
}

fn exercise_claim_proof_bundle_verify_path(
    context: &PlatformContextGuard,
    profile: DemoProfile,
    session_binding: ZkSessionBinding,
    bundle: ZkClaimProofBundle,
) -> Result<(), TestError> {
    let statement = bundle
        .decode_claimed_statement()
        .map_err(|error| TestError::Domain(error.reason()))?;
    let verification_time_unix = statement
        .presentation_expiry_unix()
        .checked_sub(1)
        .ok_or(TestError::Domain(ZkErrorReason::PresentationExpired))?;
    let request = verify_claim_proof_bundle_request(
        profile,
        &bundle,
        session_binding,
        statement.issuer(),
        verification_time_unix,
    )?;
    let claim_proof_bundle = claim_proof_bundle_to_proto(profile, &bundle)?;
    let result = dispatch_success(context, request)?;
    match result {
        ZkProviderOperationResult::ClaimProofBundleVerification(report) => {
            let required_stage_count = u8::try_from(DemoStage::ALL.len())
                .map_err(|_| TestError::Domain(ZkErrorReason::LengthOverflow))?;
            if report.bundle_kind == profile.domain_profile()
                && report.verified_stage_count == required_stage_count
                && report.statement.issuer() == statement.issuer()
            {
                Ok(())
            } else {
                Err(TestError::UnexpectedResponse)
            }
        }
        _ => Err(TestError::UnexpectedResponse),
    }?;

    assert_claim_proof_bundle_verify_failure(
        context,
        verify_claim_proof_bundle_request(
            profile,
            &bundle,
            session_binding,
            wrong_issuer(statement.issuer()),
            verification_time_unix,
        )?,
        ZkErrorReason::UntrustedIssuer,
    )?;
    assert_claim_proof_bundle_verify_failure(
        context,
        verify_claim_proof_bundle_request(
            profile,
            &bundle,
            mutate_nonce(session_binding),
            statement.issuer(),
            verification_time_unix,
        )?,
        ZkErrorReason::BindingMismatch,
    )?;
    assert_claim_proof_bundle_verify_failure(
        context,
        verify_claim_proof_bundle_request(
            profile,
            &bundle,
            mutate_audience(session_binding),
            statement.issuer(),
            verification_time_unix,
        )?,
        ZkErrorReason::BindingMismatch,
    )?;
    assert_claim_proof_bundle_verify_failure(
        context,
        verify_claim_proof_bundle_request(
            profile,
            &bundle,
            mutate_transaction_data(session_binding),
            statement.issuer(),
            verification_time_unix,
        )?,
        ZkErrorReason::BindingMismatch,
    )?;
    assert_claim_proof_bundle_verify_failure(
        context,
        verify_claim_proof_bundle_request(
            profile,
            &bundle,
            session_binding,
            statement.issuer(),
            statement.presentation_expiry_unix(),
        )?,
        ZkErrorReason::PresentationExpired,
    )?;
    let too_early_time = statement
        .presentation_expiry_unix()
        .checked_sub(
            MAX_PRESENTATION_LIFETIME_SECONDS
                .checked_add(1)
                .ok_or(TestError::Domain(ZkErrorReason::LengthOverflow))?,
        )
        .ok_or(TestError::UnexpectedResponse)?;
    assert_claim_proof_bundle_verify_failure(
        context,
        verify_claim_proof_bundle_request(
            profile,
            &bundle,
            session_binding,
            statement.issuer(),
            too_early_time,
        )?,
        ZkErrorReason::PresentationExpiryTooFar,
    )?;
    assert_claim_proof_bundle_verify_failure(
        context,
        verify_claim_proof_bundle_proto_request(
            tampered_claim_proof_bundle(claim_proof_bundle.clone())?,
            session_binding,
            statement.issuer(),
            verification_time_unix,
        ),
        ZkErrorReason::InvalidProof,
    )?;
    assert_claim_proof_bundle_verify_failure(
        context,
        verify_claim_proof_bundle_proto_request(
            malformed_claim_proof_bundle(claim_proof_bundle)?,
            session_binding,
            statement.issuer(),
            verification_time_unix,
        ),
        ZkErrorReason::EmptyInput,
    )?;
    Ok(())
}
