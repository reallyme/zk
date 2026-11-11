// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        verify_common_credential_root_with, ZkCommonCredentialRootPersonaMode,
        ZkCommonCredentialRootProof, ZkCommonCredentialRootProofSlot,
        ZkCommonCredentialRootRawPublicInputs,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProofBytes, ZkProofSuite, ZkSessionBinding},
};
use reallyme_zk_backend_bb::{
    BarretenbergBundleProvider, BarretenbergCommonCredentialRootArtifactResolver,
    BbCommonCredentialRootRawProveRequest,
};
use reallyme_zk_proto_codec::{
    common_credential_root::{
        ZkCommonCredentialRootJoinPolicyOwner, ZkCommonCredentialRootPresentation,
        ZkCommonCredentialRootRawProofPackage, ZkCommonCredentialRootWitnessPlan,
    },
    operation::{ZkCommonCredentialRootStageInputOwner, ZkCommonCredentialRootStageProveRequest},
    result::{
        encode_common_credential_root_presentation_response,
        encode_common_credential_root_stage_proof_response,
        encode_common_credential_root_verification_response,
    },
};
use zeroize::Zeroizing;

use crate::{
    context::{PlatformContext, PlatformCrsMode},
    witness::generate_common_credential_root_stage_witness,
};

pub(super) fn verify_common_credential_root(
    context: &PlatformContext,
    request_bytes: &[u8],
    presentation: &ZkCommonCredentialRootPresentation,
    join_policy: &ZkCommonCredentialRootJoinPolicyOwner,
    expected_proof_suite: ZkProofSuite,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    expected_proof_suite.require_production()?;
    if presentation.proof_suite() != expected_proof_suite {
        return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
    }
    let persona_mode = presentation.persona_mode();
    let policy = join_policy.as_borrowed(persona_mode);
    let session_binding = presentation.session_binding();
    if session_binding.nonce_hash != policy.challenge
        || session_binding.audience_hash != policy.audience_hash
        || session_binding.transaction_data_public_input() != policy.transaction_data_hash
    {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }

    let proofs = api_common_credential_root_proofs(presentation)?;
    let request = reallyme_zk_api::common_root::ZkCommonCredentialRootVerifyRequest::try_new(
        presentation.persona_mode(),
        presentation.credential_hash_algorithm(),
        expected_proof_suite,
        session_binding,
        proofs.as_slice(),
        policy,
    )?;
    let provider = BarretenbergBundleProvider::new(context.backend(), context);
    let verified = verify_common_credential_root_with(&provider, request)?;
    encode_common_credential_root_verification_response(
        request_bytes,
        verified.persona_mode(),
        verified.proof_suite(),
    )
}

fn api_common_credential_root_proofs(
    presentation: &ZkCommonCredentialRootPresentation,
) -> Result<Vec<ZkCommonCredentialRootProof>, ZkError> {
    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(ZkCommonCredentialRootProofSlot::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for package in presentation.proofs() {
        let circuit_ref = package.public_inputs().circuit_ref();
        let proof_bytes = ZkProofBytes::try_copy_from_slice(package.proof_bytes().as_bytes())?;
        let public_inputs = ZkCommonCredentialRootRawPublicInputs::try_copy_from_slice(
            circuit_ref,
            package.public_inputs().as_bytes(),
        )?;
        proofs.push(ZkCommonCredentialRootProof::try_from_parts(
            package.persona_mode(),
            package.slot(),
            package.proof_suite(),
            package.artifact_identity(),
            proof_bytes,
            public_inputs,
        )?);
    }
    Ok(proofs)
}

pub(super) fn prove_common_credential_root_stage(
    context: &PlatformContext,
    request_bytes: &[u8],
    plan: ZkCommonCredentialRootWitnessPlan,
    proof_suite: ZkProofSuite,
    input: ZkCommonCredentialRootStageInputOwner,
    expected_binding: ZkSessionBinding,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    proof_suite.require_production()?;
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let proof = prove_common_credential_root_stage_package(
        context,
        plan,
        proof_suite,
        input,
        expected_binding,
    )?;
    encode_common_credential_root_stage_proof_response(request_bytes, &proof)
}

pub(super) fn prove_common_credential_root_presentation(
    context: &PlatformContext,
    request_bytes: &[u8],
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    expected_binding: ZkSessionBinding,
    stages: Vec<ZkCommonCredentialRootStageProveRequest>,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    proof_suite.require_production()?;
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    if stages.len() != ZkCommonCredentialRootProofSlot::ALL.len() {
        return Err(ZkError::new(ZkErrorReason::MissingStage));
    }
    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(ZkCommonCredentialRootProofSlot::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for (index, stage) in stages.into_iter().enumerate() {
        let expected_slot = *ZkCommonCredentialRootProofSlot::ALL
            .get(index)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if stage.plan.persona_mode() != persona_mode
            || stage.plan.slot() != expected_slot
            || stage.plan.circuit_ref().credential_hash_algorithm != credential_hash_algorithm
            || stage.proof_suite != proof_suite
            || stage.expected_binding != expected_binding
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        proofs.push(prove_common_credential_root_stage_package(
            context,
            stage.plan,
            stage.proof_suite,
            stage.input,
            stage.expected_binding,
        )?);
    }
    let presentation = ZkCommonCredentialRootPresentation::try_from_raw_packages(
        persona_mode,
        credential_hash_algorithm,
        proof_suite,
        expected_binding,
        proofs,
    )?;
    encode_common_credential_root_presentation_response(request_bytes, &presentation)
}

fn prove_common_credential_root_stage_package(
    context: &PlatformContext,
    plan: ZkCommonCredentialRootWitnessPlan,
    proof_suite: ZkProofSuite,
    input: ZkCommonCredentialRootStageInputOwner,
    expected_binding: ZkSessionBinding,
) -> Result<ZkCommonCredentialRootRawProofPackage, ZkError> {
    if input.expected_session_binding()? != expected_binding {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    let circuit_ref = plan.circuit_ref();
    let artifacts = context.resolve_common_credential_root_artifacts(
        plan.persona_mode(),
        plan.slot(),
        circuit_ref,
        proof_suite,
    )?;
    let witness = generate_common_credential_root_stage_witness(circuit_ref, &artifacts, input)?;
    let response = context
        .backend()
        .prove_common_credential_root_raw_exact_circuit(BbCommonCredentialRootRawProveRequest {
            circuit_ref,
            proof_suite,
            artifact_identity: artifacts.artifact_identity(),
            artifacts: &artifacts,
            witness: &witness,
        })?;
    let (proof_bytes, public_inputs) = response.into_parts();
    public_inputs.validate_session_binding(expected_binding)?;
    let proof = ZkCommonCredentialRootRawProofPackage::try_from_parts(
        plan.persona_mode(),
        plan.slot(),
        proof_suite,
        artifacts.artifact_identity(),
        proof_bytes,
        public_inputs,
    )?;
    Ok(proof)
}
