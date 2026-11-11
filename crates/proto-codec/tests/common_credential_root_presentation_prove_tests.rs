// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use buffa::{DecodeOptions, EnumValue, Inline, Message, MessageField};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::{decode_operation_request, ZkProviderOperation};

fn common_credential_root_fixture_stage_request(
    lane: &str,
    mode: &str,
    slot: usize,
) -> Result<pb::ZkCommonCredentialRootStageProveOperation, ZkError> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(format!(
            "vectors/common-credential-root-stage-requests-v1/{lane}-{mode}-{slot}.pb"
        ));
    let bytes = std::fs::read(path).map_err(|_| ZkError::new(ZkErrorReason::MissingOperation))?;
    let mut request = DecodeOptions::new()
        .decode_from_slice::<pb::ZkProviderOperationRequest>(&bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    match request
        .operation
        .take()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?
    {
        pb::__buffa::oneof::zk_provider_operation_request::Operation::ProveCommonCredentialRootStage(
            operation,
        ) => Ok(*operation),
        _ => Err(ZkError::new(ZkErrorReason::MissingOperation)),
    }
}

fn common_credential_root_presentation_prove_request_from_fixtures(
    lane: &str,
    mode: &str,
) -> Result<pb::ZkProviderOperationRequest, ZkError> {
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(ZkCommonCredentialRootProofSlot::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for slot in 0..ZkCommonCredentialRootProofSlot::ALL.len() {
        stages.push(common_credential_root_fixture_stage_request(
            lane, mode, slot,
        )?);
    }
    common_credential_root_presentation_prove_request(stages)
}

fn common_credential_root_presentation_prove_request(
    stages: Vec<pb::ZkCommonCredentialRootStageProveOperation>,
) -> Result<pb::ZkProviderOperationRequest, ZkError> {
    let first = stages
        .first()
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    let persona_mode = first.persona_mode;
    let proof_suite = first.proof_suite;
    let expected_binding = first.expected_binding.clone();
    let mut stages = stages.into_iter();
    let operation = pb::ZkCommonCredentialRootPresentationProveOperation {
        persona_mode,
        proof_suite,
        expected_binding,
        root_attestation: next_presentation_stage(&mut stages)?,
        root_status: next_presentation_stage(&mut stages)?,
        lineage_0: next_presentation_stage(&mut stages)?,
        lineage_1: next_presentation_stage(&mut stages)?,
        selected_claim_0: next_presentation_stage(&mut stages)?,
        selected_claim_1: next_presentation_stage(&mut stages)?,
        session: next_presentation_stage(&mut stages)?,
        issuer_credential_status_0: next_presentation_stage(&mut stages)?,
        issuer_credential_status_1: next_presentation_stage(&mut stages)?,
        __buffa_unknown_fields: Default::default(),
    };
    if stages.next().is_some() {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }
    Ok(pb::ZkProviderOperationRequest {
        operation: Some(
            pb::__buffa::oneof::zk_provider_operation_request::Operation::ProveCommonCredentialRootPresentation(
                Box::new(operation),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    })
}

fn next_presentation_stage(
    stages: &mut impl Iterator<Item = pb::ZkCommonCredentialRootStageProveOperation>,
) -> Result<
    MessageField<
        pb::ZkCommonCredentialRootStageProveOperation,
        buffa::Inline<pb::ZkCommonCredentialRootStageProveOperation>,
    >,
    ZkError,
> {
    stages
        .next()
        .map(MessageField::some)
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))
}

fn presentation_operation_mut(
    request: &mut pb::ZkProviderOperationRequest,
) -> Result<&mut pb::ZkCommonCredentialRootPresentationProveOperation, ZkError> {
    match request.operation.as_mut() {
        Some(
            pb::__buffa::oneof::zk_provider_operation_request::Operation::ProveCommonCredentialRootPresentation(
                operation,
            ),
        ) => Ok(operation),
        _ => Err(ZkError::new(ZkErrorReason::MissingOperation)),
    }
}

fn flip_input_bytes32(
    field: &mut MessageField<pb::ZkInputBytes32, Inline<pb::ZkInputBytes32>>,
) -> Result<(), ZkError> {
    let bytes = field.get_or_insert_default();
    let first = bytes
        .value
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    *first ^= 1;
    Ok(())
}

fn assert_decode_error(
    request: &pb::ZkProviderOperationRequest,
    reason: ZkErrorReason,
) -> Result<(), ZkError> {
    match decode_operation_request(&request.encode_to_vec()) {
        Err(error) if error.reason() == reason => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle)),
    }
}

#[test]
fn common_credential_root_presentation_prove_operation_decodes_all_slots() -> Result<(), ZkError> {
    let request =
        common_credential_root_presentation_prove_request_from_fixtures("poseidon2", "private")?;
    match decode_operation_request(&request.encode_to_vec())? {
        ZkProviderOperation::ProveCommonCredentialRootPresentation {
            persona_mode,
            credential_hash_algorithm,
            proof_suite,
            stages,
            ..
        } => {
            assert_eq!(
                persona_mode,
                ZkCommonCredentialRootPersonaMode::PrivatePersona
            );
            assert_eq!(
                credential_hash_algorithm,
                ZkCredentialHashAlgorithm::Poseidon2
            );
            assert_eq!(
                proof_suite,
                ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa
            );
            assert_eq!(stages.len(), ZkCommonCredentialRootProofSlot::ALL.len());
            for (index, stage) in stages.iter().enumerate() {
                let slot = *ZkCommonCredentialRootProofSlot::ALL
                    .get(index)
                    .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
                assert_eq!(stage.plan.slot(), slot);
            }
        }
        _ => return Err(ZkError::new(ZkErrorReason::MissingOperation)),
    }
    Ok(())
}

#[test]
fn common_credential_root_presentation_prove_operation_rejects_missing_issuer_status(
) -> Result<(), ZkError> {
    let mut request =
        common_credential_root_presentation_prove_request_from_fixtures("poseidon2", "private")?;
    if let Some(
        pb::__buffa::oneof::zk_provider_operation_request::Operation::ProveCommonCredentialRootPresentation(
            operation,
        ),
    ) = request.operation.as_mut()
    {
        operation.issuer_credential_status_1 = MessageField::none();
    }
    assert!(matches!(
        decode_operation_request(&request.encode_to_vec()),
        Err(error) if error.reason() == ZkErrorReason::MissingStage
    ));
    Ok(())
}

#[test]
fn common_credential_root_presentation_prove_operation_rejects_swapped_slots() -> Result<(), ZkError>
{
    let mut request =
        common_credential_root_presentation_prove_request_from_fixtures("poseidon2", "private")?;
    if let Some(
        pb::__buffa::oneof::zk_provider_operation_request::Operation::ProveCommonCredentialRootPresentation(
            operation,
        ),
    ) = request.operation.as_mut()
    {
        core::mem::swap(&mut operation.lineage_0, &mut operation.lineage_1);
    }
    assert!(matches!(
        decode_operation_request(&request.encode_to_vec()),
        Err(error) if error.reason() == ZkErrorReason::StageMismatch
    ));
    Ok(())
}

#[test]
fn common_credential_root_presentation_prove_operation_rejects_parent_binding_replay(
) -> Result<(), ZkError> {
    let mut request =
        common_credential_root_presentation_prove_request_from_fixtures("poseidon2", "private")?;
    if let Some(
        pb::__buffa::oneof::zk_provider_operation_request::Operation::ProveCommonCredentialRootPresentation(
            operation,
        ),
    ) = request.operation.as_mut()
    {
        let binding = operation.expected_binding.get_or_insert_default();
        let first = binding
            .nonce_hash
            .first_mut()
            .ok_or(ZkError::new(ZkErrorReason::BindingMismatch))?;
        *first ^= 1;
    }
    assert!(matches!(
        decode_operation_request(&request.encode_to_vec()),
        Err(error) if error.reason() == ZkErrorReason::BindingMismatch
    ));
    Ok(())
}

#[test]
fn common_credential_root_presentation_prove_operation_rejects_mixed_expiry() -> Result<(), ZkError>
{
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(ZkCommonCredentialRootProofSlot::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for slot in 0..ZkCommonCredentialRootProofSlot::ALL.len() {
        stages.push(common_credential_root_fixture_stage_request(
            "poseidon2",
            "private",
            slot,
        )?);
    }
    let root_status = stages
        .get_mut(1)
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    match root_status.input.as_mut() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::RootStatus(input)) => {
            let presentation = input.presentation.get_or_insert_default();
            presentation.expiry_unix = presentation.expiry_unix.saturating_add(1);
        }
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }

    let request = common_credential_root_presentation_prove_request(stages)?;
    assert!(matches!(
        decode_operation_request(&request.encode_to_vec()),
        Err(error) if error.reason() == ZkErrorReason::BindingMismatch
    ));
    Ok(())
}

#[test]
fn common_credential_root_presentation_prove_operation_rejects_mixed_hash_lane(
) -> Result<(), ZkError> {
    let mut request =
        common_credential_root_presentation_prove_request_from_fixtures("poseidon2", "private")?;
    let operation = presentation_operation_mut(&mut request)?;
    let stage = operation.selected_claim_0.get_or_insert_default();
    let circuit_ref = stage.circuit_ref.get_or_insert_default();
    circuit_ref.credential_hash_algorithm =
        EnumValue::from(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256);
    assert_decode_error(&request, ZkErrorReason::StageMismatch)
}

#[test]
fn common_credential_root_presentation_prove_operation_rejects_root_status_mismatch(
) -> Result<(), ZkError> {
    let mut request =
        common_credential_root_presentation_prove_request_from_fixtures("poseidon2", "private")?;
    let operation = presentation_operation_mut(&mut request)?;
    let stage = operation.root_status.get_or_insert_default();
    match stage.input.as_mut() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::RootStatus(input)) => {
            flip_input_bytes32(&mut input.root)?;
        }
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
    assert_decode_error(&request, ZkErrorReason::BindingMismatch)
}

#[test]
fn presentation_prove_rejects_private_opening_mismatch() -> Result<(), ZkError> {
    let mut request =
        common_credential_root_presentation_prove_request_from_fixtures("poseidon2", "private")?;
    let operation = presentation_operation_mut(&mut request)?;
    let stage = operation.selected_claim_0.get_or_insert_default();
    match stage.input.as_mut() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(
            input,
        )) => {
            let proof = input.proof.get_or_insert_default();
            flip_input_bytes32(&mut proof.merkle_root)?;
        }
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
    assert_decode_error(&request, ZkErrorReason::BindingMismatch)
}

#[test]
fn presentation_prove_rejects_selected_claim_session_mismatch() -> Result<(), ZkError> {
    let mut request =
        common_credential_root_presentation_prove_request_from_fixtures("poseidon2", "private")?;
    let operation = presentation_operation_mut(&mut request)?;
    let stage = operation.selected_claim_1.get_or_insert_default();
    match stage.input.as_mut() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(
            input,
        )) => {
            flip_input_bytes32(&mut input.session_binding)?;
        }
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
    assert_decode_error(&request, ZkErrorReason::BindingMismatch)
}

#[test]
fn presentation_prove_rejects_private_persona_mismatch() -> Result<(), ZkError> {
    let mut request =
        common_credential_root_presentation_prove_request_from_fixtures("poseidon2", "private")?;
    let operation = presentation_operation_mut(&mut request)?;
    let stage = operation.selected_claim_1.get_or_insert_default();
    match stage.input.as_mut() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(
            input,
        )) => {
            let link = input.link.get_or_insert_default();
            let persona = link.persona_public_key.get_or_insert_default();
            flip_input_bytes32(&mut persona.x)?;
        }
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
    assert_decode_error(&request, ZkErrorReason::BindingMismatch)
}

#[test]
fn presentation_prove_rejects_issuer_status_mismatch() -> Result<(), ZkError> {
    let mut request =
        common_credential_root_presentation_prove_request_from_fixtures("poseidon2", "private")?;
    let operation = presentation_operation_mut(&mut request)?;
    let stage = operation.issuer_credential_status_1.get_or_insert_default();
    match stage.input.as_mut() {
        Some(
            pb::zk_common_credential_root_stage_prove_operation::Input::IssuerCredentialStatus(
                input,
            ),
        ) => {
            flip_input_bytes32(&mut input.credential_binding)?;
        }
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
    assert_decode_error(&request, ZkErrorReason::BindingMismatch)
}
