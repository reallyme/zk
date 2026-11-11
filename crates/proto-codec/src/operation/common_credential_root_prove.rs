// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot,
        COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT,
    },
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofSuite, ZkSessionBinding},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

mod validation;

use validation::{bytes32_field, public_key_field, require_same_bytes32, require_same_key};

use crate::{
    binding::session_binding_from_proto_message,
    common_credential_root::{
        common_credential_root_persona_mode_from_proto, common_credential_root_slot_from_proto,
        common_credential_root_witness_plan_for_circuit, ZkCommonCredentialRootWitnessPlan,
    },
    domain::{circuit_ref_from_proto_message, proof_suite_from_proto},
    operation::{
        common_credential_root_stage::common_credential_root_stage_input_owner_from_proto,
        secret_cleanup::{
            CommonCredentialRootPresentationProveOperationGuard,
            CommonCredentialRootStageProveOperationGuard,
        },
        ZkCommonCredentialRootStageInputOwner, ZkProviderOperation,
    },
};

/// One validated common-credential-root source-stage proving request.
pub struct ZkCommonCredentialRootStageProveRequest {
    /// Canonical common-credential-root source-circuit plan.
    pub plan: ZkCommonCredentialRootWitnessPlan,
    /// Exact transcript and witness-masking suite.
    pub proof_suite: ZkProofSuite,
    /// Secret generated input owner.
    pub input: ZkCommonCredentialRootStageInputOwner,
    /// Active presentation binding supplied by the SDK request.
    pub expected_binding: ZkSessionBinding,
}

pub(super) fn prove_common_credential_root_stage_from_proto(
    operation: pb::ZkCommonCredentialRootStageProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let request = common_credential_root_stage_prove_request_from_proto(operation)?;
    Ok(ZkProviderOperation::ProveCommonCredentialRootStage {
        plan: request.plan,
        proof_suite: request.proof_suite,
        input: request.input,
        expected_binding: request.expected_binding,
    })
}

fn common_credential_root_stage_prove_request_from_proto(
    operation: pb::ZkCommonCredentialRootStageProveOperation,
) -> Result<ZkCommonCredentialRootStageProveRequest, ZkError> {
    let mut operation = CommonCredentialRootStageProveOperationGuard::new(operation);
    let persona_mode = common_credential_root_persona_mode_from_proto(operation.persona_mode())?;
    let slot = common_credential_root_slot_from_proto(operation.slot())?;
    let circuit_ref = circuit_ref_from_proto_message(operation.take_circuit_ref())?;
    let plan = common_credential_root_witness_plan_for_circuit(persona_mode, slot, circuit_ref)?;
    let proof_suite = proof_suite_from_proto(operation.proof_suite())?;
    let expected_binding = session_binding_from_proto_message(operation.take_expected_binding())?;
    expected_binding.validate_for_circuit(plan.circuit_ref())?;
    let input = operation
        .take_input()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))
        .and_then(|input| common_credential_root_stage_input_owner_from_proto(plan, input))?;
    if input.expected_session_binding()? != expected_binding {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    Ok(ZkCommonCredentialRootStageProveRequest {
        plan,
        proof_suite,
        input,
        expected_binding,
    })
}

pub(super) fn prove_common_credential_root_presentation_from_proto(
    operation: pb::ZkCommonCredentialRootPresentationProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut operation = CommonCredentialRootPresentationProveOperationGuard::new(operation);
    let persona_mode = common_credential_root_persona_mode_from_proto(operation.persona_mode())?;
    let proof_suite = proof_suite_from_proto(operation.proof_suite())?;
    let expected_binding = session_binding_from_proto_message(operation.take_expected_binding())?;

    let mut stages = Vec::new();
    stages
        .try_reserve_exact(COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut credential_hash_algorithm: Option<ZkCredentialHashAlgorithm> = None;
    let mut presentation_expiry_unix: Option<u64> = None;
    for slot in ZkCommonCredentialRootProofSlot::ALL {
        let stage_operation = operation
            .take_stage(*slot)
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
        let stage = common_credential_root_stage_prove_request_from_proto(stage_operation)?;
        if stage.plan.persona_mode() != persona_mode || stage.plan.slot() != *slot {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if stage.proof_suite != proof_suite {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if stage.expected_binding != expected_binding {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        let stage_presentation_expiry_unix = stage.input.presentation_expiry_unix()?;
        match presentation_expiry_unix {
            Some(expected) if expected != stage_presentation_expiry_unix => {
                return Err(ZkError::new(ZkErrorReason::BindingMismatch));
            }
            Some(_) => {}
            None => presentation_expiry_unix = Some(stage_presentation_expiry_unix),
        }
        let stage_credential_hash_algorithm = stage.plan.circuit_ref().credential_hash_algorithm;
        match credential_hash_algorithm {
            Some(expected_credential_hash_algorithm)
                if expected_credential_hash_algorithm != stage_credential_hash_algorithm =>
            {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
            Some(_) => {}
            None => credential_hash_algorithm = Some(stage_credential_hash_algorithm),
        }
        stages.push(stage);
    }

    validate_common_credential_root_presentation_source_consistency(persona_mode, &stages)?;

    let credential_hash_algorithm =
        credential_hash_algorithm.ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    expected_binding.validate_for_circuit(persona_mode.source_ref(
        credential_hash_algorithm,
        ZkCommonCredentialRootProofSlot::Session,
    ))?;
    Ok(ZkProviderOperation::ProveCommonCredentialRootPresentation {
        persona_mode,
        credential_hash_algorithm,
        proof_suite,
        expected_binding,
        stages,
    })
}

fn validate_common_credential_root_presentation_source_consistency(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    stages: &[ZkCommonCredentialRootStageProveRequest],
) -> Result<(), ZkError> {
    let root_attestation = root_attestation_stage(stage_for(
        stages,
        ZkCommonCredentialRootProofSlot::RootAttestation,
    )?)?;
    let root_status = root_status_stage(stage_for(
        stages,
        ZkCommonCredentialRootProofSlot::RootStatus,
    )?)?;
    let session = session_summary(
        persona_mode,
        stage_for(stages, ZkCommonCredentialRootProofSlot::Session)?,
    )?;

    let root_join = bytes32_field(&root_attestation.root_join)?;
    let attestation_join = bytes32_field(&root_attestation.attestation_join)?;
    let root = bytes32_field(&root_attestation.root)?;
    require_same_bytes32(root_join, bytes32_field(&root_status.root_join)?)?;
    require_same_bytes32(
        attestation_join,
        bytes32_field(&root_status.attestation_join)?,
    )?;
    require_same_bytes32(root, bytes32_field(&root_status.root)?)?;

    let first_status_validation_time = validate_selected_credential_source(
        persona_mode,
        SelectedCredentialSlots {
            lineage: ZkCommonCredentialRootProofSlot::Lineage0,
            selected_claim: ZkCommonCredentialRootProofSlot::SelectedClaim0,
            issuer_status: ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0,
        },
        stages,
        &session,
        root_join,
        root,
        root_attestation.request_unix,
    )?;
    let second_status_validation_time = validate_selected_credential_source(
        persona_mode,
        SelectedCredentialSlots {
            lineage: ZkCommonCredentialRootProofSlot::Lineage1,
            selected_claim: ZkCommonCredentialRootProofSlot::SelectedClaim1,
            issuer_status: ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1,
        },
        stages,
        &session,
        root_join,
        root,
        root_attestation.request_unix,
    )?;
    if first_status_validation_time != second_status_validation_time {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    Ok(())
}

struct SelectedCredentialSlots {
    lineage: ZkCommonCredentialRootProofSlot,
    selected_claim: ZkCommonCredentialRootProofSlot,
    issuer_status: ZkCommonCredentialRootProofSlot,
}

struct SessionSourceSummary {
    session_binding: [u8; 32],
    persona_public_key: ZkIssuerPublicKey,
}

fn validate_selected_credential_source(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slots: SelectedCredentialSlots,
    stages: &[ZkCommonCredentialRootStageProveRequest],
    session: &SessionSourceSummary,
    root_join: [u8; 32],
    root: [u8; 32],
    request_unix: u64,
) -> Result<u64, ZkError> {
    let lineage = lineage_stage(stage_for(stages, slots.lineage)?)?;
    let selected_claim =
        selected_claim_summary(persona_mode, stage_for(stages, slots.selected_claim)?)?;
    let issuer_status = issuer_status_stage(stage_for(stages, slots.issuer_status)?)?;
    let lineage_slot = lineage
        .slot
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let lineage_witness = lineage
        .witness
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;

    require_same_bytes32(root_join, bytes32_field(&lineage.root_join)?)?;
    require_same_bytes32(root, bytes32_field(&lineage.root)?)?;
    require_same_bytes32(
        bytes32_field(&lineage_slot.subject_join)?,
        selected_claim.subject_join,
    )?;
    require_same_bytes32(
        bytes32_field(&lineage_slot.credential_binding)?,
        selected_claim.credential_binding,
    )?;
    require_same_key(
        public_key_field(&lineage_slot.issuer_public_key)?,
        selected_claim.issuer_public_key,
    )?;
    if lineage_slot.expiry_unix != selected_claim.expiry_unix {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }

    require_same_bytes32(
        bytes32_field(&lineage_witness.envelope_hash)?,
        selected_claim.envelope_hash,
    )?;
    require_same_bytes32(
        bytes32_field(&lineage_witness.merkle_root)?,
        selected_claim.claims_root,
    )?;
    require_same_key(
        public_key_field(&lineage_witness.subject_public_key)?,
        selected_claim.subject_public_key,
    )?;
    require_same_key(
        session.persona_public_key,
        selected_claim.persona_public_key,
    )?;
    require_same_bytes32(session.session_binding, selected_claim.session_binding)?;

    require_same_key(
        public_key_field(&issuer_status.issuer_public_key)?,
        selected_claim.issuer_public_key,
    )?;
    require_same_bytes32(
        bytes32_field(&issuer_status.credential_binding)?,
        selected_claim.credential_binding,
    )?;
    require_same_bytes32(
        bytes32_field(&issuer_status.envelope_hash)?,
        selected_claim.envelope_hash,
    )?;
    require_same_bytes32(
        bytes32_field(&issuer_status.claims_root)?,
        selected_claim.claims_root,
    )?;
    if issuer_status.presentation_expiry != selected_claim.expiry_unix {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    if issuer_status.verifier_now < request_unix
        || issuer_status.verifier_now >= selected_claim.expiry_unix
    {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    Ok(issuer_status.verifier_now)
}

struct SelectedClaimSummary {
    issuer_public_key: ZkIssuerPublicKey,
    expiry_unix: u64,
    session_binding: [u8; 32],
    subject_join: [u8; 32],
    credential_binding: [u8; 32],
    envelope_hash: [u8; 32],
    claims_root: [u8; 32],
    subject_public_key: ZkIssuerPublicKey,
    persona_public_key: ZkIssuerPublicKey,
}

fn selected_claim_summary(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    stage: &ZkCommonCredentialRootStageProveRequest,
) -> Result<SelectedClaimSummary, ZkError> {
    use pb::zk_common_credential_root_stage_prove_operation::Input;

    match (persona_mode, stage.input.active_input()) {
        (ZkCommonCredentialRootPersonaMode::PrivatePersona, Input::PrivatePersonaClaim(input)) => {
            private_selected_claim_summary(input)
        }
        (ZkCommonCredentialRootPersonaMode::PublicPersona, Input::PublicPersonaClaim(input)) => {
            public_selected_claim_summary(input)
        }
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}

fn private_selected_claim_summary(
    input: &pb::ZkCommonCredentialRootPrivatePersonaClaimInput,
) -> Result<SelectedClaimSummary, ZkError> {
    let issuer_context = input
        .issuer_context
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let disclosure = input
        .disclosure
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let proof = input
        .proof
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let link = input
        .link
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(SelectedClaimSummary {
        issuer_public_key: public_key_field(&issuer_context.issuer_public_key)?,
        expiry_unix: issuer_context.expiry_unix,
        session_binding: bytes32_field(&input.session_binding)?,
        subject_join: bytes32_field(&input.subject_join)?,
        credential_binding: bytes32_field(&disclosure.credential_binding)?,
        envelope_hash: bytes32_field(&proof.envelope_hash)?,
        claims_root: bytes32_field(&proof.merkle_root)?,
        subject_public_key: public_key_field(&link.subject_public_key)?,
        persona_public_key: public_key_field(&link.persona_public_key)?,
    })
}

fn public_selected_claim_summary(
    input: &pb::ZkCommonCredentialRootPublicPersonaClaimInput,
) -> Result<SelectedClaimSummary, ZkError> {
    let issuer_context = input
        .issuer_context
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let disclosure = input
        .disclosure
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let proof = input
        .proof
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let link = input
        .link
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(SelectedClaimSummary {
        issuer_public_key: public_key_field(&issuer_context.issuer_public_key)?,
        expiry_unix: issuer_context.expiry_unix,
        session_binding: bytes32_field(&input.session_binding)?,
        subject_join: bytes32_field(&input.subject_join)?,
        credential_binding: bytes32_field(&disclosure.credential_binding)?,
        envelope_hash: bytes32_field(&proof.envelope_hash)?,
        claims_root: bytes32_field(&proof.merkle_root)?,
        subject_public_key: public_key_field(&link.subject_public_key)?,
        persona_public_key: public_key_field(&input.persona_public_key)?,
    })
}

fn session_summary(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    stage: &ZkCommonCredentialRootStageProveRequest,
) -> Result<SessionSourceSummary, ZkError> {
    use pb::zk_common_credential_root_stage_prove_operation::Input;

    match (persona_mode, stage.input.active_input()) {
        (
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            Input::PrivatePersonaSession(input),
        ) => {
            let context = input
                .session_context
                .as_option()
                .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
            let authorization = input
                .authorization
                .as_option()
                .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
            Ok(SessionSourceSummary {
                session_binding: bytes32_field(&context.session_binding)?,
                persona_public_key: public_key_field(&authorization.persona_public_key)?,
            })
        }
        (ZkCommonCredentialRootPersonaMode::PublicPersona, Input::PublicPersonaSession(input)) => {
            let context = input
                .session_context
                .as_option()
                .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
            Ok(SessionSourceSummary {
                session_binding: bytes32_field(&context.session_binding)?,
                persona_public_key: public_key_field(&input.persona_public_key)?,
            })
        }
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}

fn stage_for(
    stages: &[ZkCommonCredentialRootStageProveRequest],
    slot: ZkCommonCredentialRootProofSlot,
) -> Result<&ZkCommonCredentialRootStageProveRequest, ZkError> {
    stages
        .iter()
        .find(|stage| stage.plan.slot() == slot)
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))
}

fn root_attestation_stage(
    stage: &ZkCommonCredentialRootStageProveRequest,
) -> Result<&pb::ZkCommonCredentialRootAttestationInput, ZkError> {
    match stage.input.active_input() {
        pb::zk_common_credential_root_stage_prove_operation::Input::RootAttestation(input) => {
            Ok(input)
        }
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}

fn root_status_stage(
    stage: &ZkCommonCredentialRootStageProveRequest,
) -> Result<&pb::ZkCommonCredentialRootStatusInput, ZkError> {
    match stage.input.active_input() {
        pb::zk_common_credential_root_stage_prove_operation::Input::RootStatus(input) => Ok(input),
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}

fn lineage_stage(
    stage: &ZkCommonCredentialRootStageProveRequest,
) -> Result<&pb::ZkCommonCredentialRootLineageInput, ZkError> {
    match stage.input.active_input() {
        pb::zk_common_credential_root_stage_prove_operation::Input::Lineage(input) => Ok(input),
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}

fn issuer_status_stage(
    stage: &ZkCommonCredentialRootStageProveRequest,
) -> Result<&pb::ZkCommonCredentialRootIssuerCredentialStatusInput, ZkError> {
    match stage.input.active_input() {
        pb::zk_common_credential_root_stage_prove_operation::Input::IssuerCredentialStatus(
            input,
        ) => Ok(input),
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}
