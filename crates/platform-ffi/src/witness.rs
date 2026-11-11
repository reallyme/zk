// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod common_credential_root;
mod input;
mod persona_credential_evidence;
mod public_inputs;

pub(crate) use common_credential_root::generate_common_credential_root_stage_witness;
pub(crate) use persona_credential_evidence::{
    generate_persona_credential_evidence_claim_root_witness,
    generate_persona_credential_evidence_current_state_witness,
    generate_persona_credential_evidence_issuer_envelope_witness,
    generate_persona_credential_evidence_selected_claim_witness,
    generate_persona_credential_evidence_signed_validity_witness,
};

use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage},
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkPublicInputs, ZkSessionBinding, ZkWitness},
};
use reallyme_zk_backend_bb::BbStageArtifacts;
use reallyme_zk_noir_witness_core::{
    circuits::{
        credential_envelope_v1::generate_witness_from_artifact_json as generate_credential_envelope_witness,
        credential_root_v1::generate_witness_from_artifact_json as generate_credential_root_witness,
        credential_subject_claim_v1_claim::generate_witness_from_artifact_json as generate_credential_subject_claim_witness,
        credential_subject_claim_v1_session::generate_witness_from_artifact_json as generate_private_session_witness,
        private_persona_claim_v1_claim::generate_witness_from_artifact_json as generate_private_persona_claim_witness,
        private_persona_claim_v1_session::generate_witness_from_artifact_json as generate_private_persona_session_witness,
    },
    CompiledProgramArtifactJson, SerializedWitnessStack, WitnessError, WitnessErrorReason,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::ZkStageWitnessInputOwner;

use self::input::{
    credential_envelope_inputs, credential_root_inputs, credential_subject_claim_inputs,
    private_persona_claim_inputs, private_persona_session_inputs, private_session_inputs,
};
use self::public_inputs::{
    credential_envelope_public_inputs, credential_root_public_inputs,
    credential_subject_claim_public_inputs, private_persona_session_public_inputs,
    private_session_public_inputs, session_binding_from_public_inputs,
};

pub(crate) struct GeneratedStageWitness {
    pub(crate) witness: ZkWitness,
    pub(crate) public_inputs: ZkPublicInputs,
    pub(crate) session_binding: ZkSessionBinding,
}

pub(crate) fn generate_stage_witness(
    circuit_ref: ZkCircuitRef,
    artifacts: &BbStageArtifacts,
    input: ZkStageWitnessInputOwner,
) -> Result<GeneratedStageWitness, ZkError> {
    let artifact_json =
        CompiledProgramArtifactJson::try_from_bytes(artifacts.bytecode().as_bytes())
            .map_err(map_witness_error)?;
    let input = input
        .active_input()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;

    use pb::zk_stage_witness_input::Input;
    match input {
        Input::CredentialSubjectClaimSession(input) => {
            ensure_ref(
                circuit_ref,
                ZkCircuitFamily::CredentialSubjectClaimV1,
                ZkCircuitStage::Session,
            )?;
            let inputs = private_session_inputs(input)?;
            finish(
                circuit_ref,
                private_session_public_inputs(circuit_ref, &inputs.public_inputs.session_context)?,
                generate_private_session_witness(artifact_json, &inputs),
            )
        }
        Input::PrivatePersonaSession(input) => {
            ensure_ref(
                circuit_ref,
                ZkCircuitFamily::PrivatePersonaClaimV1,
                ZkCircuitStage::Session,
            )?;
            let inputs = private_persona_session_inputs(input)?;
            finish(
                circuit_ref,
                private_persona_session_public_inputs(
                    circuit_ref,
                    &inputs.public_inputs.session_context,
                )?,
                generate_private_persona_session_witness(artifact_json, &inputs),
            )
        }
        Input::CredentialEnvelope(input) => {
            ensure_stage(circuit_ref, ZkCircuitStage::CredentialEnvelope)?;
            let inputs = credential_envelope_inputs(input)?;
            finish(
                circuit_ref,
                credential_envelope_public_inputs(circuit_ref, &inputs.public_inputs)?,
                generate_credential_envelope_witness(artifact_json, &inputs),
            )
        }
        Input::CredentialRoot(input) => {
            ensure_stage(circuit_ref, ZkCircuitStage::CredentialRoot)?;
            let inputs = credential_root_inputs(input)?;
            finish(
                circuit_ref,
                credential_root_public_inputs(circuit_ref, &inputs.public_inputs)?,
                generate_credential_root_witness(artifact_json, &inputs),
            )
        }
        Input::CredentialSubjectClaim(input) => {
            ensure_ref(
                circuit_ref,
                ZkCircuitFamily::CredentialSubjectClaimV1,
                ZkCircuitStage::Claim,
            )?;
            let inputs = credential_subject_claim_inputs(input)?;
            finish(
                circuit_ref,
                credential_subject_claim_public_inputs(circuit_ref, &inputs.public_inputs)?,
                generate_credential_subject_claim_witness(artifact_json, &inputs),
            )
        }
        Input::PrivatePersonaClaim(input) => {
            ensure_ref(
                circuit_ref,
                ZkCircuitFamily::PrivatePersonaClaimV1,
                ZkCircuitStage::Claim,
            )?;
            let inputs = private_persona_claim_inputs(input)?;
            finish(
                circuit_ref,
                credential_subject_claim_public_inputs(circuit_ref, &inputs.public_inputs)?,
                generate_private_persona_claim_witness(artifact_json, &inputs),
            )
        }
    }
}

fn finish(
    circuit_ref: ZkCircuitRef,
    public_inputs: ZkPublicInputs,
    witness: Result<SerializedWitnessStack, WitnessError>,
) -> Result<GeneratedStageWitness, ZkError> {
    let session_binding = session_binding_from_public_inputs(circuit_ref, &public_inputs)?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1_zeroizing(
        circuit_ref,
        witness.map_err(map_witness_error)?.into_zeroizing_bytes(),
    )?;
    Ok(GeneratedStageWitness {
        witness,
        public_inputs,
        session_binding,
    })
}

fn ensure_ref(
    circuit_ref: ZkCircuitRef,
    family: ZkCircuitFamily,
    stage: ZkCircuitStage,
) -> Result<(), ZkError> {
    if circuit_ref.family == family && circuit_ref.stage == stage {
        Ok(())
    } else {
        Err(ZkError::new(ZkErrorReason::StageMismatch))
    }
}

fn ensure_stage(circuit_ref: ZkCircuitRef, stage: ZkCircuitStage) -> Result<(), ZkError> {
    if circuit_ref.stage == stage {
        Ok(())
    } else {
        Err(ZkError::new(ZkErrorReason::StageMismatch))
    }
}

fn map_witness_error(error: WitnessError) -> ZkError {
    match error.reason {
        WitnessErrorReason::ArtifactEmpty => ZkError::new(ZkErrorReason::EmptyInput),
        WitnessErrorReason::ArtifactTooLarge => ZkError::new(ZkErrorReason::ArtifactTooLarge),
        WitnessErrorReason::ClaimValueLengthOutOfRange
        | WitnessErrorReason::MerklePathLengthOutOfRange
        | WitnessErrorReason::CommonCredentialRootStatusPathLengthOutOfRange
        | WitnessErrorReason::PreparedStatusInputOutOfRange
        | WitnessErrorReason::PreparedClaimInputOutOfRange
        | WitnessErrorReason::ClaimBundleCountOutOfRange => {
            ZkError::new(ZkErrorReason::ClaimPayloadTooLarge)
        }
        WitnessErrorReason::ArtifactUtf8Invalid
        | WitnessErrorReason::ArtifactJsonInvalid
        | WitnessErrorReason::ArtifactAbiMismatch => ZkError::new(ZkErrorReason::ArtifactMismatch),
        WitnessErrorReason::AbiEncodingFailed => ZkError::new(ZkErrorReason::InvalidProofEncoding),
        WitnessErrorReason::CircuitExecutionFailed
        | WitnessErrorReason::ForeignCallResolutionFailed
        | WitnessErrorReason::RequiredFixtureRootMissing
        | WitnessErrorReason::WitnessSerializationFailed => {
            ZkError::new(ZkErrorReason::BackendFailure)
        }
    }
}
