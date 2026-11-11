// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::DecodeOptions;
use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    proofs::{ABSENT_TRANSACTION_DATA_HASH, MAX_WITNESS_BYTES},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroize;

use super::{
    ProvingVectorMutation, MAX_ZK_PROVING_VECTOR_SET_BYTES, VECTOR_ELEMENT_MEMORY_LIMIT,
    VECTOR_RECURSION_LIMIT, VECTOR_UNKNOWN_FIELD_LIMIT,
};

pub(super) fn decode_base_operation(
    bytes: &[u8],
) -> Result<pb::ZkProviderOperationRequest, ZkError> {
    DecodeOptions::new()
        .with_recursion_limit(VECTOR_RECURSION_LIMIT)
        .with_unknown_field_limit(VECTOR_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(VECTOR_ELEMENT_MEMORY_LIMIT)
        .with_max_message_size(MAX_ZK_PROVING_VECTOR_SET_BYTES)
        .decode_from_slice(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))
}

pub(super) fn apply_mutation(
    request: &mut pb::ZkProviderOperationRequest,
    mutation: ProvingVectorMutation,
) -> Result<(), ZkError> {
    use pb::__buffa::oneof::zk_provider_operation_request::Operation;

    let operation = request
        .operation
        .as_mut()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?;
    match mutation {
        ProvingVectorMutation::None => Ok(()),
        ProvingVectorMutation::EmptyWitness => mutate_witness(operation, Vec::new()),
        ProvingVectorMutation::WitnessTooLarge => {
            let length = MAX_WITNESS_BYTES
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
            bytes.resize(length, 0);
            mutate_witness(operation, bytes)
        }
        ProvingVectorMutation::MalformedPublicInputs => {
            let Operation::ProveStage(stage) = operation else {
                return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
            };
            let public_inputs = stage.public_inputs.get_or_insert_default();
            public_inputs.encoded.zeroize();
            public_inputs.encoded.push(0);
            Ok(())
        }
        ProvingVectorMutation::WrongNonce => mutate_binding_byte(operation, true),
        ProvingVectorMutation::WrongAudience => mutate_binding_byte(operation, false),
        ProvingVectorMutation::WrongTransactionData => {
            let binding = operation_binding_mut(operation)?;
            binding.transaction_data_hash.zeroize();
            binding
                .transaction_data_hash
                .extend_from_slice(&ABSENT_TRANSACTION_DATA_HASH);
            Ok(())
        }
        ProvingVectorMutation::UnsupportedCircuitRevision => {
            let Operation::ProveStage(stage) = operation else {
                return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
            };
            let circuit_ref = stage.circuit_ref.get_or_insert_default();
            circuit_ref.circuit_revision = ZkCircuitRef::CURRENT_REVISION
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            Ok(())
        }
        ProvingVectorMutation::MissingStageWitness => {
            let witnesses = bundle_stage_witnesses_mut(operation)?;
            let removed = witnesses
                .pop()
                .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
            drop(removed);
            Ok(())
        }
        ProvingVectorMutation::ReorderedStageWitness => {
            let witnesses = bundle_stage_witnesses_mut(operation)?;
            if witnesses.len() < 2 {
                return Err(ZkError::new(ZkErrorReason::MissingStage));
            }
            witnesses.swap(0, 1);
            Ok(())
        }
        ProvingVectorMutation::CrossCircuitWitness => {
            let witnesses = bundle_stage_witnesses_mut(operation)?;
            if witnesses.len() < 2 {
                return Err(ZkError::new(ZkErrorReason::MissingStage));
            }
            let (first, remaining) = witnesses.split_at_mut(1);
            first[0].circuit_ref = remaining[0].circuit_ref.clone();
            Ok(())
        }
    }
}

fn bundle_stage_witnesses_mut(
    operation: &mut pb::__buffa::oneof::zk_provider_operation_request::Operation,
) -> Result<&mut Vec<pb::ZkWitness>, ZkError> {
    use pb::__buffa::oneof::zk_provider_operation_request::Operation;

    let Operation::ProveClaimProofBundle(bundle) = operation else {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    };
    Ok(&mut bundle
        .witness_bundle
        .get_or_insert_default()
        .stage_witnesses)
}

fn mutate_witness(
    operation: &mut pb::__buffa::oneof::zk_provider_operation_request::Operation,
    bytes: Vec<u8>,
) -> Result<(), ZkError> {
    use pb::__buffa::oneof::zk_provider_operation_request::Operation;

    let witness = match operation {
        Operation::ProveClaimProofBundle(bundle) => bundle
            .witness_bundle
            .get_or_insert_default()
            .stage_witnesses
            .first_mut()
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))?,
        Operation::ProveStage(stage) => stage.witness.get_or_insert_default(),
        Operation::ProveRetainedClaimProofBundle(_) => {
            return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
        }
        Operation::VerifyClaimProofBundle(_)
        | Operation::VerifyStage(_)
        | Operation::GetArtifactManifest(_)
        | Operation::WitnessStage(_)
        | Operation::ReleaseStageWitness(_)
        | Operation::VerifyCommonCredentialRoot(_)
        | Operation::VerifyStatusQualifiedClaimProofBundle(_)
        | Operation::ProveCommonCredentialRootStage(_)
        | Operation::ProveCommonCredentialRootPresentation(_)
        | Operation::VerifyPersonaCredentialEvidenceStage(_)
        | Operation::ProvePersonaCredentialEvidenceStage(_)
        | Operation::ProvePersonaCredentialEvidenceCurrentState(_)
        | Operation::ProvePersonaCredentialEvidenceIssuerEnvelope(_)
        | Operation::ProvePersonaCredentialEvidenceClaimRoot(_)
        | Operation::ProvePersonaCredentialEvidenceSignedValidity(_)
        | Operation::ProvePersonaCredentialEvidenceSelectedClaim(_)
        | Operation::PreparePersonaCredentialEvidencePresentationSigning(_)
        | Operation::AssemblePersonaCredentialEvidencePresentation(_) => {
            return Err(ZkError::new(ZkErrorReason::MissingOperation));
        }
    };
    witness.encoded.zeroize();
    witness.encoded = bytes;
    Ok(())
}

fn mutate_binding_byte(
    operation: &mut pb::__buffa::oneof::zk_provider_operation_request::Operation,
    nonce: bool,
) -> Result<(), ZkError> {
    use pb::__buffa::oneof::zk_provider_operation_request::Operation;

    if !matches!(operation, Operation::ProveStage(_)) {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }
    let binding = operation_binding_mut(operation)?;
    let bytes = if nonce {
        &mut binding.nonce_hash
    } else {
        &mut binding.audience_hash
    };
    let first = bytes
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::BindingMismatch))?;
    *first ^= 1;
    Ok(())
}

fn operation_binding_mut(
    operation: &mut pb::__buffa::oneof::zk_provider_operation_request::Operation,
) -> Result<&mut pb::ZkSessionBinding, ZkError> {
    use pb::__buffa::oneof::zk_provider_operation_request::Operation;

    match operation {
        Operation::ProveClaimProofBundle(bundle) => {
            Ok(bundle.session_binding.get_or_insert_default())
        }
        Operation::ProveRetainedClaimProofBundle(bundle) => {
            Ok(bundle.session_binding.get_or_insert_default())
        }
        Operation::ProveStage(stage) => Ok(stage.session_binding.get_or_insert_default()),
        Operation::VerifyClaimProofBundle(_)
        | Operation::VerifyStage(_)
        | Operation::GetArtifactManifest(_)
        | Operation::WitnessStage(_)
        | Operation::ReleaseStageWitness(_)
        | Operation::VerifyCommonCredentialRoot(_)
        | Operation::VerifyStatusQualifiedClaimProofBundle(_)
        | Operation::ProveCommonCredentialRootStage(_)
        | Operation::ProveCommonCredentialRootPresentation(_)
        | Operation::VerifyPersonaCredentialEvidenceStage(_)
        | Operation::ProvePersonaCredentialEvidenceStage(_)
        | Operation::ProvePersonaCredentialEvidenceCurrentState(_)
        | Operation::ProvePersonaCredentialEvidenceIssuerEnvelope(_)
        | Operation::ProvePersonaCredentialEvidenceClaimRoot(_)
        | Operation::ProvePersonaCredentialEvidenceSignedValidity(_)
        | Operation::ProvePersonaCredentialEvidenceSelectedClaim(_)
        | Operation::PreparePersonaCredentialEvidencePresentationSigning(_)
        | Operation::AssemblePersonaCredentialEvidencePresentation(_) => {
            Err(ZkError::new(ZkErrorReason::MissingOperation))
        }
    }
}
