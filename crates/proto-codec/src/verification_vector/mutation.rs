// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::DecodeOptions;
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkPublicInputDescriptor, ZkPublicInputName, ABSENT_TRANSACTION_DATA_HASH, MAX_PROOF_BYTES,
    },
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroize;

use crate::domain::circuit_ref_from_proto_message;
use crate::operation::MAX_ZK_PROTO_OPERATION_BYTES;

use super::{
    VerificationVectorMutation, VERIFICATION_VECTOR_ELEMENT_MEMORY_LIMIT,
    VERIFICATION_VECTOR_RECURSION_LIMIT, VERIFICATION_VECTOR_UNKNOWN_FIELD_LIMIT,
};

pub(super) fn decode_base_operation(
    bytes: &[u8],
) -> Result<pb::ZkProviderOperationRequest, ZkError> {
    DecodeOptions::new()
        .with_recursion_limit(VERIFICATION_VECTOR_RECURSION_LIMIT)
        .with_unknown_field_limit(VERIFICATION_VECTOR_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(VERIFICATION_VECTOR_ELEMENT_MEMORY_LIMIT)
        .with_max_message_size(MAX_ZK_PROTO_OPERATION_BYTES)
        .decode_from_slice(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))
}

pub(super) fn apply_mutation(
    request: &mut pb::ZkProviderOperationRequest,
    mutation: VerificationVectorMutation,
) -> Result<(), ZkError> {
    match mutation {
        VerificationVectorMutation::None => Ok(()),
        VerificationVectorMutation::EmptyProof => mutate_proof_bytes(request, Vec::new()),
        VerificationVectorMutation::ProofTooLarge => {
            let length = MAX_PROOF_BYTES
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
            bytes.resize(length, 0);
            mutate_proof_bytes(request, bytes)
        }
        VerificationVectorMutation::TamperedProof => {
            let proof = first_proof_mut(request)?;
            let first = proof
                .proof
                .first_mut()
                .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
            *first ^= 1;
            Ok(())
        }
        VerificationVectorMutation::MalformedPublicInputs => {
            let inputs = first_proof_mut(request)?
                .public_inputs
                .get_or_insert_default();
            inputs.encoded.zeroize();
            inputs.encoded.push(0);
            Ok(())
        }
        VerificationVectorMutation::WrongNonce => mutate_expected_binding(request, true),
        VerificationVectorMutation::WrongAudience => mutate_expected_binding(request, false),
        VerificationVectorMutation::WrongTransactionData => mutate_transaction_data(request),
        VerificationVectorMutation::UntrustedIssuer => mutate_trusted_issuer(request),
        VerificationVectorMutation::PresentationExpired => mutate_verification_time(request),
        VerificationVectorMutation::CredentialStatusPresent => mutate_credential_status(request),
        VerificationVectorMutation::WrongBundleSessionBinding => {
            mutate_bundle_session_binding(request)
        }
        VerificationVectorMutation::StaleArtifactManifest => {
            first_proof_mut(request)?.artifact_identity =
                Some(crate::artifact_identity::proof_identity_to_proto(
                    reallyme_zk_api::artifacts::ZkArtifactManifestDigest::from_bytes([0xa5; 32])
                        .into(),
                ));
            Ok(())
        }
        VerificationVectorMutation::UnsupportedCircuitRevision => {
            let circuit_ref = first_proof_mut(request)?
                .circuit_ref
                .get_or_insert_default();
            circuit_ref.circuit_revision =
                reallyme_zk_api::circuits::ZkCircuitRef::CURRENT_REVISION
                    .checked_add(1)
                    .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            Ok(())
        }
        VerificationVectorMutation::DuplicateStage => {
            let bundle = bundle_mut(request)?;
            let duplicate = bundle
                .claim_proof_bundle
                .get_or_insert_default()
                .stages
                .first()
                .cloned()
                .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
            let replacement = bundle
                .claim_proof_bundle
                .get_or_insert_default()
                .stages
                .last_mut()
                .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
            *replacement = duplicate;
            Ok(())
        }
        VerificationVectorMutation::MissingStage => {
            let removed = bundle_mut(request)?
                .claim_proof_bundle
                .get_or_insert_default()
                .stages
                .pop();
            if removed.is_none() {
                return Err(ZkError::new(ZkErrorReason::MissingStage));
            }
            Ok(())
        }
        VerificationVectorMutation::WrongStage => {
            let stage = bundle_mut(request)?
                .claim_proof_bundle
                .get_or_insert_default()
                .stages
                .first_mut()
                .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
            stage.stage = buffa::EnumValue::from(
                pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM,
            );
            Ok(())
        }
        VerificationVectorMutation::MixedHashLane => {
            let circuit_ref = first_proof_mut(request)?
                .circuit_ref
                .get_or_insert_default();
            circuit_ref.credential_hash_algorithm = match circuit_ref
                .credential_hash_algorithm
                .as_known()
            {
                Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256) => {
                    buffa::EnumValue::from(
                        pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2,
                    )
                }
                Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2) => {
                    buffa::EnumValue::from(
                        pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
                    )
                }
                Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_UNSPECIFIED)
                | None => {
                    return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
                }
            };
            Ok(())
        }
    }
}

fn mutate_proof_bytes(
    request: &mut pb::ZkProviderOperationRequest,
    bytes: Vec<u8>,
) -> Result<(), ZkError> {
    let proof = first_proof_mut(request)?;
    proof.proof.zeroize();
    proof.proof = bytes;
    Ok(())
}

fn first_proof_mut(
    request: &mut pb::ZkProviderOperationRequest,
) -> Result<&mut pb::ZkProofPackage, ZkError> {
    use pb::__buffa::oneof::zk_provider_operation_request::Operation;
    match request
        .operation
        .as_mut()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?
    {
        Operation::VerifyStage(stage) => Ok(stage.proof.get_or_insert_default()),
        Operation::VerifyClaimProofBundle(bundle) => Ok(bundle
            .claim_proof_bundle
            .get_or_insert_default()
            .stages
            .first_mut()
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))?
            .proof
            .get_or_insert_default()),
        Operation::ProveClaimProofBundle(_)
        | Operation::ProveRetainedClaimProofBundle(_)
        | Operation::ProveStage(_)
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

fn bundle_mut(
    request: &mut pb::ZkProviderOperationRequest,
) -> Result<&mut pb::ZkClaimProofBundleVerifyOperation, ZkError> {
    use pb::__buffa::oneof::zk_provider_operation_request::Operation;
    match request
        .operation
        .as_mut()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?
    {
        Operation::VerifyClaimProofBundle(bundle) => Ok(bundle),
        Operation::VerifyStage(_)
        | Operation::ProveClaimProofBundle(_)
        | Operation::ProveRetainedClaimProofBundle(_)
        | Operation::ProveStage(_)
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
            Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))
        }
    }
}

fn mutate_expected_binding(
    request: &mut pb::ZkProviderOperationRequest,
    nonce: bool,
) -> Result<(), ZkError> {
    let binding = expected_binding_mut(request)?;
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

fn mutate_transaction_data(request: &mut pb::ZkProviderOperationRequest) -> Result<(), ZkError> {
    let binding = expected_binding_mut(request)?;
    binding.transaction_data_hash.zeroize();
    binding
        .transaction_data_hash
        .extend_from_slice(&ABSENT_TRANSACTION_DATA_HASH);
    use pb::__buffa::oneof::zk_provider_operation_request::Operation;
    if let Some(Operation::VerifyClaimProofBundle(bundle)) = request.operation.as_mut() {
        let bundle_binding = bundle
            .claim_proof_bundle
            .get_or_insert_default()
            .session_binding
            .get_or_insert_default();
        bundle_binding.transaction_data_hash.zeroize();
        bundle_binding
            .transaction_data_hash
            .extend_from_slice(&ABSENT_TRANSACTION_DATA_HASH);
    }
    Ok(())
}

fn mutate_trusted_issuer(request: &mut pb::ZkProviderOperationRequest) -> Result<(), ZkError> {
    let bundle = bundle_mut(request)?;
    let issuer = bundle
        .trusted_issuers
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::UntrustedIssuer))?;
    let first = issuer
        .x
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    *first ^= 1;
    Ok(())
}

fn mutate_verification_time(request: &mut pb::ZkProviderOperationRequest) -> Result<(), ZkError> {
    let bundle = bundle_mut(request)?;
    bundle.verification_time_unix = bundle
        .verification_time_unix
        .checked_add(1)
        .ok_or(ZkError::new(ZkErrorReason::PresentationExpired))?;
    Ok(())
}

fn mutate_credential_status(request: &mut pb::ZkProviderOperationRequest) -> Result<(), ZkError> {
    let bundle = bundle_mut(request)?;
    bundle.credential_status_checked_at_unix = bundle.verification_time_unix.max(1);
    Ok(())
}

fn mutate_bundle_session_binding(
    request: &mut pb::ZkProviderOperationRequest,
) -> Result<(), ZkError> {
    let bundle = bundle_mut(request)?;
    mutate_binding_message(bundle.expected_binding.get_or_insert_default())?;
    mutate_binding_message(
        bundle
            .claim_proof_bundle
            .get_or_insert_default()
            .session_binding
            .get_or_insert_default(),
    )?;
    for stage in &mut bundle.claim_proof_bundle.get_or_insert_default().stages {
        let proof = stage.proof.get_or_insert_default();
        let circuit_ref = circuit_ref_from_proto_message(proof.circuit_ref.clone())?;
        let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
        let challenge_range = descriptor.field_range(ZkPublicInputName::Challenge)?;
        let first = proof
            .public_inputs
            .get_or_insert_default()
            .encoded
            .get_mut(challenge_range.start)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        *first ^= 1;
    }
    Ok(())
}

fn mutate_binding_message(binding: &mut pb::ZkSessionBinding) -> Result<(), ZkError> {
    let first = binding
        .nonce_hash
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::BindingMismatch))?;
    *first ^= 1;
    Ok(())
}

fn expected_binding_mut(
    request: &mut pb::ZkProviderOperationRequest,
) -> Result<&mut pb::ZkSessionBinding, ZkError> {
    use pb::__buffa::oneof::zk_provider_operation_request::Operation;
    match request
        .operation
        .as_mut()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?
    {
        Operation::VerifyStage(stage) => Ok(stage.expected_binding.get_or_insert_default()),
        Operation::VerifyClaimProofBundle(bundle) => {
            Ok(bundle.expected_binding.get_or_insert_default())
        }
        Operation::ProveClaimProofBundle(_)
        | Operation::ProveRetainedClaimProofBundle(_)
        | Operation::ProveStage(_)
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
