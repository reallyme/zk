// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, Message};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::ZkClaimProofBundleKind,
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProofMetadata, ZkProofSuite, ZkPublicInputs},
};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

use crate::{
    binding::session_binding_from_proto_message,
    domain::{
        bundle_kind_from_family, bundle_kind_from_proto, circuit_id_from_proto,
        circuit_ref_from_proto_message, credential_hash_algorithm_from_proto,
        production_stage_from_proto, proof_suite_from_proto,
    },
    error::error_from_proto,
    operation::{operation_from_proto, ZkProviderOperation},
};

use super::{
    ExpectedBundleProofShape, ExpectedProvingOutcome, ExpectedStageProofShape, ProvingVector,
    ProvingVectorMutation, ProvingVectorSet, MAX_PROVING_VECTORS, MAX_ZK_PROVING_VECTOR_SET_BYTES,
    PRODUCTION_STAGE_COUNT, PROVING_VECTOR_FORMAT_VERSION, VECTOR_ELEMENT_MEMORY_LIMIT,
    VECTOR_RECURSION_LIMIT, VECTOR_UNKNOWN_FIELD_LIMIT,
};

/// Decodes untrusted canonical binary proving-vector bytes.
pub fn decode_proving_vector_set(bytes: &[u8]) -> Result<ProvingVectorSet, ZkError> {
    if bytes.is_empty() {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    if bytes.len() > MAX_ZK_PROVING_VECTOR_SET_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }

    let vector_set = DecodeOptions::new()
        .with_recursion_limit(VECTOR_RECURSION_LIMIT)
        .with_unknown_field_limit(VECTOR_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(VECTOR_ELEMENT_MEMORY_LIMIT)
        .with_max_message_size(MAX_ZK_PROVING_VECTOR_SET_BYTES)
        .decode_from_slice::<pb::ZkProvingVectorSet>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;

    let canonical = Zeroizing::new(vector_set.encode_to_vec());
    let is_canonical = canonical.as_slice() == bytes;
    if !is_canonical {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }

    vector_set_from_proto(vector_set)
}

fn vector_set_from_proto(vector_set: pb::ZkProvingVectorSet) -> Result<ProvingVectorSet, ZkError> {
    if vector_set.format_version != PROVING_VECTOR_FORMAT_VERSION
        || vector_set.vectors.is_empty()
        || vector_set.vectors.len() > MAX_PROVING_VECTORS
    {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }
    let bundle_kind = bundle_kind_from_proto(vector_set.bundle_kind)?;
    let credential_hash_algorithm =
        credential_hash_algorithm_from_proto(vector_set.credential_hash_algorithm)?;
    let proof_suite = proof_suite_from_proto(vector_set.proof_suite)?;
    let mut vectors = Vec::new();
    vectors
        .try_reserve_exact(vector_set.vectors.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for (index, vector) in vector_set.vectors.into_iter().enumerate() {
        let expected_number = u32::try_from(index)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if vector.vector_number != expected_number {
            return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
        }
        vectors.push(vector_from_proto(
            vector,
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
        )?);
    }

    Ok(ProvingVectorSet {
        bundle_kind,
        credential_hash_algorithm,
        proof_suite,
        vectors,
    })
}

fn vector_from_proto(
    mut vector: pb::ZkProvingVector,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
) -> Result<ProvingVector, ZkError> {
    let mutation = mutation_from_proto(vector.mutation)?;
    let base_operation = vector
        .base_operation
        .take()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?;
    let encoded_base_operation = Zeroizing::new(base_operation.encode_to_vec());
    let domain_operation = operation_from_proto(base_operation)?;
    let operation_kind = validate_base_operation(
        &domain_operation,
        bundle_kind,
        credential_hash_algorithm,
        mutation,
    )?;
    drop(domain_operation);

    let expected_outcome = expected_outcome_from_proto(
        vector
            .expected_outcome
            .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?,
        bundle_kind,
        credential_hash_algorithm,
        proof_suite,
    )?;
    validate_mutation_outcome(mutation, operation_kind, &expected_outcome)?;

    Ok(ProvingVector {
        number: vector.vector_number,
        mutation,
        encoded_base_operation,
        expected_outcome,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProvingOperationKind {
    Stage,
    Bundle,
}

fn validate_base_operation(
    operation: &ZkProviderOperation,
    expected_profile: ZkClaimProofBundleKind,
    expected_credential_hash_algorithm: ZkCredentialHashAlgorithm,
    mutation: ProvingVectorMutation,
) -> Result<ProvingOperationKind, ZkError> {
    match operation {
        ZkProviderOperation::ProveStage { circuit_ref, .. } => {
            if bundle_kind_from_family(circuit_ref.family)? != expected_profile
                || circuit_ref.credential_hash_algorithm != expected_credential_hash_algorithm
            {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
            if matches!(
                mutation,
                ProvingVectorMutation::MissingStageWitness
                    | ProvingVectorMutation::ReorderedStageWitness
                    | ProvingVectorMutation::CrossCircuitWitness
            ) {
                return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
            }
            Ok(ProvingOperationKind::Stage)
        }
        ZkProviderOperation::ProveClaimProofBundle {
            bundle_kind,
            credential_hash_algorithm,
            ..
        }
        | ZkProviderOperation::ProveRetainedClaimProofBundle {
            bundle_kind,
            credential_hash_algorithm,
            ..
        } => {
            if *bundle_kind != expected_profile
                || *credential_hash_algorithm != expected_credential_hash_algorithm
            {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
            if matches!(
                mutation,
                ProvingVectorMutation::MalformedPublicInputs
                    | ProvingVectorMutation::WrongNonce
                    | ProvingVectorMutation::WrongAudience
                    | ProvingVectorMutation::UnsupportedCircuitRevision
            ) {
                return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
            }
            Ok(ProvingOperationKind::Bundle)
        }
        ZkProviderOperation::VerifyClaimProofBundle { .. }
        | ZkProviderOperation::VerifyStatusQualifiedClaimProofBundle { .. }
        | ZkProviderOperation::VerifyStage { .. }
        | ZkProviderOperation::GetArtifactManifest { .. }
        | ZkProviderOperation::WitnessStage { .. }
        | ZkProviderOperation::ReleaseStageWitness { .. }
        | ZkProviderOperation::VerifyCommonCredentialRoot { .. }
        | ZkProviderOperation::ProveCommonCredentialRootStage { .. }
        | ZkProviderOperation::ProveCommonCredentialRootPresentation { .. }
        | ZkProviderOperation::VerifyPersonaCredentialEvidenceStage { .. }
        | ZkProviderOperation::ProvePersonaCredentialEvidenceStage { .. }
        | ZkProviderOperation::ProvePersonaCredentialEvidenceCurrentState { .. }
        | ZkProviderOperation::ProvePersonaCredentialEvidenceIssuerEnvelope { .. }
        | ZkProviderOperation::ProvePersonaCredentialEvidenceClaimRoot { .. }
        | ZkProviderOperation::ProvePersonaCredentialEvidenceSignedValidity { .. }
        | ZkProviderOperation::ProvePersonaCredentialEvidenceSelectedClaim { .. }
        | ZkProviderOperation::PreparePersonaCredentialEvidencePresentationSigning { .. }
        | ZkProviderOperation::AssemblePersonaCredentialEvidencePresentation { .. } => {
            Err(ZkError::new(ZkErrorReason::MissingOperation))
        }
    }
}

fn mutation_from_proto(
    mutation: buffa::EnumValue<pb::ZkProvingVectorMutation>,
) -> Result<ProvingVectorMutation, ZkError> {
    match mutation.as_known() {
        Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_NONE) => {
            Ok(ProvingVectorMutation::None)
        }
        Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_EMPTY_WITNESS) => {
            Ok(ProvingVectorMutation::EmptyWitness)
        }
        Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WITNESS_TOO_LARGE) => {
            Ok(ProvingVectorMutation::WitnessTooLarge)
        }
        Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_MALFORMED_PUBLIC_INPUTS) => {
            Ok(ProvingVectorMutation::MalformedPublicInputs)
        }
        Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WRONG_NONCE) => {
            Ok(ProvingVectorMutation::WrongNonce)
        }
        Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WRONG_AUDIENCE) => {
            Ok(ProvingVectorMutation::WrongAudience)
        }
        Some(
            pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_UNSUPPORTED_TRANSACTION_DATA,
        )
        | Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WRONG_TRANSACTION_DATA) => {
            Ok(ProvingVectorMutation::WrongTransactionData)
        }
        Some(
            pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_UNSUPPORTED_CIRCUIT_VERSION,
        ) => Ok(ProvingVectorMutation::UnsupportedCircuitRevision),
        Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_MISSING_STAGE_WITNESS) => {
            Ok(ProvingVectorMutation::MissingStageWitness)
        }
        Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_REORDERED_STAGE_WITNESS) => {
            Ok(ProvingVectorMutation::ReorderedStageWitness)
        }
        Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_CROSS_CIRCUIT_WITNESS) => {
            Ok(ProvingVectorMutation::CrossCircuitWitness)
        }
        Some(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))
        }
    }
}

fn expected_outcome_from_proto(
    outcome: pb::__buffa::oneof::zk_proving_vector::ExpectedOutcome,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
) -> Result<ExpectedProvingOutcome, ZkError> {
    use pb::__buffa::oneof::zk_proving_vector::ExpectedOutcome;

    match outcome {
        ExpectedOutcome::StageProof(shape) => Ok(ExpectedProvingOutcome::Stage(
            expected_stage_from_proto(*shape, bundle_kind, credential_hash_algorithm, proof_suite)?,
        )),
        ExpectedOutcome::ClaimProofBundle(shape) => Ok(ExpectedProvingOutcome::Bundle(Box::new(
            expected_bundle_from_proto(
                *shape,
                bundle_kind,
                credential_hash_algorithm,
                proof_suite,
            )?,
        ))),
        ExpectedOutcome::Error(error) => {
            Ok(ExpectedProvingOutcome::Error(error_from_proto(*error)?))
        }
    }
}

fn expected_stage_from_proto(
    mut shape: pb::ZkExpectedStageProofShape,
    expected_profile: ZkClaimProofBundleKind,
    expected_credential_hash_algorithm: ZkCredentialHashAlgorithm,
    expected_suite: ZkProofSuite,
) -> Result<ExpectedStageProofShape, ZkError> {
    let bundle_kind = bundle_kind_from_proto(shape.bundle_kind)?;
    let stage = production_stage_from_proto(shape.stage)?;
    if bundle_kind != expected_profile {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let metadata = metadata_from_proto(
        shape
            .metadata
            .take()
            .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?,
    )?;
    let expected_ref = bundle_kind.source_ref(expected_credential_hash_algorithm, stage);
    if metadata.circuit_ref() != expected_ref
        || metadata.circuit_id() != bundle_kind.circuit_id()
        || metadata.proof_suite() != expected_suite
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let mut public_inputs = shape
        .public_inputs
        .take()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let public_inputs =
        ZkPublicInputs::try_from_bytes(core::mem::take(&mut public_inputs.encoded))?;
    let session_binding = session_binding_from_proto_message(shape.session_binding)?;
    session_binding.decode_and_validate(expected_ref, &public_inputs)?;

    Ok(ExpectedStageProofShape {
        bundle_kind,
        stage,
        metadata,
        public_inputs,
        session_binding,
    })
}

fn expected_bundle_from_proto(
    shape: pb::ZkExpectedClaimProofBundleProofShape,
    expected_profile: ZkClaimProofBundleKind,
    expected_credential_hash_algorithm: ZkCredentialHashAlgorithm,
    expected_suite: ZkProofSuite,
) -> Result<ExpectedBundleProofShape, ZkError> {
    let bundle_kind = bundle_kind_from_proto(shape.bundle_kind)?;
    let credential_hash_algorithm =
        credential_hash_algorithm_from_proto(shape.credential_hash_algorithm)?;
    let proof_suite = proof_suite_from_proto(shape.proof_suite)?;
    let session_binding = session_binding_from_proto_message(shape.session_binding)?;
    if bundle_kind != expected_profile
        || credential_hash_algorithm != expected_credential_hash_algorithm
        || proof_suite != expected_suite
        || shape.stages.len() != PRODUCTION_STAGE_COUNT
    {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }

    let mut stages = Vec::new();
    stages
        .try_reserve_exact(PRODUCTION_STAGE_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for (index, stage_shape) in shape.stages.into_iter().enumerate() {
        let stage = expected_stage_from_proto(
            stage_shape,
            expected_profile,
            expected_credential_hash_algorithm,
            expected_suite,
        )?;
        if stage.stage.index()
            != u8::try_from(index).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
            || stage.session_binding != session_binding
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        stages.push(stage);
    }
    let stages: [ExpectedStageProofShape; PRODUCTION_STAGE_COUNT] = stages
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?;

    Ok(ExpectedBundleProofShape {
        bundle_kind,
        credential_hash_algorithm,
        proof_suite,
        session_binding,
        stages,
    })
}

fn metadata_from_proto(mut metadata: pb::ZkProofMetadata) -> Result<ZkProofMetadata, ZkError> {
    let circuit_id = circuit_id_from_proto(metadata.circuit_id)?;
    if metadata.circuit_id_string != circuit_id.as_str() {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let circuit_ref = circuit_ref_from_proto_message(core::mem::take(&mut metadata.circuit_ref))?;
    let proof_suite = proof_suite_from_proto(metadata.proof_suite)?;
    let verification_key_sha256_bytes = core::mem::take(&mut metadata.verification_key_sha256);
    let verification_key_sha256 = Digest32::from_bytes(
        verification_key_sha256_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?,
    );
    if circuit_ref.circuit_id() != circuit_id {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }

    Ok(ZkProofMetadata::new(
        circuit_ref,
        *verification_key_sha256.as_bytes(),
        proof_suite,
    ))
}

fn validate_mutation_outcome(
    mutation: ProvingVectorMutation,
    operation_kind: ProvingOperationKind,
    outcome: &ExpectedProvingOutcome,
) -> Result<(), ZkError> {
    match (mutation, operation_kind, outcome) {
        (
            ProvingVectorMutation::None,
            ProvingOperationKind::Stage,
            ExpectedProvingOutcome::Stage(_),
        )
        | (
            ProvingVectorMutation::None,
            ProvingOperationKind::Bundle,
            ExpectedProvingOutcome::Bundle(_),
        ) => Ok(()),
        (ProvingVectorMutation::None, _, _) => {
            Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))
        }
        (_, _, ExpectedProvingOutcome::Error(error))
            if error.reason() == expected_mutation_error(mutation) =>
        {
            Ok(())
        }
        _ => Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle)),
    }
}

const fn expected_mutation_error(mutation: ProvingVectorMutation) -> ZkErrorReason {
    match mutation {
        ProvingVectorMutation::None => ZkErrorReason::InvalidClaimProofBundle,
        ProvingVectorMutation::EmptyWitness => ZkErrorReason::EmptyInput,
        ProvingVectorMutation::WitnessTooLarge => ZkErrorReason::WitnessTooLarge,
        ProvingVectorMutation::MalformedPublicInputs => ZkErrorReason::InvalidProofEncoding,
        ProvingVectorMutation::WrongNonce | ProvingVectorMutation::WrongAudience => {
            ZkErrorReason::BindingMismatch
        }
        ProvingVectorMutation::WrongTransactionData => ZkErrorReason::BindingMismatch,
        ProvingVectorMutation::UnsupportedCircuitRevision => ZkErrorReason::UnsupportedCircuit,
        ProvingVectorMutation::MissingStageWitness => ZkErrorReason::MissingStage,
        ProvingVectorMutation::ReorderedStageWitness
        | ProvingVectorMutation::CrossCircuitWitness => ZkErrorReason::StageMismatch,
    }
}
