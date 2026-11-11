// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, Message};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

use crate::{
    domain::{
        bundle_kind_from_family, bundle_kind_from_proto, credential_hash_algorithm_from_proto,
        proof_suite_from_proto,
    },
    operation::{operation_from_proto, ZkProviderOperation},
    release::{artifact_pin_from_proto, ReleaseArtifactPin, MAX_RELEASE_VERIFICATION_VECTORS},
    result::{
        operation_response_from_proto, ZkProviderOperationOutcome, ZkProviderOperationResult,
    },
};

use super::{
    verification_request_sha256, ExpectedVerificationOutcome, VerificationVector,
    VerificationVectorMutation, VerificationVectorSet, ARTIFACTS_PER_VECTOR_SET,
    MAX_ZK_VERIFICATION_VECTOR_SET_BYTES, VERIFICATION_VECTOR_ELEMENT_MEMORY_LIMIT,
    VERIFICATION_VECTOR_FORMAT_VERSION, VERIFICATION_VECTOR_RECURSION_LIMIT,
    VERIFICATION_VECTOR_UNKNOWN_FIELD_LIMIT,
};

/// Decodes untrusted canonical binary verification-vector bytes.
pub fn decode_verification_vector_set(bytes: &[u8]) -> Result<VerificationVectorSet, ZkError> {
    if bytes.is_empty() {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    if bytes.len() > MAX_ZK_VERIFICATION_VECTOR_SET_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let vector_set = DecodeOptions::new()
        .with_recursion_limit(VERIFICATION_VECTOR_RECURSION_LIMIT)
        .with_unknown_field_limit(VERIFICATION_VECTOR_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(VERIFICATION_VECTOR_ELEMENT_MEMORY_LIMIT)
        .with_max_message_size(MAX_ZK_VERIFICATION_VECTOR_SET_BYTES)
        .decode_from_slice::<pb::ZkVerificationVectorSet>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let canonical = Zeroizing::new(vector_set.encode_to_vec());
    let is_canonical = canonical.as_slice() == bytes;
    if !is_canonical {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    vector_set_from_proto(vector_set)
}

fn vector_set_from_proto(
    vector_set: pb::ZkVerificationVectorSet,
) -> Result<VerificationVectorSet, ZkError> {
    let maximum_vectors = usize::try_from(MAX_RELEASE_VERIFICATION_VECTORS)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if vector_set.format_version != VERIFICATION_VECTOR_FORMAT_VERSION
        || vector_set.vectors.is_empty()
        || vector_set.vectors.len() > maximum_vectors
    {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }
    let bundle_kind = bundle_kind_from_proto(vector_set.bundle_kind)?;
    let credential_hash_algorithm =
        credential_hash_algorithm_from_proto(vector_set.credential_hash_algorithm)?;
    let proof_suite = proof_suite_from_proto(vector_set.proof_suite)?;
    let artifact_manifests = validate_artifact_pins(
        vector_set.artifact_manifests,
        bundle_kind,
        credential_hash_algorithm,
    )?;

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
            &artifact_manifests,
        )?);
    }
    Ok(VerificationVectorSet {
        bundle_kind,
        credential_hash_algorithm,
        proof_suite,
        artifact_manifests,
        vectors,
    })
}

fn validate_artifact_pins(
    pins: Vec<pb::ZkReleaseArtifactPin>,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<Vec<ReleaseArtifactPin>, ZkError> {
    if pins.len() != ARTIFACTS_PER_VECTOR_SET {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let mut converted = Vec::new();
    converted
        .try_reserve_exact(ARTIFACTS_PER_VECTOR_SET)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for (index, pin) in pins.into_iter().enumerate() {
        let pin = artifact_pin_from_proto(pin)?;
        let expected_stage = ZkClaimProofBundleStage::ALL
            .get(index)
            .copied()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        if pin.bundle_kind() != bundle_kind
            || pin.stage() != expected_stage
            || pin.circuit_ref()
                != bundle_kind.source_ref(credential_hash_algorithm, expected_stage)
            || converted.iter().any(|existing: &ReleaseArtifactPin| {
                existing.manifest_sha256() == pin.manifest_sha256()
            })
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        converted.push(pin);
    }
    Ok(converted)
}

fn vector_from_proto(
    mut vector: pb::ZkVerificationVector,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    artifact_manifests: &[ReleaseArtifactPin],
) -> Result<VerificationVector, ZkError> {
    let mutation = mutation_from_proto(vector.mutation)?;
    let base_operation = vector
        .base_operation
        .take()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?;
    let encoded_base_operation = Zeroizing::new(base_operation.encode_to_vec());
    let operation_kind = validate_base_operation(
        operation_from_proto(base_operation)?,
        bundle_kind,
        credential_hash_algorithm,
        proof_suite,
        artifact_manifests,
    )?;
    let expected_response = operation_response_from_proto(
        vector
            .expected_response
            .take()
            .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?,
    )?;
    let expected_request_sha256 = expected_response.request_sha256();
    let expected_outcome = expected_response.into_outcome();
    validate_expected_outcome(
        mutation,
        operation_kind,
        &expected_outcome,
        bundle_kind,
        proof_suite,
    )?;
    if expected_request_sha256 != verification_request_sha256(&encoded_base_operation, mutation)? {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    Ok(VerificationVector {
        number: vector.vector_number,
        mutation,
        encoded_base_operation,
        expected_outcome: expected_outcome_from_provider(expected_outcome)?,
    })
}

enum VerificationOperationKind {
    Stage(reallyme_zk_api::circuits::ZkCircuitRef),
    Bundle(Box<reallyme_zk_api::claim_bundle::ZkClaimedStatement>),
}

#[derive(Debug, Clone, Copy)]
struct ProofPinExpectation {
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    stage: ZkClaimProofBundleStage,
}

fn validate_base_operation(
    operation: ZkProviderOperation,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    artifact_manifests: &[ReleaseArtifactPin],
) -> Result<VerificationOperationKind, ZkError> {
    match operation {
        ZkProviderOperation::VerifyStage { proof, .. } => {
            let circuit_ref = proof.circuit_ref();
            let stage = ZkClaimProofBundleStage::ALL
                .iter()
                .copied()
                .find(|stage| stage.source_stage() == circuit_ref.stage)
                .ok_or(ZkError::new(ZkErrorReason::StageMismatch))?;
            validate_proof_pin(
                ProofPinExpectation {
                    bundle_kind,
                    credential_hash_algorithm,
                    proof_suite,
                    stage,
                },
                circuit_ref,
                proof.proof_suite(),
                proof.artifact_identity(),
                artifact_manifests,
            )?;
            Ok(VerificationOperationKind::Stage(circuit_ref))
        }
        ZkProviderOperation::VerifyClaimProofBundle {
            claim_proof_bundle, ..
        } => {
            if claim_proof_bundle.bundle_kind() != bundle_kind
                || claim_proof_bundle.proof_suite() != proof_suite
            {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
            for stage_proof in claim_proof_bundle.stage_proofs() {
                let circuit_ref = stage_proof.proof().circuit_ref();
                validate_proof_pin(
                    ProofPinExpectation {
                        bundle_kind,
                        credential_hash_algorithm,
                        proof_suite,
                        stage: stage_proof.stage(),
                    },
                    circuit_ref,
                    stage_proof.proof().proof_suite(),
                    stage_proof.proof().artifact_identity(),
                    artifact_manifests,
                )?;
            }
            Ok(VerificationOperationKind::Bundle(Box::new(
                claim_proof_bundle.decode_claimed_statement()?,
            )))
        }
        ZkProviderOperation::ProveClaimProofBundle { .. }
        | ZkProviderOperation::ProveRetainedClaimProofBundle { .. }
        | ZkProviderOperation::VerifyStatusQualifiedClaimProofBundle { .. }
        | ZkProviderOperation::ProveStage { .. }
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

fn validate_proof_pin(
    expected: ProofPinExpectation,
    circuit_ref: reallyme_zk_api::circuits::ZkCircuitRef,
    actual_suite: ZkProofSuite,
    actual_manifest: reallyme_zk_api::artifacts::ZkArtifactIdentity,
    artifact_manifests: &[ReleaseArtifactPin],
) -> Result<(), ZkError> {
    let pin = artifact_manifests
        .get(usize::from(expected.stage.index()))
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    if bundle_kind_from_family(circuit_ref.family)? != expected.bundle_kind
        || circuit_ref
            != expected
                .bundle_kind
                .source_ref(expected.credential_hash_algorithm, expected.stage)
        || actual_suite != expected.proof_suite
        || reallyme_zk_api::artifacts::ZkArtifactIdentity::from(pin.manifest_sha256())
            != actual_manifest
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(())
}

fn mutation_from_proto(
    mutation: buffa::EnumValue<pb::ZkVerificationVectorMutation>,
) -> Result<VerificationVectorMutation, ZkError> {
    use pb::ZkVerificationVectorMutation as Mutation;
    match mutation.as_known() {
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE) => {
            Ok(VerificationVectorMutation::None)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_EMPTY_PROOF) => {
            Ok(VerificationVectorMutation::EmptyProof)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_PROOF_TOO_LARGE) => {
            Ok(VerificationVectorMutation::ProofTooLarge)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_TAMPERED_PROOF) => {
            Ok(VerificationVectorMutation::TamperedProof)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_MALFORMED_PUBLIC_INPUTS) => {
            Ok(VerificationVectorMutation::MalformedPublicInputs)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_NONCE) => {
            Ok(VerificationVectorMutation::WrongNonce)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_AUDIENCE) => {
            Ok(VerificationVectorMutation::WrongAudience)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_UNSUPPORTED_TRANSACTION_DATA)
        | Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_TRANSACTION_DATA) => {
            Ok(VerificationVectorMutation::WrongTransactionData)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_UNTRUSTED_ISSUER) => {
            Ok(VerificationVectorMutation::UntrustedIssuer)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_PRESENTATION_EXPIRED) => {
            Ok(VerificationVectorMutation::PresentationExpired)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_CREDENTIAL_STATUS_PRESENT) => {
            Ok(VerificationVectorMutation::CredentialStatusPresent)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_BUNDLE_SESSION_BINDING) => {
            Ok(VerificationVectorMutation::WrongBundleSessionBinding)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_STALE_ARTIFACT_MANIFEST) => {
            Ok(VerificationVectorMutation::StaleArtifactManifest)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_UNSUPPORTED_CIRCUIT_VERSION) => {
            Ok(VerificationVectorMutation::UnsupportedCircuitRevision)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_DUPLICATE_STAGE) => {
            Ok(VerificationVectorMutation::DuplicateStage)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_MISSING_STAGE) => {
            Ok(VerificationVectorMutation::MissingStage)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_STAGE) => {
            Ok(VerificationVectorMutation::WrongStage)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_MIXED_HASH_LANE) => {
            Ok(VerificationVectorMutation::MixedHashLane)
        }
        Some(Mutation::ZK_VERIFICATION_VECTOR_MUTATION_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))
        }
    }
}

fn validate_expected_outcome(
    mutation: VerificationVectorMutation,
    kind: VerificationOperationKind,
    outcome: &ZkProviderOperationOutcome,
    bundle_kind: ZkClaimProofBundleKind,
    proof_suite: ZkProofSuite,
) -> Result<(), ZkError> {
    if mutation == VerificationVectorMutation::None {
        return match (kind, outcome) {
            (
                VerificationOperationKind::Stage(expected_ref),
                ZkProviderOperationOutcome::Success(result),
            ) => match result.as_ref() {
                ZkProviderOperationResult::StageVerification(verification)
                    if verification.proof_suite == proof_suite
                        && verification.circuit_ref == Some(expected_ref) =>
                {
                    Ok(())
                }
                _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
            },
            (
                VerificationOperationKind::Bundle(expected_statement),
                ZkProviderOperationOutcome::Success(result),
            ) => match result.as_ref() {
                ZkProviderOperationResult::ClaimProofBundleVerification(verification)
                    if verification.bundle_kind == bundle_kind
                        && verification.proof_suite == proof_suite
                        && verification.statement == *expected_statement =>
                {
                    Ok(())
                }
                _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
            },
            _ => Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle)),
        };
    }
    if is_bundle_only_mutation(mutation) && !matches!(kind, VerificationOperationKind::Bundle(_)) {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }
    match outcome {
        ZkProviderOperationOutcome::Failure(error)
            if error.reason() == expected_mutation_error(mutation) =>
        {
            Ok(())
        }
        _ => Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle)),
    }
}

fn expected_outcome_from_provider(
    outcome: ZkProviderOperationOutcome,
) -> Result<ExpectedVerificationOutcome, ZkError> {
    match outcome {
        ZkProviderOperationOutcome::Failure(error) => Ok(ExpectedVerificationOutcome::Error(error)),
        ZkProviderOperationOutcome::Success(result) => match *result {
            ZkProviderOperationResult::StageVerification(verification) => {
                Ok(ExpectedVerificationOutcome::Stage(verification))
            }
            ZkProviderOperationResult::ClaimProofBundleVerification(verification) => {
                Ok(ExpectedVerificationOutcome::Bundle(verification))
            }
            ZkProviderOperationResult::ClaimProofBundle(_)
            | ZkProviderOperationResult::StatusQualifiedClaimProofBundleVerification(_)
            | ZkProviderOperationResult::StageProof(_)
            | ZkProviderOperationResult::ArtifactManifest(_)
            | ZkProviderOperationResult::StageWitness(_)
            | ZkProviderOperationResult::StageWitnessRelease(_)
            | ZkProviderOperationResult::CommonCredentialRootVerification(_)
            | ZkProviderOperationResult::CommonCredentialRootStageProof(_)
            | ZkProviderOperationResult::CommonCredentialRootPresentation(_)
            | ZkProviderOperationResult::PersonaCredentialEvidenceStageVerification(_)
            | ZkProviderOperationResult::PersonaCredentialEvidenceStageProof(_)
            | ZkProviderOperationResult::PersonaCredentialEvidencePresentationSigningChallenge(_)
            | ZkProviderOperationResult::PersonaCredentialEvidencePresentation(_) => {
                Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))
            }
        },
    }
}

const fn is_bundle_only_mutation(mutation: VerificationVectorMutation) -> bool {
    matches!(
        mutation,
        VerificationVectorMutation::DuplicateStage
            | VerificationVectorMutation::MissingStage
            | VerificationVectorMutation::WrongStage
            | VerificationVectorMutation::MixedHashLane
            | VerificationVectorMutation::UntrustedIssuer
            | VerificationVectorMutation::PresentationExpired
            | VerificationVectorMutation::CredentialStatusPresent
            | VerificationVectorMutation::WrongBundleSessionBinding
    )
}

const fn expected_mutation_error(mutation: VerificationVectorMutation) -> ZkErrorReason {
    match mutation {
        VerificationVectorMutation::None => ZkErrorReason::InvalidClaimProofBundle,
        VerificationVectorMutation::EmptyProof => ZkErrorReason::EmptyInput,
        VerificationVectorMutation::ProofTooLarge => ZkErrorReason::ProofTooLarge,
        VerificationVectorMutation::TamperedProof => ZkErrorReason::InvalidProof,
        VerificationVectorMutation::MalformedPublicInputs => ZkErrorReason::InvalidProofEncoding,
        VerificationVectorMutation::WrongNonce | VerificationVectorMutation::WrongAudience => {
            ZkErrorReason::BindingMismatch
        }
        VerificationVectorMutation::WrongTransactionData => ZkErrorReason::BindingMismatch,
        VerificationVectorMutation::UntrustedIssuer => ZkErrorReason::UntrustedIssuer,
        VerificationVectorMutation::PresentationExpired => ZkErrorReason::PresentationExpired,
        VerificationVectorMutation::CredentialStatusPresent => ZkErrorReason::MalformedProtobuf,
        VerificationVectorMutation::WrongBundleSessionBinding => ZkErrorReason::BindingMismatch,
        VerificationVectorMutation::UnsupportedCircuitRevision => ZkErrorReason::UnsupportedCircuit,
        VerificationVectorMutation::StaleArtifactManifest => ZkErrorReason::ArtifactMismatch,
        VerificationVectorMutation::DuplicateStage => ZkErrorReason::DuplicateStage,
        VerificationVectorMutation::MissingStage => ZkErrorReason::MissingStage,
        VerificationVectorMutation::WrongStage | VerificationVectorMutation::MixedHashLane => {
            ZkErrorReason::StageMismatch
        }
    }
}
