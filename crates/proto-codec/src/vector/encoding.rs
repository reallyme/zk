// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::ZkCircuitId,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkSessionBinding,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

use crate::artifact::{
    circuit_ref_to_proto, credential_hash_algorithm_to_proto, proof_suite_to_proto,
};

use super::{
    decode_proving_vector_set, BundleProvingVectorInput, StageProvingVectorInput,
    MAX_ZK_PROVING_VECTOR_SET_BYTES, PRODUCTION_STAGE_COUNT, PROVING_VECTOR_FORMAT_VERSION,
};

/// Encodes a canonical real-material bundle vector set.
///
/// Every negative case is a deterministic mutation of the same validated base
/// operation; alternate unchecked witness envelopes never enter the builder.
pub fn encode_bundle_proving_vector_set(
    input: BundleProvingVectorInput<'_>,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let cases = [
        (
            pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_EMPTY_WITNESS,
            ZkErrorReason::EmptyInput,
        ),
        (
            pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WITNESS_TOO_LARGE,
            ZkErrorReason::WitnessTooLarge,
        ),
        (
            pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WRONG_TRANSACTION_DATA,
            ZkErrorReason::BindingMismatch,
        ),
        (
            pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_MISSING_STAGE_WITNESS,
            ZkErrorReason::MissingStage,
        ),
        (
            pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_REORDERED_STAGE_WITNESS,
            ZkErrorReason::StageMismatch,
        ),
        (
            pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_CROSS_CIRCUIT_WITNESS,
            ZkErrorReason::StageMismatch,
        ),
    ];
    let mut vectors = Vec::new();
    vectors
        .try_reserve_exact(
            cases
                .len()
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?,
        )
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    vectors.push(pb::ZkProvingVector {
        vector_number: 1,
        mutation: EnumValue::from(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_NONE),
        base_operation: MessageField::some(bundle_operation_to_proto(&input)?),
        expected_outcome: Some(
            pb::__buffa::oneof::zk_proving_vector::ExpectedOutcome::ClaimProofBundle(Box::new(
                expected_bundle_to_proto(&input),
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    });
    for (index, (mutation, reason)) in cases.into_iter().enumerate() {
        let vector_number = u32::try_from(index)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
            .checked_add(2)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        vectors.push(pb::ZkProvingVector {
            vector_number,
            mutation: EnumValue::from(mutation),
            base_operation: MessageField::some(bundle_operation_to_proto(&input)?),
            expected_outcome: Some(
                pb::__buffa::oneof::zk_proving_vector::ExpectedOutcome::Error(Box::new(
                    crate::error::error_to_proto(ZkError::new(reason)),
                )),
            ),
            __buffa_unknown_fields: Default::default(),
        });
    }
    let vector_set = pb::ZkProvingVectorSet {
        format_version: PROVING_VECTOR_FORMAT_VERSION,
        bundle_kind: EnumValue::from(bundle_kind_to_proto(input.bundle_kind)),
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm_to_proto(
            input.credential_hash_algorithm,
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(input.proof_suite)),
        vectors,
        __buffa_unknown_fields: Default::default(),
    };
    let encoded = Zeroizing::new(vector_set.encode_to_vec());
    if encoded.len() > MAX_ZK_PROVING_VECTOR_SET_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let _validated = decode_proving_vector_set(&encoded)?;
    Ok(encoded)
}

fn bundle_operation_to_proto(
    input: &BundleProvingVectorInput<'_>,
) -> Result<pb::ZkProviderOperationRequest, ZkError> {
    let mut stage_witnesses = Vec::new();
    stage_witnesses
        .try_reserve_exact(PRODUCTION_STAGE_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for stage in ZkClaimProofBundleStage::ALL {
        let witness = input.witness_bundle.stage_witness(*stage)?;
        stage_witnesses.push(pb::ZkWitness {
            encoded: witness.expose_bytes().to_vec(),
            circuit_ref: MessageField::some(circuit_ref_to_proto(witness.circuit_ref())),
            encoding: EnumValue::from(
                pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1,
            ),
            __buffa_unknown_fields: Default::default(),
        });
    }

    Ok(pb::ZkProviderOperationRequest {
        operation: Some(
            pb::__buffa::oneof::zk_provider_operation_request::Operation::ProveClaimProofBundle(
                Box::new(pb::ZkClaimProofBundleProveOperation {
                    bundle_kind: EnumValue::from(bundle_kind_to_proto(input.bundle_kind)),
                    credential_hash_algorithm: EnumValue::from(credential_hash_algorithm_to_proto(
                        input.credential_hash_algorithm,
                    )),
                    proof_suite: EnumValue::from(proof_suite_to_proto(input.proof_suite)),
                    session_binding: MessageField::some(session_binding_to_proto(
                        input.session_binding,
                    )),
                    witness_bundle: MessageField::some(pb::ZkClaimProofBundleWitness {
                        bundle_kind: EnumValue::from(bundle_kind_to_proto(input.bundle_kind)),
                        credential_hash_algorithm: EnumValue::from(
                            credential_hash_algorithm_to_proto(input.credential_hash_algorithm),
                        ),
                        stage_witnesses,
                        __buffa_unknown_fields: Default::default(),
                    }),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    })
}

fn expected_bundle_to_proto(
    input: &BundleProvingVectorInput<'_>,
) -> pb::ZkExpectedClaimProofBundleProofShape {
    pb::ZkExpectedClaimProofBundleProofShape {
        bundle_kind: EnumValue::from(bundle_kind_to_proto(input.bundle_kind)),
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm_to_proto(
            input.credential_hash_algorithm,
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(input.proof_suite)),
        session_binding: MessageField::some(session_binding_to_proto(input.session_binding)),
        stages: input
            .stages
            .iter()
            .map(|stage| expected_stage_to_proto(input, *stage))
            .collect(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn expected_stage_to_proto(
    input: &BundleProvingVectorInput<'_>,
    stage: StageProvingVectorInput<'_>,
) -> pb::ZkExpectedStageProofShape {
    let circuit_ref = input
        .bundle_kind
        .source_ref(input.credential_hash_algorithm, stage.stage);
    let circuit_id = circuit_ref.circuit_id();
    pb::ZkExpectedStageProofShape {
        bundle_kind: EnumValue::from(bundle_kind_to_proto(input.bundle_kind)),
        stage: EnumValue::from(production_stage_to_proto(stage.stage)),
        metadata: MessageField::some(pb::ZkProofMetadata {
            circuit_id: EnumValue::from(circuit_id_to_proto(circuit_id)),
            circuit_id_string: circuit_id.as_str().to_owned(),
            verification_key_sha256: stage.verification_key_sha256.to_vec(),
            circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
            proof_suite: EnumValue::from(proof_suite_to_proto(input.proof_suite)),
            __buffa_unknown_fields: Default::default(),
        }),
        public_inputs: MessageField::some(pb::ZkPublicInputs {
            encoded: stage.public_inputs.as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }),
        session_binding: MessageField::some(session_binding_to_proto(input.session_binding)),
        __buffa_unknown_fields: Default::default(),
    }
}

fn session_binding_to_proto(binding: ZkSessionBinding) -> pb::ZkSessionBinding {
    pb::ZkSessionBinding {
        nonce_hash: binding.nonce_hash.to_vec(),
        audience_hash: binding.audience_hash.to_vec(),
        transaction_data_hash: binding
            .transaction_data_hash
            .map_or_else(Vec::new, |hash| hash.to_vec()),
        __buffa_unknown_fields: Default::default(),
    }
}

const fn bundle_kind_to_proto(bundle_kind: ZkClaimProofBundleKind) -> pb::ZkClaimProofBundleKind {
    match bundle_kind {
        ZkClaimProofBundleKind::CredentialSubjectClaimV1 => {
            pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1
        }
        ZkClaimProofBundleKind::PrivatePersonaClaimV1 => {
            pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1
        }
        _ => pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_UNSPECIFIED,
    }
}

const fn production_stage_to_proto(stage: ZkClaimProofBundleStage) -> pb::ZkClaimProofBundleStage {
    match stage {
        ZkClaimProofBundleStage::Session => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION
        }
        ZkClaimProofBundleStage::CredentialEnvelope => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE
        }
        ZkClaimProofBundleStage::CredentialRoot => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT
        }
        ZkClaimProofBundleStage::Claim => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM
        }
        _ => pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_UNSPECIFIED,
    }
}

const fn circuit_id_to_proto(circuit_id: ZkCircuitId) -> pb::ZkCircuitId {
    match circuit_id {
        ZkCircuitId::CredentialSubjectClaimV1 => {
            pb::ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1
        }
        ZkCircuitId::PrivatePersonaClaimV1 => {
            pb::ZkCircuitId::ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1
        }
        ZkCircuitId::CommonCredentialRootV1 => {
            pb::ZkCircuitId::ZK_CIRCUIT_ID_COMMON_CREDENTIAL_ROOT_V1
        }
        ZkCircuitId::PersonaCredentialEvidenceV1 => {
            pb::ZkCircuitId::ZK_CIRCUIT_ID_PERSONA_CREDENTIAL_EVIDENCE_V1
        }
        _ => pb::ZkCircuitId::ZK_CIRCUIT_ID_UNSPECIFIED,
    }
}
