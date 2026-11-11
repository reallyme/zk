// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProof, ZkSessionBinding},
};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

use crate::{
    artifact::{circuit_id_to_proto, circuit_ref_to_proto, proof_suite_to_proto},
    domain::CLAIM_PROOF_BUNDLE_FORMAT_VERSION,
    error::error_to_proto,
    release::{artifact_pin_to_proto, bundle_kind_to_proto, production_stage_to_proto},
};

use super::{
    decode_verification_vector_set, verification_request_sha256,
    ClaimProofBundleVerificationVectorInput, VerificationVectorMutation, ARTIFACTS_PER_VECTOR_SET,
    MAX_ZK_VERIFICATION_VECTOR_SET_BYTES, VERIFICATION_VECTOR_FORMAT_VERSION,
};

/// Encodes one positive bundle verification plus every stable negative case.
///
/// Each negative vector mutates the same verified base proof bundle. The
/// encoded result is re-decoded before return so release assembly cannot emit
/// a vector set that the public conformance boundary would reject.
pub fn encode_claim_proof_bundle_verification_vector_set(
    input: ClaimProofBundleVerificationVectorInput<'_>,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let cases = [
        (
            VerificationVectorMutation::EmptyProof,
            ZkErrorReason::EmptyInput,
        ),
        (
            VerificationVectorMutation::ProofTooLarge,
            ZkErrorReason::ProofTooLarge,
        ),
        (
            VerificationVectorMutation::TamperedProof,
            ZkErrorReason::InvalidProof,
        ),
        (
            VerificationVectorMutation::MalformedPublicInputs,
            ZkErrorReason::InvalidProofEncoding,
        ),
        (
            VerificationVectorMutation::WrongNonce,
            ZkErrorReason::BindingMismatch,
        ),
        (
            VerificationVectorMutation::WrongAudience,
            ZkErrorReason::BindingMismatch,
        ),
        (
            VerificationVectorMutation::WrongTransactionData,
            ZkErrorReason::BindingMismatch,
        ),
        (
            VerificationVectorMutation::UntrustedIssuer,
            ZkErrorReason::UntrustedIssuer,
        ),
        (
            VerificationVectorMutation::PresentationExpired,
            ZkErrorReason::PresentationExpired,
        ),
        (
            VerificationVectorMutation::CredentialStatusPresent,
            ZkErrorReason::MalformedProtobuf,
        ),
        (
            VerificationVectorMutation::WrongBundleSessionBinding,
            ZkErrorReason::BindingMismatch,
        ),
        (
            VerificationVectorMutation::StaleArtifactManifest,
            ZkErrorReason::ArtifactMismatch,
        ),
        (
            VerificationVectorMutation::UnsupportedCircuitRevision,
            ZkErrorReason::UnsupportedCircuit,
        ),
        (
            VerificationVectorMutation::DuplicateStage,
            ZkErrorReason::DuplicateStage,
        ),
        (
            VerificationVectorMutation::MissingStage,
            ZkErrorReason::MissingStage,
        ),
        (
            VerificationVectorMutation::WrongStage,
            ZkErrorReason::StageMismatch,
        ),
        (
            VerificationVectorMutation::MixedHashLane,
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
    vectors.push(verification_vector_to_proto(
        &input,
        1,
        VerificationVectorMutation::None,
        None,
    )?);
    for (index, (mutation, reason)) in cases.into_iter().enumerate() {
        let vector_number = u32::try_from(index)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
            .checked_add(2)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        vectors.push(verification_vector_to_proto(
            &input,
            vector_number,
            mutation,
            Some(reason),
        )?);
    }
    let vector_set = pb::ZkVerificationVectorSet {
        format_version: VERIFICATION_VECTOR_FORMAT_VERSION,
        bundle_kind: EnumValue::from(bundle_kind_to_proto(input.bundle_kind)),
        credential_hash_algorithm: EnumValue::from(
            crate::artifact::credential_hash_algorithm_to_proto(input.credential_hash_algorithm),
        ),
        proof_suite: EnumValue::from(proof_suite_to_proto(input.proof_suite)),
        artifact_manifests: input
            .artifact_manifests
            .iter()
            .copied()
            .map(artifact_pin_to_proto)
            .collect(),
        vectors,
        __buffa_unknown_fields: Default::default(),
    };
    let encoded = Zeroizing::new(vector_set.encode_to_vec());
    if encoded.len() > MAX_ZK_VERIFICATION_VECTOR_SET_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let _validated = decode_verification_vector_set(&encoded)?;
    Ok(encoded)
}

fn verification_vector_to_proto(
    input: &ClaimProofBundleVerificationVectorInput<'_>,
    vector_number: u32,
    mutation: VerificationVectorMutation,
    expected_error: Option<ZkErrorReason>,
) -> Result<pb::ZkVerificationVector, ZkError> {
    let base_operation = claim_proof_bundle_verify_operation_to_proto(input)?;
    let base_operation_bytes = Zeroizing::new(base_operation.encode_to_vec());
    let request_sha256 = verification_request_sha256(&base_operation_bytes, mutation)?;
    let expected_response = match expected_error {
        Some(reason) => error_response_to_proto(reason, request_sha256),
        None => success_response_to_proto(input, request_sha256)?,
    };
    Ok(pb::ZkVerificationVector {
        vector_number,
        mutation: EnumValue::from(mutation_to_proto(mutation)),
        base_operation: MessageField::some(base_operation),
        expected_response: MessageField::some(expected_response),
        __buffa_unknown_fields: Default::default(),
    })
}

fn claim_proof_bundle_verify_operation_to_proto(
    input: &ClaimProofBundleVerificationVectorInput<'_>,
) -> Result<pb::ZkProviderOperationRequest, ZkError> {
    let statement = input.claim_proof_bundle.decode_claimed_statement()?;
    let verification_time_unix = statement
        .presentation_expiry_unix()
        .checked_sub(1)
        .ok_or(ZkError::new(ZkErrorReason::PresentationExpired))?;
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(ARTIFACTS_PER_VECTOR_SET)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for stage_proof in input.claim_proof_bundle.stage_proofs() {
        stages.push(pb::ZkClaimProofBundleStageProofPackage {
            bundle_kind: EnumValue::from(bundle_kind_to_proto(input.bundle_kind)),
            stage: EnumValue::from(production_stage_to_proto(stage_proof.stage())),
            proof: MessageField::some(proof_to_proto(stage_proof.proof())?),
            __buffa_unknown_fields: Default::default(),
        });
    }
    let binding = input.claim_proof_bundle.session_binding();
    Ok(pb::ZkProviderOperationRequest {
        operation: Some(
            pb::__buffa::oneof::zk_provider_operation_request::Operation::VerifyClaimProofBundle(
                Box::new(pb::ZkClaimProofBundleVerifyOperation {
                    claim_proof_bundle: MessageField::some(pb::ZkClaimProofBundle {
                        bundle_kind: EnumValue::from(bundle_kind_to_proto(input.bundle_kind)),
                        format_version: CLAIM_PROOF_BUNDLE_FORMAT_VERSION,
                        stages,
                        session_binding: MessageField::some(session_binding_to_proto(binding)),
                        credential_hash_algorithm: EnumValue::from(
                            crate::artifact::credential_hash_algorithm_to_proto(
                                input.credential_hash_algorithm,
                            ),
                        ),
                        proof_suite: EnumValue::from(proof_suite_to_proto(input.proof_suite)),
                        __buffa_unknown_fields: Default::default(),
                    }),
                    expected_binding: MessageField::some(session_binding_to_proto(binding)),
                    trusted_issuers: vec![issuer_public_key_to_proto(statement.issuer())],
                    verification_time_unix,
                    credential_status_checked_at_unix: 0,
                    expected_proof_suite: EnumValue::from(proof_suite_to_proto(input.proof_suite)),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    })
}

fn proof_to_proto(proof: &ZkProof) -> Result<pb::ZkProofPackage, ZkError> {
    let circuit_ref = proof.circuit_ref();
    Ok(pb::ZkProofPackage {
        circuit_id: EnumValue::from(circuit_id_to_proto(proof.circuit_id())),
        circuit_id_string: proof.circuit_id().as_str().to_owned(),
        proof: proof.proof_bytes().to_vec(),
        public_inputs: MessageField::some(pb::ZkPublicInputs {
            encoded: proof.public_inputs().as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }),
        artifact_identity: Some(crate::artifact_identity::proof_identity_to_proto(
            proof.artifact_identity(),
        )),
        named_public_inputs: Vec::new(),
        circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
        proof_suite: EnumValue::from(proof_suite_to_proto(proof.proof_suite())),
        __buffa_unknown_fields: Default::default(),
    })
}

fn success_response_to_proto(
    input: &ClaimProofBundleVerificationVectorInput<'_>,
    request_sha256: Digest32,
) -> Result<pb::ZkProviderOperationResponse, ZkError> {
    let statement = input.claim_proof_bundle.decode_claimed_statement()?;
    let session_link_commitment = input.claim_proof_bundle.session_link_commitment()?;
    let verified_stage_count = u32::try_from(ARTIFACTS_PER_VECTOR_SET)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    Ok(pb::ZkProviderOperationResponse {
        outcome: Some(
            pb::__buffa::oneof::zk_provider_operation_response::Outcome::Result(Box::new(
                pb::ZkProviderOperationResult {
                    result: Some(
                        pb::__buffa::oneof::zk_provider_operation_result::Result::ClaimProofBundleVerification(
                            Box::new(pb::ZkPresentationBoundClaimBundleVerification {
                                bundle_kind: EnumValue::from(bundle_kind_to_proto(
                                    input.bundle_kind,
                                )),
                                verified_stage_count,
                                proof_suite: EnumValue::from(proof_suite_to_proto(
                                    input.proof_suite,
                                )),
                            statement: MessageField::some(claimed_statement_to_proto(
                                    &statement,
                                    session_link_commitment,
                                )?),
                                __buffa_unknown_fields: Default::default(),
                            }),
                        ),
                    ),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        request_sha256: request_sha256.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn issuer_public_key_to_proto(
    key: impl Into<reallyme_zk_api::keys::ZkP256PublicKey>,
) -> pb::ZkP256PublicKey {
    let key = key.into();
    pb::ZkP256PublicKey {
        x: key.x.to_vec(),
        y: key.y.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn claimed_statement_to_proto(
    statement: &reallyme_zk_api::claim_bundle::ZkClaimedStatement,
    session_link_commitment: [u8; 32],
) -> Result<pb::ZkPresentationBoundClaimStatement, ZkError> {
    let mut claim_value = vec![0u8; 64];
    let disclosed_value = statement.claim_value();
    claim_value[..disclosed_value.len()].copy_from_slice(disclosed_value);
    let claim_value_length = u32::try_from(disclosed_value.len())
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let persona = match statement.persona() {
        Some(persona) => MessageField::some(issuer_public_key_to_proto(persona)),
        None => MessageField::none(),
    };
    Ok(pb::ZkPresentationBoundClaimStatement {
        issuer: MessageField::some(issuer_public_key_to_proto(statement.issuer())),
        persona,
        claim_name_hash: statement.claim_name_hash().to_vec(),
        claim_value,
        claim_value_length,
        presentation_expiry_unix: statement.presentation_expiry_unix(),
        session_link_commitment: session_link_commitment.to_vec(),
        credential_binding: statement.credential_binding().to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn error_response_to_proto(
    reason: ZkErrorReason,
    request_sha256: Digest32,
) -> pb::ZkProviderOperationResponse {
    pb::ZkProviderOperationResponse {
        outcome: Some(
            pb::__buffa::oneof::zk_provider_operation_response::Outcome::Error(Box::new(
                error_to_proto(ZkError::new(reason)),
            )),
        ),
        request_sha256: request_sha256.as_bytes().to_vec(),
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

const fn mutation_to_proto(
    mutation: VerificationVectorMutation,
) -> pb::ZkVerificationVectorMutation {
    match mutation {
        VerificationVectorMutation::None => {
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE
        }
        VerificationVectorMutation::EmptyProof => {
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_EMPTY_PROOF
        }
        VerificationVectorMutation::ProofTooLarge => {
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_PROOF_TOO_LARGE
        }
        VerificationVectorMutation::TamperedProof => {
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_TAMPERED_PROOF
        }
        VerificationVectorMutation::MalformedPublicInputs => pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_MALFORMED_PUBLIC_INPUTS,
        VerificationVectorMutation::WrongNonce => {
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_NONCE
        }
        VerificationVectorMutation::WrongAudience => {
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_AUDIENCE
        }
        VerificationVectorMutation::WrongTransactionData => pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_TRANSACTION_DATA,
        VerificationVectorMutation::UntrustedIssuer => pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_UNTRUSTED_ISSUER,
        VerificationVectorMutation::PresentationExpired => pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_PRESENTATION_EXPIRED,
        VerificationVectorMutation::CredentialStatusPresent => pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_CREDENTIAL_STATUS_PRESENT,
        VerificationVectorMutation::WrongBundleSessionBinding => pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_BUNDLE_SESSION_BINDING,
        VerificationVectorMutation::StaleArtifactManifest => pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_STALE_ARTIFACT_MANIFEST,
        VerificationVectorMutation::UnsupportedCircuitRevision => pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_UNSUPPORTED_CIRCUIT_VERSION,
        VerificationVectorMutation::DuplicateStage => {
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_DUPLICATE_STAGE
        }
        VerificationVectorMutation::MissingStage => {
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_MISSING_STAGE
        }
        VerificationVectorMutation::WrongStage => {
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_STAGE
        }
        VerificationVectorMutation::MixedHashLane => {
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_MIXED_HASH_LANE
        }
    }
}
