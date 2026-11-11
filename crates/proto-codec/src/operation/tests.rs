// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    bundle::validate_trusted_issuer_count, decode_operation_request,
    encode_sensitive_operation_request, secret_cleanup::zeroize_operation_request_proto,
    ZkProviderOperation, ZkSensitiveProviderRequest,
};
use buffa::{EnumValue, MessageField};
use reallyme_zk_api::{claim_bundle::MAX_TRUSTED_ISSUERS, errors::ZkErrorReason};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    zk_provider_operation_request::Operation, ZkArtifactManifestOperation, ZkCircuitFamily,
    ZkCircuitRef, ZkCircuitStage, ZkClaimProofBundleProveOperation, ZkClaimProofBundleWitness,
    ZkCommonCredentialRootLineageInput, ZkCommonCredentialRootPrivatePersonaClaimInput,
    ZkCommonCredentialRootStageProveOperation, ZkCredentialHashAlgorithm, ZkInputClaimDisclosure,
    ZkInputCommonCredentialRootLineageWitness, ZkInputMerkleClaimProof, ZkInputMerklePath,
    ZkProofSuite, ZkProviderOperationRequest, ZkStageProveOperation, ZkWitness, ZkWitnessEncoding,
};

#[test]
fn trusted_issuer_count_has_stable_boundaries() {
    assert!(matches!(
        validate_trusted_issuer_count(0),
        Err(error) if error.reason() == ZkErrorReason::UntrustedIssuer
    ));
    assert!(validate_trusted_issuer_count(MAX_TRUSTED_ISSUERS).is_ok());
    assert!(matches!(
        validate_trusted_issuer_count(MAX_TRUSTED_ISSUERS.saturating_add(1)),
        Err(error) if error.reason() == ZkErrorReason::PublicKeyTooLarge
    ));
}

#[test]
fn request_cleanup_reaches_stage_prove_witness_bytes() {
    let mut request = ZkProviderOperationRequest {
        operation: Some(Operation::ProveStage(Box::new(ZkStageProveOperation {
            circuit_ref: MessageField::some(ZkCircuitRef::default()),
            witness: MessageField::some(witness_with_bytes(vec![1, 2, 3])),
            public_inputs: MessageField::none(),
            session_binding: MessageField::none(),
            proof_suite: EnumValue::from(0),
            witness_handle: MessageField::none(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };

    zeroize_operation_request_proto(&mut request);

    let cleaned = match request.operation {
        Some(Operation::ProveStage(mut operation)) => operation.witness.take().is_none(),
        _ => false,
    };
    assert!(cleaned);
}

#[test]
fn request_cleanup_reaches_all_claim_proof_bundle_witness_bytes() {
    let mut request = ZkProviderOperationRequest {
        operation: Some(Operation::ProveClaimProofBundle(Box::new(
            ZkClaimProofBundleProveOperation {
                witness_bundle: MessageField::some(ZkClaimProofBundleWitness {
                    stage_witnesses: vec![
                        witness_with_bytes(vec![1, 2, 3]),
                        witness_with_bytes(vec![4, 5, 6]),
                    ],
                    __buffa_unknown_fields: Default::default(),
                    ..Default::default()
                }),
                __buffa_unknown_fields: Default::default(),
                ..Default::default()
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    zeroize_operation_request_proto(&mut request);

    let cleaned = match request.operation {
        Some(Operation::ProveClaimProofBundle(mut operation)) => {
            operation.witness_bundle.take().is_none()
        }
        _ => false,
    };
    assert!(cleaned);
}

#[test]
fn request_cleanup_clears_common_credential_root_nested_stage_scalars() {
    let mut request = ZkProviderOperationRequest {
        operation: Some(Operation::ProveCommonCredentialRootStage(Box::new(
            ZkCommonCredentialRootStageProveOperation {
                input: Some(
                    reallyme_zk_proto::generated::proto::reallyme::zk::v1::zk_common_credential_root_stage_prove_operation::Input::Lineage(Box::new(
                        ZkCommonCredentialRootLineageInput {
                            witness: MessageField::some(ZkInputCommonCredentialRootLineageWitness {
                                merkle_leaf_index: 7,
                                merkle_path: MessageField::some(merkle_path_with_len(6)),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )),
                ),
                __buffa_unknown_fields: Default::default(),
                ..Default::default()
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    zeroize_operation_request_proto(&mut request);

    let cleaned = match request.operation {
        Some(Operation::ProveCommonCredentialRootStage(mut operation)) => {
            matches!(
                operation.input.take(),
                Some(
                    reallyme_zk_proto::generated::proto::reallyme::zk::v1::zk_common_credential_root_stage_prove_operation::Input::Lineage(
                        input
                    )
                ) if input.witness.as_option().is_none()
            )
        }
        _ => false,
    };
    assert!(cleaned);
}

#[test]
fn request_cleanup_clears_common_credential_root_selected_claim_scalars() {
    let mut request = ZkProviderOperationRequest {
        operation: Some(Operation::ProveCommonCredentialRootStage(Box::new(
            ZkCommonCredentialRootStageProveOperation {
                input: Some(
                    reallyme_zk_proto::generated::proto::reallyme::zk::v1::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(Box::new(
                        ZkCommonCredentialRootPrivatePersonaClaimInput {
                            disclosure: MessageField::some(ZkInputClaimDisclosure {
                                value_length: 9,
                                ..Default::default()
                            }),
                            proof: MessageField::some(merkle_claim_proof(3, 6)),
                            ..Default::default()
                        },
                    )),
                ),
                __buffa_unknown_fields: Default::default(),
                ..Default::default()
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    zeroize_operation_request_proto(&mut request);

    let cleaned = match request.operation {
        Some(Operation::ProveCommonCredentialRootStage(mut operation)) => {
            matches!(
                operation.input.take(),
                Some(
                    reallyme_zk_proto::generated::proto::reallyme::zk::v1::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(
                        input
                    )
                ) if input.disclosure.as_option().is_none()
                    && input.proof.as_option().is_none()
            )
        }
        _ => false,
    };
    assert!(cleaned);
}

#[test]
fn sensitive_operation_encoder_round_trips_canonical_request(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let request = ZkProviderOperationRequest {
        operation: Some(Operation::GetArtifactManifest(Box::new(
            ZkArtifactManifestOperation {
                circuit_ref: MessageField::some(ZkCircuitRef {
                    credential_hash_algorithm: EnumValue::from(ZkCredentialHashAlgorithm::Sha256),
                    family: EnumValue::from(ZkCircuitFamily::CredentialSubjectClaimV1),
                    stage: EnumValue::from(ZkCircuitStage::Claim),
                    circuit_revision: 1,
                    __buffa_unknown_fields: Default::default(),
                }),
                proof_suite: EnumValue::from(ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded = encode_sensitive_operation_request(ZkSensitiveProviderRequest::new(request))?;
    assert!(matches!(
        decode_operation_request(encoded.as_slice()),
        Ok(ZkProviderOperation::GetArtifactManifest { .. })
    ));
    Ok(())
}

fn witness_with_bytes(encoded: Vec<u8>) -> ZkWitness {
    ZkWitness {
        encoded,
        circuit_ref: MessageField::some(ZkCircuitRef {
            stage: EnumValue::from(ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM),
            circuit_revision: 1,
            __buffa_unknown_fields: Default::default(),
            ..Default::default()
        }),
        encoding: EnumValue::from(ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1),
        __buffa_unknown_fields: Default::default(),
    }
}

fn merkle_path_with_len(path_length: u32) -> ZkInputMerklePath {
    let mut path = ZkInputMerklePath::default();
    path.path_length = path_length;
    path
}

fn merkle_claim_proof(leaf_index: u32, path_length: u32) -> ZkInputMerkleClaimProof {
    let mut proof = ZkInputMerkleClaimProof::default();
    proof.leaf_index = leaf_index;
    proof.path = MessageField::some(merkle_path_with_len(path_length));
    proof
}
