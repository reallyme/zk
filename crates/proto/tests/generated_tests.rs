// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use buffa::{EnumValue, Enumeration, Message, MessageField};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    __buffa::oneof::{
        zk_error::Detail as ZkErrorDetail,
        zk_provider_operation_request::Operation as ProviderOperation,
        zk_proving_vector::ExpectedOutcome as VectorExpectedOutcome,
    },
    ZkArtifactErrorReason, ZkBackendErrorReason, ZkBindingErrorReason, ZkCircuitErrorReason,
    ZkCircuitFamily, ZkCircuitId, ZkCircuitStage, ZkClaimProofBundleErrorReason,
    ZkClaimProofBundleKind, ZkClaimProofBundleProveOperation, ZkClaimProofBundleStage,
    ZkClaimProofBundleWitness, ZkCredentialHashAlgorithm, ZkError, ZkErrorReason,
    ZkInputErrorReason, ZkProofErrorReason, ZkProofPackage, ZkProofSuite,
    ZkProviderOperationRequest, ZkProviderOperationResponse, ZkProvingVector,
    ZkProvingVectorMutation, ZkProvingVectorSet, ZkSemanticGuarantee, ZkStageVerifyOperation,
    ZkTransportErrorReason, ZkVerificationVector, ZkVerificationVectorMutation,
    ZkVerificationVectorSet, ZkWitness, ZkWitnessEncoding, ZkWitnessView,
};

#[test]
fn circuit_id_enum_value_is_stable() {
    assert_eq!(
        ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1.to_i32(),
        1
    );
    assert_eq!(
        ZkCircuitId::ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1.to_i32(),
        2
    );
    assert_eq!(
        ZkCircuitId::ZK_CIRCUIT_ID_COMMON_CREDENTIAL_ROOT_V1.to_i32(),
        3
    );
}

#[test]
fn exact_circuit_ref_enum_values_are_stable() {
    assert_eq!(
        ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1.to_i32(),
        1
    );
    assert_eq!(
        ZkCircuitFamily::ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1.to_i32(),
        2
    );
    assert_eq!(
        ZkCircuitFamily::ZK_CIRCUIT_FAMILY_COMMON_CREDENTIAL_ROOT_V1.to_i32(),
        3
    );
    assert_eq!(ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION.to_i32(), 1);
    assert_eq!(
        ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE.to_i32(),
        2
    );
    assert_eq!(ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ROOT.to_i32(), 3);
    assert_eq!(ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM.to_i32(), 4);
    assert_eq!(ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM_BUNDLE_4.to_i32(), 5);
    assert_eq!(ZkCircuitStage::ZK_CIRCUIT_STAGE_PUBLIC_SESSION.to_i32(), 12);
}

#[test]
fn private_persona_semantic_value_is_stable() {
    assert_eq!(
        ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_PRIVATE_PERSONA_BINDING.to_i32(),
        6
    );
}

#[test]
fn claim_proof_bundle_kind_values_are_stable() {
    assert_eq!(
        ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1.to_i32(),
        1
    );
    assert_eq!(
        ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1.to_i32(),
        2
    );
}

#[test]
fn production_stage_enum_values_are_stable() {
    assert_eq!(
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION.to_i32(),
        1
    );
    assert_eq!(
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE.to_i32(),
        2
    );
    assert_eq!(
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT.to_i32(),
        3
    );
    assert_eq!(
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM.to_i32(),
        4
    );
}

#[test]
fn proof_suite_enum_values_are_stable() {
    assert_eq!(
        ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA.to_i32(),
        1
    );
    assert_eq!(ZkProofSuite::from_i32(99), None);
    assert_eq!(
        ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_ZK_NO_IPA.to_i32(),
        2
    );
    assert_eq!(
        ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_UNMASKED_NO_IPA.to_i32(),
        4
    );
    assert_eq!(
        ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_UNMASKED_NO_IPA.to_i32(),
        3
    );
}

#[test]
fn proving_vector_mutation_values_are_stable() {
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_NONE.to_i32(),
        1
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_EMPTY_WITNESS.to_i32(),
        2
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WITNESS_TOO_LARGE.to_i32(),
        3
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_MALFORMED_PUBLIC_INPUTS.to_i32(),
        4
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WRONG_NONCE.to_i32(),
        5
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WRONG_AUDIENCE.to_i32(),
        6
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_UNSUPPORTED_TRANSACTION_DATA.to_i32(),
        7
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_UNSUPPORTED_CIRCUIT_VERSION.to_i32(),
        8
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_MISSING_STAGE_WITNESS.to_i32(),
        9
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_REORDERED_STAGE_WITNESS.to_i32(),
        10
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_CROSS_CIRCUIT_WITNESS.to_i32(),
        11
    );
    assert_eq!(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WRONG_TRANSACTION_DATA.to_i32(),
        12
    );
}

#[test]
fn verification_vector_mutation_values_are_stable() {
    assert_eq!(
        ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE.to_i32(),
        1
    );
    assert_eq!(
        ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_UNSUPPORTED_TRANSACTION_DATA
            .to_i32(),
        8
    );
    assert_eq!(
        ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_STALE_ARTIFACT_MANIFEST
            .to_i32(),
        9
    );
    assert_eq!(
        ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_MIXED_HASH_LANE.to_i32(),
        14
    );
    assert_eq!(
        ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_TRANSACTION_DATA
            .to_i32(),
        15
    );
}

#[test]
fn proving_vector_debug_does_not_expose_witness_bytes() {
    let request = ZkProviderOperationRequest {
        operation: Some(ProviderOperation::ProveClaimProofBundle(Box::new(
            ZkClaimProofBundleProveOperation {
                bundle_kind: EnumValue::from(
                    ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                ),
                credential_hash_algorithm: EnumValue::from(
                    ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
                ),
                proof_suite: EnumValue::from(
                    ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                ),
                session_binding: MessageField::none(),
                witness_bundle: MessageField::some(ZkClaimProofBundleWitness {
                    bundle_kind: EnumValue::from(
                        ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                    ),
                    credential_hash_algorithm: EnumValue::from(
                        ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
                    ),
                    stage_witnesses: vec![ZkWitness {
                        encoded: vec![201, 202, 203],
                        circuit_ref: MessageField::none(),
                        encoding: EnumValue::from(
                            ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1,
                        ),
                        __buffa_unknown_fields: Default::default(),
                    }],
                    __buffa_unknown_fields: Default::default(),
                }),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };
    let vector_set = ZkProvingVectorSet {
        format_version: 1,
        bundle_kind: EnumValue::from(
            ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ),
        credential_hash_algorithm: EnumValue::from(
            ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        vectors: vec![ZkProvingVector {
            vector_number: 1,
            mutation: EnumValue::from(ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_NONE),
            base_operation: MessageField::some(request),
            expected_outcome: Some(VectorExpectedOutcome::Error(Box::new(ZkError {
                reason: EnumValue::from(ZkErrorReason::ZK_ERROR_REASON_BACKEND_FAILURE),
                detail: None,
                __buffa_unknown_fields: Default::default(),
            }))),
            __buffa_unknown_fields: Default::default(),
        }],
        __buffa_unknown_fields: Default::default(),
    };
    let debug = format!("{vector_set:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("201"));
    assert!(!debug.contains("202"));
    assert!(!debug.contains("203"));
}

#[test]
fn verification_vector_debug_does_not_expose_proof_bytes() {
    let mut proof = ZkProofPackage::default();
    proof.proof = vec![211, 212, 213];
    let request = ZkProviderOperationRequest {
        operation: Some(ProviderOperation::VerifyStage(Box::new(
            ZkStageVerifyOperation {
                proof: MessageField::some(proof),
                expected_binding: MessageField::none(),
                expected_proof_suite: EnumValue::from(
                    ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                ),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };
    let vector_set = ZkVerificationVectorSet {
        format_version: 1,
        bundle_kind: EnumValue::from(
            ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ),
        credential_hash_algorithm: EnumValue::from(
            ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        artifact_manifests: Vec::new(),
        vectors: vec![ZkVerificationVector {
            vector_number: 1,
            mutation: EnumValue::from(
                ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE,
            ),
            base_operation: MessageField::some(request),
            expected_response: MessageField::some(ZkProviderOperationResponse::default()),
            __buffa_unknown_fields: Default::default(),
        }],
        __buffa_unknown_fields: Default::default(),
    };
    let debug = format!("{vector_set:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("211"));
    assert!(!debug.contains("212"));
    assert!(!debug.contains("213"));
}

#[test]
fn claim_proof_bundle_error_values_are_stable() {
    assert_eq!(
        ZkErrorReason::ZK_ERROR_REASON_INVALID_CLAIM_PROOF_BUNDLE.to_i32(),
        16
    );
    assert_eq!(ZkErrorReason::ZK_ERROR_REASON_DUPLICATE_STAGE.to_i32(), 17);
    assert_eq!(ZkErrorReason::ZK_ERROR_REASON_MISSING_STAGE.to_i32(), 18);
    assert_eq!(ZkErrorReason::ZK_ERROR_REASON_STAGE_MISMATCH.to_i32(), 19);
    assert_eq!(
        ZkErrorReason::ZK_ERROR_REASON_WITNESS_TOO_LARGE.to_i32(),
        20
    );
}

#[test]
fn transport_error_values_are_stable() {
    assert_eq!(
        ZkErrorReason::ZK_ERROR_REASON_MALFORMED_PROTOBUF.to_i32(),
        21
    );
    assert_eq!(ZkErrorReason::ZK_ERROR_REASON_MALFORMED_JSON.to_i32(), 22);
    assert_eq!(
        ZkErrorReason::ZK_ERROR_REASON_MISSING_OPERATION.to_i32(),
        23
    );
    assert_eq!(
        ZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT.to_i32(),
        24
    );
    assert_eq!(
        ZkErrorReason::ZK_ERROR_REASON_MESSAGE_TOO_LARGE.to_i32(),
        25
    );
    assert_eq!(
        ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_MESSAGE_TOO_LARGE.to_i32(),
        5
    );
}

#[test]
fn artifact_size_error_values_are_stable() {
    assert_eq!(
        ZkErrorReason::ZK_ERROR_REASON_ARTIFACT_TOO_LARGE.to_i32(),
        26
    );
    assert_eq!(
        ZkArtifactErrorReason::ZK_ARTIFACT_ERROR_REASON_ARTIFACT_TOO_LARGE.to_i32(),
        2
    );
}

#[test]
fn unsupported_proof_suite_error_values_are_stable() {
    assert_eq!(
        ZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE.to_i32(),
        27
    );
    assert_eq!(
        ZkProofErrorReason::ZK_PROOF_ERROR_REASON_UNSUPPORTED_PROOF_SUITE.to_i32(),
        3
    );
}

#[test]
fn witness_encoding_values_are_stable() {
    assert_eq!(
        ZkWitnessEncoding::ZK_WITNESS_ENCODING_UNSPECIFIED.to_i32(),
        0
    );
    assert_eq!(
        ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1.to_i32(),
        1
    );
}

#[test]
fn witness_debug_is_redacted() {
    let witness = ZkWitness {
        encoded: vec![101, 102, 103],
        circuit_ref: MessageField::none(),
        encoding: EnumValue::from(ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1),
        __buffa_unknown_fields: Default::default(),
    };
    let debug = format!("{witness:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("101"));
}

#[test]
fn witness_protojson_is_binary_only() {
    assert!(serde_json::to_string(&ZkWitness::default()).is_err());
    assert!(serde_json::from_slice::<ZkWitness>(br#"{}"#).is_err());
    assert!(serde_json::from_slice::<ZkWitness>(br#"{"encoded":"ZGVtbw=="}"#).is_err());

    let witness_bundle = ZkClaimProofBundleWitness {
        stage_witnesses: vec![ZkWitness::default()],
        ..Default::default()
    };
    assert!(serde_json::to_string(&witness_bundle).is_err());
    assert!(serde_json::from_slice::<ZkClaimProofBundleWitness>(
        br#"{"stageWitnesses":[{"encoded":"ZGVtbw=="}]}"#,
    )
    .is_err());
    assert!(serde_json::to_string(&ZkWitnessView::default()).is_err());
}

#[test]
fn structured_error_detail_enum_values_are_stable() {
    assert_eq!(
        ZkCircuitErrorReason::ZK_CIRCUIT_ERROR_REASON_UNKNOWN_CIRCUIT.to_i32(),
        1
    );
    assert_eq!(
        ZkInputErrorReason::ZK_INPUT_ERROR_REASON_LENGTH_OVERFLOW.to_i32(),
        7
    );
    assert_eq!(
        ZkInputErrorReason::ZK_INPUT_ERROR_REASON_WITNESS_TOO_LARGE.to_i32(),
        8
    );
    assert_eq!(
        ZkInputErrorReason::ZK_INPUT_ERROR_REASON_RESOURCE_EXHAUSTED.to_i32(),
        9
    );
    assert_eq!(
        ZkErrorReason::ZK_ERROR_REASON_RESOURCE_EXHAUSTED.to_i32(),
        31
    );
    assert_eq!(
        ZkProofErrorReason::ZK_PROOF_ERROR_REASON_INVALID_PROOF.to_i32(),
        2
    );
    assert_eq!(
        ZkClaimProofBundleErrorReason::ZK_CLAIM_PROOF_BUNDLE_ERROR_REASON_STAGE_MISMATCH.to_i32(),
        4
    );
    assert_eq!(
        ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_BINDING_MISMATCH.to_i32(),
        1
    );
    assert_eq!(
        ZkArtifactErrorReason::ZK_ARTIFACT_ERROR_REASON_ARTIFACT_MISMATCH.to_i32(),
        1
    );
    assert_eq!(
        ZkBackendErrorReason::ZK_BACKEND_ERROR_REASON_BACKEND_FAILURE.to_i32(),
        2
    );
}

#[test]
fn structured_error_round_trips_with_buffa() {
    let error = ZkError {
        reason: EnumValue::from(ZkErrorReason::ZK_ERROR_REASON_BINDING_MISMATCH),
        detail: Some(ZkErrorDetail::BindingReason(EnumValue::from(
            ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_BINDING_MISMATCH,
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded = error.encode_to_vec();
    let decoded = ZkError::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(decoded, error);
}

#[test]
fn structured_error_round_trips_with_buffa_json() {
    let error = ZkError {
        reason: EnumValue::from(ZkErrorReason::ZK_ERROR_REASON_BINDING_MISMATCH),
        detail: Some(ZkErrorDetail::BindingReason(EnumValue::from(
            ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_BINDING_MISMATCH,
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded = serde_json::to_vec(&error).unwrap();
    let decoded = serde_json::from_slice::<ZkError>(&encoded).unwrap();

    assert_eq!(decoded, error);
}

#[path = "generated_tests/provider_operations.rs"]
mod provider_operations;
#[path = "generated_tests/sensitive_bindings.rs"]
mod sensitive_bindings;
