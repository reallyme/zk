// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    bundle_operation, circuit_ref, credential_subject_claim_input_with_merkle_depth,
    decode_operation_request, error_reason, exact_stage_witnesses, operation_from_proto, request,
    witness_stage_operation, EnumValue, MessageField, Operation, ZkCircuitRef,
    ZkClaimProofBundleKind, ZkErrorReason, ZkProofSuite, ZkProviderOperation,
    ZkStageProveOperation, ZkWitness, ZkWitnessEncoding,
};

fn claim_path_admission(
    path_length: u32,
    sibling_count: usize,
) -> Result<ZkProviderOperation, ZkErrorReason> {
    operation_from_proto(request(Operation::WitnessStage(Box::new(
        witness_stage_operation(
            circuit_ref(),
            credential_subject_claim_input_with_merkle_depth(path_length, sibling_count),
        ),
    ))))
    .map_err(|error| error.reason())
}

#[test]
fn witness_stage_admits_only_the_fixed_claim_tree_depth() {
    assert!(matches!(
        claim_path_admission(6, 6),
        Ok(ZkProviderOperation::WitnessStage { .. })
    ));
    for (path_length, sibling_count) in [(0_u32, 0_usize), (1, 1), (5, 5)] {
        assert!(matches!(
            claim_path_admission(path_length, sibling_count),
            Err(ZkErrorReason::InvalidProofEncoding)
        ));
    }
    for (path_length, sibling_count) in [(6_u32, 5_usize), (5, 6), (6, 0), (0, 6)] {
        assert!(matches!(
            claim_path_admission(path_length, sibling_count),
            Err(ZkErrorReason::InvalidProofEncoding)
        ));
    }
    for (path_length, sibling_count) in [(7_u32, 7_usize), (7, 6), (6, 7)] {
        assert!(matches!(
            claim_path_admission(path_length, sibling_count),
            Err(ZkErrorReason::ClaimPayloadTooLarge)
        ));
    }
}

#[test]
fn unspecified_witness_encoding_fails_closed() {
    let mut stage_witnesses = exact_stage_witnesses();
    stage_witnesses[0].encoding =
        EnumValue::from(ZkWitnessEncoding::ZK_WITNESS_ENCODING_UNSPECIFIED);

    assert_eq!(
        error_reason(operation_from_proto(request(
            Operation::ProveClaimProofBundle(Box::new(bundle_operation(stage_witnesses)))
        ))),
        ZkErrorReason::MalformedProtobuf
    );
}

#[test]
fn unknown_witness_encoding_fails_closed() {
    let mut stage_witnesses = exact_stage_witnesses();
    stage_witnesses[0].encoding = EnumValue::from(65_535);

    assert_eq!(
        error_reason(operation_from_proto(request(
            Operation::ProveClaimProofBundle(Box::new(bundle_operation(stage_witnesses)))
        ))),
        ZkErrorReason::MalformedProtobuf
    );
}

#[test]
fn stage_prove_invalid_circuit_ref_fails_before_witness_admission() {
    let message = request(Operation::ProveStage(Box::new(ZkStageProveOperation {
        circuit_ref: MessageField::some(ZkCircuitRef::default()),
        witness: MessageField::some(ZkWitness {
            encoded: vec![7, 8, 9],
            circuit_ref: MessageField::some(circuit_ref()),
            encoding: EnumValue::from(ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1),
            __buffa_unknown_fields: Default::default(),
        }),
        public_inputs: MessageField::none(),
        session_binding: MessageField::none(),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        witness_handle: MessageField::none(),
        __buffa_unknown_fields: Default::default(),
    })));

    assert_eq!(
        error_reason(operation_from_proto(message)),
        ZkErrorReason::UnsupportedCircuit
    );
}

#[test]
fn bundle_invalid_profile_fails_before_witness_bundle_admission() {
    let mut operation = bundle_operation(exact_stage_witnesses());
    operation.bundle_kind =
        EnumValue::from(ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_UNSPECIFIED);

    assert_eq!(
        error_reason(operation_from_proto(request(
            Operation::ProveClaimProofBundle(Box::new(operation))
        ))),
        ZkErrorReason::InvalidClaimProofBundle
    );
}

#[test]
fn partial_bundle_conversion_failure_fails_closed() {
    let mut stage_witnesses = exact_stage_witnesses();
    stage_witnesses[1].encoding =
        EnumValue::from(ZkWitnessEncoding::ZK_WITNESS_ENCODING_UNSPECIFIED);

    assert_eq!(
        error_reason(operation_from_proto(request(
            Operation::ProveClaimProofBundle(Box::new(bundle_operation(stage_witnesses)))
        ))),
        ZkErrorReason::MalformedProtobuf
    );
}

#[test]
fn unknown_claim_proof_bundle_wire_field_fails_closed() {
    // Unknown nested fields must fail before semantic admission. Field 99
    // is outside this contract and is not a compatibility reservation.
    assert_eq!(
        error_reason(decode_operation_request(&[0x0a, 0x03, 0x9a, 0x06, 0x00])),
        ZkErrorReason::MalformedProtobuf
    );
}

#[test]
fn incomplete_claim_proof_bundle_witness_fails_closed() {
    let mut stage_witnesses = exact_stage_witnesses();
    let _removed = stage_witnesses.pop();

    assert_eq!(
        error_reason(operation_from_proto(request(
            Operation::ProveClaimProofBundle(Box::new(bundle_operation(stage_witnesses)))
        ))),
        ZkErrorReason::MissingStage
    );
}

#[test]
fn reordered_claim_proof_bundle_witness_fails_closed() {
    let mut stage_witnesses = exact_stage_witnesses();
    stage_witnesses.swap(0, 1);

    assert_eq!(
        error_reason(operation_from_proto(request(
            Operation::ProveClaimProofBundle(Box::new(bundle_operation(stage_witnesses)))
        ))),
        ZkErrorReason::StageMismatch
    );
}
