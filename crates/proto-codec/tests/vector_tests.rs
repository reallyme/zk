// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::{
        ZkCircuitFamily as DomainFamily, ZkCircuitRef as DomainRef, ZkCircuitStage as DomainStage,
        ZkCredentialHashAlgorithm as DomainHash,
    },
    claim_bundle::{
        ZkClaimProofBundleKind as DomainProfile, ZkClaimProofBundleStage as DomainProductionStage,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProofSuite as DomainProofSuite, ZkPublicInputDescriptor, ZkPublicInputName,
        ZkSessionBinding as DomainBinding, ZkWitness as DomainWitness,
        ABSENT_TRANSACTION_DATA_HASH,
    },
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    __buffa::oneof::{
        zk_provider_operation_request::Operation, zk_proving_vector::ExpectedOutcome,
    },
    ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage, ZkClaimProofBundleKind,
    ZkClaimProofBundleStage, ZkCredentialHashAlgorithm, ZkExpectedStageProofShape, ZkProofMetadata,
    ZkProofSuite, ZkProviderOperationRequest, ZkProvingVector, ZkProvingVectorMutation,
    ZkProvingVectorSet, ZkPublicInputs, ZkSessionBinding, ZkStageProveOperation, ZkWitness,
    ZkWitnessEncoding,
};
use reallyme_zk_proto_codec::{
    error::error_to_proto,
    operation::ZkProviderOperation,
    vector::{
        decode_proving_vector_set, encode_bundle_proving_vector_set, BundleProvingVectorInput,
        ExpectedProvingOutcome, ProvingVectorMutation, StageProvingVectorInput,
    },
};

fn circuit_ref() -> ZkCircuitRef {
    ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(
            ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        family: EnumValue::from(ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1),
        stage: EnumValue::from(ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION),
        circuit_revision: 1,
        __buffa_unknown_fields: Default::default(),
    }
}

fn binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: vec![11; 32],
        audience_hash: vec![22; 32],
        transaction_data_hash: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn public_inputs() -> Result<ZkPublicInputs, ZkError> {
    let domain_ref = DomainRef::new(
        DomainHash::Sha256,
        DomainFamily::CredentialSubjectClaimV1,
        DomainStage::Session,
    );
    let descriptor = ZkPublicInputDescriptor::for_circuit(domain_ref)?;
    let mut encoded = vec![0_u8; descriptor.encoded_len()?];
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::Challenge)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&[11; 32]);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::AudienceHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&[22; 32]);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::TransactionDataHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&ABSENT_TRANSACTION_DATA_HASH);
    Ok(ZkPublicInputs {
        encoded,
        __buffa_unknown_fields: Default::default(),
    })
}

fn domain_binding() -> DomainBinding {
    DomainBinding {
        nonce_hash: [11; 32],
        audience_hash: [22; 32],
        transaction_data_hash: None,
    }
}

fn domain_public_inputs(
    circuit_ref: DomainRef,
) -> Result<reallyme_zk_api::proofs::ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut encoded = vec![0_u8; descriptor.encoded_len()?];
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::Challenge)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&domain_binding().nonce_hash);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::AudienceHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&domain_binding().audience_hash);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::TransactionDataHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&ABSENT_TRANSACTION_DATA_HASH);
    reallyme_zk_api::proofs::ZkPublicInputs::try_from_bytes(encoded)
}

fn base_operation() -> Result<ZkProviderOperationRequest, ZkError> {
    Ok(ZkProviderOperationRequest {
        operation: Some(Operation::ProveStage(Box::new(ZkStageProveOperation {
            circuit_ref: MessageField::some(circuit_ref()),
            witness: MessageField::some(ZkWitness {
                encoded: vec![31, 32, 33],
                circuit_ref: MessageField::some(circuit_ref()),
                encoding: EnumValue::from(
                    ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1,
                ),
                __buffa_unknown_fields: Default::default(),
            }),
            public_inputs: MessageField::some(public_inputs()?),
            session_binding: MessageField::some(binding()),
            proof_suite: EnumValue::from(
                ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            witness_handle: MessageField::none(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    })
}

fn expected_stage() -> Result<ZkExpectedStageProofShape, ZkError> {
    Ok(ZkExpectedStageProofShape {
        bundle_kind: EnumValue::from(
            ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ),
        stage: EnumValue::from(ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION),
        metadata: MessageField::some(ZkProofMetadata {
            circuit_id: EnumValue::from(ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1),
            circuit_id_string: "rm-zk-credential-subject-claim-v1".to_owned(),
            verification_key_sha256: vec![44; 32],
            circuit_ref: MessageField::some(circuit_ref()),
            proof_suite: EnumValue::from(
                ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            __buffa_unknown_fields: Default::default(),
        }),
        public_inputs: MessageField::some(public_inputs()?),
        session_binding: MessageField::some(binding()),
        __buffa_unknown_fields: Default::default(),
    })
}

fn vector(
    number: u32,
    mutation: ZkProvingVectorMutation,
    expected_outcome: ExpectedOutcome,
) -> Result<ZkProvingVector, ZkError> {
    Ok(ZkProvingVector {
        vector_number: number,
        mutation: EnumValue::from(mutation),
        base_operation: MessageField::some(base_operation()?),
        expected_outcome: Some(expected_outcome),
        __buffa_unknown_fields: Default::default(),
    })
}

fn valid_vector_set() -> Result<ZkProvingVectorSet, ZkError> {
    Ok(ZkProvingVectorSet {
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
        vectors: vec![vector(
            1,
            ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_NONE,
            ExpectedOutcome::StageProof(Box::new(expected_stage()?)),
        )?],
        __buffa_unknown_fields: Default::default(),
    })
}

fn mutated_vector_set(
    mutation: ZkProvingVectorMutation,
    expected_reason: ZkErrorReason,
) -> Result<ZkProvingVectorSet, ZkError> {
    let mut set = valid_vector_set()?;
    set.vectors = vec![vector(
        1,
        mutation,
        ExpectedOutcome::Error(Box::new(error_to_proto(ZkError::new(expected_reason)))),
    )?];
    Ok(set)
}

#[test]
fn canonical_stage_vector_decodes_and_executes() -> Result<(), ZkError> {
    let encoded = valid_vector_set()?.encode_to_vec();
    let decoded = decode_proving_vector_set(&encoded)?;

    assert_eq!(decoded.vectors().len(), 1);
    assert_eq!(decoded.vectors()[0].number(), 1);
    assert_eq!(decoded.vectors()[0].mutation(), ProvingVectorMutation::None);
    assert!(matches!(
        decoded.vectors()[0].expected_outcome(),
        ExpectedProvingOutcome::Stage(_)
    ));
    let vector = decoded
        .into_vectors()
        .pop()
        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?;
    assert!(matches!(
        vector.execute()?,
        ZkProviderOperation::ProveStage { .. }
    ));
    Ok(())
}

#[test]
fn canonical_real_bundle_vector_encodes_decodes_and_executes() -> Result<(), ZkError> {
    let bundle_kind = DomainProfile::CredentialSubjectClaimV1;
    let credential_hash_algorithm = DomainHash::Sha256;
    let session_ref =
        bundle_kind.source_ref(credential_hash_algorithm, DomainProductionStage::Session);
    let envelope_ref = bundle_kind.source_ref(
        credential_hash_algorithm,
        DomainProductionStage::CredentialEnvelope,
    );
    let root_ref = bundle_kind.source_ref(
        credential_hash_algorithm,
        DomainProductionStage::CredentialRoot,
    );
    let claim_ref = bundle_kind.source_ref(credential_hash_algorithm, DomainProductionStage::Claim);
    let session_inputs = domain_public_inputs(session_ref)?;
    let envelope_inputs = domain_public_inputs(envelope_ref)?;
    let root_inputs = domain_public_inputs(root_ref)?;
    let claim_inputs = domain_public_inputs(claim_ref)?;
    let witness_bundle =
        reallyme_zk_api::claim_bundle::ZkClaimProofBundleWitness::try_from_stage_witnesses(
            bundle_kind,
            credential_hash_algorithm,
            vec![
                DomainWitness::try_from_noir_witness_stack_v1(session_ref, vec![1, 2, 3])?,
                DomainWitness::try_from_noir_witness_stack_v1(envelope_ref, vec![4, 5, 6])?,
                DomainWitness::try_from_noir_witness_stack_v1(root_ref, vec![7, 8, 9])?,
                DomainWitness::try_from_noir_witness_stack_v1(claim_ref, vec![10, 11, 12])?,
            ],
        )?;
    let stages = [
        StageProvingVectorInput::try_new(
            bundle_kind,
            credential_hash_algorithm,
            DomainProductionStage::Session,
            [41; 32],
            &session_inputs,
            domain_binding(),
        )?,
        StageProvingVectorInput::try_new(
            bundle_kind,
            credential_hash_algorithm,
            DomainProductionStage::CredentialEnvelope,
            [42; 32],
            &envelope_inputs,
            domain_binding(),
        )?,
        StageProvingVectorInput::try_new(
            bundle_kind,
            credential_hash_algorithm,
            DomainProductionStage::CredentialRoot,
            [43; 32],
            &root_inputs,
            domain_binding(),
        )?,
        StageProvingVectorInput::try_new(
            bundle_kind,
            credential_hash_algorithm,
            DomainProductionStage::Claim,
            [44; 32],
            &claim_inputs,
            domain_binding(),
        )?,
    ];
    let proof_suite = DomainProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa;
    let input = BundleProvingVectorInput::try_new_for_suite(
        bundle_kind,
        credential_hash_algorithm,
        proof_suite,
        &witness_bundle,
        domain_binding(),
        stages,
    )?;

    let encoded = encode_bundle_proving_vector_set(input)?;
    let decoded = decode_proving_vector_set(&encoded)?;
    assert_eq!(decoded.proof_suite(), proof_suite);
    assert_eq!(decoded.vectors().len(), 7);
    assert!(matches!(
        decoded.vectors()[0].expected_outcome(),
        ExpectedProvingOutcome::Bundle(_)
    ));
    let mut vectors = decoded.into_vectors().into_iter();
    let vector = vectors
        .next()
        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?;
    let operation = vector.execute()?;
    let ZkProviderOperation::ProveClaimProofBundle {
        proof_suite: operation_suite,
        witness_bundle,
        ..
    } = operation
    else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    assert_eq!(operation_suite, proof_suite);
    assert_eq!(
        witness_bundle
            .stage_witness(DomainProductionStage::Claim)?
            .circuit_ref(),
        claim_ref
    );
    for vector in vectors {
        let expected = match vector.mutation() {
            ProvingVectorMutation::EmptyWitness => ZkErrorReason::EmptyInput,
            ProvingVectorMutation::WitnessTooLarge => ZkErrorReason::WitnessTooLarge,
            ProvingVectorMutation::WrongTransactionData => ZkErrorReason::BindingMismatch,
            ProvingVectorMutation::MissingStageWitness => ZkErrorReason::MissingStage,
            ProvingVectorMutation::ReorderedStageWitness
            | ProvingVectorMutation::CrossCircuitWitness => ZkErrorReason::StageMismatch,
            ProvingVectorMutation::None
            | ProvingVectorMutation::MalformedPublicInputs
            | ProvingVectorMutation::WrongNonce
            | ProvingVectorMutation::WrongAudience
            | ProvingVectorMutation::UnsupportedCircuitRevision => {
                return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
            }
        };
        let error = vector
            .execute()
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), expected);
    }
    Ok(())
}

#[test]
fn empty_witness_mutation_returns_exact_typed_error() -> Result<(), ZkError> {
    let set = mutated_vector_set(
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_EMPTY_WITNESS,
        ZkErrorReason::EmptyInput,
    )?;
    let decoded = decode_proving_vector_set(&set.encode_to_vec())?;
    let error = decoded
        .into_vectors()
        .pop()
        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?
        .execute()
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::EmptyInput);
    Ok(())
}

#[test]
fn every_stage_negative_mutation_returns_its_exact_typed_error() -> Result<(), ZkError> {
    let cases = [
        (
            ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WITNESS_TOO_LARGE,
            ZkErrorReason::WitnessTooLarge,
        ),
        (
            ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_MALFORMED_PUBLIC_INPUTS,
            ZkErrorReason::InvalidProofEncoding,
        ),
        (
            ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WRONG_NONCE,
            ZkErrorReason::BindingMismatch,
        ),
        (
            ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WRONG_AUDIENCE,
            ZkErrorReason::BindingMismatch,
        ),
        (
            ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_WRONG_TRANSACTION_DATA,
            ZkErrorReason::BindingMismatch,
        ),
        (
            ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_UNSUPPORTED_TRANSACTION_DATA,
            ZkErrorReason::BindingMismatch,
        ),
        (
            ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_UNSUPPORTED_CIRCUIT_VERSION,
            ZkErrorReason::UnsupportedCircuit,
        ),
    ];

    for (mutation, expected_reason) in cases {
        let encoded = mutated_vector_set(mutation, expected_reason)?.encode_to_vec();
        let error = decode_proving_vector_set(&encoded)?
            .into_vectors()
            .pop()
            .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?
            .execute()
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), expected_reason);
    }
    Ok(())
}

#[test]
fn duplicate_wire_encoding_is_rejected_as_noncanonical() -> Result<(), ZkError> {
    let mut encoded = valid_vector_set()?.encode_to_vec();
    encoded.extend_from_slice(&[0x08, 0x01]);
    let reason = decode_proving_vector_set(&encoded)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::MalformedProtobuf));
    Ok(())
}

#[test]
fn vector_numbers_must_be_contiguous_and_one_based() -> Result<(), ZkError> {
    let mut set = valid_vector_set()?;
    set.vectors[0].vector_number = 2;
    let reason = decode_proving_vector_set(&set.encode_to_vec())
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::InvalidClaimProofBundle));
    Ok(())
}

#[test]
fn mutation_and_expected_error_must_match() -> Result<(), ZkError> {
    let wrong_error = error_to_proto(ZkError::new(ZkErrorReason::BindingMismatch));
    let mut set = valid_vector_set()?;
    set.vectors = vec![vector(
        1,
        ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_EMPTY_WITNESS,
        ExpectedOutcome::Error(Box::new(wrong_error)),
    )?];
    let reason = decode_proving_vector_set(&set.encode_to_vec())
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::InvalidClaimProofBundle));
    Ok(())
}

#[test]
fn vector_set_header_must_name_the_exact_supported_contract() -> Result<(), ZkError> {
    let mut wrong_version = valid_vector_set()?;
    wrong_version.format_version = 2;
    let version_reason = decode_proving_vector_set(&wrong_version.encode_to_vec())
        .err()
        .map(|error| error.reason());

    let mut wrong_profile = valid_vector_set()?;
    wrong_profile.bundle_kind = EnumValue::from(
        ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
    );
    let profile_reason = decode_proving_vector_set(&wrong_profile.encode_to_vec())
        .err()
        .map(|error| error.reason());

    assert_eq!(version_reason, Some(ZkErrorReason::InvalidClaimProofBundle));
    assert_eq!(profile_reason, Some(ZkErrorReason::StageMismatch));
    Ok(())
}
