// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm as DomainHash,
    claim_bundle::{
        ZkClaimProofBundleKind as DomainBundleKind, ZkClaimProofBundleStage as DomainStage,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProofSuite as DomainProofSuite, ZkPublicInputDescriptor, ZkPublicInputName,
        ABSENT_TRANSACTION_DATA_HASH,
    },
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    self as pb,
    __buffa::oneof::{
        zk_provider_operation_request::Operation, zk_provider_operation_response::Outcome,
        zk_provider_operation_result::Result as ProviderResult,
    },
};
use reallyme_zk_proto_codec::{
    error::error_to_proto,
    operation::ZkProviderOperation,
    verification_vector::{
        decode_verification_vector_set, encode_claim_proof_bundle_verification_vector_set,
        verification_request_sha256, ClaimProofBundleVerificationVectorInput,
        ExpectedVerificationOutcome, VerificationVectorMutation,
    },
};

const NONCE: [u8; 32] = [11; 32];
const AUDIENCE: [u8; 32] = [22; 32];

#[path = "verification_vector_tests/bundle_expectation_tests.rs"]
mod bundle_expectation_tests;
#[path = "verification_vector_tests/policy_mutation_tests.rs"]
mod policy_mutation_tests;

fn proto_hash(hash: DomainHash) -> pb::ZkCredentialHashAlgorithm {
    match hash {
        DomainHash::Sha256 => pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        DomainHash::Poseidon2 => {
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2
        }
        _ => pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_UNSPECIFIED,
    }
}

fn proto_stage(stage: DomainStage) -> pb::ZkClaimProofBundleStage {
    match stage {
        DomainStage::Session => pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
        DomainStage::CredentialEnvelope => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE
        }
        DomainStage::CredentialRoot => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT
        }
        DomainStage::Claim => pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM,
        _ => pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_UNSPECIFIED,
    }
}

fn circuit_stage(stage: DomainStage) -> pb::ZkCircuitStage {
    match stage {
        DomainStage::Session => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION,
        DomainStage::CredentialEnvelope => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE,
        DomainStage::CredentialRoot => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ROOT,
        DomainStage::Claim => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM,
        _ => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_UNSPECIFIED,
    }
}

fn circuit_ref(hash: DomainHash, stage: DomainStage) -> pb::ZkCircuitRef {
    pb::ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(proto_hash(hash)),
        family: EnumValue::from(pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1),
        stage: EnumValue::from(circuit_stage(stage)),
        circuit_revision: 1,
        __buffa_unknown_fields: Default::default(),
    }
}

fn binding() -> pb::ZkSessionBinding {
    pb::ZkSessionBinding {
        nonce_hash: NONCE.to_vec(),
        audience_hash: AUDIENCE.to_vec(),
        transaction_data_hash: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn issuer_public_key() -> pb::ZkP256PublicKey {
    pb::ZkP256PublicKey {
        x: vec![21; 32],
        y: vec![22; 32],
        __buffa_unknown_fields: Default::default(),
    }
}

fn verified_statement() -> pb::ZkPresentationBoundClaimStatement {
    let mut claim_value = vec![0; 64];
    claim_value[0] = 26;
    pb::ZkPresentationBoundClaimStatement {
        issuer: MessageField::some(issuer_public_key()),
        persona: MessageField::none(),
        claim_name_hash: vec![25; 32],
        claim_value,
        claim_value_length: 1,
        presentation_expiry_unix: 42,
        session_link_commitment: vec![27; 32],
        credential_binding: vec![28; 32],
        __buffa_unknown_fields: Default::default(),
    }
}

fn public_inputs(hash: DomainHash, stage: DomainStage) -> Result<pb::ZkPublicInputs, ZkError> {
    let reference = DomainBundleKind::CredentialSubjectClaimV1.source_ref(hash, stage);
    let descriptor = ZkPublicInputDescriptor::for_circuit(reference)?;
    let mut encoded = vec![0_u8; descriptor.encoded_len()?];
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::Challenge)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&NONCE);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::AudienceHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&AUDIENCE);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::TransactionDataHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&ABSENT_TRANSACTION_DATA_HASH);
    for (name, value) in [
        (ZkPublicInputName::IssuerPublicKeyX, [21; 32]),
        (ZkPublicInputName::IssuerPublicKeyY, [22; 32]),
        (ZkPublicInputName::SessionBinding, [27; 32]),
        (ZkPublicInputName::EnvelopeBinding, [23; 32]),
        (ZkPublicInputName::CredentialBinding, [28; 32]),
        (ZkPublicInputName::ClaimNameHash, [25; 32]),
    ] {
        if descriptor.fields().iter().any(|field| field.name == name) {
            encoded
                .get_mut(descriptor.field_range(name)?)
                .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
                .copy_from_slice(&value);
        }
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::ValueLength)
    {
        encoded
            .get_mut(descriptor.field_range(ZkPublicInputName::ValueLength)?)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
            .copy_from_slice(&1_u32.to_be_bytes());
        let value_range = descriptor.field_range(ZkPublicInputName::Value)?;
        let value = encoded
            .get_mut(value_range)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        value[0] = 26;
    }
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::ExpiryUnix)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&42_u64.to_be_bytes());
    Ok(pb::ZkPublicInputs {
        encoded,
        __buffa_unknown_fields: Default::default(),
    })
}

fn manifest_digest(stage: DomainStage) -> pb::ZkArtifactManifestDigest {
    pb::ZkArtifactManifestDigest {
        value: vec![stage.index().saturating_add(1); 32],
        __buffa_unknown_fields: Default::default(),
    }
}

fn proof(hash: DomainHash, stage: DomainStage) -> Result<pb::ZkProofPackage, ZkError> {
    Ok(pb::ZkProofPackage {
        circuit_id: EnumValue::from(pb::ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1),
        circuit_id_string: "rm-zk-credential-subject-claim-v1".to_owned(),
        proof: vec![31, stage.index(), 33],
        public_inputs: MessageField::some(public_inputs(hash, stage)?),
        artifact_identity: Some(manifest_digest(stage).into()),
        named_public_inputs: Vec::new(),
        circuit_ref: MessageField::some(circuit_ref(hash, stage)),
        proof_suite: EnumValue::from(
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        __buffa_unknown_fields: Default::default(),
    })
}

fn artifact_pins(hash: DomainHash) -> Vec<pb::ZkReleaseArtifactPin> {
    DomainStage::ALL
        .iter()
        .copied()
        .map(|stage| pb::ZkReleaseArtifactPin {
            bundle_kind: EnumValue::from(
                pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ),
            stage: EnumValue::from(proto_stage(stage)),
            circuit_ref: MessageField::some(circuit_ref(hash, stage)),
            artifact_manifest_sha256: MessageField::some(manifest_digest(stage)),
            __buffa_unknown_fields: Default::default(),
        })
        .collect()
}

fn stage_operation(hash: DomainHash) -> Result<pb::ZkProviderOperationRequest, ZkError> {
    Ok(pb::ZkProviderOperationRequest {
        operation: Some(Operation::VerifyStage(Box::new(
            pb::ZkStageVerifyOperation {
                proof: MessageField::some(proof(hash, DomainStage::Session)?),
                expected_binding: MessageField::some(binding()),
                expected_proof_suite: EnumValue::from(
                    pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                ),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    })
}

fn bundle_operation(hash: DomainHash) -> Result<pb::ZkProviderOperationRequest, ZkError> {
    let mut stages = Vec::new();
    for stage in DomainStage::ALL {
        stages.push(pb::ZkClaimProofBundleStageProofPackage {
            bundle_kind: EnumValue::from(
                pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ),
            stage: EnumValue::from(proto_stage(*stage)),
            proof: MessageField::some(proof(hash, *stage)?),
            __buffa_unknown_fields: Default::default(),
        });
    }
    Ok(pb::ZkProviderOperationRequest {
        operation: Some(Operation::VerifyClaimProofBundle(Box::new(
            pb::ZkClaimProofBundleVerifyOperation {
                claim_proof_bundle: MessageField::some(pb::ZkClaimProofBundle {
                    bundle_kind: EnumValue::from(
                        pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                    ),
                    format_version: 1,
                    stages,
                    session_binding: MessageField::some(binding()),
                    credential_hash_algorithm: EnumValue::from(proto_hash(hash)),
                    proof_suite: EnumValue::from(
                        pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                    ),
                    __buffa_unknown_fields: Default::default(),
                }),
                expected_binding: MessageField::some(binding()),
                trusted_issuers: vec![issuer_public_key()],
                verification_time_unix: 41,
                credential_status_checked_at_unix: 0,
                expected_proof_suite: EnumValue::from(
                    pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                ),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    })
}

fn success_response(bundle: bool) -> pb::ZkProviderOperationResponse {
    let result = if bundle {
        ProviderResult::ClaimProofBundleVerification(Box::new(pb::ZkPresentationBoundClaimBundleVerification {
            bundle_kind: EnumValue::from(
                pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ),
            verified_stage_count: 4,
            proof_suite: EnumValue::from(
                pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            statement: MessageField::some(verified_statement()),
            __buffa_unknown_fields: Default::default(),
        }))
    } else {
        ProviderResult::StageVerification(Box::new(pb::ZkVerification {
            circuit_id: EnumValue::from(pb::ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1),
            circuit_ref: MessageField::some(circuit_ref(DomainHash::Sha256, DomainStage::Session)),
            bundle_kind: EnumValue::from(
                pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ),
            proof_suite: EnumValue::from(
                pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            __buffa_unknown_fields: Default::default(),
        }))
    };
    pb::ZkProviderOperationResponse {
        outcome: Some(Outcome::Result(Box::new(pb::ZkProviderOperationResult {
            result: Some(result),
            __buffa_unknown_fields: Default::default(),
        }))),
        request_sha256: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn error_response(reason: ZkErrorReason) -> pb::ZkProviderOperationResponse {
    pb::ZkProviderOperationResponse {
        outcome: Some(Outcome::Error(Box::new(error_to_proto(ZkError::new(
            reason,
        ))))),
        request_sha256: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn vector_set(
    mutation: pb::ZkVerificationVectorMutation,
    mut expected_response: pb::ZkProviderOperationResponse,
    bundle: bool,
) -> Result<pb::ZkVerificationVectorSet, ZkError> {
    let hash = DomainHash::Sha256;
    let base_operation = if bundle {
        bundle_operation(hash)?
    } else {
        stage_operation(hash)?
    };
    expected_response.request_sha256 = match verification_request_sha256(
        &base_operation.encode_to_vec(),
        domain_mutation(mutation)?,
    ) {
        Ok(digest) => digest.as_bytes().to_vec(),
        Err(_) => vec![0; 32],
    };
    Ok(pb::ZkVerificationVectorSet {
        format_version: 1,
        bundle_kind: EnumValue::from(
            pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ),
        credential_hash_algorithm: EnumValue::from(proto_hash(hash)),
        proof_suite: EnumValue::from(
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        artifact_manifests: artifact_pins(hash),
        vectors: vec![pb::ZkVerificationVector {
            vector_number: 1,
            mutation: EnumValue::from(mutation),
            base_operation: MessageField::some(base_operation),
            expected_response: MessageField::some(expected_response),
            __buffa_unknown_fields: Default::default(),
        }],
        __buffa_unknown_fields: Default::default(),
    })
}

fn domain_mutation(
    mutation: pb::ZkVerificationVectorMutation,
) -> Result<VerificationVectorMutation, ZkError> {
    use pb::ZkVerificationVectorMutation as Proto;
    match mutation {
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_NONE => Ok(VerificationVectorMutation::None),
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_EMPTY_PROOF => {
            Ok(VerificationVectorMutation::EmptyProof)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_PROOF_TOO_LARGE => {
            Ok(VerificationVectorMutation::ProofTooLarge)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_TAMPERED_PROOF => {
            Ok(VerificationVectorMutation::TamperedProof)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_MALFORMED_PUBLIC_INPUTS => {
            Ok(VerificationVectorMutation::MalformedPublicInputs)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_NONCE => {
            Ok(VerificationVectorMutation::WrongNonce)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_AUDIENCE => {
            Ok(VerificationVectorMutation::WrongAudience)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_UNSUPPORTED_TRANSACTION_DATA
        | Proto::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_TRANSACTION_DATA => {
            Ok(VerificationVectorMutation::WrongTransactionData)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_UNTRUSTED_ISSUER => {
            Ok(VerificationVectorMutation::UntrustedIssuer)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_PRESENTATION_EXPIRED => {
            Ok(VerificationVectorMutation::PresentationExpired)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_CREDENTIAL_STATUS_PRESENT => {
            Ok(VerificationVectorMutation::CredentialStatusPresent)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_BUNDLE_SESSION_BINDING => {
            Ok(VerificationVectorMutation::WrongBundleSessionBinding)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_STALE_ARTIFACT_MANIFEST => {
            Ok(VerificationVectorMutation::StaleArtifactManifest)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_UNSUPPORTED_CIRCUIT_VERSION => {
            Ok(VerificationVectorMutation::UnsupportedCircuitRevision)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_DUPLICATE_STAGE => {
            Ok(VerificationVectorMutation::DuplicateStage)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_MISSING_STAGE => {
            Ok(VerificationVectorMutation::MissingStage)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_STAGE => {
            Ok(VerificationVectorMutation::WrongStage)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_MIXED_HASH_LANE => {
            Ok(VerificationVectorMutation::MixedHashLane)
        }
        Proto::ZK_VERIFICATION_VECTOR_MUTATION_UNSPECIFIED => {
            Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))
        }
    }
}

#[test]
fn canonical_stage_and_bundle_vectors_decode_and_execute() -> Result<(), ZkError> {
    for bundle in [false, true] {
        let encoded = vector_set(
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE,
            success_response(bundle),
            bundle,
        )?
        .encode_to_vec();
        let decoded = decode_verification_vector_set(&encoded)?;
        assert_eq!(decoded.artifact_manifests().len(), 4);
        let vector = decoded
            .into_vectors()
            .pop()
            .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?;
        assert_eq!(vector.mutation(), VerificationVectorMutation::None);
        assert!(matches!(
            vector.expected_outcome(),
            ExpectedVerificationOutcome::Stage(_) | ExpectedVerificationOutcome::Bundle(_)
        ));
        let operation = vector.execute()?;
        assert_eq!(
            matches!(
                operation,
                ZkProviderOperation::VerifyClaimProofBundle { .. }
            ),
            bundle
        );
    }
    Ok(())
}

#[test]
fn canonical_real_bundle_encoder_covers_every_mutation() -> Result<(), ZkError> {
    let hash = DomainHash::Sha256;
    let base_operation = bundle_operation(hash)?.encode_to_vec();
    let claim_proof_bundle =
        match reallyme_zk_proto_codec::operation::decode_operation_request(&base_operation)? {
            ZkProviderOperation::VerifyClaimProofBundle {
                claim_proof_bundle, ..
            } => claim_proof_bundle,
            _ => return Err(ZkError::new(ZkErrorReason::MissingOperation)),
        };
    let seed = vector_set(
        pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE,
        success_response(true),
        true,
    )?
    .encode_to_vec();
    let seed = decode_verification_vector_set(&seed)?;
    let pins = seed.artifact_manifests();
    let artifact_manifests = [
        *pins
            .first()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?,
        *pins
            .get(1)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?,
        *pins
            .get(2)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?,
        *pins
            .get(3)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?,
    ];
    let mut wrong_hash_manifests = artifact_manifests;
    wrong_hash_manifests[0] = reallyme_zk_proto_codec::release::ReleaseArtifactPin::try_new(
        DomainBundleKind::CredentialSubjectClaimV1,
        DomainStage::Session,
        DomainBundleKind::CredentialSubjectClaimV1
            .source_ref(DomainHash::Poseidon2, DomainStage::Session),
        artifact_manifests[0].manifest_sha256(),
    )?;
    let wrong_hash_reason = ClaimProofBundleVerificationVectorInput::try_new(
        DomainBundleKind::CredentialSubjectClaimV1,
        hash,
        &claim_proof_bundle,
        wrong_hash_manifests,
    )
    .err()
    .map(|error| error.reason());
    assert_eq!(wrong_hash_reason, Some(ZkErrorReason::ArtifactMismatch));

    let input = ClaimProofBundleVerificationVectorInput::try_new(
        DomainBundleKind::CredentialSubjectClaimV1,
        hash,
        &claim_proof_bundle,
        artifact_manifests,
    )?;
    let encoded = encode_claim_proof_bundle_verification_vector_set(input)?;
    let decoded = decode_verification_vector_set(&encoded)?;

    assert_eq!(decoded.vectors().len(), 18);
    assert_eq!(
        decoded.vectors().first().map(|vector| vector.mutation()),
        Some(VerificationVectorMutation::None)
    );
    assert_eq!(
        decoded.vectors().last().map(|vector| vector.mutation()),
        Some(VerificationVectorMutation::MixedHashLane)
    );
    Ok(())
}

#[test]
fn compatibility_suite_is_preserved_by_verification_vectors() -> Result<(), ZkError> {
    let hash = DomainHash::Sha256;
    let proto_suite =
        pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_UNMASKED_NO_IPA;
    let domain_suite = DomainProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa;
    let mut operation = bundle_operation(hash)?;
    let Operation::VerifyClaimProofBundle(bundle) = operation
        .operation
        .as_mut()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?
    else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    bundle.expected_proof_suite = EnumValue::from(proto_suite);
    let claim_proof_bundle = bundle.claim_proof_bundle.get_or_insert_default();
    claim_proof_bundle.proof_suite = EnumValue::from(proto_suite);
    for stage in &mut claim_proof_bundle.stages {
        stage.proof.get_or_insert_default().proof_suite = EnumValue::from(proto_suite);
    }
    let claim_proof_bundle = match reallyme_zk_proto_codec::operation::decode_operation_request(
        &operation.encode_to_vec(),
    )? {
        ZkProviderOperation::VerifyClaimProofBundle {
            claim_proof_bundle, ..
        } => claim_proof_bundle,
        _ => return Err(ZkError::new(ZkErrorReason::MissingOperation)),
    };

    let seed = decode_verification_vector_set(
        &vector_set(
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE,
            success_response(true),
            true,
        )?
        .encode_to_vec(),
    )?;
    let pins = seed.artifact_manifests();
    let artifact_manifests = [
        *pins
            .first()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?,
        *pins
            .get(1)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?,
        *pins
            .get(2)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?,
        *pins
            .get(3)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?,
    ];
    let encoded = encode_claim_proof_bundle_verification_vector_set(
        ClaimProofBundleVerificationVectorInput::try_new_for_suite(
            DomainBundleKind::CredentialSubjectClaimV1,
            hash,
            domain_suite,
            &claim_proof_bundle,
            artifact_manifests,
        )?,
    )?;
    let decoded = decode_verification_vector_set(&encoded)?;
    assert_eq!(decoded.proof_suite(), domain_suite);
    let operation = decoded
        .into_vectors()
        .into_iter()
        .next()
        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?
        .execute()?;
    let ZkProviderOperation::VerifyClaimProofBundle {
        claim_proof_bundle,
        expected_proof_suite,
        ..
    } = operation
    else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    assert_eq!(expected_proof_suite, domain_suite);
    assert_eq!(claim_proof_bundle.proof_suite(), domain_suite);
    Ok(())
}

#[test]
fn preflight_mutations_return_exact_typed_errors() -> Result<(), ZkError> {
    let cases = [
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_EMPTY_PROOF,
            ZkErrorReason::EmptyInput,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_PROOF_TOO_LARGE,
            ZkErrorReason::ProofTooLarge,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_MALFORMED_PUBLIC_INPUTS,
            ZkErrorReason::InvalidProofEncoding,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_NONCE,
            ZkErrorReason::BindingMismatch,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_AUDIENCE,
            ZkErrorReason::BindingMismatch,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_TRANSACTION_DATA,
            ZkErrorReason::BindingMismatch,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_UNSUPPORTED_TRANSACTION_DATA,
            ZkErrorReason::BindingMismatch,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_UNSUPPORTED_CIRCUIT_VERSION,
            ZkErrorReason::UnsupportedCircuit,
        ),
    ];
    for (mutation, expected) in cases {
        let encoded = vector_set(mutation, error_response(expected), false)?.encode_to_vec();
        let error = decode_verification_vector_set(&encoded)?
            .into_vectors()
            .pop()
            .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?
            .execute()
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), expected);
    }
    Ok(())
}

#[test]
fn provider_checked_mutations_remain_valid_verification_operations() -> Result<(), ZkError> {
    let cases = [
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_TAMPERED_PROOF,
            ZkErrorReason::InvalidProof,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_STALE_ARTIFACT_MANIFEST,
            ZkErrorReason::ArtifactMismatch,
        ),
    ];
    for (mutation, expected) in cases {
        let encoded = vector_set(mutation, error_response(expected), false)?.encode_to_vec();
        assert!(matches!(
            decode_verification_vector_set(&encoded)?
                .into_vectors()
                .pop()
                .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?
                .execute()?,
            ZkProviderOperation::VerifyStage { .. }
        ));
    }
    Ok(())
}

#[test]
fn bundle_shape_mutations_return_exact_typed_errors() -> Result<(), ZkError> {
    let cases = [
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_DUPLICATE_STAGE,
            ZkErrorReason::DuplicateStage,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_MISSING_STAGE,
            ZkErrorReason::MissingStage,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_STAGE,
            ZkErrorReason::StageMismatch,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_MIXED_HASH_LANE,
            ZkErrorReason::StageMismatch,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_CREDENTIAL_STATUS_PRESENT,
            ZkErrorReason::MalformedProtobuf,
        ),
    ];
    for (mutation, expected) in cases {
        let encoded = vector_set(mutation, error_response(expected), true)?.encode_to_vec();
        let error = decode_verification_vector_set(&encoded)?
            .into_vectors()
            .pop()
            .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?
            .execute()
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), expected);
    }
    Ok(())
}

#[test]
fn bundle_only_mutation_is_rejected_for_stage_vector() -> Result<(), ZkError> {
    let encoded = vector_set(
        pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_MISSING_STAGE,
        error_response(ZkErrorReason::MissingStage),
        false,
    )?
    .encode_to_vec();
    let reason = decode_verification_vector_set(&encoded)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::InvalidClaimProofBundle));
    Ok(())
}

#[test]
fn duplicate_wire_encoding_is_rejected_as_noncanonical() -> Result<(), ZkError> {
    let mut encoded = vector_set(
        pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE,
        success_response(false),
        false,
    )?
    .encode_to_vec();
    encoded.extend_from_slice(&[0x08, 0x01]);
    let reason = decode_verification_vector_set(&encoded)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::MalformedProtobuf));
    Ok(())
}

#[test]
fn expected_stage_identity_must_match_the_base_operation() -> Result<(), ZkError> {
    let mut response = success_response(false);
    let Some(Outcome::Result(result)) = response.outcome.as_mut() else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    let Some(ProviderResult::StageVerification(verification)) = result.result.as_mut() else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    verification.circuit_ref =
        MessageField::some(circuit_ref(DomainHash::Sha256, DomainStage::Claim));
    let encoded = vector_set(
        pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE,
        response,
        false,
    )?
    .encode_to_vec();
    let reason = decode_verification_vector_set(&encoded)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::StageMismatch));
    Ok(())
}

#[test]
fn mutation_expected_error_must_match_exactly() -> Result<(), ZkError> {
    let encoded = vector_set(
        pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_EMPTY_PROOF,
        error_response(ZkErrorReason::InvalidProof),
        false,
    )?
    .encode_to_vec();
    let reason = decode_verification_vector_set(&encoded)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::InvalidClaimProofBundle));
    Ok(())
}

#[path = "verification_vector_tests/artifact_identity_tests.rs"]
mod artifact_identity_tests;
