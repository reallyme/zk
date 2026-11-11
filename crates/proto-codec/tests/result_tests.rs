// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical provider-result conversion tests.

#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::circuit_ref_capabilities,
    circuits::ZkCredentialHashAlgorithm as DomainCredentialHashAlgorithm,
    claim_bundle::{
        verify_presentation_bound_claim_bundle_with, ZkClaimProofBundle as DomainClaimProofBundle,
        ZkClaimProofBundleKind as DomainProfile, ZkClaimProofBundleStage as DomainStage,
        ZkClaimProofBundleStageProof as DomainStageProof, ZkPresentationBoundClaimBundleVerifier,
        ZkPresentationBoundClaimBundleVerifyRequest,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProof as DomainProof, ZkProofSuite as DomainProofSuite, ZkPublicInputDescriptor,
        ZkPublicInputName, ZkPublicInputs as DomainPublicInputs, ZkSessionBinding,
        ABSENT_TRANSACTION_DATA_HASH,
    },
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactToolchain, Digest32, ProductionArtifactManifestDraft,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    zk_provider_operation_response::Outcome, zk_provider_operation_result::Result as ProtoResult,
    ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage, ZkClaimProofBundleKind,
    ZkCredentialHashAlgorithm, ZkP256PublicKey,
    ZkPresentationBoundClaimBundleVerification as ProtoClaimProofBundleVerification,
    ZkPresentationBoundClaimStatement, ZkProofSuite, ZkProviderOperationResponse,
    ZkProviderOperationResult, ZkVerification,
};
use reallyme_zk_proto_codec::error::error_to_proto;
use reallyme_zk_proto_codec::result::{
    decode_operation_response, encode_artifact_manifest_response,
    encode_claim_proof_bundle_response, encode_claim_proof_bundle_verification_response,
    encode_operation_failure_response, encode_stage_proof_response,
    encode_stage_verification_response, ZkProviderOperationOutcome,
    ZkProviderOperationResult as DomainResult,
};

fn response(result: ProtoResult) -> ZkProviderOperationResponse {
    ZkProviderOperationResponse {
        outcome: Some(Outcome::Result(Box::new(ZkProviderOperationResult {
            result: Some(result),
            __buffa_unknown_fields: Default::default(),
        }))),
        request_sha256: vec![7; 32],
        __buffa_unknown_fields: Default::default(),
    }
}

fn verified_statement() -> ZkPresentationBoundClaimStatement {
    ZkPresentationBoundClaimStatement {
        issuer: MessageField::some(ZkP256PublicKey {
            x: vec![21; 32],
            y: vec![22; 32],
            __buffa_unknown_fields: Default::default(),
        }),
        persona: MessageField::none(),
        claim_name_hash: vec![25; 32],
        claim_value: {
            let mut value = vec![0; 64];
            value[0] = 26;
            value
        },
        claim_value_length: 1,
        presentation_expiry_unix: 42,
        session_link_commitment: vec![27; 32],
        credential_binding: vec![28; 32],
        __buffa_unknown_fields: Default::default(),
    }
}

fn session_binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [1; 32],
        audience_hash: [2; 32],
        transaction_data_hash: None,
    }
}

fn error_reason<T>(result: Result<T, ZkError>) -> ZkErrorReason {
    result
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::BackendFailure))
        .reason()
}

fn canonical_public_inputs(stage: DomainStage) -> Result<Vec<u8>, ZkError> {
    let circuit_ref = DomainProfile::CredentialSubjectClaimV1
        .source_ref(DomainCredentialHashAlgorithm::Sha256, stage);
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::Challenge,
        &[1_u8; 32],
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::AudienceHash,
        &[2_u8; 32],
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::TransactionDataHash,
        &ABSENT_TRANSACTION_DATA_HASH,
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::ExpiryUnix,
        &42_u64.to_be_bytes(),
    )?;
    for (name, value) in [
        (ZkPublicInputName::SessionBinding, [10_u8; 32]),
        (ZkPublicInputName::EnvelopeBinding, [11_u8; 32]),
        (ZkPublicInputName::CredentialBinding, [12_u8; 32]),
    ] {
        if descriptor.fields().iter().any(|field| field.name == name) {
            write_public_input(bytes.as_mut_slice(), descriptor, name, &value)?;
        }
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::IssuerPublicKeyX)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::IssuerPublicKeyX,
            &[21_u8; 32],
        )?;
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::IssuerPublicKeyY)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::IssuerPublicKeyY,
            &[22_u8; 32],
        )?;
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::PersonaPublicKeyX)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::PersonaPublicKeyX,
            &[23_u8; 32],
        )?;
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::PersonaPublicKeyY)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::PersonaPublicKeyY,
            &[24_u8; 32],
        )?;
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::ValueLength)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::ValueLength,
            &1_u32.to_be_bytes(),
        )?;
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::Value)
    {
        let mut value = [0_u8; 64];
        value[0] = 26;
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::Value,
            &value,
        )?;
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::ClaimNameHash)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::ClaimNameHash,
            &[25_u8; 32],
        )?;
    }
    Ok(bytes)
}

fn write_public_input(
    bytes: &mut [u8],
    descriptor: ZkPublicInputDescriptor,
    name: ZkPublicInputName,
    value: &[u8],
) -> Result<(), ZkError> {
    let target = bytes
        .get_mut(descriptor.field_range(name)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if target.len() != value.len() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    target.copy_from_slice(value);
    Ok(())
}

fn stage_proof() -> Result<DomainProof, ZkError> {
    stage_proof_for_stage(DomainStage::Claim)
}

fn stage_proof_for_stage(stage: DomainStage) -> Result<DomainProof, ZkError> {
    let circuit_ref = DomainProfile::CredentialSubjectClaimV1
        .source_ref(DomainCredentialHashAlgorithm::Sha256, stage);
    DomainProof::try_from_exact_parts(
        DomainProfile::CredentialSubjectClaimV1.circuit_id(),
        circuit_ref,
        DomainProofSuite::PRODUCTION,
        ZkArtifactManifestDigest::from_bytes([31; 32]),
        vec![0xa5; 48],
        DomainPublicInputs::try_from_bytes(canonical_public_inputs(stage)?)?,
    )
}

fn claim_proof_bundle() -> Result<DomainClaimProofBundle, ZkError> {
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(DomainStage::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for stage in DomainStage::ALL {
        stages.push(DomainStageProof::try_from_parts(
            DomainProfile::CredentialSubjectClaimV1,
            *stage,
            stage_proof_for_stage(*stage)?,
        )?);
    }
    DomainClaimProofBundle::try_from_stage_proofs(
        DomainProfile::CredentialSubjectClaimV1,
        session_binding(),
        stages,
    )
}

struct AcceptingBundleVerifier;

impl ZkPresentationBoundClaimBundleVerifier for AcceptingBundleVerifier {
    fn verify_presentation_bound_claim_bundle_evidence(
        &self,
        _request: ZkPresentationBoundClaimBundleVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        Ok(())
    }
}

fn sealed_manifest() -> Result<reallyme_zk_artifacts::ProductionArtifactManifest, ZkError> {
    let bundle_kind = DomainProfile::CredentialSubjectClaimV1;
    let stage = DomainStage::Claim;
    let circuit_ref = bundle_kind.source_ref(DomainCredentialHashAlgorithm::Sha256, stage);
    let draft = ProductionArtifactManifestDraft::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        DomainProofSuite::PRODUCTION,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        circuit_ref_capabilities(circuit_ref)?,
        ArtifactDigests {
            noir_source_sha256: Digest32::from_bytes([3; 32]),
            bytecode_sha256: Digest32::from_bytes([4; 32]),
            verification_key_sha256: Digest32::from_bytes([5; 32]),
            capability_registry_sha256: Digest32::from_bytes([6; 32]),
            vector_set_sha256: vec![Digest32::from_bytes([7; 32])],
        },
    )?;
    Ok(
        reallyme_zk_proto_codec::artifact::seal_artifact_manifest(draft)?
            .into_parts()
            .0,
    )
}

#[test]
fn missing_response_outcome_fails_closed() {
    let mut response = ZkProviderOperationResponse::default();
    response.request_sha256 = vec![7; 32];
    assert_eq!(
        error_reason(decode_operation_response(&response.encode_to_vec())),
        ZkErrorReason::MissingOperation
    );
}

#[test]
fn typed_error_outcome_round_trips_to_domain() -> Result<(), ZkError> {
    let response = ZkProviderOperationResponse {
        outcome: Some(Outcome::Error(Box::new(error_to_proto(ZkError::new(
            ZkErrorReason::BackendUnavailable,
        ))))),
        request_sha256: vec![7; 32],
        __buffa_unknown_fields: Default::default(),
    };

    match decode_operation_response(&response.encode_to_vec())?.into_outcome() {
        ZkProviderOperationOutcome::Failure(error) => {
            assert_eq!(error.reason(), ZkErrorReason::BackendUnavailable);
            Ok(())
        }
        ZkProviderOperationOutcome::Success(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn canonical_typed_error_bytes_decode_to_domain() -> Result<(), ZkError> {
    let response = ZkProviderOperationResponse {
        outcome: Some(Outcome::Error(Box::new(error_to_proto(ZkError::new(
            ZkErrorReason::BackendUnavailable,
        ))))),
        request_sha256: vec![7; 32],
        __buffa_unknown_fields: Default::default(),
    };

    match decode_operation_response(&response.encode_to_vec())?.into_outcome() {
        ZkProviderOperationOutcome::Failure(error) => {
            assert_eq!(error.reason(), ZkErrorReason::BackendUnavailable);
            Ok(())
        }
        ZkProviderOperationOutcome::Success(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn failure_response_encoder_binds_exact_request_hash() -> Result<(), ZkError> {
    let request = b"malformed but bounded request";
    let encoded = encode_operation_failure_response(
        request.as_slice(),
        ZkError::new(ZkErrorReason::MalformedProtobuf),
    )?;

    let decoded = decode_operation_response(encoded.as_slice())?;
    assert_eq!(decoded.request_sha256(), Digest32::sha256(request));
    match decoded.into_outcome() {
        ZkProviderOperationOutcome::Failure(error) => {
            assert_eq!(error.reason(), ZkErrorReason::MalformedProtobuf);
            Ok(())
        }
        ZkProviderOperationOutcome::Success(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn stage_proof_success_encoder_round_trips() -> Result<(), ZkError> {
    let request = b"canonical request bytes";
    let proof = stage_proof()?;
    let encoded = encode_stage_proof_response(request.as_slice(), &proof)?;
    let decoded = decode_operation_response(encoded.as_slice())?;
    assert_eq!(decoded.request_sha256(), Digest32::sha256(request));
    match decoded.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            DomainResult::StageProof(decoded_proof) => {
                assert_eq!(decoded_proof.circuit_ref(), proof.circuit_ref());
                assert_eq!(decoded_proof.public_inputs(), proof.public_inputs());
                Ok(())
            }
            _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
        },
        ZkProviderOperationOutcome::Failure(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn stage_verification_success_encoder_round_trips() -> Result<(), ZkError> {
    let request = b"canonical verify request";
    let proof = stage_proof()?;
    let encoded = encode_stage_verification_response(request.as_slice(), &proof)?;
    let decoded = decode_operation_response(encoded.as_slice())?;
    assert_eq!(decoded.request_sha256(), Digest32::sha256(request));
    match decoded.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            DomainResult::StageVerification(report) => {
                assert_eq!(report.circuit_ref, Some(proof.circuit_ref()));
                assert_eq!(report.proof_suite, DomainProofSuite::PRODUCTION);
                Ok(())
            }
            _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
        },
        ZkProviderOperationOutcome::Failure(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn claim_proof_bundle_success_encoder_round_trips() -> Result<(), ZkError> {
    let request = b"canonical bundle prove request";
    let bundle = claim_proof_bundle()?;
    let encoded = encode_claim_proof_bundle_response(request.as_slice(), &bundle)?;
    let decoded = decode_operation_response(encoded.as_slice())?;
    assert_eq!(decoded.request_sha256(), Digest32::sha256(request));
    match decoded.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            DomainResult::ClaimProofBundle(decoded_bundle) => {
                assert_eq!(decoded_bundle.bundle_kind(), bundle.bundle_kind());
                assert_eq!(decoded_bundle.proof_suite(), bundle.proof_suite());
                assert_eq!(decoded_bundle.session_binding(), bundle.session_binding());
                assert_eq!(
                    decoded_bundle.stage_proofs().len(),
                    bundle.stage_proofs().len()
                );
                Ok(())
            }
            _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
        },
        ZkProviderOperationOutcome::Failure(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn claim_proof_bundle_verification_success_encoder_round_trips() -> Result<(), ZkError> {
    let request = b"canonical bundle verify request";
    let bundle = claim_proof_bundle()?;
    let statement = bundle.decode_claimed_statement()?;
    let trusted_issuers = [statement.issuer()];
    let verification_request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        &bundle,
        DomainProofSuite::PRODUCTION,
        session_binding(),
        &trusted_issuers,
        41,
    )?;
    let verification = verify_presentation_bound_claim_bundle_with(
        &AcceptingBundleVerifier,
        verification_request,
    )?;
    let encoded =
        encode_claim_proof_bundle_verification_response(request.as_slice(), &verification)?;
    let decoded = decode_operation_response(encoded.as_slice())?;
    assert_eq!(decoded.request_sha256(), Digest32::sha256(request));
    match decoded.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            DomainResult::ClaimProofBundleVerification(report) => {
                assert_eq!(report.bundle_kind, DomainProfile::CredentialSubjectClaimV1);
                assert_eq!(report.verified_stage_count, 4);
                assert_eq!(report.proof_suite, DomainProofSuite::PRODUCTION);
                assert_eq!(report.statement.claim_value(), &[26]);
                assert_eq!(report.statement.credential_binding(), [12; 32]);
                assert_eq!(report.session_link_commitment, [10; 32]);
                let debug = format!("{report:?}");
                assert!(debug.contains("ZkClaimProofBundleVerificationReport"));
                assert!(debug.contains("session_link_commitment"));
                assert!(!debug.contains("10"));
                assert!(!debug.contains("26"));
                Ok(())
            }
            _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
        },
        ZkProviderOperationOutcome::Failure(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn artifact_manifest_success_encoder_round_trips() -> Result<(), ZkError> {
    let request = b"canonical artifact request";
    let manifest = sealed_manifest()?;
    let encoded = encode_artifact_manifest_response(request.as_slice(), &manifest)?;
    let decoded = decode_operation_response(encoded.as_slice())?;
    assert_eq!(decoded.request_sha256(), Digest32::sha256(request));
    match decoded.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            DomainResult::ArtifactManifest(decoded_manifest) => {
                assert_eq!(
                    decoded_manifest.manifest_sha256(),
                    manifest.manifest_sha256()
                );
                Ok(())
            }
            _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
        },
        ZkProviderOperationOutcome::Failure(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn response_byte_decoder_rejects_malformed_unknown_and_nonminimal_bytes() {
    assert_eq!(
        error_reason(decode_operation_response(&[0x80])),
        ZkErrorReason::MalformedProtobuf
    );
    assert_eq!(
        error_reason(decode_operation_response(&[0x18, 0x00])),
        ZkErrorReason::MalformedProtobuf
    );
    assert_eq!(
        error_reason(decode_operation_response(&[
            0x92, 0x00, 0x04, 0x08, 0x0b, 0x40, 0x01,
        ])),
        ZkErrorReason::MalformedProtobuf
    );
}

#[test]
fn claim_proof_bundle_verification_requires_every_production_stage() -> Result<(), ZkError> {
    let valid = response(ProtoResult::ClaimProofBundleVerification(Box::new(
        ProtoClaimProofBundleVerification {
            bundle_kind: EnumValue::from(
                ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ),
            verified_stage_count: 4,
            proof_suite: EnumValue::from(
                ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            statement: MessageField::some(verified_statement()),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    match decode_operation_response(&valid.encode_to_vec())?.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            DomainResult::ClaimProofBundleVerification(verification) => {
                assert_eq!(verification.verified_stage_count, 4);
                assert_eq!(verification.proof_suite, DomainProofSuite::PRODUCTION);
            }
            _ => return Err(ZkError::new(ZkErrorReason::BackendFailure)),
        },
        ZkProviderOperationOutcome::Failure(_) => {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
    }

    let incomplete = response(ProtoResult::ClaimProofBundleVerification(Box::new(
        ProtoClaimProofBundleVerification {
            bundle_kind: EnumValue::from(
                ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ),
            verified_stage_count: 3,
            proof_suite: EnumValue::from(
                ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            statement: MessageField::some(verified_statement()),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    assert_eq!(
        error_reason(decode_operation_response(&incomplete.encode_to_vec())),
        ZkErrorReason::InvalidClaimProofBundle
    );
    Ok(())
}

#[test]
fn claim_proof_bundle_verification_rejects_unknown_suite_number() {
    let verification = response(ProtoResult::ClaimProofBundleVerification(Box::new(
        ProtoClaimProofBundleVerification {
            bundle_kind: EnumValue::from(
                ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ),
            verified_stage_count: 4,
            proof_suite: EnumValue::from(99),
            statement: MessageField::some(verified_statement()),
            __buffa_unknown_fields: Default::default(),
        },
    )));

    assert_eq!(
        error_reason(decode_operation_response(&verification.encode_to_vec())),
        ZkErrorReason::UnsupportedProofSuite
    );
}

#[test]
fn stage_verification_rejects_unspecified_suite() {
    let verification = ZkVerification {
        circuit_id: EnumValue::from(ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1),
        circuit_ref: MessageField::some(ZkCircuitRef {
            credential_hash_algorithm: EnumValue::from(
                ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
            ),
            family: EnumValue::from(ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1),
            stage: EnumValue::from(ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM),
            circuit_revision: 1,
            __buffa_unknown_fields: Default::default(),
        }),
        bundle_kind: EnumValue::from(
            ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ),
        proof_suite: EnumValue::from(ZkProofSuite::ZK_PROOF_SUITE_UNSPECIFIED),
        __buffa_unknown_fields: Default::default(),
    };

    assert_eq!(
        error_reason(decode_operation_response(
            &response(ProtoResult::StageVerification(Box::new(verification))).encode_to_vec(),
        )),
        ZkErrorReason::UnsupportedProofSuite
    );
}

#[test]
fn stage_verification_rejects_bundle_kind_identity_mismatch() {
    let verification = ZkVerification {
        circuit_id: EnumValue::from(ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1),
        circuit_ref: MessageField::some(ZkCircuitRef {
            credential_hash_algorithm: EnumValue::from(
                ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
            ),
            family: EnumValue::from(ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1),
            stage: EnumValue::from(ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM),
            circuit_revision: 1,
            __buffa_unknown_fields: Default::default(),
        }),
        bundle_kind: EnumValue::from(
            ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
        ),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        __buffa_unknown_fields: Default::default(),
    };

    assert_eq!(
        error_reason(decode_operation_response(
            &response(ProtoResult::StageVerification(Box::new(verification))).encode_to_vec(),
        )),
        ZkErrorReason::StageMismatch
    );
}
