// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Domain conversion tests for generated protobuf bindings.

#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration, Message, MessageField};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{
        ZkCircuitFamily as DomainCircuitFamily, ZkCircuitRef as DomainCircuitRef,
        ZkCircuitStage as DomainCircuitStage,
        ZkCredentialHashAlgorithm as DomainCredentialHashAlgorithm,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkPublicInputDescriptor, ZkPublicInputName, ABSENT_TRANSACTION_DATA_HASH},
};
use reallyme_zk_artifacts::{
    ArtifactManifestPin, ProductionArtifactManifest, ProductionArtifactManifestDraft,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    __buffa::oneof::zk_error::Detail as ProtoZkErrorDetail, Digest, ZkArtifactManifest,
    ZkCircuitCapabilities, ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage,
    ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimProofBundleStage,
    ZkClaimProofBundleStageProofPackage, ZkCredentialHashAlgorithm, ZkDisclosureMode,
    ZkError as ProtoZkError, ZkErrorReason as ProtoZkErrorReason, ZkPersonaBinding, ZkProofPackage,
    ZkProofSuite, ZkPublicInputs, ZkSemanticGuarantee, ZkSessionBinding, ZkSubjectBinding,
};
use reallyme_zk_proto_codec::{
    artifact::{artifact_manifest_to_proto, decode_artifact_manifest, seal_artifact_manifest},
    error::{error_reason_to_proto, error_to_proto, error_to_proto_reason},
};

#[path = "domain_tests/canonical_admission.rs"]
mod canonical_admission;
use canonical_admission::{admit_artifact_manifest, admit_claim_proof_bundle, admit_error};

const ALL_ERROR_REASONS: &[(ZkErrorReason, ProtoZkErrorReason)] = &[
    (
        ZkErrorReason::UnknownCircuit,
        ProtoZkErrorReason::ZK_ERROR_REASON_UNKNOWN_CIRCUIT,
    ),
    (
        ZkErrorReason::UnsupportedCircuit,
        ProtoZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_CIRCUIT,
    ),
    (
        ZkErrorReason::EmptyInput,
        ProtoZkErrorReason::ZK_ERROR_REASON_EMPTY_INPUT,
    ),
    (
        ZkErrorReason::ProofTooLarge,
        ProtoZkErrorReason::ZK_ERROR_REASON_PROOF_TOO_LARGE,
    ),
    (
        ZkErrorReason::PublicInputsTooLarge,
        ProtoZkErrorReason::ZK_ERROR_REASON_PUBLIC_INPUTS_TOO_LARGE,
    ),
    (
        ZkErrorReason::WitnessTooLarge,
        ProtoZkErrorReason::ZK_ERROR_REASON_WITNESS_TOO_LARGE,
    ),
    (
        ZkErrorReason::LengthOverflow,
        ProtoZkErrorReason::ZK_ERROR_REASON_LENGTH_OVERFLOW,
    ),
    (
        ZkErrorReason::InvalidProofEncoding,
        ProtoZkErrorReason::ZK_ERROR_REASON_INVALID_PROOF_ENCODING,
    ),
    (
        ZkErrorReason::InvalidProof,
        ProtoZkErrorReason::ZK_ERROR_REASON_INVALID_PROOF,
    ),
    (
        ZkErrorReason::BindingMismatch,
        ProtoZkErrorReason::ZK_ERROR_REASON_BINDING_MISMATCH,
    ),
    (
        ZkErrorReason::ArtifactMismatch,
        ProtoZkErrorReason::ZK_ERROR_REASON_ARTIFACT_MISMATCH,
    ),
    (
        ZkErrorReason::BackendUnavailable,
        ProtoZkErrorReason::ZK_ERROR_REASON_BACKEND_UNAVAILABLE,
    ),
    (
        ZkErrorReason::BackendFailure,
        ProtoZkErrorReason::ZK_ERROR_REASON_BACKEND_FAILURE,
    ),
    (
        ZkErrorReason::InvalidPublicInputName,
        ProtoZkErrorReason::ZK_ERROR_REASON_INVALID_PUBLIC_INPUT_NAME,
    ),
    (
        ZkErrorReason::PublicKeyTooLarge,
        ProtoZkErrorReason::ZK_ERROR_REASON_PUBLIC_KEY_TOO_LARGE,
    ),
    (
        ZkErrorReason::ClaimPayloadTooLarge,
        ProtoZkErrorReason::ZK_ERROR_REASON_CLAIM_PAYLOAD_TOO_LARGE,
    ),
    (
        ZkErrorReason::InvalidClaimProofBundle,
        ProtoZkErrorReason::ZK_ERROR_REASON_INVALID_CLAIM_PROOF_BUNDLE,
    ),
    (
        ZkErrorReason::DuplicateStage,
        ProtoZkErrorReason::ZK_ERROR_REASON_DUPLICATE_STAGE,
    ),
    (
        ZkErrorReason::MissingStage,
        ProtoZkErrorReason::ZK_ERROR_REASON_MISSING_STAGE,
    ),
    (
        ZkErrorReason::StageMismatch,
        ProtoZkErrorReason::ZK_ERROR_REASON_STAGE_MISMATCH,
    ),
    (
        ZkErrorReason::MalformedProtobuf,
        ProtoZkErrorReason::ZK_ERROR_REASON_MALFORMED_PROTOBUF,
    ),
    (
        ZkErrorReason::MalformedJson,
        ProtoZkErrorReason::ZK_ERROR_REASON_MALFORMED_JSON,
    ),
    (
        ZkErrorReason::MissingOperation,
        ProtoZkErrorReason::ZK_ERROR_REASON_MISSING_OPERATION,
    ),
    (
        ZkErrorReason::UnsupportedTransport,
        ProtoZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT,
    ),
    (
        ZkErrorReason::MessageTooLarge,
        ProtoZkErrorReason::ZK_ERROR_REASON_MESSAGE_TOO_LARGE,
    ),
    (
        ZkErrorReason::ArtifactTooLarge,
        ProtoZkErrorReason::ZK_ERROR_REASON_ARTIFACT_TOO_LARGE,
    ),
    (
        ZkErrorReason::UnsupportedProofSuite,
        ProtoZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE,
    ),
    (
        ZkErrorReason::UntrustedIssuer,
        ProtoZkErrorReason::ZK_ERROR_REASON_UNTRUSTED_ISSUER,
    ),
    (
        ZkErrorReason::PresentationExpired,
        ProtoZkErrorReason::ZK_ERROR_REASON_PRESENTATION_EXPIRED,
    ),
    (
        ZkErrorReason::PresentationExpiryTooFar,
        ProtoZkErrorReason::ZK_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR,
    ),
    (
        ZkErrorReason::ResourceExhausted,
        ProtoZkErrorReason::ZK_ERROR_REASON_RESOURCE_EXHAUSTED,
    ),
];

fn digest(value: u8) -> Digest {
    Digest {
        value: vec![value; 32],
        __buffa_unknown_fields: Default::default(),
    }
}

fn capabilities() -> ZkCircuitCapabilities {
    ZkCircuitCapabilities {
        subject_binding: EnumValue::from(ZkSubjectBinding::ZK_SUBJECT_BINDING_REQUIRED),
        persona_binding: EnumValue::from(ZkPersonaBinding::ZK_PERSONA_BINDING_REQUIRED),
        may_be_correlated: true,
        predicate_types: Vec::new(),
        disclosure_modes: vec![EnumValue::from(ZkDisclosureMode::ZK_DISCLOSURE_MODE_REVEAL)],
        semantic_guarantees: vec![
            EnumValue::from(ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_SESSION_BOUND),
            EnumValue::from(ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_AUDIENCE_BOUND),
            EnumValue::from(ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_TRANSACTION_DATA_BOUND),
            EnumValue::from(ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_CLAIM_INTEGRITY),
            EnumValue::from(ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_PRIVATE_PERSONA_BINDING),
        ],
        __buffa_unknown_fields: Default::default(),
    }
}

fn circuit_ref() -> ZkCircuitRef {
    circuit_ref_for_stage(ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM)
}

fn circuit_ref_for_stage(stage: ZkCircuitStage) -> ZkCircuitRef {
    ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(
            ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        family: EnumValue::from(ZkCircuitFamily::ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1),
        stage: EnumValue::from(stage),
        circuit_revision: 1,
        __buffa_unknown_fields: Default::default(),
    }
}

fn manifest() -> ZkArtifactManifest {
    ZkArtifactManifest {
        circuit_id: EnumValue::from(ZkCircuitId::ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1),
        credential_hash_algorithm: EnumValue::from(
            ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        nargo_version: "1.0.0".to_owned(),
        barretenberg_version: "1.0.0".to_owned(),
        noir_source_sha256: MessageField::some(digest(1)),
        bytecode_sha256: MessageField::some(digest(2)),
        verification_key_sha256: MessageField::some(digest(3)),
        capability_registry_sha256: MessageField::some(digest(4)),
        vector_set_sha256: vec![digest(5)],
        capabilities: MessageField::some(capabilities()),
        circuit_ref: MessageField::some(circuit_ref()),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

fn production_to_circuit_stage(stage: ZkClaimProofBundleStage) -> ZkCircuitStage {
    match stage {
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION => {
            ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION
        }
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE => {
            ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE
        }
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT => {
            ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ROOT
        }
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM => {
            ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM
        }
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_UNSPECIFIED => {
            ZkCircuitStage::ZK_CIRCUIT_STAGE_UNSPECIFIED
        }
    }
}

fn proof_package(stage: ZkClaimProofBundleStage) -> Result<ZkProofPackage, ZkError> {
    Ok(ZkProofPackage {
        circuit_id: EnumValue::from(ZkCircuitId::ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1),
        circuit_id_string: "rm-zk-private-persona-claim-v1".to_owned(),
        proof: vec![stage as u8, 9],
        public_inputs: MessageField::some(ZkPublicInputs {
            encoded: canonical_public_inputs(stage)?,
            __buffa_unknown_fields: Default::default(),
        }),
        artifact_identity: Some(
            reallyme_zk_proto::generated::proto::reallyme::zk::v1::ZkArtifactManifestDigest {
                value: vec![7; 32],
                __buffa_unknown_fields: Default::default(),
            }
            .into(),
        ),
        named_public_inputs: Vec::new(),
        circuit_ref: MessageField::some(circuit_ref_for_stage(production_to_circuit_stage(stage))),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        __buffa_unknown_fields: Default::default(),
    })
}

fn stage_package(
    stage: ZkClaimProofBundleStage,
) -> Result<ZkClaimProofBundleStageProofPackage, ZkError> {
    Ok(ZkClaimProofBundleStageProofPackage {
        bundle_kind: EnumValue::from(
            ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
        ),
        stage: EnumValue::from(stage),
        proof: MessageField::some(proof_package(stage)?),
        __buffa_unknown_fields: Default::default(),
    })
}

fn session_binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: vec![1_u8; 32],
        audience_hash: vec![2_u8; 32],
        transaction_data_hash: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn claim_proof_bundle() -> Result<ZkClaimProofBundle, ZkError> {
    Ok(ZkClaimProofBundle {
        bundle_kind: EnumValue::from(
            ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
        ),
        format_version: 1,
        stages: vec![
            stage_package(ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION)?,
            stage_package(
                ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE,
            )?,
            stage_package(ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT)?,
            stage_package(ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM)?,
        ],
        session_binding: MessageField::some(session_binding()),
        credential_hash_algorithm: EnumValue::from(
            ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        __buffa_unknown_fields: Default::default(),
    })
}

#[test]
fn claim_proof_bundle_rejects_unrecognized_bundle_version() -> Result<(), ZkError> {
    let mut bundle = claim_proof_bundle()?;
    bundle.format_version = 2;
    let error = admit_claim_proof_bundle(bundle)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedCircuit);
    Ok(())
}

#[test]
fn claim_proof_bundle_rejects_inconsistent_proof_metadata() -> Result<(), ZkError> {
    let mut bundle = claim_proof_bundle()?;
    let first_stage = bundle
        .stages
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    first_stage.proof.get_or_insert_default().circuit_id_string = "wrong".to_owned();
    let error = admit_claim_proof_bundle(bundle)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}

#[test]
fn claim_proof_bundle_rejects_retired_suite_number() -> Result<(), ZkError> {
    let mut bundle = claim_proof_bundle()?;
    bundle.proof_suite = EnumValue::from(2);
    let error = admit_claim_proof_bundle(bundle)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedProofSuite);
    Ok(())
}

#[test]
fn claim_proof_bundle_rejects_retired_stage_suite_number() -> Result<(), ZkError> {
    let mut bundle = claim_proof_bundle()?;
    let first_stage = bundle
        .stages
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    first_stage.proof.get_or_insert_default().proof_suite = EnumValue::from(2);
    let error = admit_claim_proof_bundle(bundle)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedProofSuite);
    Ok(())
}

fn canonical_public_inputs(stage: ZkClaimProofBundleStage) -> Result<Vec<u8>, ZkError> {
    let domain_stage = match stage {
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION => DomainCircuitStage::Session,
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE => {
            DomainCircuitStage::CredentialEnvelope
        }
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT => {
            DomainCircuitStage::CredentialRoot
        }
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM => DomainCircuitStage::Claim,
        ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_UNSPECIFIED => {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
    };
    let circuit_ref = DomainCircuitRef::new(
        DomainCredentialHashAlgorithm::Sha256,
        DomainCircuitFamily::PrivatePersonaClaimV1,
        domain_stage,
    );
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
        (ZkPublicInputName::IssuerPublicKeyX, [3_u8; 32]),
        (ZkPublicInputName::IssuerPublicKeyY, [4_u8; 32]),
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
        value[0] = 5;
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::Value,
            &value,
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

#[test]
fn error_reason_converts_to_proto_reason() {
    for (domain, proto) in ALL_ERROR_REASONS {
        assert_eq!(error_reason_to_proto(*domain), *proto);
        assert_eq!(error_to_proto_reason(ZkError::new(*domain)), *proto);
        assert_eq!(
            domain.reason_code(),
            u32::try_from(proto.to_i32()).unwrap_or_default()
        );
    }
}

#[test]
fn structured_error_converts_to_proto_and_back() -> Result<(), ZkError> {
    for (domain, proto_reason) in ALL_ERROR_REASONS {
        let domain_error = ZkError::new(*domain);
        let proto_error = error_to_proto(domain_error);

        assert_eq!(proto_error.reason, EnumValue::from(*proto_reason));
        assert_eq!(admit_error(proto_error)?, domain_error);
    }
    Ok(())
}

#[test]
fn structured_error_rejects_missing_detail() {
    let proto_error = ProtoZkError {
        reason: EnumValue::from(ProtoZkErrorReason::ZK_ERROR_REASON_BACKEND_FAILURE),
        detail: None,
        __buffa_unknown_fields: Default::default(),
    };

    let err = admit_error(proto_error)
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::UnknownCircuit));

    assert_eq!(err.reason(), ZkErrorReason::MalformedProtobuf);
}

#[test]
fn structured_error_rejects_unknown_detail_enum() {
    let proto_error = ProtoZkError {
        reason: EnumValue::from(ProtoZkErrorReason::ZK_ERROR_REASON_BACKEND_FAILURE),
        detail: Some(ProtoZkErrorDetail::BackendReason(EnumValue::from(65_535))),
        __buffa_unknown_fields: Default::default(),
    };

    let err = admit_error(proto_error)
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::UnknownCircuit));

    assert_eq!(err.reason(), ZkErrorReason::MalformedProtobuf);
}

#[test]
fn structured_error_rejects_mismatched_top_level_reason() {
    let mut proto_error = error_to_proto(ZkError::new(ZkErrorReason::BindingMismatch));
    proto_error.reason = EnumValue::from(ProtoZkErrorReason::ZK_ERROR_REASON_BACKEND_FAILURE);

    let err = admit_error(proto_error)
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::UnknownCircuit));

    assert_eq!(err.reason(), ZkErrorReason::MalformedProtobuf);
}

#[test]
fn artifact_manifest_converts_to_domain_manifest() -> Result<(), ZkError> {
    let manifest = admit_artifact_manifest(manifest())?;

    assert_eq!(manifest.circuit_ref().revision, 1);
    assert_eq!(manifest.semantic_guarantees().len(), 5);
    assert_eq!(manifest.digests().bytecode_sha256.as_bytes(), &[2_u8; 32]);
    assert_eq!(manifest.toolchain().nargo_version().as_bytes(), b"1.0.0");
    assert_eq!(
        manifest.proof_suite(),
        reallyme_zk_api::proofs::ZkProofSuite::PRODUCTION
    );
    assert_eq!(
        manifest.toolchain().barretenberg_version().as_bytes(),
        b"1.0.0"
    );
    Ok(())
}

#[test]
fn canonical_artifact_manifest_bytes_decode_to_the_same_identity() -> Result<(), ZkError> {
    let source = manifest();
    let bytes = source.encode_to_vec();
    let decoded = decode_artifact_manifest(&bytes)?;
    let direct = admit_artifact_manifest(source)?;

    assert_eq!(decoded, direct);
    Ok(())
}

#[test]
fn duplicate_artifact_manifest_wire_field_is_rejected() {
    let mut bytes = manifest().encode_to_vec();
    bytes.extend_from_slice(&[0x18, 0x01]);
    let reason = decode_artifact_manifest(&bytes)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::MalformedProtobuf));
}

#[test]
fn artifact_manifest_round_trips_canonical_protobuf() -> Result<(), ZkError> {
    let source = manifest();
    let expected_bytes = source.encode_to_vec();
    let domain = admit_artifact_manifest(source)?;
    let encoded = artifact_manifest_to_proto(&domain)?;

    assert_eq!(encoded.encode_to_vec(), expected_bytes);
    assert_eq!(admit_artifact_manifest(encoded)?, domain);
    Ok(())
}

#[test]
fn artifact_manifest_draft_seals_to_canonical_identity() -> Result<(), ZkError> {
    let source = manifest();
    let expected_bytes = source.encode_to_vec();
    let decoded = admit_artifact_manifest(source)?;
    let draft = ProductionArtifactManifestDraft::try_new(
        decoded.bundle_kind(),
        decoded.stage(),
        decoded.circuit_ref(),
        decoded.proof_suite(),
        decoded.toolchain(),
        decoded.capabilities(),
        decoded.digests().clone(),
    )?;
    let sealed = seal_artifact_manifest(draft)?;

    assert_eq!(sealed.protobuf().encode_to_vec(), expected_bytes);
    assert_eq!(sealed.manifest(), &decoded);
    Ok(())
}

#[test]
fn artifact_manifest_encoding_rejects_stale_identity() -> Result<(), ZkError> {
    let domain = admit_artifact_manifest(manifest())?;
    let stale = ProductionArtifactManifest::try_new(
        domain.bundle_kind(),
        domain.stage(),
        domain.circuit_ref(),
        ArtifactManifestPin::try_new(
            domain.proof_suite(),
            ZkArtifactManifestDigest::from_bytes([255_u8; 32]),
        )?,
        domain.toolchain(),
        domain.capabilities(),
        domain.digests().clone(),
    )?;
    let error = artifact_manifest_to_proto(&stale)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn artifact_manifest_identity_covers_canonical_protobuf_fields() -> Result<(), ZkError> {
    let first = admit_artifact_manifest(manifest())?;
    let mut changed = manifest();
    changed.nargo_version = "1.0.1".to_owned();
    let second = admit_artifact_manifest(changed)?;

    assert_ne!(first.manifest_sha256(), second.manifest_sha256());
    Ok(())
}

#[test]
fn artifact_manifest_rejects_retired_suite_number() -> Result<(), ZkError> {
    let mut manifest = manifest();
    manifest.proof_suite = EnumValue::from(2);
    let error = admit_artifact_manifest(manifest)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedProofSuite);
    Ok(())
}

#[test]
fn artifact_manifest_rejects_inconsistent_string_version() -> Result<(), ZkError> {
    let mut manifest = manifest();
    manifest
        .circuit_ref
        .get_or_insert_default()
        .circuit_revision = 2;

    let error = admit_artifact_manifest(manifest)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedCircuit);
    Ok(())
}

#[test]
fn artifact_manifest_rejects_invalid_toolchain_version() -> Result<(), ZkError> {
    let mut manifest = manifest();
    manifest.nargo_version = "../nargo".to_owned();

    let error = admit_artifact_manifest(manifest)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn artifact_manifest_rejects_missing_digest() -> Result<(), ZkError> {
    let mut manifest = manifest();
    manifest.bytecode_sha256 = MessageField::none();

    let err = admit_artifact_manifest(manifest)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn artifact_manifest_rejects_unknown_circuit_family() -> Result<(), ZkError> {
    let mut manifest = manifest();
    let mut circuit_ref = circuit_ref();
    circuit_ref.family = EnumValue::from(99);
    manifest.circuit_ref = MessageField::some(circuit_ref);

    let err = admit_artifact_manifest(manifest)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::UnknownCircuit);
    Ok(())
}

#[test]
fn artifact_manifest_rejects_claim_bundle_4_stage_for_production() -> Result<(), ZkError> {
    let mut manifest = manifest();
    let mut circuit_ref = circuit_ref();
    circuit_ref.stage = EnumValue::from(ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM_BUNDLE_4);
    manifest.circuit_ref = MessageField::some(circuit_ref);

    let err = admit_artifact_manifest(manifest)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::UnsupportedCircuit);
    Ok(())
}

#[path = "domain_tests/claim_proof_bundle_tests.rs"]
mod claim_proof_bundle_tests;
#[path = "domain_tests/status_qualified_tests.rs"]
mod status_qualified_tests;

#[path = "domain_tests/artifact_unknown_fields_tests.rs"]
mod artifact_unknown_fields_tests;

#[path = "domain_tests/capability_tests.rs"]
mod capability_tests;
