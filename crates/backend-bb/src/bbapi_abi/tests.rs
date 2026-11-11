// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    command::BbapiSrsInitProfile,
    compiled_program_json::decode_gzip_with_limit,
    message::{
        BbapiMessage, BN254_FR_MODULUS, VERIFIER_CRS_G1_PREFIX_BYTES, VERIFIER_CRS_G2_BYTES,
    },
    pack::{field_is_canonical, pack_array_header, pack_bin, pack_map_header, pack_str},
    BbapiCircuitProveCommand, BbapiCircuitVerifyCommand, BbapiSrsInitCommand,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::{write::GzEncoder, Compression};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::circuit_ref_capabilities,
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProof, ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputs, ZkSessionBinding,
        ZkWitness, MAX_WITNESS_BYTES,
    },
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactKind, ArtifactManifestPin, ArtifactToolchain, Digest32,
    ProductionArtifactManifest, VerifiedArtifactBytes,
};
use std::io::Write;

use crate::{
    public_input_codec::BarretenbergPublicInputCodec, BbStageArtifacts, BbStageProveRequest,
};

const EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES: usize = 9_152;

fn rejected_reason(bytes: &[u8]) -> Result<ZkErrorReason, ZkError> {
    let error = BbapiMessage::try_from_slice(bytes)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(error.reason())
}

fn circuit_ref() -> ZkCircuitRef {
    ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Session,
    )
}

fn exact_public_inputs() -> Result<ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref())?;
    ZkPublicInputs::try_from_bytes(vec![17_u8; descriptor.encoded_len()?])
}

fn verified_vk() -> Result<VerifiedArtifactBytes, ZkError> {
    let bytes = vec![99_u8; 64];
    VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        bytes,
        Digest32::sha256(&[99_u8; 64]),
    )
}

fn verified_artifact(kind: ArtifactKind) -> Result<VerifiedArtifactBytes, ZkError> {
    let bytes = vec![99_u8; 64];
    VerifiedArtifactBytes::try_from_bytes(kind, bytes, Digest32::sha256(&[99_u8; 64]))
}

fn stage_artifacts() -> Result<BbStageArtifacts, ZkError> {
    stage_artifacts_with_program(compiled_program_json(&[0x04, 0x31, 0x59, 0x26])?)
}

fn stage_artifacts_with_program(bytecode: Vec<u8>) -> Result<BbStageArtifacts, ZkError> {
    let bytecode_digest = Digest32::sha256(bytecode.as_slice());
    let verification_key = vec![99_u8; 64];
    let verification_key_digest = Digest32::sha256(verification_key.as_slice());
    let manifest = ProductionArtifactManifest::try_new(
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkClaimProofBundleStage::Session,
        circuit_ref(),
        ArtifactManifestPin::try_new(
            ZkProofSuite::PRODUCTION,
            ZkArtifactManifestDigest::from_bytes([7_u8; 32]),
        )?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        circuit_ref_capabilities(circuit_ref())?,
        ArtifactDigests {
            noir_source_sha256: Digest32::from_bytes([1_u8; 32]),
            bytecode_sha256: bytecode_digest,
            verification_key_sha256: verification_key_digest,
            capability_registry_sha256: Digest32::from_bytes([3_u8; 32]),
            vector_set_sha256: vec![Digest32::from_bytes([4_u8; 32])],
        },
    )?;
    let bytecode = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::AcirBytecode,
        bytecode,
        bytecode_digest,
    )?;
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        verification_key,
        verification_key_digest,
    )?;
    BbStageArtifacts::try_new(manifest, bytecode, verification_key)
}

fn compiled_program_json(acir_bytecode: &[u8]) -> Result<Vec<u8>, ZkError> {
    let compressed = gzip_bytes(acir_bytecode)?;
    let encoded = STANDARD.encode(compressed.as_slice());
    Ok(format!(r#"{{"bytecode":"{encoded}"}}"#).into_bytes())
}

fn gzip_bytes(bytes: &[u8]) -> Result<Vec<u8>, ZkError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    encoder
        .finish()
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))
}

#[test]
fn gzip_decoder_accepts_exact_limit_and_rejects_expansion() -> Result<(), ZkError> {
    let compressed = gzip_bytes(&[0x17, 0x2a, 0x3d, 0x4e])?;
    let decoded = decode_gzip_with_limit(
        &compressed,
        4,
        ZkErrorReason::WitnessTooLarge,
        ZkErrorReason::InvalidProofEncoding,
    )?;
    assert_eq!(decoded.as_slice(), [0x17, 0x2a, 0x3d, 0x4e]);

    let error = decode_gzip_with_limit(
        &compressed,
        3,
        ZkErrorReason::WitnessTooLarge,
        ZkErrorReason::InvalidProofEncoding,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::WitnessTooLarge);
    Ok(())
}

#[test]
fn gzip_decoder_rejects_corruption_without_returning_plaintext() -> Result<(), ZkError> {
    let mut compressed = gzip_bytes(&[0x17, 0x2a, 0x3d, 0x4e])?;
    let last_index = compressed
        .len()
        .checked_sub(1)
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    compressed[last_index] ^= 0xff;
    let error = decode_gzip_with_limit(
        &compressed,
        4,
        ZkErrorReason::WitnessTooLarge,
        ZkErrorReason::InvalidProofEncoding,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

fn prove_response(
    public_inputs: &[u8],
    proof: &[u8],
    _verification_key: &[u8],
) -> Result<Vec<u8>, ZkError> {
    prove_response_with_empty_returned_vk(public_inputs, proof)
}

fn prove_response_with_vk_fields(
    public_inputs: &[u8],
    proof: &[u8],
    verification_key: &[u8],
    verification_key_fields: &[u8],
) -> Result<Vec<u8>, ZkError> {
    let mut response = Vec::new();
    pack_array_header(&mut response, 2)?;
    pack_str(&mut response, "CircuitProveResponse")?;
    pack_map_header(&mut response, 3)?;
    pack_str(&mut response, "public_inputs")?;
    pack_field_vector_unchecked(&mut response, public_inputs)?;
    pack_str(&mut response, "proof")?;
    pack_field_vector_unchecked(&mut response, proof)?;
    pack_str(&mut response, "vk")?;
    pack_map_header(&mut response, 3)?;
    pack_str(&mut response, "bytes")?;
    pack_bin(&mut response, verification_key)?;
    pack_str(&mut response, "fields")?;
    pack_field_vector_unchecked(&mut response, verification_key_fields)?;
    pack_str(&mut response, "hash")?;
    pack_bin(&mut response, &[42_u8; 32])?;
    Ok(response)
}

fn prove_response_with_empty_returned_vk(
    public_inputs: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, ZkError> {
    let mut response = Vec::new();
    pack_array_header(&mut response, 2)?;
    pack_str(&mut response, "CircuitProveResponse")?;
    pack_map_header(&mut response, 3)?;
    pack_str(&mut response, "public_inputs")?;
    pack_field_vector_unchecked(&mut response, public_inputs)?;
    pack_str(&mut response, "proof")?;
    pack_field_vector_unchecked(&mut response, proof)?;
    pack_str(&mut response, "vk")?;
    pack_map_header(&mut response, 3)?;
    pack_str(&mut response, "bytes")?;
    pack_empty_bin(&mut response);
    pack_str(&mut response, "fields")?;
    pack_array_header(&mut response, 0)?;
    pack_str(&mut response, "hash")?;
    pack_empty_bin(&mut response);
    Ok(response)
}

fn pack_empty_bin(output: &mut Vec<u8>) {
    output.push(0xc4);
    output.push(0x00);
}

fn pack_field_vector_unchecked(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ZkError> {
    let remainder = bytes.len() % crate::BARRETENBERG_FIELD_BYTES;
    if remainder != 0 {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let field_count = bytes
        .len()
        .checked_div(crate::BARRETENBERG_FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    pack_array_header(output, field_count)?;
    for field in bytes.chunks(crate::BARRETENBERG_FIELD_BYTES) {
        pack_bin(output, field)?;
    }
    Ok(())
}

fn verifier_g1_prefix() -> [u8; VERIFIER_CRS_G1_PREFIX_BYTES] {
    let mut bytes = [0_u8; VERIFIER_CRS_G1_PREFIX_BYTES];
    bytes[31] = 1;
    bytes
}

fn verifier_g2_point() -> [u8; VERIFIER_CRS_G2_BYTES] {
    let mut bytes = [0_u8; VERIFIER_CRS_G2_BYTES];
    bytes[63] = 2;
    bytes[127] = 3;
    bytes
}

fn proof_with_len_and_suite(
    proof_len: usize,
    proof_suite: ZkProofSuite,
) -> Result<ZkProof, ZkError> {
    ZkProof::try_from_exact_parts(
        circuit_ref().circuit_id(),
        circuit_ref(),
        proof_suite,
        ZkArtifactManifestDigest::from_bytes([7_u8; 32]),
        vec![23_u8; proof_len],
        exact_public_inputs()?,
    )
}

fn proof_with_len(proof_len: usize) -> Result<ZkProof, ZkError> {
    proof_with_len_and_suite(proof_len, ZkProofSuite::PRODUCTION)
}

#[test]
fn admits_bounded_array_envelope() -> Result<(), ZkError> {
    let command = [
        0x91,
        0x92,
        0xa0 | 0x0d,
        b'C',
        b'i',
        b'r',
        b'c',
        b'u',
        b'i',
        b't',
        b'V',
        b'e',
        b'r',
        b'i',
        b'f',
        b'y',
        0x81,
        0xa8,
        b's',
        b'e',
        b't',
        b't',
        b'i',
        b'n',
        b'g',
        b's',
        0x80,
    ];

    let message = BbapiMessage::try_from_slice(&command)?;

    assert_eq!(message.as_bytes(), command.as_slice());
    Ok(())
}

#[test]
fn rejects_trailing_bytes() -> Result<(), ZkError> {
    let reason = rejected_reason(&[0x90, 0xc0])?;

    assert_eq!(reason, ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn rejects_duplicate_map_keys() -> Result<(), ZkError> {
    let duplicate = [0x91, 0x82, 0xa1, b'a', 0xc3, 0xa1, b'a', 0xc2];
    let reason = rejected_reason(&duplicate)?;

    assert_eq!(reason, ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn rejects_non_string_map_keys() -> Result<(), ZkError> {
    let non_string_key = [0x91, 0x81, 0x01, 0xc3];
    let reason = rejected_reason(&non_string_key)?;

    assert_eq!(reason, ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn rejects_malformed_truncated_payloads() -> Result<(), ZkError> {
    let reason = rejected_reason(&[0x91, 0xc4, 0x02, 0xaa])?;

    assert_eq!(reason, ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn rejects_empty_envelope() -> Result<(), ZkError> {
    let reason = rejected_reason(&[])?;

    assert_eq!(reason, ZkErrorReason::EmptyInput);
    Ok(())
}

#[test]
fn verify_command_is_wrapper_constructed_and_redacted() -> Result<(), ZkError> {
    let proof = proof_with_len(EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES)?;
    let verification_key = verified_vk()?;

    let command = BbapiCircuitVerifyCommand::try_new(&verification_key, &proof)?;
    let debug = format!("{command:?}");

    assert!(command.as_bytes().starts_with(&[0x91, 0x92]));
    assert!(command
        .as_bytes()
        .windows(13)
        .any(|window| window == b"CircuitVerify"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("23"));
    assert!(!debug.contains("99"));
    Ok(())
}

fn reviewed_settings_bytes() -> &'static [u8] {
    &[
        0xa8, b's', b'e', b't', b't', b'i', b'n', b'g', b's', 0x84, 0xb0, b'i', b'p', b'a', b'_',
        b'a', b'c', b'c', b'u', b'm', b'u', b'l', b'a', b't', b'i', b'o', b'n', 0xc2, 0xb0, b'o',
        b'r', b'a', b'c', b'l', b'e', b'_', b'h', b'a', b's', b'h', b'_', b't', b'y', b'p', b'e',
        0xa6, b'k', b'e', b'c', b'c', b'a', b'k', 0xaa, b'd', b'i', b's', b'a', b'b', b'l', b'e',
        b'_', b'z', b'k', 0xc2, 0xbb, b'o', b'p', b't', b'i', b'm', b'i', b'z', b'e', b'd', b'_',
        b's', b'o', b'l', b'i', b'd', b'i', b't', b'y', b'_', b'v', b'e', b'r', b'i', b'f', b'i',
        b'e', b'r', 0xc2,
    ]
}

#[test]
fn verify_command_pins_reviewed_bbapi_settings() -> Result<(), ZkError> {
    let proof = proof_with_len(EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES)?;
    let verification_key = verified_vk()?;
    let command = BbapiCircuitVerifyCommand::try_new(&verification_key, &proof)?;
    let expected_settings = reviewed_settings_bytes();

    assert!(command
        .as_bytes()
        .windows(expected_settings.len())
        .any(|window| window == expected_settings));
    Ok(())
}

#[test]
fn prove_command_pins_reviewed_bbapi_settings() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1(
        circuit_ref(),
        gzip_bytes(&[0x03, 0x91, 0x91, 0x01])?,
    )?;
    let command = BbapiCircuitProveCommand::try_new(BbStageProveRequest {
        bundle_kind: ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        stage: ZkClaimProofBundleStage::Session,
        circuit_ref: circuit_ref(),
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        witness: &witness,
        session_binding: ZkSessionBinding {
            nonce_hash: [1_u8; 32],
            audience_hash: [2_u8; 32],
            transaction_data_hash: None,
        },
    })?;
    let settings = reviewed_settings_bytes();
    assert_eq!(
        command
            .as_bytes()
            .windows(settings.len())
            .filter(|window| *window == settings)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn prove_command_is_wrapper_constructed_and_redacted() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1(
        circuit_ref(),
        gzip_bytes(&[0x03, 0x91, 0x91, 0x01])?,
    )?;

    let command = BbapiCircuitProveCommand::try_new(BbStageProveRequest {
        bundle_kind: ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        stage: ZkClaimProofBundleStage::Session,
        circuit_ref: circuit_ref(),
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        witness: &witness,
        session_binding: ZkSessionBinding {
            nonce_hash: [1_u8; 32],
            audience_hash: [2_u8; 32],
            transaction_data_hash: None,
        },
    })?;
    let debug = format!("{command:?}");

    assert!(command.as_bytes().starts_with(&[0x91, 0x92]));
    assert!(command
        .as_bytes()
        .windows(12)
        .any(|window| window == b"CircuitProve"));
    assert!(command
        .as_bytes()
        .windows(7)
        .any(|window| window == b"witness"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("77"));
    assert!(!debug.contains("99"));
    Ok(())
}

#[test]
fn prove_command_unwraps_noir_containers_for_bbapi() -> Result<(), ZkError> {
    let raw_acir = [0x04, 0x31, 0x59, 0x26, 0x53, 0x58];
    let raw_witness = [0x03, 0x91, 0x91, 0x01, 0x7a, 0x21];
    let program_json = compiled_program_json(&raw_acir)?;
    let compressed_witness = gzip_bytes(&raw_witness)?;
    let artifacts = stage_artifacts_with_program(program_json.clone())?;
    let witness =
        ZkWitness::try_from_noir_witness_stack_v1(circuit_ref(), compressed_witness.clone())?;

    let command = BbapiCircuitProveCommand::try_new(BbStageProveRequest {
        bundle_kind: ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        stage: ZkClaimProofBundleStage::Session,
        circuit_ref: circuit_ref(),
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        witness: &witness,
        session_binding: ZkSessionBinding {
            nonce_hash: [1_u8; 32],
            audience_hash: [2_u8; 32],
            transaction_data_hash: None,
        },
    })?;

    assert!(command
        .as_bytes()
        .windows(raw_acir.len())
        .any(|window| window == raw_acir));
    assert!(command
        .as_bytes()
        .windows(raw_witness.len())
        .any(|window| window == raw_witness));
    assert!(!command
        .as_bytes()
        .windows(program_json.len())
        .any(|window| window == program_json.as_slice()));
    assert!(!command
        .as_bytes()
        .windows(compressed_witness.len())
        .any(|window| window == compressed_witness.as_slice()));
    Ok(())
}

#[test]
fn prove_command_rejects_malformed_program_json() -> Result<(), ZkError> {
    let artifacts = stage_artifacts_with_program(br#"{"bytecode":"not-base64"}"#.to_vec())?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1(
        circuit_ref(),
        gzip_bytes(&[0x03, 0x91, 0x91, 0x01])?,
    )?;

    let error = BbapiCircuitProveCommand::try_new(BbStageProveRequest {
        bundle_kind: ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        stage: ZkClaimProofBundleStage::Session,
        circuit_ref: circuit_ref(),
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        witness: &witness,
        session_binding: ZkSessionBinding {
            nonce_hash: [1_u8; 32],
            audience_hash: [2_u8; 32],
            transaction_data_hash: None,
        },
    })
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::MalformedJson);
    Ok(())
}

#[test]
fn prove_command_rejects_malformed_witness_gzip() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref(), vec![0x03, 0x91])?;

    let error = BbapiCircuitProveCommand::try_new(BbStageProveRequest {
        bundle_kind: ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        stage: ZkClaimProofBundleStage::Session,
        circuit_ref: circuit_ref(),
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        witness: &witness,
        session_binding: ZkSessionBinding {
            nonce_hash: [1_u8; 32],
            audience_hash: [2_u8; 32],
            transaction_data_hash: None,
        },
    })
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn prove_command_rejects_witness_gzip_expansion_over_limit() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let oversized = vec![0_u8; MAX_WITNESS_BYTES.saturating_add(1)];
    let witness =
        ZkWitness::try_from_noir_witness_stack_v1(circuit_ref(), gzip_bytes(&oversized)?)?;

    let error = BbapiCircuitProveCommand::try_new(BbStageProveRequest {
        bundle_kind: ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        stage: ZkClaimProofBundleStage::Session,
        circuit_ref: circuit_ref(),
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        witness: &witness,
        session_binding: ZkSessionBinding {
            nonce_hash: [1_u8; 32],
            audience_hash: [2_u8; 32],
            transaction_data_hash: None,
        },
    })
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::WitnessTooLarge);
    Ok(())
}

#[test]
fn verify_command_rejects_non_field_aligned_proofs() -> Result<(), ZkError> {
    let proof = proof_with_len(63)?;
    let verification_key = verified_vk()?;

    let error = BbapiCircuitVerifyCommand::try_new(&verification_key, &proof)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn verify_command_rejects_wrong_circuit_proof_length() -> Result<(), ZkError> {
    let wrong_len = EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES
        .checked_add(crate::BARRETENBERG_FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let proof = proof_with_len(wrong_len)?;
    let verification_key = verified_vk()?;

    let error = BbapiCircuitVerifyCommand::try_new(&verification_key, &proof)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn verify_command_rejects_noncanonical_proof_fields() -> Result<(), ZkError> {
    let mut proof_bytes = vec![0_u8; EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES];
    let first_field = proof_bytes
        .get_mut(..crate::BARRETENBERG_FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    first_field.copy_from_slice(&BN254_FR_MODULUS);
    let proof = ZkProof::try_from_exact_parts(
        circuit_ref().circuit_id(),
        circuit_ref(),
        ZkProofSuite::PRODUCTION,
        ZkArtifactManifestDigest::from_bytes([7_u8; 32]),
        proof_bytes,
        exact_public_inputs()?,
    )?;
    let verification_key = verified_vk()?;

    let error = BbapiCircuitVerifyCommand::try_new(&verification_key, &proof)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn compact_public_inputs_encode_to_canonical_backend_fields() -> Result<(), ZkError> {
    let encoded = BarretenbergPublicInputCodec::encode(circuit_ref(), &exact_public_inputs()?)?;

    for field in encoded.chunks(crate::BARRETENBERG_FIELD_BYTES) {
        assert!(field_is_canonical(field)?);
    }
    Ok(())
}

#[test]
fn verify_command_rejects_non_verification_key_artifacts() -> Result<(), ZkError> {
    let proof = proof_with_len(EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES)?;
    let bytecode = verified_artifact(ArtifactKind::AcirBytecode)?;

    let error = BbapiCircuitVerifyCommand::try_new(&bytecode, &proof)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn verify_command_rejects_non_production_suites() -> Result<(), ZkError> {
    let proof = proof_with_len_and_suite(
        EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES,
        ZkProofSuite::BarretenbergUltraHonkPoseidon2ZkNoIpa,
    )?;
    let verification_key = verified_vk()?;

    let error = BbapiCircuitVerifyCommand::try_new(&verification_key, &proof)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedProofSuite);
    Ok(())
}

#[test]
fn srs_init_command_is_exact_one_point_verifier_schema() -> Result<(), ZkError> {
    let g1 = verifier_g1_prefix();
    let g2 = verifier_g2_point();

    let command = BbapiSrsInitCommand::try_new_verifier(&g1, &g2)?;

    assert!(command.as_bytes().starts_with(&[0x91, 0x92, 0xaa]));
    assert!(command
        .as_bytes()
        .windows(10)
        .any(|window| window == b"SrsInitSrs"));
    assert!(command
        .as_bytes()
        .windows(10)
        .any(|window| window == b"points_buf"));
    assert!(command
        .as_bytes()
        .windows(10)
        .any(|window| window == b"num_points"));
    assert!(command
        .as_bytes()
        .windows(8)
        .any(|window| window == b"g2_point"));
    assert!(command
        .as_bytes()
        .windows(3)
        .any(|window| window == [0xc4, 0x40, g1[0]]));
    assert!(command
        .as_bytes()
        .windows(3)
        .any(|window| window == [0xc4, 0x80, g2[0]]));
    Ok(())
}

#[test]
fn srs_init_command_rejects_wrong_crs_lengths() -> Result<(), ZkError> {
    let g1 = verifier_g1_prefix();
    let g2 = verifier_g2_point();

    let short_g1 = g1
        .get(1..)
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let error = BbapiSrsInitCommand::try_new_verifier(short_g1, &g2)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);

    let short_g2 = g2
        .get(1..)
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let error = BbapiSrsInitCommand::try_new_verifier(&g1, short_g2)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn srs_init_command_encodes_explicit_multi_point_profile() -> Result<(), ZkError> {
    let g1 = [7_u8; 192];
    let g2 = verifier_g2_point();

    let command = BbapiSrsInitCommand::try_new(
        &g1,
        &g2,
        BbapiSrsInitProfile {
            g1_prefix_bytes: 192,
            g2_bytes: VERIFIER_CRS_G2_BYTES,
            num_points: 3,
        },
    )?;

    assert!(command
        .as_bytes()
        .windows(3)
        .any(|window| window == [0xc4, 0xc0, g1[0]]));
    assert!(command.as_bytes().windows(1).any(|window| window == [0x03]));
    Ok(())
}

mod response;
