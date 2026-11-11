// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceSourceStage},
    proofs::ZkProofSuite,
};

use crate::{
    bbapi_abi::{
        decode_circuit_prove_raw_common_credential_root_response,
        decode_circuit_prove_raw_prepared_response, decode_circuit_prove_response,
        decode_circuit_verify_response, decode_srs_init_response,
        message::BN254_FR_MODULUS,
        pack::{pack_array_header, pack_bin, pack_field_vector, pack_map_header, pack_str},
    },
    public_input_codec::BarretenbergPublicInputCodec,
};

use super::{
    circuit_ref, exact_public_inputs, prove_response, prove_response_with_empty_returned_vk,
    prove_response_with_vk_fields, stage_artifacts,
};

const ROOT_STATUS_RAW_PUBLIC_INPUT_BYTES: usize = 192 * crate::BARRETENBERG_FIELD_BYTES;

fn common_credential_root_root_status_ref() -> ZkCircuitRef {
    ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::RootStatus,
    )
}

fn root_status_raw_public_inputs() -> Vec<u8> {
    vec![0_u8; ROOT_STATUS_RAW_PUBLIC_INPUT_BYTES]
}

fn prepared_claim_raw_public_inputs() -> Vec<u8> {
    let mut fields = vec![0_u8; 291 * crate::BARRETENBERG_FIELD_BYTES];
    for (field, value) in [(0, 1), (32, 2), (64, 3), (96, 4), (128, 5), (162, 6)] {
        fields[field * 32 + 31] = value;
    }
    fields[160 * 32 + 31] = 100;
    fields[161 * 32 + 31] = 200;
    fields[194 * 32 + 31] = 1;
    fields[195 * 32 + 31] = 18;
    fields[259 * 32 + 31] = 7;
    fields
}

#[test]
fn raw_prepared_prove_response_checks_abi_profile_and_proof_bytes() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let circuit_ref = ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        .source_ref(ZkCredentialHashAlgorithm::Sha256);
    let mode = ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1;
    let identity = reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes([11; 32]);
    let mut fields = prepared_claim_raw_public_inputs();
    let response = prove_response_with_empty_returned_vk(&fields, &[42; 32])?;
    let proof = decode_circuit_prove_raw_prepared_response(
        mode,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        identity,
        artifacts.verification_key(),
        &response,
    )?;
    assert_eq!(proof.public_inputs().as_bytes(), fields);
    assert_eq!(proof.proof_bytes().as_bytes(), [42; 32]);

    let wrong_profile = decode_circuit_prove_raw_prepared_response(
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        identity,
        artifacts.verification_key(),
        &response,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(wrong_profile.reason(), ZkErrorReason::StageMismatch);

    fields[0] = 1;
    let malformed = prove_response_with_empty_returned_vk(&fields, &[42; 32])?;
    let invalid_abi = decode_circuit_prove_raw_prepared_response(
        mode,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        identity,
        artifacts.verification_key(),
        &malformed,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(invalid_abi.reason(), ZkErrorReason::InvalidProofEncoding);

    let empty = prove_response_with_empty_returned_vk(&prepared_claim_raw_public_inputs(), &[])?;
    let empty_proof = decode_circuit_prove_raw_prepared_response(
        mode,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        identity,
        artifacts.verification_key(),
        &empty,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(empty_proof.reason(), ZkErrorReason::EmptyInput);
    Ok(())
}

fn error_response(message: &str) -> Result<Vec<u8>, ZkError> {
    let mut response = Vec::new();
    pack_array_header(&mut response, 2)?;
    pack_str(&mut response, "ErrorResponse")?;
    pack_map_header(&mut response, 1)?;
    pack_str(&mut response, "message")?;
    pack_str(&mut response, message)?;
    Ok(response)
}

#[test]
fn decodes_exact_successful_circuit_verify_response() -> Result<(), ZkError> {
    let response = [
        0x92, 0xb5, b'C', b'i', b'r', b'c', b'u', b'i', b't', b'V', b'e', b'r', b'i', b'f', b'y',
        b'R', b'e', b's', b'p', b'o', b'n', b's', b'e', 0x81, 0xa8, b'v', b'e', b'r', b'i', b'f',
        b'i', b'e', b'd', 0xc3,
    ];

    decode_circuit_verify_response(&response)?;
    Ok(())
}

#[test]
fn verify_response_rejects_nonminimal_msgpack_widths() -> Result<(), ZkError> {
    let mut canonical = Vec::new();
    pack_array_header(&mut canonical, 2)?;
    pack_str(&mut canonical, "CircuitVerifyResponse")?;
    pack_map_header(&mut canonical, 1)?;
    pack_str(&mut canonical, "verified")?;
    canonical.push(0xc3);

    let mut wide_array = vec![0xdc, 0x00, 0x02];
    wide_array.extend_from_slice(&canonical[1..]);

    let mut wide_string = vec![0x92, 0xd9, 21];
    wide_string.extend_from_slice(&canonical[2..]);

    let map_offset = 1 + 1 + 21;
    let mut wide_map = canonical[..map_offset].to_vec();
    wide_map.extend_from_slice(&[0xde, 0x00, 0x01]);
    wide_map.extend_from_slice(&canonical[map_offset + 1..]);

    for response in [wide_array, wide_string, wide_map] {
        let error = decode_circuit_verify_response(&response)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    }
    Ok(())
}

#[test]
fn srs_response_rejects_nonminimal_binary_width() -> Result<(), ZkError> {
    let mut response = Vec::new();
    pack_array_header(&mut response, 2)?;
    pack_str(&mut response, "SrsInitSrsResponse")?;
    pack_map_header(&mut response, 1)?;
    pack_str(&mut response, "points_buf")?;
    response.extend_from_slice(&[0xc5, 0x00, 0x00]);

    let error = decode_srs_init_response(&response)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn decodes_exact_successful_circuit_prove_response() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let public_inputs =
        BarretenbergPublicInputCodec::encode(circuit_ref(), &exact_public_inputs()?)?;
    let response = prove_response(
        public_inputs.as_slice(),
        &proof,
        artifacts.verification_key().as_bytes(),
    )?;

    let decoded =
        decode_circuit_prove_response(circuit_ref(), artifacts.verification_key(), &response)?;

    assert_eq!(decoded.proof_bytes().as_bytes(), proof);
    assert_eq!(decoded.public_inputs(), &exact_public_inputs()?);
    Ok(())
}

#[test]
fn prove_response_rejects_returned_vk_mismatch() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let public_inputs =
        BarretenbergPublicInputCodec::encode(circuit_ref(), &exact_public_inputs()?)?;
    let response =
        prove_response_with_vk_fields(public_inputs.as_slice(), &proof, &[55_u8; 64], &proof)?;

    let error = decode_circuit_prove_response(
        circuit_ref(),
        artifacts.verification_key(),
        response.as_slice(),
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn prove_response_rejects_nonempty_matching_supplied_vk_echo() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let public_inputs =
        BarretenbergPublicInputCodec::encode(circuit_ref(), &exact_public_inputs()?)?;
    let response = prove_response_with_vk_fields(
        public_inputs.as_slice(),
        &proof,
        artifacts.verification_key().as_bytes(),
        &proof,
    )?;

    let error =
        decode_circuit_prove_response(circuit_ref(), artifacts.verification_key(), &response)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn prove_response_accepts_canonical_empty_supplied_vk_echo() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let public_inputs =
        BarretenbergPublicInputCodec::encode(circuit_ref(), &exact_public_inputs()?)?;
    let response = prove_response_with_empty_returned_vk(public_inputs.as_slice(), &proof)?;

    let decoded =
        decode_circuit_prove_response(circuit_ref(), artifacts.verification_key(), &response)?;

    assert_eq!(decoded.proof_bytes().as_bytes(), proof);
    assert_eq!(decoded.public_inputs(), &exact_public_inputs()?);
    Ok(())
}

#[test]
fn raw_common_credential_root_prove_response_accepts_exact_raw_fields() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let public_inputs = root_status_raw_public_inputs();
    let response = prove_response_with_empty_returned_vk(public_inputs.as_slice(), &proof)?;

    let decoded = decode_circuit_prove_raw_common_credential_root_response(
        common_credential_root_root_status_ref(),
        artifacts.verification_key(),
        response.as_slice(),
    )?;

    assert_eq!(decoded.proof_bytes().as_bytes(), proof);
    assert_eq!(decoded.public_inputs().as_bytes(), public_inputs.as_slice());
    assert_eq!(
        decoded.public_inputs().circuit_ref(),
        common_credential_root_root_status_ref()
    );
    Ok(())
}

#[test]
fn compact_prove_response_rejects_raw_common_credential_root_fields() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let public_inputs = root_status_raw_public_inputs();
    let response = prove_response_with_empty_returned_vk(public_inputs.as_slice(), &proof)?;

    let error = decode_circuit_prove_response(
        common_credential_root_root_status_ref(),
        artifacts.verification_key(),
        response.as_slice(),
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedCircuit);
    Ok(())
}

#[test]
fn raw_common_credential_root_prove_response_rejects_malformed_raw_field() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let mut public_inputs = root_status_raw_public_inputs();
    public_inputs[0] = 1;
    let response = prove_response_with_empty_returned_vk(public_inputs.as_slice(), &proof)?;

    let error = decode_circuit_prove_raw_common_credential_root_response(
        common_credential_root_root_status_ref(),
        artifacts.verification_key(),
        response.as_slice(),
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn raw_common_credential_root_prove_response_rejects_empty_proof() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let public_inputs = root_status_raw_public_inputs();
    let response = prove_response_with_empty_returned_vk(public_inputs.as_slice(), &[])?;

    let error = decode_circuit_prove_raw_common_credential_root_response(
        common_credential_root_root_status_ref(),
        artifacts.verification_key(),
        response.as_slice(),
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::EmptyInput);
    Ok(())
}

#[test]
fn prove_response_rejects_noncanonical_public_input_fields() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let response = prove_response(
        &BN254_FR_MODULUS,
        &proof,
        artifacts.verification_key().as_bytes(),
    )?;

    let error =
        decode_circuit_prove_response(circuit_ref(), artifacts.verification_key(), &response)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn prove_response_rejects_noncanonical_proof_fields() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let public_inputs =
        BarretenbergPublicInputCodec::encode(circuit_ref(), &exact_public_inputs()?)?;
    let response = prove_response(
        public_inputs.as_slice(),
        &BN254_FR_MODULUS,
        artifacts.verification_key().as_bytes(),
    )?;

    let error =
        decode_circuit_prove_response(circuit_ref(), artifacts.verification_key(), &response)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn prove_response_rejects_noncanonical_vk_fields() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let public_inputs =
        BarretenbergPublicInputCodec::encode(circuit_ref(), &exact_public_inputs()?)?;
    let response = prove_response_with_vk_fields(
        public_inputs.as_slice(),
        &proof,
        artifacts.verification_key().as_bytes(),
        &BN254_FR_MODULUS,
    )?;

    let error =
        decode_circuit_prove_response(circuit_ref(), artifacts.verification_key(), &response)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn prove_response_rejects_trailing_bytes() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let public_inputs =
        BarretenbergPublicInputCodec::encode(circuit_ref(), &exact_public_inputs()?)?;
    let mut response = prove_response(
        public_inputs.as_slice(),
        &proof,
        artifacts.verification_key().as_bytes(),
    )?;
    response.push(0xc0);

    let error =
        decode_circuit_prove_response(circuit_ref(), artifacts.verification_key(), &response)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn prove_response_rejects_extra_top_level_fields() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let public_inputs =
        BarretenbergPublicInputCodec::encode(circuit_ref(), &exact_public_inputs()?)?;
    let mut response = Vec::new();
    pack_array_header(&mut response, 2)?;
    pack_str(&mut response, "CircuitProveResponse")?;
    pack_map_header(&mut response, 4)?;
    pack_str(&mut response, "public_inputs")?;
    pack_field_vector(&mut response, public_inputs.as_slice())?;
    pack_str(&mut response, "proof")?;
    pack_field_vector(&mut response, &proof)?;
    pack_str(&mut response, "vk")?;
    pack_map_header(&mut response, 3)?;
    pack_str(&mut response, "bytes")?;
    pack_bin(&mut response, artifacts.verification_key().as_bytes())?;
    pack_str(&mut response, "fields")?;
    pack_field_vector(&mut response, &proof)?;
    pack_str(&mut response, "hash")?;
    pack_bin(&mut response, &[42_u8; 32])?;
    pack_str(&mut response, "extra")?;
    pack_str(&mut response, "ignored")?;

    let error =
        decode_circuit_prove_response(circuit_ref(), artifacts.verification_key(), &response)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn prove_response_rejects_reordered_top_level_fields() -> Result<(), ZkError> {
    let artifacts = stage_artifacts()?;
    let proof = [0_u8; 32];
    let public_inputs =
        BarretenbergPublicInputCodec::encode(circuit_ref(), &exact_public_inputs()?)?;
    let mut response = Vec::new();
    pack_array_header(&mut response, 2)?;
    pack_str(&mut response, "CircuitProveResponse")?;
    pack_map_header(&mut response, 3)?;
    pack_str(&mut response, "proof")?;
    pack_field_vector(&mut response, &proof)?;
    pack_str(&mut response, "public_inputs")?;
    pack_field_vector(&mut response, public_inputs.as_slice())?;
    pack_str(&mut response, "vk")?;
    pack_map_header(&mut response, 3)?;
    pack_str(&mut response, "bytes")?;
    pack_bin(&mut response, artifacts.verification_key().as_bytes())?;
    pack_str(&mut response, "fields")?;
    pack_field_vector(&mut response, &proof)?;
    pack_str(&mut response, "hash")?;
    pack_bin(&mut response, &[42_u8; 32])?;

    let error =
        decode_circuit_prove_response(circuit_ref(), artifacts.verification_key(), &response)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn decodes_false_circuit_verify_response_as_invalid_proof() -> Result<(), ZkError> {
    let response = [
        0x92, 0xb5, b'C', b'i', b'r', b'c', b'u', b'i', b't', b'V', b'e', b'r', b'i', b'f', b'y',
        b'R', b'e', b's', b'p', b'o', b'n', b's', b'e', 0x81, 0xa8, b'v', b'e', b'r', b'i', b'f',
        b'i', b'e', b'd', 0xc2,
    ];

    let error = decode_circuit_verify_response(&response)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProof);
    Ok(())
}

#[test]
fn decodes_reviewed_verify_error_response_as_invalid_proof() -> Result<(), ZkError> {
    let response = error_response("Proof verification failed")?;

    let error = decode_circuit_verify_response(response.as_slice())
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProof);
    Ok(())
}

#[test]
fn verify_error_response_keeps_outages_as_backend_failure() -> Result<(), ZkError> {
    let response = error_response("failed to read verification key")?;

    let error = decode_circuit_verify_response(response.as_slice())
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn decodes_exact_successful_srs_init_response() -> Result<(), ZkError> {
    let response = [
        0x92, 0xb2, b'S', b'r', b's', b'I', b'n', b'i', b't', b'S', b'r', b's', b'R', b'e', b's',
        b'p', b'o', b'n', b's', b'e', 0x81, 0xaa, b'p', b'o', b'i', b'n', b't', b's', b'_', b'b',
        b'u', b'f', 0xc4, 0x00,
    ];

    decode_srs_init_response(&response)?;
    Ok(())
}

#[test]
fn srs_init_response_rejects_non_empty_points_buf() -> Result<(), ZkError> {
    let response = [
        0x92, 0xb2, b'S', b'r', b's', b'I', b'n', b'i', b't', b'S', b'r', b's', b'R', b'e', b's',
        b'p', b'o', b'n', b's', b'e', 0x81, 0xaa, b'p', b'o', b'i', b'n', b't', b's', b'_', b'b',
        b'u', b'f', 0xc4, 0x01, 0x00,
    ];

    let error = decode_srs_init_response(&response)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn srs_init_response_rejects_trailing_bytes() -> Result<(), ZkError> {
    let response = [
        0x92, 0xb2, b'S', b'r', b's', b'I', b'n', b'i', b't', b'S', b'r', b's', b'R', b'e', b's',
        b'p', b'o', b'n', b's', b'e', 0x81, 0xaa, b'p', b'o', b'i', b'n', b't', b's', b'_', b'b',
        b'u', b'f', 0xc4, 0x00, 0xc0,
    ];

    let error = decode_srs_init_response(&response)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn decodes_error_response_without_exposing_message_text() -> Result<(), ZkError> {
    let response = [
        0x92, 0xad, b'E', b'r', b'r', b'o', b'r', b'R', b'e', b's', b'p', b'o', b'n', b's', b'e',
        0x81, 0xa7, b'm', b'e', b's', b's', b'a', b'g', b'e', 0xb6, b'd', b'i', b's', b'c', b'a',
        b'r', b'd', b'e', b'd', b' ', b'u', b'p', b's', b't', b'r', b'e', b'a', b'm', b' ', b't',
        b'e', b'x', b't',
    ];

    let error = decode_circuit_verify_response(&response)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    let debug = format!("{error:?}");

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    assert!(!debug.contains("discarded"));
    assert!(!debug.contains("upstream"));
    Ok(())
}

#[test]
fn rejects_circuit_verify_response_with_extra_fields() -> Result<(), ZkError> {
    let response = [
        0x92, 0xb5, b'C', b'i', b'r', b'c', b'u', b'i', b't', b'V', b'e', b'r', b'i', b'f', b'y',
        b'R', b'e', b's', b'p', b'o', b'n', b's', b'e', 0x82, 0xa8, b'v', b'e', b'r', b'i', b'f',
        b'i', b'e', b'd', 0xc3, 0xa5, b'e', b'x', b't', b'r', b'a', 0xc3,
    ];

    let error = decode_circuit_verify_response(&response)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn rejects_circuit_verify_response_with_trailing_bytes() -> Result<(), ZkError> {
    let response = [
        0x92, 0xb5, b'C', b'i', b'r', b'c', b'u', b'i', b't', b'V', b'e', b'r', b'i', b'f', b'y',
        b'R', b'e', b's', b'p', b'o', b'n', b's', b'e', 0x81, 0xa8, b'v', b'e', b'r', b'i', b'f',
        b'i', b'e', b'd', 0xc3, 0xc0,
    ];

    let error = decode_circuit_verify_response(&response)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}
