// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{BarretenbergPublicInputCodec, BARRETENBERG_FIELD_BYTES};
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCredentialHashAlgorithm},
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkPublicInputDescriptor, ZkPublicInputs},
};

fn compact_inputs(circuit_ref: ZkCircuitRef) -> Result<ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let bytes = (0_u8..=250_u8)
        .cycle()
        .take(descriptor.encoded_len()?)
        .collect();
    ZkPublicInputs::try_from_bytes(bytes)
}

#[test]
fn every_compact_circuit_round_trips_field_serialization() -> Result<(), ZkError> {
    let mut covered = 0_usize;
    for circuit_ref in ZkCircuitRef::ALL.iter().copied().filter(|circuit_ref| {
        matches!(
            circuit_ref.family,
            ZkCircuitFamily::CredentialSubjectClaimV1 | ZkCircuitFamily::PrivatePersonaClaimV1
        )
    }) {
        covered = covered
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let compact = compact_inputs(circuit_ref)?;
        let encoded = BarretenbergPublicInputCodec::encode(circuit_ref, &compact)?;
        let decoded = BarretenbergPublicInputCodec::decode(circuit_ref, &encoded)?;

        assert_eq!(decoded, compact);
        assert_eq!(
            encoded.len(),
            ZkPublicInputDescriptor::for_circuit(circuit_ref)?
                .flattened_element_count()?
                .checked_mul(BARRETENBERG_FIELD_BYTES)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?
        );
    }
    assert_eq!(covered, 20);
    Ok(())
}

#[test]
fn compact_codec_rejects_raw_circuit_families() -> Result<(), ZkError> {
    for circuit_ref in [
        ZkCircuitRef::new(
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::CommonCredentialRootV1,
            reallyme_zk_api::circuits::ZkCircuitStage::RootAttestation,
        ),
        reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
            .source_ref(ZkCredentialHashAlgorithm::Sha256),
    ] {
        let error = BarretenbergPublicInputCodec::serialized_len(circuit_ref)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), ZkErrorReason::UnsupportedCircuit);
    }
    Ok(())
}

#[test]
fn decoder_rejects_non_canonical_byte_field() -> Result<(), ZkError> {
    let circuit_ref = *ZkCircuitRef::ALL
        .first()
        .ok_or(ZkError::new(ZkErrorReason::UnsupportedCircuit))?;
    let compact = compact_inputs(circuit_ref)?;
    let mut encoded = BarretenbergPublicInputCodec::encode(circuit_ref, &compact)?;
    let prefix = encoded
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    *prefix = 1;

    let error = BarretenbergPublicInputCodec::decode(circuit_ref, &encoded)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn decoder_rejects_truncated_field_serialization() -> Result<(), ZkError> {
    let circuit_ref = *ZkCircuitRef::ALL
        .first()
        .ok_or(ZkError::new(ZkErrorReason::UnsupportedCircuit))?;
    let compact = compact_inputs(circuit_ref)?;
    let mut encoded = BarretenbergPublicInputCodec::encode(circuit_ref, &compact)?;
    encoded.pop();

    let error = BarretenbergPublicInputCodec::decode(circuit_ref, &encoded)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn separate_and_complete_results_normalize_identically() -> Result<(), ZkError> {
    let circuit_ref = *ZkCircuitRef::ALL
        .first()
        .ok_or(ZkError::new(ZkErrorReason::UnsupportedCircuit))?;
    let compact = compact_inputs(circuit_ref)?;
    let serialized = BarretenbergPublicInputCodec::encode(circuit_ref, &compact)?;
    let proof = [7_u8, 8_u8, 9_u8];
    let mut complete = Vec::new();
    complete
        .try_reserve_exact(
            serialized
                .len()
                .checked_add(proof.len())
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?,
        )
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    complete.extend_from_slice(&serialized);
    complete.extend_from_slice(&proof);

    let separate =
        BarretenbergPublicInputCodec::normalize_separate_result(circuit_ref, &serialized, &proof)?;
    let combined = BarretenbergPublicInputCodec::normalize_complete_proof(circuit_ref, &complete)?;

    assert_eq!(separate, combined);
    Ok(())
}
