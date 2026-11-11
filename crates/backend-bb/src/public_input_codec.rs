// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Barretenberg field serialization for compiler-pinned public inputs.

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProofBytes, ZkPublicInputDescriptor, ZkPublicInputType, ZkPublicInputs},
};

use crate::BbStageProveResponse;

/// Serialized byte width of one BN254 scalar field element.
pub const BARRETENBERG_FIELD_BYTES: usize = 32;

const U32_BYTES: usize = 4;
const U64_BYTES: usize = 8;
const BYTE_FIELD_VALUE_INDEX: usize = BARRETENBERG_FIELD_BYTES - 1;
const ZERO_FIELD: [u8; BARRETENBERG_FIELD_BYTES] = [0_u8; BARRETENBERG_FIELD_BYTES];

/// Converts between Barretenberg's flattened field encoding and the canonical
/// compact provider ABI.
#[derive(Debug, Clone, Copy, Default)]
pub struct BarretenbergPublicInputCodec;

impl BarretenbergPublicInputCodec {
    /// Exact serialized Barretenberg public-input byte length for a circuit.
    pub fn serialized_len(circuit_ref: ZkCircuitRef) -> Result<usize, ZkError> {
        ZkPublicInputDescriptor::for_circuit(circuit_ref)?
            .flattened_element_count()?
            .checked_mul(BARRETENBERG_FIELD_BYTES)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))
    }

    /// Encodes compact public inputs as 32-byte big-endian BN254 field values.
    pub fn encode(
        circuit_ref: ZkCircuitRef,
        public_inputs: &ZkPublicInputs,
    ) -> Result<Vec<u8>, ZkError> {
        let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
        if public_inputs.as_bytes().len() != descriptor.encoded_len()? {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }

        let serialized_len = Self::serialized_len(circuit_ref)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(serialized_len)
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;

        let mut compact_offset = 0_usize;
        for field in descriptor.fields() {
            let compact = take_compact_value(
                public_inputs.as_bytes(),
                &mut compact_offset,
                field.input_type.encoded_len(),
            )?;
            encode_value(field.input_type, compact, &mut encoded)?;
        }

        if compact_offset != public_inputs.as_bytes().len() || encoded.len() != serialized_len {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        Ok(encoded)
    }

    /// Decodes exact Barretenberg field bytes into the compact provider ABI.
    pub fn decode(circuit_ref: ZkCircuitRef, serialized: &[u8]) -> Result<ZkPublicInputs, ZkError> {
        let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
        if serialized.len() != Self::serialized_len(circuit_ref)? {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }

        let compact_len = descriptor.encoded_len()?;
        let mut compact = Vec::new();
        compact
            .try_reserve_exact(compact_len)
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;

        let mut serialized_offset = 0_usize;
        for field in descriptor.fields() {
            decode_value(
                field.input_type,
                serialized,
                &mut serialized_offset,
                &mut compact,
            )?;
        }

        if serialized_offset != serialized.len() || compact.len() != compact_len {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        ZkPublicInputs::try_from_bytes(compact)
    }

    /// Normalizes an iOS-style result with separate backend public inputs and
    /// proof bytes.
    pub fn normalize_separate_result(
        circuit_ref: ZkCircuitRef,
        serialized_public_inputs: &[u8],
        proof_bytes: &[u8],
    ) -> Result<BbStageProveResponse, ZkError> {
        ZkProofBytes::validate_length(proof_bytes.len())?;
        let public_inputs = Self::decode(circuit_ref, serialized_public_inputs)?;
        let proof_bytes = ZkProofBytes::try_copy_from_slice(proof_bytes)?;
        BbStageProveResponse::try_from_bounded_parts(circuit_ref, proof_bytes, public_inputs)
    }

    /// Normalizes an Android-style complete proof whose public fields are the
    /// leading serialized elements.
    pub fn normalize_complete_proof(
        circuit_ref: ZkCircuitRef,
        complete_proof: &[u8],
    ) -> Result<BbStageProveResponse, ZkError> {
        let public_inputs_len = Self::serialized_len(circuit_ref)?;
        let maximum_complete_len = public_inputs_len
            .checked_add(reallyme_zk_api::proofs::MAX_PROOF_BYTES)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if complete_proof.len() > maximum_complete_len {
            return Err(ZkError::new(ZkErrorReason::ProofTooLarge));
        }

        let serialized_public_inputs = complete_proof
            .get(..public_inputs_len)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        let proof_bytes = complete_proof
            .get(public_inputs_len..)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        Self::normalize_separate_result(circuit_ref, serialized_public_inputs, proof_bytes)
    }
}

fn encode_value(
    input_type: ZkPublicInputType,
    compact: &[u8],
    encoded: &mut Vec<u8>,
) -> Result<(), ZkError> {
    match input_type {
        ZkPublicInputType::Bytes32 | ZkPublicInputType::Bytes64 => {
            encode_byte_elements(compact, encoded)
        }
        ZkPublicInputType::U64 => append_scalar(compact, U64_BYTES, encoded),
        ZkPublicInputType::U32 => append_scalar(compact, U32_BYTES, encoded),
        _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    }
}

fn encode_byte_elements(compact: &[u8], encoded: &mut Vec<u8>) -> Result<(), ZkError> {
    let padding = ZERO_FIELD
        .get(..BYTE_FIELD_VALUE_INDEX)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    for byte in compact {
        encoded.extend_from_slice(padding);
        encoded.push(*byte);
    }
    Ok(())
}

fn append_scalar(
    compact: &[u8],
    expected_len: usize,
    encoded: &mut Vec<u8>,
) -> Result<(), ZkError> {
    if compact.len() != expected_len {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let padding_len = BARRETENBERG_FIELD_BYTES
        .checked_sub(compact.len())
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let padding = ZERO_FIELD
        .get(..padding_len)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    encoded.extend_from_slice(padding);
    encoded.extend_from_slice(compact);
    Ok(())
}

fn decode_value(
    input_type: ZkPublicInputType,
    serialized: &[u8],
    serialized_offset: &mut usize,
    compact: &mut Vec<u8>,
) -> Result<(), ZkError> {
    match input_type {
        ZkPublicInputType::Bytes32 | ZkPublicInputType::Bytes64 => {
            let element_count = input_type.flattened_element_count();
            for _ in 0..element_count {
                let field = take_serialized_field(serialized, serialized_offset)?;
                let prefix = field
                    .get(..BYTE_FIELD_VALUE_INDEX)
                    .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
                if prefix.iter().any(|byte| *byte != 0) {
                    return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
                }
                compact.push(
                    *field
                        .get(BYTE_FIELD_VALUE_INDEX)
                        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
                );
            }
            Ok(())
        }
        ZkPublicInputType::U64 => decode_scalar(serialized, serialized_offset, U64_BYTES, compact),
        ZkPublicInputType::U32 => decode_scalar(serialized, serialized_offset, U32_BYTES, compact),
        _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    }
}

fn decode_scalar(
    serialized: &[u8],
    serialized_offset: &mut usize,
    scalar_len: usize,
    compact: &mut Vec<u8>,
) -> Result<(), ZkError> {
    let field = take_serialized_field(serialized, serialized_offset)?;
    let value_offset = BARRETENBERG_FIELD_BYTES
        .checked_sub(scalar_len)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let prefix = field
        .get(..value_offset)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if prefix.iter().any(|byte| *byte != 0) {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let value = field
        .get(value_offset..)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    compact.extend_from_slice(value);
    Ok(())
}

fn take_compact_value<'a>(
    compact: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], ZkError> {
    let end = offset
        .checked_add(length)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let value = compact
        .get(*offset..end)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    *offset = end;
    Ok(value)
}

fn take_serialized_field<'a>(
    serialized: &'a [u8],
    offset: &mut usize,
) -> Result<&'a [u8], ZkError> {
    let end = offset
        .checked_add(BARRETENBERG_FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let field = serialized
        .get(*offset..end)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    *offset = end;
    Ok(field)
}

#[cfg(test)]
mod tests;
