// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage},
    errors::{ZkError, ZkErrorReason},
};

use super::{expected_raw_len, CLAIM_VALUE_BYTES_MAX_U32, RAW_FIELD_BYTES};

#[derive(Clone, Copy)]
enum RawFieldEncoding {
    Byte,
    U32 { max: u32 },
    U64,
}

pub(super) fn validate_raw_public_inputs(
    circuit_ref: ZkCircuitRef,
    bytes: &[u8],
) -> Result<(), ZkError> {
    let expected = expected_raw_len(circuit_ref)?;
    if bytes.len() != expected {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let (fields, remainder) = bytes.as_chunks::<RAW_FIELD_BYTES>();
    if !remainder.is_empty() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    for (index, field) in fields.iter().enumerate() {
        match raw_field_encoding(circuit_ref, index)? {
            RawFieldEncoding::Byte => validate_field_high_zeros(field, RAW_FIELD_BYTES - 1)?,
            RawFieldEncoding::U32 { max } => {
                validate_field_high_zeros(field, RAW_FIELD_BYTES - 4)?;
                let value = u32_from_field(field)?;
                if value == 0 || value > max {
                    return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
                }
            }
            RawFieldEncoding::U64 => validate_field_high_zeros(field, RAW_FIELD_BYTES - 8)?,
        }
    }
    Ok(())
}

pub(super) fn session_field_start(circuit_ref: ZkCircuitRef) -> Result<usize, ZkError> {
    match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => Ok(98),
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus)
        | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage)
        | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::IssuerCredentialStatus)
        | (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => Ok(0),
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim)
        | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicSession) => Ok(64),
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicPersonaClaim) => Ok(128),
        _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    }
}

pub(super) fn read_public_bytes32(bytes: &[u8], start_field: usize) -> Result<[u8; 32], ZkError> {
    let mut value = [0_u8; 32];
    for (offset, byte) in value.iter_mut().enumerate() {
        let field = start_field
            .checked_add(offset)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let position = field
            .checked_mul(RAW_FIELD_BYTES)
            .and_then(|start| start.checked_add(RAW_FIELD_BYTES - 1))
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        *byte = *bytes
            .get(position)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    }
    Ok(value)
}

pub(super) fn read_public_byte(bytes: &[u8], field_index: usize) -> Result<u8, ZkError> {
    let position = field_index
        .checked_mul(RAW_FIELD_BYTES)
        .and_then(|start| start.checked_add(RAW_FIELD_BYTES - 1))
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    bytes
        .get(position)
        .copied()
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

pub(super) fn read_public_u64(bytes: &[u8], field_index: usize) -> Result<u64, ZkError> {
    let start = field_index
        .checked_mul(RAW_FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let end = start
        .checked_add(RAW_FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let field = bytes
        .get(start..end)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    validate_field_high_zeros(field, RAW_FIELD_BYTES - 8)?;
    let tail = field
        .get(RAW_FIELD_BYTES - 8..RAW_FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let value =
        <[u8; 8]>::try_from(tail).map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    Ok(u64::from_be_bytes(value))
}

pub(super) fn u32_from_field(field: &[u8]) -> Result<u32, ZkError> {
    let tail = field
        .get(RAW_FIELD_BYTES - 4..RAW_FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let bytes: [u8; 4] = tail
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    Ok(u32::from_be_bytes(bytes))
}

fn raw_field_encoding(
    circuit_ref: ZkCircuitRef,
    index: usize,
) -> Result<RawFieldEncoding, ZkError> {
    match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => {
            Ok(if matches!(index, 96 | 97) {
                RawFieldEncoding::U64
            } else {
                RawFieldEncoding::Byte
            })
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus) => {
            Ok(RawFieldEncoding::Byte)
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage) => Ok(if index == 192 {
            RawFieldEncoding::U64
        } else {
            RawFieldEncoding::Byte
        }),
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::IssuerCredentialStatus) => {
            Ok(if matches!(index, 160 | 225 | 291) {
                RawFieldEncoding::U64
            } else {
                RawFieldEncoding::Byte
            })
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim) => {
            claim_raw_field_encoding(index, 0)
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicPersonaClaim) => {
            claim_raw_field_encoding(index, 64)
        }
        (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => {
            session_raw_field_encoding(index, 0)
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicSession) => {
            session_raw_field_encoding(index, 64)
        }
        _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    }
}

fn claim_raw_field_encoding(index: usize, offset: usize) -> Result<RawFieldEncoding, ZkError> {
    let expiry_index = offset
        .checked_add(160)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let value_length_index = offset
        .checked_add(257)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    if index == expiry_index {
        Ok(RawFieldEncoding::U64)
    } else if index == value_length_index {
        Ok(RawFieldEncoding::U32 {
            max: CLAIM_VALUE_BYTES_MAX_U32,
        })
    } else {
        Ok(RawFieldEncoding::Byte)
    }
}

fn session_raw_field_encoding(index: usize, offset: usize) -> Result<RawFieldEncoding, ZkError> {
    let expiry_index = offset
        .checked_add(96)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    Ok(if index == expiry_index {
        RawFieldEncoding::U64
    } else {
        RawFieldEncoding::Byte
    })
}

fn validate_field_high_zeros(field: &[u8], high_len: usize) -> Result<(), ZkError> {
    let high = field
        .get(..high_len)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if high.iter().any(|byte| *byte != 0) {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(())
}
