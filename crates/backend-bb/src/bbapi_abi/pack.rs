// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};

use crate::{
    bbapi_abi::message::{
        BbapiLimits, BN254_FR_MODULUS, MAX_BBAPI_ARRAY_ENTRIES, MAX_BBAPI_MAP_ENTRIES,
        MAX_BBAPI_STRING_BYTES,
    },
    public_input_codec::BARRETENBERG_FIELD_BYTES,
};

pub(super) fn pack_verify_settings(
    output: &mut Vec<u8>,
    limits: BbapiLimits,
) -> Result<(), ZkError> {
    pack_map_header_with_limits(output, 4, limits)?;
    pack_str_with_limits(output, "ipa_accumulation", limits)?;
    pack_bool_with_limits(output, false, limits)?;
    pack_str_with_limits(output, "oracle_hash_type", limits)?;
    pack_str_with_limits(output, "keccak", limits)?;
    pack_str_with_limits(output, "disable_zk", limits)?;
    pack_bool_with_limits(output, false, limits)?;
    pack_str_with_limits(output, "optimized_solidity_verifier", limits)?;
    pack_bool_with_limits(output, false, limits)?;
    Ok(())
}

pub(super) fn pack_field_vector(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ZkError> {
    let remainder = bytes.len() % BARRETENBERG_FIELD_BYTES;
    if remainder != 0 {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let field_count = bytes
        .len()
        .checked_div(BARRETENBERG_FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    pack_array_header(output, field_count)?;
    for field in bytes.chunks(BARRETENBERG_FIELD_BYTES) {
        if !field_is_canonical(field)? {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        pack_bin(output, field)?;
    }
    Ok(())
}

pub(super) fn field_is_canonical(field: &[u8]) -> Result<bool, ZkError> {
    let field: &[u8; BARRETENBERG_FIELD_BYTES] = field
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    for (left, right) in field.iter().zip(BN254_FR_MODULUS.iter()) {
        if left < right {
            return Ok(true);
        }
        if left > right {
            return Ok(false);
        }
    }
    Ok(false)
}

fn pack_bool_with_limits(
    output: &mut Vec<u8>,
    value: bool,
    limits: BbapiLimits,
) -> Result<(), ZkError> {
    push_byte_with_limits(output, if value { 0xc3 } else { 0xc2 }, limits)
}

pub(super) fn pack_uint_with_limits(
    output: &mut Vec<u8>,
    value: u64,
    limits: BbapiLimits,
) -> Result<(), ZkError> {
    if value <= 0x7f {
        push_byte_with_limits(
            output,
            u8::try_from(value).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
            limits,
        )
    } else if u8::try_from(value).is_ok() {
        push_byte_with_limits(output, 0xcc, limits)?;
        push_byte_with_limits(
            output,
            u8::try_from(value).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
            limits,
        )
    } else if u16::try_from(value).is_ok() {
        push_byte_with_limits(output, 0xcd, limits)?;
        push_bytes_with_limits(
            output,
            &u16::try_from(value)
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
                .to_be_bytes(),
            limits,
        )
    } else if u32::try_from(value).is_ok() {
        push_byte_with_limits(output, 0xce, limits)?;
        push_bytes_with_limits(
            output,
            &u32::try_from(value)
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
                .to_be_bytes(),
            limits,
        )
    } else {
        push_byte_with_limits(output, 0xcf, limits)?;
        push_bytes_with_limits(output, &value.to_be_bytes(), limits)
    }
}

pub(super) fn pack_str(output: &mut Vec<u8>, value: &str) -> Result<(), ZkError> {
    pack_str_with_limits(output, value, BbapiLimits::standard())
}

pub(super) fn pack_str_with_limits(
    output: &mut Vec<u8>,
    value: &str,
    limits: BbapiLimits,
) -> Result<(), ZkError> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_BBAPI_STRING_BYTES {
        return Err(ZkError::new(ZkErrorReason::BackendFailure));
    }
    if bytes.len() <= 31 {
        let len =
            u8::try_from(bytes.len()).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        push_byte_with_limits(output, 0xa0 | len, limits)?;
    } else if u8::try_from(bytes.len()).is_ok() {
        push_byte_with_limits(output, 0xd9, limits)?;
        push_byte_with_limits(
            output,
            u8::try_from(bytes.len()).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
            limits,
        )?;
    } else if u16::try_from(bytes.len()).is_ok() {
        push_byte_with_limits(output, 0xda, limits)?;
        push_bytes_with_limits(
            output,
            &u16::try_from(bytes.len())
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
                .to_be_bytes(),
            limits,
        )?;
    } else {
        push_byte_with_limits(output, 0xdb, limits)?;
        push_bytes_with_limits(
            output,
            &u32::try_from(bytes.len())
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
                .to_be_bytes(),
            limits,
        )?;
    }
    push_bytes_with_limits(output, bytes, limits)
}

pub(super) fn pack_bin(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ZkError> {
    pack_bin_with_limits(output, bytes, BbapiLimits::standard())
}

pub(super) fn pack_bin_with_limits(
    output: &mut Vec<u8>,
    bytes: &[u8],
    limits: BbapiLimits,
) -> Result<(), ZkError> {
    if bytes.is_empty() {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    if bytes.len() > limits.binary_bytes {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    if u8::try_from(bytes.len()).is_ok() {
        push_byte_with_limits(output, 0xc4, limits)?;
        push_byte_with_limits(
            output,
            u8::try_from(bytes.len()).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
            limits,
        )?;
    } else if u16::try_from(bytes.len()).is_ok() {
        push_byte_with_limits(output, 0xc5, limits)?;
        push_bytes_with_limits(
            output,
            &u16::try_from(bytes.len())
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
                .to_be_bytes(),
            limits,
        )?;
    } else {
        push_byte_with_limits(output, 0xc6, limits)?;
        push_bytes_with_limits(
            output,
            &u32::try_from(bytes.len())
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
                .to_be_bytes(),
            limits,
        )?;
    }
    push_bytes_with_limits(output, bytes, limits)
}

pub(super) fn pack_array_header(output: &mut Vec<u8>, size: usize) -> Result<(), ZkError> {
    pack_array_header_with_limits(output, size, BbapiLimits::standard())
}

pub(super) fn pack_array_header_with_limits(
    output: &mut Vec<u8>,
    size: usize,
    limits: BbapiLimits,
) -> Result<(), ZkError> {
    if size
        > usize::try_from(MAX_BBAPI_ARRAY_ENTRIES)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
    {
        return Err(ZkError::new(ZkErrorReason::BackendFailure));
    }
    if size <= 15 {
        let len = u8::try_from(size).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        push_byte_with_limits(output, 0x90 | len, limits)
    } else if u16::try_from(size).is_ok() {
        push_byte_with_limits(output, 0xdc, limits)?;
        push_bytes_with_limits(
            output,
            &u16::try_from(size)
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
                .to_be_bytes(),
            limits,
        )
    } else {
        push_byte_with_limits(output, 0xdd, limits)?;
        push_bytes_with_limits(
            output,
            &u32::try_from(size)
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
                .to_be_bytes(),
            limits,
        )
    }
}

pub(super) fn pack_map_header(output: &mut Vec<u8>, size: usize) -> Result<(), ZkError> {
    pack_map_header_with_limits(output, size, BbapiLimits::standard())
}

pub(super) fn pack_map_header_with_limits(
    output: &mut Vec<u8>,
    size: usize,
    limits: BbapiLimits,
) -> Result<(), ZkError> {
    if size
        > usize::try_from(MAX_BBAPI_MAP_ENTRIES)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
    {
        return Err(ZkError::new(ZkErrorReason::BackendFailure));
    }
    if size <= 15 {
        let len = u8::try_from(size).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        push_byte_with_limits(output, 0x80 | len, limits)
    } else {
        push_byte_with_limits(output, 0xde, limits)?;
        push_bytes_with_limits(
            output,
            &u16::try_from(size)
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
                .to_be_bytes(),
            limits,
        )
    }
}

fn push_byte_with_limits(
    output: &mut Vec<u8>,
    byte: u8,
    limits: BbapiLimits,
) -> Result<(), ZkError> {
    validate_append(output.len(), 1, limits.message_bytes)?;
    output
        .try_reserve_exact(1)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    output.push(byte);
    Ok(())
}

fn push_bytes_with_limits(
    output: &mut Vec<u8>,
    bytes: &[u8],
    limits: BbapiLimits,
) -> Result<(), ZkError> {
    validate_append(output.len(), bytes.len(), limits.message_bytes)?;
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn validate_append(
    current_len: usize,
    additional_len: usize,
    max_length: usize,
) -> Result<(), ZkError> {
    let new_len = current_len
        .checked_add(additional_len)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    if new_len > max_length {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    Ok(())
}
