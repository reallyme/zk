// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};

use crate::public_input_codec::BARRETENBERG_FIELD_BYTES;

/// Maximum encoded BBAPI command or response accepted across the narrow ABI.
const MAX_BBAPI_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum binary value accepted inside a BBAPI MessagePack envelope.
pub(super) const MAX_BBAPI_BINARY_BYTES: usize = 16 * 1024 * 1024;
/// Maximum encoded `SrsInitSrs` command accepted for the full prover CRS lane.
const MAX_BBAPI_SRS_MESSAGE_BYTES: usize = 67_109_568;
/// Maximum encoded `CircuitProve` command accepted by the ReallyMe shim.
const MAX_BBAPI_PROVE_MESSAGE_BYTES: usize = 67_109_568;
pub(super) const MAX_BBAPI_STRING_BYTES: usize = 4096;
/// Maximum field-vector entries accepted for BBAPI proof/public-input arrays.
///
/// This is `MAX_PROOF_BYTES / 32`, kept as a reviewed literal to avoid
/// implicit casts in boundary arithmetic.
pub(super) const MAX_BBAPI_ARRAY_ENTRIES: u32 = 8192;
pub(super) const MAX_BBAPI_MAP_ENTRIES: u32 = 64;
const MAX_BBAPI_DEPTH: u8 = 16;
pub(crate) const VERIFIER_CRS_G1_PREFIX_BYTES: usize = 64;
pub(crate) const VERIFIER_CRS_G2_BYTES: usize = 128;
pub(super) const VERIFIER_CRS_G1_POINTS: u64 = 1;
pub(crate) const FULL_PROVER_CRS_G1_PREFIX_BYTES: usize = 67_108_928;
pub(crate) const FULL_PROVER_CRS_G1_POINTS: u64 = 1_048_577;
pub(super) const BN254_FR_MODULUS: [u8; BARRETENBERG_FIELD_BYTES] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Borrowed, strictly validated BBAPI MessagePack envelope.
#[derive(PartialEq, Eq)]
pub(super) struct BbapiMessage<'a> {
    bytes: &'a [u8],
}

impl<'a> BbapiMessage<'a> {
    /// Validates a BBAPI command or response envelope without copying it.
    pub(super) fn try_from_slice(bytes: &'a [u8]) -> Result<Self, ZkError> {
        Self::try_from_slice_with_limits(bytes, BbapiLimits::standard())
    }

    pub(super) fn try_from_slice_with_limits(
        bytes: &'a [u8],
        limits: BbapiLimits,
    ) -> Result<Self, ZkError> {
        validate_message_length_with_limit(bytes.len(), limits.message_bytes)?;
        let parser = MsgpackParser { bytes, limits };
        parser.validate_root_array()?;
        Ok(Self { bytes })
    }

    /// Borrows the exact encoded envelope bytes.
    #[must_use]
    pub(super) const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

#[derive(Clone, Copy)]
pub(super) struct BbapiLimits {
    pub(super) message_bytes: usize,
    pub(super) binary_bytes: usize,
}

impl BbapiLimits {
    pub(super) const fn standard() -> Self {
        Self {
            message_bytes: MAX_BBAPI_MESSAGE_BYTES,
            binary_bytes: MAX_BBAPI_BINARY_BYTES,
        }
    }

    pub(super) const fn srs() -> Self {
        Self {
            message_bytes: MAX_BBAPI_SRS_MESSAGE_BYTES,
            binary_bytes: FULL_PROVER_CRS_G1_PREFIX_BYTES,
        }
    }

    pub(super) const fn prove() -> Self {
        Self {
            message_bytes: MAX_BBAPI_PROVE_MESSAGE_BYTES,
            binary_bytes: FULL_PROVER_CRS_G1_PREFIX_BYTES,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum MsgpackErrorReason {
    EmptyInput,
    MessageTooLarge,
    LengthOverflow,
    Truncated,
    UnsupportedType,
    NonCanonicalEncoding,
    NestingLimitExceeded,
    CollectionTooLarge,
    StringTooLarge,
    BinaryTooLarge,
    NonStringMapKey,
    DuplicateMapKey,
    TrailingBytes,
    RootNotArray,
    ResourceExhausted,
}

impl MsgpackErrorReason {
    pub(super) const fn zk_reason(self) -> ZkErrorReason {
        match self {
            Self::EmptyInput => ZkErrorReason::EmptyInput,
            Self::MessageTooLarge => ZkErrorReason::MessageTooLarge,
            Self::LengthOverflow => ZkErrorReason::LengthOverflow,
            Self::BinaryTooLarge => ZkErrorReason::MessageTooLarge,
            Self::ResourceExhausted => ZkErrorReason::ResourceExhausted,
            Self::Truncated
            | Self::UnsupportedType
            | Self::NonCanonicalEncoding
            | Self::NestingLimitExceeded
            | Self::CollectionTooLarge
            | Self::StringTooLarge
            | Self::NonStringMapKey
            | Self::DuplicateMapKey
            | Self::TrailingBytes
            | Self::RootNotArray => ZkErrorReason::BackendFailure,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedValue<'a> {
    String(&'a [u8]),
    Array,
    Other,
}

struct MsgpackParser<'a> {
    bytes: &'a [u8],
    limits: BbapiLimits,
}

impl<'a> MsgpackParser<'a> {
    fn validate_root_array(&self) -> Result<(), ZkError> {
        let (kind, offset) = self
            .parse_value(0, 0)
            .map_err(|reason| ZkError::new(reason.zk_reason()))?;
        if kind != ParsedValue::Array {
            return Err(ZkError::new(MsgpackErrorReason::RootNotArray.zk_reason()));
        }
        if offset != self.bytes.len() {
            return Err(ZkError::new(MsgpackErrorReason::TrailingBytes.zk_reason()));
        }
        Ok(())
    }

    fn parse_value(
        &self,
        offset: usize,
        depth: u8,
    ) -> Result<(ParsedValue<'a>, usize), MsgpackErrorReason> {
        if depth > MAX_BBAPI_DEPTH {
            return Err(MsgpackErrorReason::NestingLimitExceeded);
        }
        let (tag, offset) = self.read_u8(offset)?;
        match tag {
            0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => Ok((ParsedValue::Other, offset)),
            0x80..=0x8f => self.parse_map(offset, u32::from(tag & 0x0f), depth),
            0x90..=0x9f => self.parse_array(offset, u32::from(tag & 0x0f), depth),
            0xa0..=0xbf => self.parse_string(offset, usize::from(tag & 0x1f)),
            0xc4 => {
                let (size, offset) = self.read_u8(offset)?;
                self.parse_binary(offset, usize::from(size))
            }
            0xc5 => {
                let (size, offset) = self.read_u16(offset)?;
                self.parse_binary(offset, usize::from(size))
            }
            0xc6 => {
                let (size, offset) = self.read_u32(offset)?;
                self.parse_binary(
                    offset,
                    usize::try_from(size).map_err(|_| MsgpackErrorReason::LengthOverflow)?,
                )
            }
            0xcc => self.skip(offset, 1),
            0xcd => self.skip(offset, 2),
            0xce => self.skip(offset, 4),
            0xcf => self.skip(offset, 8),
            0xd0 => self.skip(offset, 1),
            0xd1 => self.skip(offset, 2),
            0xd2 => self.skip(offset, 4),
            0xd3 => self.skip(offset, 8),
            0xd9 => {
                let (size, offset) = self.read_u8(offset)?;
                self.parse_string(offset, usize::from(size))
            }
            0xda => {
                let (size, offset) = self.read_u16(offset)?;
                self.parse_string(offset, usize::from(size))
            }
            0xdb => {
                let (size, offset) = self.read_u32(offset)?;
                self.parse_string(
                    offset,
                    usize::try_from(size).map_err(|_| MsgpackErrorReason::LengthOverflow)?,
                )
            }
            0xdc => {
                let (size, offset) = self.read_u16(offset)?;
                self.parse_array(offset, u32::from(size), depth)
            }
            0xdd => {
                let (size, offset) = self.read_u32(offset)?;
                self.parse_array(offset, size, depth)
            }
            0xde => {
                let (size, offset) = self.read_u16(offset)?;
                self.parse_map(offset, u32::from(size), depth)
            }
            0xdf => {
                let (size, offset) = self.read_u32(offset)?;
                self.parse_map(offset, size, depth)
            }
            _ => Err(MsgpackErrorReason::UnsupportedType),
        }
    }

    fn parse_array(
        &self,
        mut offset: usize,
        size: u32,
        depth: u8,
    ) -> Result<(ParsedValue<'a>, usize), MsgpackErrorReason> {
        ensure_array_size(size)?;
        for _ in 0..size {
            let (_kind, next_offset) = self.parse_value(offset, depth.saturating_add(1))?;
            offset = next_offset;
        }
        Ok((ParsedValue::Array, offset))
    }

    fn parse_map(
        &self,
        mut offset: usize,
        size: u32,
        depth: u8,
    ) -> Result<(ParsedValue<'a>, usize), MsgpackErrorReason> {
        ensure_map_size(size)?;
        let key_count = usize::try_from(size).map_err(|_| MsgpackErrorReason::LengthOverflow)?;
        let mut keys = Vec::new();
        keys.try_reserve_exact(key_count)
            .map_err(|_| MsgpackErrorReason::ResourceExhausted)?;
        for _ in 0..size {
            let (key, next_offset) = self.parse_value(offset, depth.saturating_add(1))?;
            let ParsedValue::String(key_bytes) = key else {
                return Err(MsgpackErrorReason::NonStringMapKey);
            };
            if keys.contains(&key_bytes) {
                return Err(MsgpackErrorReason::DuplicateMapKey);
            }
            keys.push(key_bytes);
            let (_value, value_offset) = self.parse_value(next_offset, depth.saturating_add(1))?;
            offset = value_offset;
        }
        Ok((ParsedValue::Other, offset))
    }

    fn parse_string(
        &self,
        offset: usize,
        size: usize,
    ) -> Result<(ParsedValue<'a>, usize), MsgpackErrorReason> {
        if size > MAX_BBAPI_STRING_BYTES {
            return Err(MsgpackErrorReason::StringTooLarge);
        }
        let (bytes, offset) = self.read_exact(offset, size)?;
        Ok((ParsedValue::String(bytes), offset))
    }

    fn parse_binary(
        &self,
        offset: usize,
        size: usize,
    ) -> Result<(ParsedValue<'a>, usize), MsgpackErrorReason> {
        if size > self.limits.binary_bytes {
            return Err(MsgpackErrorReason::BinaryTooLarge);
        }
        let (_bytes, offset) = self.read_exact(offset, size)?;
        Ok((ParsedValue::Other, offset))
    }

    fn skip(
        &self,
        offset: usize,
        size: usize,
    ) -> Result<(ParsedValue<'a>, usize), MsgpackErrorReason> {
        let (_bytes, offset) = self.read_exact(offset, size)?;
        Ok((ParsedValue::Other, offset))
    }

    fn read_u8(&self, offset: usize) -> Result<(u8, usize), MsgpackErrorReason> {
        let (bytes, offset) = self.read_exact(offset, 1)?;
        Ok((bytes[0], offset))
    }

    fn read_u16(&self, offset: usize) -> Result<(u16, usize), MsgpackErrorReason> {
        let (bytes, offset) = self.read_exact(offset, 2)?;
        Ok((u16::from_be_bytes([bytes[0], bytes[1]]), offset))
    }

    fn read_u32(&self, offset: usize) -> Result<(u32, usize), MsgpackErrorReason> {
        let (bytes, offset) = self.read_exact(offset, 4)?;
        Ok((
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            offset,
        ))
    }

    fn read_exact(
        &self,
        offset: usize,
        size: usize,
    ) -> Result<(&'a [u8], usize), MsgpackErrorReason> {
        let end = offset
            .checked_add(size)
            .ok_or(MsgpackErrorReason::LengthOverflow)?;
        let bytes = self
            .bytes
            .get(offset..end)
            .ok_or(MsgpackErrorReason::Truncated)?;
        Ok((bytes, end))
    }
}

pub(crate) fn validate_message_length(length: usize) -> Result<(), ZkError> {
    validate_message_length_with_limit(length, MAX_BBAPI_MESSAGE_BYTES)
}

pub(super) fn validate_message_length_with_limit(
    length: usize,
    max_length: usize,
) -> Result<(), ZkError> {
    if length == 0 {
        return Err(ZkError::new(MsgpackErrorReason::EmptyInput.zk_reason()));
    }
    if length > max_length {
        return Err(ZkError::new(
            MsgpackErrorReason::MessageTooLarge.zk_reason(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_array_size(size: u32) -> Result<(), MsgpackErrorReason> {
    if size > MAX_BBAPI_ARRAY_ENTRIES {
        return Err(MsgpackErrorReason::CollectionTooLarge);
    }
    Ok(())
}

pub(super) fn ensure_map_size(size: u32) -> Result<(), MsgpackErrorReason> {
    if size > MAX_BBAPI_MAP_ENTRIES {
        return Err(MsgpackErrorReason::CollectionTooLarge);
    }
    Ok(())
}
