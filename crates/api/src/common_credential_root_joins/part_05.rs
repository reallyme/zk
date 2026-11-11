// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Clone, Copy)]
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn new(bytes: &'a [u8], count: usize) -> Result<Self, ZkError> {
        let expected = count
            .checked_mul(FIELD_BYTES)
            .ok_or(error(ZkErrorReason::LengthOverflow))?;
        if bytes.len() != expected {
            return Err(error(ZkErrorReason::InvalidProofEncoding));
        }
        Ok(Self(bytes))
    }

    fn field(self, index: usize) -> Result<&'a [u8], ZkError> {
        let start = index
            .checked_mul(FIELD_BYTES)
            .ok_or(error(ZkErrorReason::LengthOverflow))?;
        let end = start
            .checked_add(FIELD_BYTES)
            .ok_or(error(ZkErrorReason::LengthOverflow))?;
        self.0
            .get(start..end)
            .ok_or(error(ZkErrorReason::InvalidProofEncoding))
    }

    fn byte(self, index: usize) -> Result<u8, ZkError> {
        let field = self.field(index)?;
        if field[..FIELD_BYTES - 1].iter().any(|byte| *byte != 0) {
            return Err(error(ZkErrorReason::InvalidProofEncoding));
        }
        Ok(field[FIELD_BYTES - 1])
    }

    fn bytes32(self, first: usize) -> Result<[u8; 32], ZkError> {
        let mut value = [0_u8; 32];
        for (offset, byte) in value.iter_mut().enumerate() {
            *byte = self.byte(
                first
                    .checked_add(offset)
                    .ok_or(error(ZkErrorReason::LengthOverflow))?,
            )?;
        }
        Ok(value)
    }

    fn bytes64(self, first: usize) -> Result<Zeroizing<[u8; CLAIM_VALUE_BYTES]>, ZkError> {
        let mut value = Zeroizing::new([0_u8; CLAIM_VALUE_BYTES]);
        for (offset, byte) in value.iter_mut().enumerate() {
            *byte = self.byte(
                first
                    .checked_add(offset)
                    .ok_or(error(ZkErrorReason::LengthOverflow))?,
            )?;
        }
        Ok(value)
    }

    fn key(self, first: usize) -> Result<ZkIssuerPublicKey, ZkError> {
        Ok(ZkIssuerPublicKey {
            x: self.bytes32(first)?,
            y: self.bytes32(field_index(first, 32)?)?,
        })
    }

    fn u64(self, index: usize) -> Result<u64, ZkError> {
        let field = self.field(index)?;
        let high = field
            .get(..FIELD_BYTES - 8)
            .ok_or(error(ZkErrorReason::InvalidProofEncoding))?;
        if high.iter().any(|byte| *byte != 0) {
            return Err(error(ZkErrorReason::InvalidProofEncoding));
        }
        let tail: [u8; 8] = field[FIELD_BYTES - 8..]
            .try_into()
            .map_err(|_| error(ZkErrorReason::InvalidProofEncoding))?;
        Ok(u64::from_be_bytes(tail))
    }

    fn u32(self, index: usize) -> Result<u32, ZkError> {
        let field = self.field(index)?;
        let high = field
            .get(..FIELD_BYTES - 4)
            .ok_or(error(ZkErrorReason::InvalidProofEncoding))?;
        if high.iter().any(|byte| *byte != 0) {
            return Err(error(ZkErrorReason::InvalidProofEncoding));
        }
        let tail: [u8; 4] = field[FIELD_BYTES - 4..]
            .try_into()
            .map_err(|_| error(ZkErrorReason::InvalidProofEncoding))?;
        Ok(u32::from_be_bytes(tail))
    }
}
