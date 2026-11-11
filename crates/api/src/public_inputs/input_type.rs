// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{HASH_BYTES, U32_BYTES, U64_BYTES, VALUE_BYTES};

/// Canonical compact encoding for one Noir ABI value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkPublicInputType {
    /// One 32-byte hash or curve coordinate.
    Bytes32,
    /// One big-endian `u64`.
    U64,
    /// One big-endian `u32`.
    U32,
    /// One zero-padded 64-byte claim value.
    Bytes64,
}

impl ZkPublicInputType {
    /// Byte length in the canonical compact provider encoding.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::Bytes32 => HASH_BYTES,
            Self::U64 => U64_BYTES,
            Self::U32 => U32_BYTES,
            Self::Bytes64 => VALUE_BYTES,
        }
    }

    /// Number of flattened Noir field elements represented by this value.
    ///
    /// Byte arrays contribute one field element per byte, while integer
    /// scalars contribute one field element each. Backend adapters use this
    /// compiler-ABI fact without moving backend serialization into this crate.
    #[must_use]
    pub const fn flattened_element_count(self) -> usize {
        match self {
            Self::Bytes32 => HASH_BYTES,
            Self::U64 | Self::U32 => 1,
            Self::Bytes64 => VALUE_BYTES,
        }
    }
}
