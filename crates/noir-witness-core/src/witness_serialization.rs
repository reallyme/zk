// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encode the pinned Noir witness wire format while owning its plaintext bytes.
//!
//! Noir 1.0.0 first serializes into an ordinary `Vec<u8>` and then gzips it.
//! That intermediate buffer contains every private witness value and is freed
//! without a wipe. Keep the exact format and compression policy, but place the
//! intermediate and compressed buffers under zeroizing owners from creation.

use std::io::{self, Read, Write};

use acir::{native_types::WitnessStack, SerializationFormat};
use acvm::FieldElement;
use flate2::{bufread::GzEncoder, Compression};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    domain::SerializedWitnessStack,
    error::{WitnessError, WitnessErrorReason},
};

const FORMAT_MARKER_BYTES: usize = 1;
const COMPRESSION_HEADROOM_DIVISOR: usize = 16;
const COMPRESSION_FIXED_HEADROOM_BYTES: usize = 1024;
const COMPRESSION_READ_CHUNK_BYTES: usize = 8192;

pub(crate) fn serialize_witness_stack(
    witness_stack: &WitnessStack<FieldElement>,
) -> Result<SerializedWitnessStack, WitnessError> {
    // Count first so the plaintext owner never reallocates and frees an
    // unwiped former backing allocation while serializing private fields.
    let mut counter = CountingWriter::default();
    serialize_msgpack(witness_stack, &mut counter)?;
    let plaintext_len = counter
        .len
        .checked_add(FORMAT_MARKER_BYTES)
        .ok_or(WitnessError::new(
            WitnessErrorReason::WitnessSerializationFailed,
        ))?;
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(plaintext_len)
        .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?;
    let format_marker: u8 = SerializationFormat::MsgpackCompact.into();
    plaintext.push(format_marker);
    let mut plaintext_writer = CapacityWriter {
        bytes: &mut plaintext,
        limit: plaintext_len,
    };
    serialize_msgpack(witness_stack, &mut plaintext_writer)?;
    if plaintext.len() != plaintext_len {
        return Err(WitnessError::new(
            WitnessErrorReason::WitnessSerializationFailed,
        ));
    }

    let mut compressor = GzEncoder::new(plaintext.as_slice(), Compression::best());
    let compressed_capacity = plaintext_len
        .checked_add(plaintext_len / COMPRESSION_HEADROOM_DIVISOR)
        .and_then(|len| len.checked_add(COMPRESSION_FIXED_HEADROOM_BYTES))
        .ok_or(WitnessError::new(
            WitnessErrorReason::WitnessSerializationFailed,
        ))?;
    let mut compressed = Zeroizing::new(Vec::new());
    compressed
        .try_reserve_exact(compressed_capacity)
        .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?;
    let mut chunk = Zeroizing::new([0_u8; COMPRESSION_READ_CHUNK_BYTES]);
    loop {
        let count = compressor
            .read(chunk.as_mut_slice())
            .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?;
        if count == 0 {
            break;
        }
        let next_len = compressed
            .len()
            .checked_add(count)
            .ok_or(WitnessError::new(
                WitnessErrorReason::WitnessSerializationFailed,
            ))?;
        if next_len > compressed_capacity {
            return Err(WitnessError::new(
                WitnessErrorReason::WitnessSerializationFailed,
            ));
        }
        compressed.extend_from_slice(&chunk[..count]);
    }
    Ok(SerializedWitnessStack::from_zeroizing_bytes(compressed))
}

fn serialize_msgpack<W: Write>(
    witness_stack: &WitnessStack<FieldElement>,
    writer: &mut W,
) -> Result<(), WitnessError> {
    // Match the pinned ACIR serializer's tuple layout and iterable byte mode.
    let serializer =
        rmp_serde::Serializer::new(writer).with_bytes(rmp_serde::config::BytesMode::ForceIterables);
    Serialize::serialize(witness_stack, &mut serializer.with_struct_tuple())
        .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))
}

#[derive(Default)]
struct CountingWriter {
    len: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.len = self
            .len
            .checked_add(bytes.len())
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CapacityWriter<'a> {
    bytes: &'a mut Zeroizing<Vec<u8>>,
    limit: usize,
}

impl Write for CapacityWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(io::ErrorKind::InvalidData)?;
        if next_len > self.limit {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
