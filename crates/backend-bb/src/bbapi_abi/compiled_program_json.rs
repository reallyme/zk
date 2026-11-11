// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::Read;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::GzDecoder;
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_artifacts::MAX_ACIR_BYTECODE_BYTES;
use serde::Deserialize;
use zeroize::Zeroizing;

const DECOMPRESSION_CHUNK_BYTES: usize = 8192;

#[derive(Deserialize)]
struct CompiledProgramContainer<'a> {
    #[serde(borrow)]
    bytecode: &'a str,
}

/// Extracts the compressed ACIR payload from a verified Noir compiled-program
/// artifact. The surrounding JSON is a tool-owned artifact container, not a
/// provider operation boundary, so this is the only BB adapter JSON exception.
pub(super) fn decode_compiled_program_bytecode(
    program_json: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let container: CompiledProgramContainer<'_> = serde_json::from_slice(program_json)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedJson))?;
    if container.bytecode.is_empty() {
        return Err(ZkError::new(ZkErrorReason::MalformedJson));
    }
    let compressed = Zeroizing::new(
        STANDARD
            .decode(container.bytecode.as_bytes())
            .map_err(|_| ZkError::new(ZkErrorReason::MalformedJson))?,
    );

    decode_gzip_with_limit(
        compressed.as_slice(),
        MAX_ACIR_BYTECODE_BYTES,
        ZkErrorReason::ArtifactTooLarge,
        ZkErrorReason::ArtifactMismatch,
    )
}

pub(super) fn decode_gzip_with_limit(
    compressed: &[u8],
    max_bytes: usize,
    too_large_reason: ZkErrorReason,
    malformed_reason: ZkErrorReason,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    if compressed.is_empty() {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }

    let read_limit = u64::try_from(max_bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
        .checked_add(1)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    // A growing Vec can free a former backing allocation while it contains
    // plaintext witness bytes. Count through a zeroizing scratch buffer first,
    // then allocate the exact size and forbid growth during the second pass.
    let mut scratch = Zeroizing::new([0_u8; DECOMPRESSION_CHUNK_BYTES]);
    let mut decoder = GzDecoder::new(compressed).take(read_limit);
    let mut decoded_len = 0_usize;
    loop {
        let count = decoder
            .read(scratch.as_mut())
            .map_err(|_| ZkError::new(malformed_reason))?;
        if count == 0 {
            break;
        }
        decoded_len = decoded_len
            .checked_add(count)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if decoded_len > max_bytes {
            return Err(ZkError::new(too_large_reason));
        }
    }
    if decoded_len == 0 {
        return Err(ZkError::new(malformed_reason));
    }

    let mut decoded = Zeroizing::new(Vec::new());
    decoded
        .try_reserve_exact(decoded_len)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut decoder = GzDecoder::new(compressed).take(read_limit);
    loop {
        let count = decoder
            .read(scratch.as_mut())
            .map_err(|_| ZkError::new(malformed_reason))?;
        if count == 0 {
            break;
        }
        let next_len = decoded
            .len()
            .checked_add(count)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if next_len > decoded_len || next_len > decoded.capacity() {
            return Err(ZkError::new(malformed_reason));
        }
        decoded.extend_from_slice(&scratch[..count]);
    }
    if decoded.len() != decoded_len {
        return Err(ZkError::new(malformed_reason));
    }

    Ok(decoded)
}
