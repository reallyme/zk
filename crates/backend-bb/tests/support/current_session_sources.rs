// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs,
    io::{Read, Take},
    path::PathBuf,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::GzDecoder;
use reallyme_zk_api::proofs::MAX_WITNESS_BYTES;
use reallyme_zk_artifacts::MAX_ACIR_BYTECODE_BYTES;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::SmokeError;

pub(super) struct CurrentSessionSources {
    pub(super) bytecode: Vec<u8>,
    pub(super) compressed_witness: Zeroizing<Vec<u8>>,
    pub(super) bbapi_bytecode: Zeroizing<Vec<u8>>,
    pub(super) bbapi_witness: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
struct CompiledProgramContainer {
    bytecode: String,
}

impl CurrentSessionSources {
    pub(super) fn load(root: PathBuf) -> Result<Self, SmokeError> {
        let target = root
            .join("sha256")
            .join("families")
            .join("private_persona_claim_v1")
            .join("session")
            .join("target");
        let bytecode = fs::read(target.join("credential_private_persona_claim_v1_session.json"))?;
        let compressed_witness = Zeroizing::new(fs::read(
            target.join("credential_private_persona_claim_v1_session.gz"),
        )?);
        let bbapi_bytecode = decode_compiled_program_bytecode(bytecode.as_slice())?;
        let bbapi_witness =
            decode_gzip_with_limit(compressed_witness.as_slice(), MAX_WITNESS_BYTES)?;
        Ok(Self {
            bytecode,
            compressed_witness,
            bbapi_bytecode,
            bbapi_witness,
        })
    }
}

fn decode_compiled_program_bytecode(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, SmokeError> {
    let container: CompiledProgramContainer =
        serde_json::from_slice(bytes).map_err(|_| SmokeError::UnexpectedSchema)?;
    if container.bytecode.is_empty() {
        return Err(SmokeError::UnexpectedSchema);
    }
    let compressed = Zeroizing::new(
        STANDARD
            .decode(container.bytecode.as_bytes())
            .map_err(|_| SmokeError::UnexpectedSchema)?,
    );
    decode_gzip_with_limit(compressed.as_slice(), MAX_ACIR_BYTECODE_BYTES)
}

fn decode_gzip_with_limit(
    compressed: &[u8],
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SmokeError> {
    if compressed.is_empty() {
        return Err(SmokeError::UnexpectedLength);
    }
    let read_limit = u64::try_from(max_bytes)
        .map_err(|_| SmokeError::LengthOverflow)?
        .checked_add(1)
        .ok_or(SmokeError::LengthOverflow)?;
    let mut decoder: Take<GzDecoder<&[u8]>> = GzDecoder::new(compressed).take(read_limit);
    let mut decoded = Zeroizing::new(Vec::new());
    decoded
        .try_reserve_exact(max_bytes.min(compressed.len()))
        .map_err(|_| SmokeError::ResourceExhausted)?;
    decoder
        .read_to_end(&mut decoded)
        .map_err(|_| SmokeError::UnexpectedSchema)?;
    if decoded.is_empty() {
        return Err(SmokeError::UnexpectedSchema);
    }
    if decoded.len() > max_bytes {
        return Err(SmokeError::UnexpectedLength);
    }
    Ok(decoded)
}
