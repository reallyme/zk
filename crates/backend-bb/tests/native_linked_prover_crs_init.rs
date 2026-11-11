// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opt-in full prover CRS initialization against the linked Barretenberg archive.

#![cfg(feature = "native")]

use std::{env, fs, fs::File, io::Read, path::PathBuf};

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_backend_bb::{BarretenbergProverCrs, NativeBarretenbergBackend};
use thiserror::Error;

const ENABLE_ENV: &str = "REALLYME_NATIVE_PROVER_CRS_INIT";
const G1_PATH_ENV: &str = "REALLYME_BN254_G1_PATH";
const G2_PATH_ENV: &str = "REALLYME_BN254_G2_PATH";
const FULL_PROVER_G1_PREFIX_BYTES: usize = 67_108_928;
const VERIFIER_G2_BYTES: usize = 128;

#[test]
fn native_backend_initializes_full_prover_crs() -> Result<(), SmokeError> {
    if env::var_os(ENABLE_ENV).is_none() {
        return Ok(());
    }

    let g1_prefix = read_g1_prefix(required_path(G1_PATH_ENV)?)?;
    let g2 = read_g2(required_path(G2_PATH_ENV)?)?;
    let crs = BarretenbergProverCrs::try_from_pinned_slices(g1_prefix.as_slice(), g2.as_slice())?;
    let backend = NativeBarretenbergBackend::try_new()?;

    backend.initialize_prover_crs(crs)?;

    Ok(())
}

fn required_path(name: &str) -> Result<PathBuf, SmokeError> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or(SmokeError::MissingEnvironment)
}

fn read_g1_prefix(path: PathBuf) -> Result<Vec<u8>, SmokeError> {
    let mut file = File::open(path)?;
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(FULL_PROVER_G1_PREFIX_BYTES)
        .map_err(|_| SmokeError::ResourceExhausted)?;
    prefix.resize(FULL_PROVER_G1_PREFIX_BYTES, 0);
    file.read_exact(prefix.as_mut_slice())?;
    Ok(prefix)
}

fn read_g2(path: PathBuf) -> Result<[u8; VERIFIER_G2_BYTES], SmokeError> {
    let bytes = fs::read(path)?;
    bytes.try_into().map_err(|_| SmokeError::UnexpectedLength)
}

#[derive(Debug, Error)]
enum SmokeError {
    #[error("required environment variable is missing")]
    MissingEnvironment,
    #[error("unexpected CRS length")]
    UnexpectedLength,
    #[error("resource exhausted")]
    ResourceExhausted,
    #[error("I/O failed")]
    Io(#[from] std::io::Error),
    #[error("ZK backend failed: {0:?}")]
    Zk(ZkErrorReason),
}

impl From<ZkError> for SmokeError {
    fn from(error: ZkError) -> Self {
        Self::Zk(error.reason())
    }
}
