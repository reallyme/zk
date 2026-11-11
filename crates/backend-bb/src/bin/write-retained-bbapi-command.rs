// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Writes dev-only retained BBAPI command fixtures for promotion gates.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::MAX_WITNESS_BYTES,
};
use reallyme_zk_artifacts::{MAX_ACIR_BYTECODE_BYTES, MAX_VERIFICATION_KEY_BYTES};
use reallyme_zk_backend_bb::retained_command::{
    encode_retained_full_prover_srs_command, encode_retained_prove_command,
};
use thiserror::Error;
use zeroize::Zeroizing;

const PROVE_ARGUMENT_COUNT: usize = 7;
const SRS_ARGUMENT_COUNT: usize = 3;
const PROVER_G1_PREFIX_BYTES: usize = 67_108_928;
const G2_BYTES: usize = 128;

fn main() -> Result<(), RetainedCommandError> {
    match parse_arguments(std::env::args_os())? {
        Arguments::Prove(arguments) => write_prove_command(arguments),
        Arguments::Srs(arguments) => write_srs_command(arguments),
    }
}

enum Arguments {
    Prove(ProveArguments),
    Srs(SrsArguments),
}

struct ProveArguments {
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    bytecode: PathBuf,
    verification_key: PathBuf,
    witness: PathBuf,
    output: PathBuf,
}

struct SrsArguments {
    g1: PathBuf,
    g2: PathBuf,
    output: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetainedCommandErrorReason {
    InvalidArguments,
    Filesystem(std::io::ErrorKind),
    Zk(ZkErrorReason),
}

#[derive(Debug, Error)]
#[error("retained BBAPI command generation failed")]
struct RetainedCommandError {
    reason: RetainedCommandErrorReason,
}

impl RetainedCommandError {
    const fn new(reason: RetainedCommandErrorReason) -> Self {
        Self { reason }
    }
}

impl From<ZkError> for RetainedCommandError {
    fn from(error: ZkError) -> Self {
        Self::new(RetainedCommandErrorReason::Zk(error.reason()))
    }
}

impl From<std::io::Error> for RetainedCommandError {
    fn from(error: std::io::Error) -> Self {
        Self::new(RetainedCommandErrorReason::Filesystem(error.kind()))
    }
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, RetainedCommandError> {
    let mut arguments = arguments.into_iter();
    let _executable = arguments.next();
    let mode = arguments
        .next()
        .ok_or_else(invalid_arguments)?
        .into_string()
        .map_err(|_| invalid_arguments())?;
    match mode.as_str() {
        "prove" => parse_prove_arguments(arguments).map(Arguments::Prove),
        "srs" => parse_srs_arguments(arguments).map(Arguments::Srs),
        _ => Err(invalid_arguments()),
    }
}

fn parse_prove_arguments(
    arguments: impl Iterator<Item = OsString>,
) -> Result<ProveArguments, RetainedCommandError> {
    let values = collect_exact(arguments, PROVE_ARGUMENT_COUNT)?;
    Ok(ProveArguments {
        bundle_kind: parse_profile(&values[0])?,
        stage: parse_stage(&values[1])?,
        credential_hash_algorithm: parse_hash(&values[2])?,
        bytecode: PathBuf::from(&values[3]),
        verification_key: PathBuf::from(&values[4]),
        witness: PathBuf::from(&values[5]),
        output: PathBuf::from(&values[6]),
    })
}

fn parse_srs_arguments(
    arguments: impl Iterator<Item = OsString>,
) -> Result<SrsArguments, RetainedCommandError> {
    let values = collect_exact(arguments, SRS_ARGUMENT_COUNT)?;
    Ok(SrsArguments {
        g1: PathBuf::from(&values[0]),
        g2: PathBuf::from(&values[1]),
        output: PathBuf::from(&values[2]),
    })
}

fn collect_exact(
    mut arguments: impl Iterator<Item = OsString>,
    expected: usize,
) -> Result<Vec<OsString>, RetainedCommandError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(expected)
        .map_err(|_| invalid_arguments())?;
    for _ in 0..expected {
        values.push(arguments.next().ok_or_else(invalid_arguments)?);
    }
    if arguments.next().is_some() {
        return Err(invalid_arguments());
    }
    Ok(values)
}

fn parse_profile(value: &OsString) -> Result<ZkClaimProofBundleKind, RetainedCommandError> {
    match value.to_str() {
        Some("credential_subject_claim_v1") => Ok(ZkClaimProofBundleKind::CredentialSubjectClaimV1),
        Some("private_persona_claim_v1") => Ok(ZkClaimProofBundleKind::PrivatePersonaClaimV1),
        Some(_) | None => Err(invalid_arguments()),
    }
}

fn parse_stage(value: &OsString) -> Result<ZkClaimProofBundleStage, RetainedCommandError> {
    match value.to_str() {
        Some("session") => Ok(ZkClaimProofBundleStage::Session),
        Some("credential_envelope") => Ok(ZkClaimProofBundleStage::CredentialEnvelope),
        Some("credential_root") => Ok(ZkClaimProofBundleStage::CredentialRoot),
        Some("claim") => Ok(ZkClaimProofBundleStage::Claim),
        Some(_) | None => Err(invalid_arguments()),
    }
}

fn parse_hash(value: &OsString) -> Result<ZkCredentialHashAlgorithm, RetainedCommandError> {
    match value.to_str() {
        Some("sha256") => Ok(ZkCredentialHashAlgorithm::Sha256),
        Some("poseidon2") => Ok(ZkCredentialHashAlgorithm::Poseidon2),
        Some(_) | None => Err(invalid_arguments()),
    }
}

fn write_prove_command(arguments: ProveArguments) -> Result<(), RetainedCommandError> {
    let bytecode = read_bounded(arguments.bytecode, MAX_ACIR_BYTECODE_BYTES)?;
    let verification_key = read_bounded(arguments.verification_key, MAX_VERIFICATION_KEY_BYTES)?;
    let witness = read_bounded_zeroizing(arguments.witness, MAX_WITNESS_BYTES)?;
    let command = encode_retained_prove_command(
        arguments.bundle_kind,
        arguments.stage,
        arguments.credential_hash_algorithm,
        bytecode,
        verification_key,
        witness,
    )?;
    write_new_secret(&arguments.output, command.as_slice())
}

fn write_srs_command(arguments: SrsArguments) -> Result<(), RetainedCommandError> {
    let g1 = read_prefix(arguments.g1, PROVER_G1_PREFIX_BYTES)?;
    let g2 = read_exact(arguments.g2, G2_BYTES)?;
    let command = encode_retained_full_prover_srs_command(&g1, &g2)?;
    write_new_secret(&arguments.output, command.as_slice())
}

fn read_bounded(path: PathBuf, max_bytes: usize) -> Result<Vec<u8>, RetainedCommandError> {
    let metadata = fs::metadata(&path)?;
    let max_u64 = u64::try_from(max_bytes).map_err(|_| invalid_arguments())?;
    if metadata.len() == 0 || metadata.len() > max_u64 {
        return Err(invalid_arguments());
    }
    fs::read(path).map_err(RetainedCommandError::from)
}

fn read_bounded_zeroizing(
    path: PathBuf,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, RetainedCommandError> {
    let file = File::open(path)?;
    let max_u64 = u64::try_from(max_bytes).map_err(|_| invalid_arguments())?;
    let declared_len = file.metadata()?.len();
    if declared_len == 0 || declared_len > max_u64 {
        return Err(invalid_arguments());
    }
    // Reserve before reading so no allocator growth frees a witness-bearing buffer.
    let limit = max_bytes.checked_add(1).ok_or_else(invalid_arguments)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(limit)
        .map_err(|_| invalid_arguments())?;
    file.take(u64::try_from(limit).map_err(|_| invalid_arguments())?)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(invalid_arguments());
    }
    Ok(bytes)
}

fn write_new_secret(path: &Path, bytes: &[u8]) -> Result<(), RetainedCommandError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path)?;
    finish_new_secret_write(path, file, |file| {
        file.write_all(bytes).and_then(|()| file.sync_all())
    })
}

fn finish_new_secret_write(
    path: &Path,
    mut file: File,
    write_and_sync: impl FnOnce(&mut File) -> std::io::Result<()>,
) -> Result<(), RetainedCommandError> {
    if let Err(error) = write_and_sync(&mut file) {
        // A failed write must not leave a partial witness command on disk.
        let _ = file.set_len(0);
        remove_partial_output_if_owned(path, &file);
        return Err(error.into());
    }
    Ok(())
}

fn remove_partial_output_if_owned(path: &Path, file: &File) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let Ok(created) = file.metadata() else {
            return;
        };
        let Ok(current) = fs::symlink_metadata(path) else {
            return;
        };
        if created.dev() != current.dev() || created.ino() != current.ino() {
            return;
        }
    }
    // Do not remove a path that another writer may have replaced. On non-Unix
    // targets the owned descriptor has been truncated, but identity is unknown.
    #[cfg(unix)]
    let _ = fs::remove_file(path);
    #[cfg(not(unix))]
    let _ = (path, file);
}

fn read_prefix(path: PathBuf, len: usize) -> Result<Vec<u8>, RetainedCommandError> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| invalid_arguments())?;
    bytes.resize(len, 0);
    file.read_exact(bytes.as_mut_slice())?;
    Ok(bytes)
}

fn read_exact(path: PathBuf, len: usize) -> Result<Vec<u8>, RetainedCommandError> {
    let mut bytes = read_bounded(path, len)?;
    if bytes.len() != len {
        bytes.clear();
        return Err(invalid_arguments());
    }
    Ok(bytes)
}

const fn invalid_arguments() -> RetainedCommandError {
    RetainedCommandError::new(RetainedCommandErrorReason::InvalidArguments)
}

#[cfg(test)]
#[path = "write-retained-bbapi-command/tests.rs"]
mod tests;
