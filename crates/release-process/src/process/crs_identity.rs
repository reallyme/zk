// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admit the explicit full-prover CRS before invoking modern Barretenberg.

use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use sha2::{Digest, Sha256};

use crate::{ReleaseCommand, ReleaseProcessError, ReleaseProcessErrorReason, ReleaseTool};

const G1_FILE: &str = "bn254_g1.dat";
const G2_FILE: &str = "bn254_g2.dat";
const G1_BYTES: u64 = 134_217_792;
const G2_BYTES: u64 = 128;
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const G1_SHA256: [u8; 32] = [
    0xea, 0x60, 0x69, 0xe3, 0x56, 0x3a, 0xd7, 0x9f, 0x18, 0x6d, 0x1c, 0x00, 0x88, 0x49, 0x93, 0x09,
    0xcb, 0xda, 0xeb, 0x54, 0x25, 0x43, 0x46, 0x76, 0x0f, 0xfe, 0xc7, 0xfe, 0x15, 0xae, 0x49, 0xcd,
];
const G2_SHA256: [u8; 32] = [
    0x01, 0x79, 0x7b, 0xfc, 0x4d, 0xe5, 0xa9, 0x6f, 0x0e, 0x51, 0x6a, 0x9e, 0xa4, 0x53, 0x7d, 0x18,
    0x78, 0x6d, 0xc3, 0x0c, 0xb9, 0x91, 0xac, 0xa4, 0x27, 0x4c, 0x95, 0x82, 0x2b, 0x69, 0xc3, 0x2f,
];

pub(crate) fn require_modern_crs_identity(
    command: &ReleaseCommand,
) -> Result<(), ReleaseProcessError> {
    if command.tool != ReleaseTool::Barretenberg {
        return Ok(());
    }
    // The legacy CLI begins with -c; version queries begin with --version.
    // Modern write_vk/prove/verify place their operation first and -c second.
    let Some(first) = command.arguments.first() else {
        return Ok(());
    };
    if first != "write_vk" && first != "prove" && first != "verify" {
        return Ok(());
    }
    let [_, flag, directory, ..] = command.arguments.as_slice() else {
        return mismatch();
    };
    if flag != "-c" {
        return mismatch();
    }
    let directory = Path::new(directory);
    if !directory.is_absolute()
        || fs::symlink_metadata(directory)
            .map_err(|_| crs_error())?
            .file_type()
            .is_symlink()
    {
        return mismatch();
    }
    verify_file(&directory.join(G1_FILE), G1_BYTES, G1_SHA256)?;
    verify_file(&directory.join(G2_FILE), G2_BYTES, G2_SHA256)?;
    Ok(())
}

fn verify_file(
    path: &Path,
    expected_bytes: u64,
    expected_sha256: [u8; 32],
) -> Result<(), ReleaseProcessError> {
    let before = fs::symlink_metadata(path).map_err(|_| crs_error())?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() != expected_bytes {
        return mismatch();
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut file: File = options.open(path).map_err(|_| crs_error())?;
    let opened = file.metadata()?;
    if !same_file(&before, &opened) {
        return mismatch();
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| {
                ReleaseProcessError::new(ReleaseProcessErrorReason::CrsIdentityMismatch)
            })?)
            .ok_or(ReleaseProcessError::new(
                ReleaseProcessErrorReason::CrsIdentityMismatch,
            ))?;
        if total > expected_bytes {
            return mismatch();
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_bytes || !same_file(&opened, &file.metadata()?) {
        return mismatch();
    }
    let digest = hasher.finalize();
    if digest.as_slice() != expected_sha256 {
        return mismatch();
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    first.dev() == second.dev()
        && first.ino() == second.ino()
        && first.len() == second.len()
        && first.mode() == second.mode()
}

#[cfg(not(unix))]
fn same_file(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    first.len() == second.len()
        && first.is_file() == second.is_file()
        && first.modified().ok() == second.modified().ok()
}

fn mismatch<T>() -> Result<T, ReleaseProcessError> {
    Err(crs_error())
}

fn crs_error() -> ReleaseProcessError {
    ReleaseProcessError::new(ReleaseProcessErrorReason::CrsIdentityMismatch)
}

#[cfg(test)]
mod tests;
