// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use zeroize::Zeroizing;

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{CliError, CliErrorReason};

pub(crate) fn read_bounded_public(path: &Path, max_bytes: usize) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(map_input_io_error)?;
    let declared_len = file
        .metadata()
        .map_err(map_input_io_error)?
        .len()
        .try_into()
        .map_err(|_| CliError::new(CliErrorReason::InputTooLarge))?;
    validate_input_len(declared_len, max_bytes)?;
    let read_limit = u64::try_from(max_bytes)
        .map_err(|_| CliError::new(CliErrorReason::InputTooLarge))?
        .checked_add(1)
        .ok_or(CliError::new(CliErrorReason::InputTooLarge))?;
    let mut reader = file.take(read_limit);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(declared_len)
        .map_err(|_| CliError::new(CliErrorReason::InputTooLarge))?;
    reader.read_to_end(&mut bytes).map_err(map_input_io_error)?;
    validate_input_len(bytes.len(), max_bytes)?;
    Ok(bytes)
}

#[cfg(feature = "native")]
pub(crate) fn read_bounded_secret(
    path: &Path,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    read_secret_bytes(path, max_bytes)
}

pub(crate) fn read_bounded_secret_utf8(
    path: &Path,
    max_bytes: usize,
) -> Result<Zeroizing<String>, CliError> {
    let mut bytes = read_secret_bytes(path, max_bytes)?;
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(error) => {
            let _invalid_bytes = Zeroizing::new(error.into_bytes());
            Err(CliError::new(CliErrorReason::InvalidInput))
        }
    }
}

// Allocate the entire permitted range before reading. Growing a Vec after it
// contains a secret can leave the previous allocation uncleared by the allocator.
fn read_secret_bytes(path: &Path, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let file = File::open(path).map_err(map_input_io_error)?;
    let declared_len = file
        .metadata()
        .map_err(map_input_io_error)?
        .len()
        .try_into()
        .map_err(|_| CliError::new(CliErrorReason::InputTooLarge))?;
    validate_input_len(declared_len, max_bytes)?;
    let max_with_sentinel = max_bytes
        .checked_add(1)
        .ok_or(CliError::new(CliErrorReason::InputTooLarge))?;
    let read_limit = u64::try_from(max_with_sentinel)
        .map_err(|_| CliError::new(CliErrorReason::InputTooLarge))?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(max_with_sentinel)
        .map_err(|_| CliError::new(CliErrorReason::InputTooLarge))?;
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(map_input_io_error)?;
    validate_input_len(bytes.len(), max_bytes)?;
    Ok(bytes)
}

#[cfg(feature = "native")]
pub(crate) fn write_new_public(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(map_output_io_error)?;
    file.write_all(bytes).map_err(map_output_io_error)?;
    file.sync_all().map_err(map_output_io_error)
}

pub(crate) fn write_new_secret(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_err(map_output_io_error)?;
    finish_new_secret_write(path, file, |file| {
        file.write_all(bytes).and_then(|()| file.sync_all())
    })
}

fn finish_new_secret_write(
    path: &Path,
    mut file: File,
    write_and_sync: impl FnOnce(&mut File) -> std::io::Result<()>,
) -> Result<(), CliError> {
    if let Err(error) = write_and_sync(&mut file) {
        // Clear bytes already written before attempting to remove the new file.
        // Retain the original I/O error even if cleanup itself fails.
        let _ = file.set_len(0);
        remove_partial_output_if_owned(path, &file);
        return Err(map_output_io_error(error));
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
    // Without a stable file identity check, a replacement at this path might
    // belong to another writer. The owned descriptor was already truncated.
    #[cfg(unix)]
    let _ = fs::remove_file(path);
    #[cfg(not(unix))]
    let _ = (path, file);
}

fn validate_input_len(length: usize, max_bytes: usize) -> Result<(), CliError> {
    if length == 0 {
        return Err(CliError::new(CliErrorReason::InvalidInput));
    }
    if length > max_bytes {
        return Err(CliError::new(CliErrorReason::InputTooLarge));
    }
    Ok(())
}

fn map_input_io_error(error: std::io::Error) -> CliError {
    match error.kind() {
        std::io::ErrorKind::InvalidData => CliError::new(CliErrorReason::InvalidInput),
        _ => CliError::new(CliErrorReason::IoUnavailable),
    }
}

fn map_output_io_error(error: std::io::Error) -> CliError {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => CliError::new(CliErrorReason::OutputAlreadyExists),
        _ => CliError::new(CliErrorReason::IoUnavailable),
    }
}

#[cfg(test)]
#[path = "io/tests.rs"]
mod tests;
