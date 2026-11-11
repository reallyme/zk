// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use sha2::{Digest, Sha256};

use super::validation::validate_regular_file;
use crate::{ReleaseProcessError, ReleaseProcessErrorReason, ReleaseTool};

const MAX_RELEASE_TOOL_BYTES: u64 = 1024 * 1024 * 1024;
const TOOL_HASH_BUFFER_BYTES: usize = 64 * 1024;

pub(super) fn require_tool_digest(
    path: &Path,
    expected: [u8; 32],
    tool: ReleaseTool,
) -> Result<(), ReleaseProcessError> {
    if hash_executable(path)? != expected {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::ToolDigestMismatch(tool),
        ));
    }
    Ok(())
}

fn hash_executable(path: &Path) -> Result<[u8; 32], ReleaseProcessError> {
    validate_executable(path)?;
    let before = fs::symlink_metadata(path)?;
    if before.len() > MAX_RELEASE_TOOL_BYTES {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file: File = options.open(path)?;
    let opened = file.metadata()?;
    if !same_tool_file(&before, &opened) {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; TOOL_HASH_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total =
            total
                .checked_add(u64::try_from(read).map_err(|_| {
                    ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidPath)
                })?)
                .ok_or(ReleaseProcessError::new(
                    ReleaseProcessErrorReason::InvalidPath,
                ))?;
        if total > MAX_RELEASE_TOOL_BYTES {
            return Err(ReleaseProcessError::new(
                ReleaseProcessErrorReason::InvalidPath,
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if total != opened.len() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(bytes)
}

#[cfg(unix)]
fn same_tool_file(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    before.dev() == opened.dev()
        && before.ino() == opened.ino()
        && before.len() == opened.len()
        && before.mode() == opened.mode()
}

#[cfg(not(unix))]
fn same_tool_file(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    before.len() == opened.len()
        && before.is_file() == opened.is_file()
        && before.modified().ok() == opened.modified().ok()
}

pub(super) fn validate_executable(path: &Path) -> Result<(), ReleaseProcessError> {
    if !path.is_absolute() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    validate_regular_file(path)
}
