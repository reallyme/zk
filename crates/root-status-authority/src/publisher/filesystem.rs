// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Owner-only publisher directory, bounded reads, and lock lifetime.

use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use reallyme_zk_proto_codec::common_credential_root_active_set_publication::MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES;
use zeroize::Zeroizing;

use super::{error, RootStatusPublisherError, RootStatusPublisherReason};
use crate::secure_files::{self, FileAccess, StoreFile};

pub(super) fn sync_parent_directory(path: &Path) -> Result<(), RootStatusPublisherError> {
    let parent = path
        .parent()
        .ok_or_else(|| error(RootStatusPublisherReason::InvalidStore))?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let parent_file = options
        .open(parent)
        .map_err(|_| error(RootStatusPublisherReason::Storage))?;
    parent_file
        .sync_all()
        .map_err(|_| error(RootStatusPublisherReason::Storage))
}

pub(super) struct PublicationLock<'a>(pub(super) &'a File);

impl Drop for PublicationLock<'_> {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub(super) fn open_private_directory(path: &Path) -> Result<File, RootStatusPublisherError> {
    if !path.is_absolute() {
        return Err(error(RootStatusPublisherReason::InvalidStore));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| error(RootStatusPublisherReason::InvalidStore))?;
    let metadata = file
        .metadata()
        .map_err(|_| error(RootStatusPublisherReason::InvalidStore))?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(error(RootStatusPublisherReason::InvalidStore));
    }
    Ok(file)
}

pub(super) fn read_publication(
    directory: &File,
    entry: StoreFile,
) -> Result<Zeroizing<Vec<u8>>, RootStatusPublisherError> {
    let file = secure_files::open(directory, entry, false, FileAccess::Read)?;
    let declared = file
        .metadata()
        .map_err(|_| error(RootStatusPublisherReason::Storage))?
        .len();
    let limit = u64::try_from(MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES)
        .map_err(|_| error(RootStatusPublisherReason::Range))?;
    if declared == 0 || declared > limit {
        return Err(error(RootStatusPublisherReason::InvalidState));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let capacity =
        usize::try_from(declared).map_err(|_| error(RootStatusPublisherReason::Range))?;
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| error(RootStatusPublisherReason::Storage))?;
    file.take(
        limit
            .checked_add(1)
            .ok_or_else(|| error(RootStatusPublisherReason::Range))?,
    )
    .read_to_end(&mut bytes)
    .map_err(|_| error(RootStatusPublisherReason::Storage))?;
    if bytes.is_empty() || bytes.len() > MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES {
        return Err(error(RootStatusPublisherReason::InvalidState));
    }
    Ok(bytes)
}

pub(super) fn current_unix() -> Result<u64, RootStatusPublisherError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| error(RootStatusPublisherReason::ClockRollback))
}
