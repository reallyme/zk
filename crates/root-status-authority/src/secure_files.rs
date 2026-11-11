// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! File operations scoped to the directory inode opened at enrollment.

use std::{ffi::CStr, fs::File, os::unix::fs::MetadataExt};

use crate::publisher::{error, RootStatusPublisherError, RootStatusPublisherReason};

const PRIVATE_FILE_MODE: libc::mode_t = 0o600;

/// Fixed names prevent callers from introducing path traversal or separators.
#[derive(Clone, Copy)]
pub(crate) enum StoreFile {
    Lock,
    Publication,
    Pending,
    Intent,
}

impl StoreFile {
    const fn name(self) -> &'static CStr {
        match self {
            Self::Lock => c"publication.lock",
            Self::Publication => c"publication.pb",
            Self::Pending => c"publication.pending",
            Self::Intent => c"publication.intent.pb",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FileAccess {
    Read,
    ReadWrite,
}

#[allow(unsafe_code)]
mod syscalls {
    use std::{
        ffi::CStr,
        fs::File,
        io,
        mem::MaybeUninit,
        os::{fd::AsRawFd, fd::FromRawFd},
    };

    pub(super) fn open(
        directory: &File,
        name: &CStr,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> io::Result<File> {
        // Darwin's mode_t is narrower than Linux's. The variadic argument must
        // undergo C's integer promotion even where that conversion is a no-op.
        #[allow(clippy::useless_conversion)]
        let promoted_mode = libc::c_uint::from(mode);
        // SAFETY: the directory descriptor remains live for the call and
        // `name` is NUL-terminated. The successful descriptor is owned once.
        let descriptor =
            unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, promoted_mode) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor and no other File
        // or owner has been constructed from it.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    pub(super) fn exists(directory: &File, name: &CStr) -> io::Result<bool> {
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: both descriptors and pointers are valid for this call;
        // fstatat initializes metadata on success, before assume_init.
        let result = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(true);
        }
        let failure = io::Error::last_os_error();
        if failure.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(failure)
        }
    }

    pub(super) fn remove(directory: &File, name: &CStr) -> io::Result<()> {
        // SAFETY: the directory descriptor and NUL-terminated name are live;
        // flags zero removes only a directory entry, never a directory.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn replace(directory: &File, from: &CStr, to: &CStr) -> io::Result<()> {
        // SAFETY: both names are fixed, NUL-terminated components and the
        // directory descriptor stays live throughout the atomic rename.
        let result = unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                from.as_ptr(),
                directory.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

pub(crate) fn exists(directory: &File, entry: StoreFile) -> Result<bool, RootStatusPublisherError> {
    syscalls::exists(directory, entry.name()).map_err(|_| error(RootStatusPublisherReason::Storage))
}

pub(crate) fn open(
    directory: &File,
    entry: StoreFile,
    create_new: bool,
    access: FileAccess,
) -> Result<File, RootStatusPublisherError> {
    if create_new && matches!(access, FileAccess::Read) {
        return Err(error(RootStatusPublisherReason::InvalidStore));
    }
    let access_flag = match access {
        FileAccess::Read => libc::O_RDONLY,
        FileAccess::ReadWrite => libc::O_RDWR,
    };
    let creation_flags = if create_new {
        libc::O_CREAT | libc::O_EXCL
    } else {
        0
    };
    let file = syscalls::open(
        directory,
        entry.name(),
        access_flag | creation_flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        PRIVATE_FILE_MODE,
    )
    .map_err(|_| error(RootStatusPublisherReason::InvalidStore))?;
    let metadata = file
        .metadata()
        .map_err(|_| error(RootStatusPublisherReason::InvalidStore))?;
    let directory_metadata = directory
        .metadata()
        .map_err(|_| error(RootStatusPublisherReason::InvalidStore))?;
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.uid() != directory_metadata.uid()
        || metadata.dev() != directory_metadata.dev()
    {
        return Err(error(RootStatusPublisherReason::InvalidStore));
    }
    Ok(file)
}

pub(crate) fn remove(directory: &File, entry: StoreFile) -> Result<(), RootStatusPublisherError> {
    syscalls::remove(directory, entry.name()).map_err(|_| error(RootStatusPublisherReason::Storage))
}

pub(crate) fn replace(
    directory: &File,
    from: StoreFile,
    to: StoreFile,
) -> Result<(), RootStatusPublisherError> {
    syscalls::replace(directory, from.name(), to.name())
        .map_err(|_| error(RootStatusPublisherReason::Storage))
}
