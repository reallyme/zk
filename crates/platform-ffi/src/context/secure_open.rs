// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(unix)]
use std::{
    ffi::CString,
    fs::File,
    os::{fd::AsRawFd, unix::ffi::OsStrExt, unix::io::FromRawFd},
    path::{Component, Path},
};

#[cfg(not(unix))]
use std::{fs::File, path::Path};

#[cfg(unix)]
pub(super) fn open_root_directory(path: &Path) -> std::io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `path` is a live NUL-terminated buffer for the call. The
    // returned descriptor is transferred into a single owned `File`.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    descriptor_to_file(descriptor)
}

#[cfg(unix)]
pub(super) fn open_relative_regular_file(
    root: &File,
    relative_path: &Path,
) -> std::io::Result<File> {
    let mut components = relative_path.components().peekable();
    if components.peek().is_none() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    // SAFETY: `fcntl` borrows a valid descriptor and returns a new owned
    // descriptor on success.
    let duplicate = unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    let mut current = descriptor_to_file(duplicate)?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        let name = CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let final_component = components.peek().is_none();
        let flags = if final_component {
            // Reject a replaced FIFO after open without waiting for a writer
            // while the dispatch lease is held.
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW
        };
        // SAFETY: `current` owns a directory descriptor, and `name` is a
        // live NUL-terminated component for this call.
        let descriptor = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        current = descriptor_to_file(descriptor)?;
    }
    Ok(current)
}

#[cfg(unix)]
pub(super) fn open_absolute_regular_file(path: &Path) -> std::io::Result<File> {
    if !path.is_absolute() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `path` is a live NUL-terminated buffer for the call. The
    // returned descriptor is transferred into a single owned `File`.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    descriptor_to_file(descriptor)
}

#[cfg(unix)]
fn descriptor_to_file(descriptor: libc::c_int) -> std::io::Result<File> {
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a non-negative descriptor returned by `open`, `openat`, or
    // `fcntl` is newly owned here.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(not(unix))]
pub(super) fn open_root_directory(_path: &Path) -> std::io::Result<File> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(not(unix))]
pub(super) fn open_relative_regular_file(
    _root: &File,
    _relative_path: &Path,
) -> std::io::Result<File> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(not(unix))]
pub(super) fn open_absolute_regular_file(path: &Path) -> std::io::Result<File> {
    if !path.is_absolute() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    File::open(path)
}
