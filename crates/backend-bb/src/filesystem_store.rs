// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native bounded reads from the canonical sealed artifact package tree.

use std::{
    fs::File,
    io::{Read, Take},
    path::{Path, PathBuf},
};

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_artifacts::{
    ArtifactBytes, ArtifactKind, ArtifactPackageLayout, ProductionArtifactManifest,
};

use crate::BarretenbergArtifactStore;

/// Native filesystem byte store rooted at one explicit artifact directory.
///
/// This type intentionally omits `Debug`: absolute host paths do not belong in
/// diagnostics. The store derives every child path from closed manifest enums,
/// rejects symlinks at each package directory and file, and bounds allocation
/// from the artifact kind before reading.
pub struct NativeFilesystemArtifactStore {
    artifact_root: PathBuf,
    artifact_root_directory: File,
}

impl NativeFilesystemArtifactStore {
    /// Validates an absolute, existing, non-symlinked artifact root.
    pub fn try_new(artifact_root: &Path) -> Result<Self, ZkError> {
        if !artifact_root.is_absolute() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let artifact_root_directory =
            secure_open::open_root_directory(artifact_root).map_err(map_filesystem_error)?;
        Ok(Self {
            artifact_root: artifact_root.to_path_buf(),
            artifact_root_directory,
        })
    }

    fn layout(
        &self,
        manifest: &ProductionArtifactManifest,
    ) -> Result<ArtifactPackageLayout, ZkError> {
        ArtifactPackageLayout::try_new(
            &self.artifact_root,
            manifest.circuit_ref().credential_hash_algorithm,
            manifest.bundle_kind(),
            manifest.stage(),
            manifest.manifest_sha256(),
        )
    }

    fn read(
        &self,
        manifest: &ProductionArtifactManifest,
        kind: ArtifactKind,
    ) -> Result<ArtifactBytes, ZkError> {
        let layout = self.layout(manifest)?;
        let path = match kind {
            ArtifactKind::AcirBytecode => layout.program(),
            ArtifactKind::VerificationKey => layout.verification_key(),
        };
        let relative = path
            .strip_prefix(&self.artifact_root)
            .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        read_bounded_file(&self.artifact_root_directory, relative, kind)
    }
}

impl BarretenbergArtifactStore for NativeFilesystemArtifactStore {
    fn bytecode_bytes(
        &self,
        manifest: &ProductionArtifactManifest,
    ) -> Result<ArtifactBytes, ZkError> {
        self.read(manifest, ArtifactKind::AcirBytecode)
    }

    fn verification_key_bytes(
        &self,
        manifest: &ProductionArtifactManifest,
    ) -> Result<ArtifactBytes, ZkError> {
        self.read(manifest, ArtifactKind::VerificationKey)
    }
}

fn read_bounded_file(
    root: &File,
    relative_path: &Path,
    kind: ArtifactKind,
) -> Result<ArtifactBytes, ZkError> {
    let file = secure_open::open_relative_regular_file(root, relative_path)
        .map_err(map_filesystem_error)?;
    let opened = file.metadata().map_err(map_filesystem_error)?;
    if !opened.is_file() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let declared_len =
        usize::try_from(opened.len()).map_err(|_| ZkError::new(ZkErrorReason::ArtifactTooLarge))?;
    kind.validate_length(declared_len)?;
    let read_limit = u64::try_from(kind.max_bytes())
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
        .checked_add(1)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut reader: Take<File> = file.take(read_limit);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(declared_len)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    reader
        .read_to_end(&mut bytes)
        .map_err(map_filesystem_error)?;
    let after = reader.get_ref().metadata().map_err(map_filesystem_error)?;
    if after.len() != opened.len() || bytes.len() != declared_len {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    ArtifactBytes::try_from_bytes(kind, bytes)
}

fn map_filesystem_error(error: std::io::Error) -> ZkError {
    let path_rejected = matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
    ) || rejected_path_component(&error);
    if path_rejected {
        ZkError::new(ZkErrorReason::ArtifactMismatch)
    } else {
        ZkError::new(ZkErrorReason::BackendFailure)
    }
}

#[cfg(unix)]
fn rejected_path_component(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ELOOP) | Some(libc::ENOTDIR)
    )
}

#[cfg(not(unix))]
const fn rejected_path_component(_error: &std::io::Error) -> bool {
    false
}

#[allow(unsafe_code)]
mod secure_open {
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
        // SAFETY: `path` is a live NUL-terminated buffer for the duration of
        // the call. The returned descriptor is uniquely transferred to File.
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
        // SAFETY: `fcntl` borrows a valid live descriptor. A successful result
        // is a new owned descriptor transferred exactly once into File.
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
                // A replaced regular file may be a FIFO. Nonblocking open lets
                // the metadata check reject it without hanging the prover.
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
            } else {
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW
            };
            // SAFETY: `current` owns a valid directory descriptor and `name`
            // remains live and NUL-terminated for the call. Each returned
            // descriptor is transferred exactly once into File.
            let descriptor = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
            current = descriptor_to_file(descriptor)?;
        }
        Ok(current)
    }

    #[cfg(unix)]
    fn descriptor_to_file(descriptor: libc::c_int) -> std::io::Result<File> {
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a non-negative descriptor returned by open/openat/fcntl is
        // newly owned here and is transferred exactly once into File.
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
}

#[cfg(test)]
mod tests;
