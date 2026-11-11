// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Take},
    path::{Component, Path, PathBuf},
};

use reallyme_zk_artifact_package::{
    ArtifactSourceFile, MAX_NOIR_SOURCE_BYTES, MAX_NOIR_SOURCE_FILES,
};

use crate::{ReleaseAssemblyError, ReleaseAssemblyErrorReason};

const NARGO_MANIFEST: &str = "Nargo.toml";
const SOURCE_DIRECTORY: &str = "src";
const NOIR_SOURCE_EXTENSION: &str = "nr";
const MAX_SOURCE_DEPTH: usize = 16;

struct SourceFileOwner {
    relative_path: PathBuf,
    contents: Vec<u8>,
}

pub(crate) struct SourceTree {
    files: Vec<SourceFileOwner>,
}

impl SourceTree {
    pub(crate) fn load(
        workspace_root: &Path,
        circuit_directory: &Path,
    ) -> Result<Self, ReleaseAssemblyError> {
        validate_directory(workspace_root)?;
        validate_directory(circuit_directory)?;
        if !circuit_directory.starts_with(workspace_root) {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidPath,
            ));
        }
        let mut files = Vec::new();
        files
            .try_reserve_exact(2)
            .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?;
        let mut visited = BTreeSet::new();
        let mut active = BTreeSet::new();
        let workspace_directory = secure_open::open_root_directory(workspace_root)
            .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::InvalidPath))?;
        collect_package_closure(
            &workspace_directory,
            workspace_root,
            circuit_directory,
            0,
            &mut visited,
            &mut active,
            &mut files,
        )?;
        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        if files.len() > MAX_NOIR_SOURCE_FILES {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::LengthOverflow,
            ));
        }
        let mut total_bytes = 0_usize;
        for file in &files {
            total_bytes =
                total_bytes
                    .checked_add(file.contents.len())
                    .ok_or(ReleaseAssemblyError::new(
                        ReleaseAssemblyErrorReason::LengthOverflow,
                    ))?;
            if total_bytes > MAX_NOIR_SOURCE_BYTES {
                return Err(ReleaseAssemblyError::new(
                    ReleaseAssemblyErrorReason::LengthOverflow,
                ));
            }
        }
        Ok(Self { files })
    }

    pub(crate) fn borrowed_files(
        &self,
    ) -> Result<Vec<ArtifactSourceFile<'_>>, ReleaseAssemblyError> {
        let mut files = Vec::new();
        files
            .try_reserve_exact(self.files.len())
            .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?;
        for file in &self.files {
            files.push(ArtifactSourceFile::try_new(
                &file.relative_path,
                &file.contents,
            )?);
        }
        Ok(files)
    }
}

#[cfg(test)]
mod test_support;

fn collect_package_closure(
    workspace_directory: &File,
    workspace_root: &Path,
    package_directory: &Path,
    depth: usize,
    visited: &mut BTreeSet<PathBuf>,
    active: &mut BTreeSet<PathBuf>,
    files: &mut Vec<SourceFileOwner>,
) -> Result<(), ReleaseAssemblyError> {
    if depth > MAX_SOURCE_DEPTH {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ));
    }
    let relative_package = package_directory
        .strip_prefix(workspace_root)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::InvalidPath))?
        .to_path_buf();
    if active.contains(&relative_package) {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ));
    }
    if !visited.insert(relative_package.clone()) {
        return Ok(());
    }
    active.insert(relative_package.clone());

    let manifest_path = package_directory.join(NARGO_MANIFEST);
    let manifest_bytes = read_bounded_file(
        workspace_directory,
        workspace_root,
        &manifest_path,
        MAX_NOIR_SOURCE_BYTES,
    )?;
    files.push(SourceFileOwner {
        relative_path: relative_package.join(NARGO_MANIFEST),
        contents: manifest_bytes.clone(),
    });
    collect_noir_sources(
        workspace_directory,
        workspace_root,
        &package_directory.join(SOURCE_DIRECTORY),
        0,
        files,
    )?;

    let dependencies = parse_path_dependencies(&manifest_bytes)?;
    for dependency in dependencies {
        let dependency_directory =
            resolve_dependency_directory(workspace_root, package_directory, dependency.as_path())?;
        collect_package_closure(
            workspace_directory,
            workspace_root,
            &dependency_directory,
            depth.checked_add(1).ok_or(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::LengthOverflow,
            ))?,
            visited,
            active,
            files,
        )?;
    }
    active.remove(&relative_package);
    Ok(())
}

pub(crate) fn parse_path_dependencies(
    manifest: &[u8],
) -> Result<Vec<PathBuf>, ReleaseAssemblyError> {
    let manifest = core::str::from_utf8(manifest)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::InvalidPath))?;
    let manifest = toml::from_str::<toml::Value>(manifest)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::InvalidPath))?;
    let Some(dependencies) = manifest.get("dependencies") else {
        return Ok(Vec::new());
    };
    let dependencies = dependencies.as_table().ok_or(ReleaseAssemblyError::new(
        ReleaseAssemblyErrorReason::InvalidPath,
    ))?;
    let mut paths = Vec::new();
    paths
        .try_reserve_exact(dependencies.len())
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?;
    for (name, specification) in dependencies {
        if name.is_empty() {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidPath,
            ));
        }
        let specification = specification.as_table().ok_or(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ))?;
        if specification.len() != 1 {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidPath,
            ));
        }
        let path = specification
            .get("path")
            .and_then(toml::Value::as_str)
            .ok_or(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidPath,
            ))?;
        if path.is_empty() || path.contains('\\') || path.contains('"') {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidPath,
            ));
        }
        paths.push(PathBuf::from(path));
    }
    Ok(paths)
}

fn resolve_dependency_directory(
    workspace_root: &Path,
    package_directory: &Path,
    dependency: &Path,
) -> Result<PathBuf, ReleaseAssemblyError> {
    if dependency.is_absolute() {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ));
    }
    let mut normalized = package_directory.to_path_buf();
    for component in dependency.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => normalized.push(segment),
            Component::ParentDir => {
                if !normalized.pop() || !normalized.starts_with(workspace_root) {
                    return Err(ReleaseAssemblyError::new(
                        ReleaseAssemblyErrorReason::InvalidPath,
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ReleaseAssemblyError::new(
                    ReleaseAssemblyErrorReason::InvalidPath,
                ));
            }
        }
    }
    if !normalized.starts_with(workspace_root) {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ));
    }
    reject_symlinked_path(workspace_root, &normalized)?;
    validate_directory(&normalized)?;
    Ok(normalized)
}

fn reject_symlinked_path(workspace_root: &Path, path: &Path) -> Result<(), ReleaseAssemblyError> {
    let relative = path
        .strip_prefix(workspace_root)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::InvalidPath))?;
    let mut current = workspace_root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidPath,
            ));
        };
        current.push(segment);
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidPath,
            ));
        }
    }
    Ok(())
}

fn collect_noir_sources(
    workspace_directory: &File,
    workspace_root: &Path,
    directory: &Path,
    depth: usize,
    files: &mut Vec<SourceFileOwner>,
) -> Result<(), ReleaseAssemblyError> {
    if depth > MAX_SOURCE_DEPTH {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ));
    }
    validate_directory(directory)?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidPath,
            ));
        }
        if metadata.is_dir() {
            collect_noir_sources(
                workspace_directory,
                workspace_root,
                &path,
                depth.checked_add(1).ok_or(ReleaseAssemblyError::new(
                    ReleaseAssemblyErrorReason::LengthOverflow,
                ))?,
                files,
            )?;
        } else if metadata.is_file() && path.extension() == Some(OsStr::new(NOIR_SOURCE_EXTENSION))
        {
            let relative_path = path
                .strip_prefix(workspace_root)
                .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::InvalidPath))?
                .to_path_buf();
            files.push(SourceFileOwner {
                relative_path,
                contents: read_bounded_file(
                    workspace_directory,
                    workspace_root,
                    &path,
                    MAX_NOIR_SOURCE_BYTES,
                )?,
            });
            if files.len() > MAX_NOIR_SOURCE_FILES {
                return Err(ReleaseAssemblyError::new(
                    ReleaseAssemblyErrorReason::LengthOverflow,
                ));
            }
        }
    }
    Ok(())
}

fn read_bounded_file(
    workspace_directory: &File,
    workspace_root: &Path,
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, ReleaseAssemblyError> {
    let relative_path = path
        .strip_prefix(workspace_root)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::InvalidPath))?;
    let file = secure_open::open_relative_regular_file(workspace_directory, relative_path)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::InvalidPath))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ));
    }
    let declared_len = usize::try_from(metadata.len())
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?;
    if declared_len == 0 || declared_len > maximum {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::LengthOverflow,
        ));
    }
    let limit = u64::try_from(maximum)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?
        .checked_add(1)
        .ok_or(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::LengthOverflow,
        ))?;
    let mut reader: Take<File> = file.take(limit);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(declared_len)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?;
    reader.read_to_end(&mut bytes)?;
    if bytes.len() != declared_len || bytes.len() > maximum {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::LengthOverflow,
        ));
    }
    Ok(bytes)
}

pub(crate) fn validate_directory(path: &Path) -> Result<(), ReleaseAssemblyError> {
    if !path.is_absolute() {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ));
    }
    Ok(())
}

pub(crate) fn validate_empty_directory(path: &Path) -> Result<(), ReleaseAssemblyError> {
    validate_directory(path)?;
    if fs::read_dir(path)?.next().transpose()?.is_some() {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ));
    }
    Ok(())
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
        // SAFETY: the CString is live and NUL-terminated for the call. The
        // returned descriptor is transferred exactly once into File.
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
        // SAFETY: fcntl borrows a valid descriptor. Its successful result is a
        // distinct descriptor transferred exactly once into File.
        let duplicate = unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        let mut current = descriptor_to_file(duplicate)?;
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
            };
            let name = CString::new(name.as_bytes())
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
            let flags = if components.peek().is_none() {
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW
            } else {
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW
            };
            // SAFETY: current is a live directory descriptor and name is a
            // live NUL-terminated component. Ownership of the returned
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
        // SAFETY: descriptor is newly owned after a successful libc call and
        // is transferred exactly once into File.
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
