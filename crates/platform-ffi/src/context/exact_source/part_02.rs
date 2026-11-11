// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "diagnostic-exact-source")]
fn recompute_source_closure_digest(
    root: &Path,
    circuit_ref: ZkCircuitRef,
) -> Result<Digest32, ZkError> {
    ensure_directory_not_symlink(root)?;
    let mut source_paths = Vec::new();
    let mut budget = SourceTraversalBudget::new();
    collect_source_files(
        root,
        exact_source_circuit_name(circuit_ref).as_str(),
        0,
        &mut budget,
        &mut source_paths,
    )?;
    let vendor = root.join("vendor");
    match fs::symlink_metadata(&vendor) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(metadata) if metadata.is_dir() => {
            collect_source_files(root, "vendor", 0, &mut budget, &mut source_paths)?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(map_filesystem_error(error)),
    }
    source_paths.sort();

    let mut closure_lines = Vec::new();
    let mut source_bytes_total = 0_usize;
    for source_path in source_paths {
        let source_bytes = read_bounded_regular_file_with_limit(
            &root.join(source_path.as_str()),
            MAX_EXACT_SOURCE_FILE_BYTES,
        )?;
        source_bytes_total = source_bytes_total
            .checked_add(source_bytes.len())
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if source_bytes_total > MAX_EXACT_SOURCE_TOTAL_BYTES {
            return Err(ZkError::new(ZkErrorReason::ArtifactTooLarge));
        }
        let source_digest = Digest32::sha256(source_bytes.as_slice());
        let additional_len = source_path
            .len()
            .checked_add(1)
            .and_then(|len| len.checked_add(64))
            .and_then(|len| len.checked_add(1))
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        closure_lines
            .try_reserve_exact(additional_len)
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        closure_lines.extend_from_slice(source_path.as_bytes());
        closure_lines.extend_from_slice(b"\t");
        closure_lines.extend_from_slice(hex32(source_digest.as_bytes()).as_bytes());
        closure_lines.extend_from_slice(b"\n");
    }
    Ok(Digest32::sha256(closure_lines.as_slice()))
}

#[cfg(feature = "diagnostic-exact-source")]
pub(crate) struct SourceTraversalBudget {
    entries: usize,
    directories: usize,
}

#[cfg(feature = "diagnostic-exact-source")]
impl SourceTraversalBudget {
    pub(crate) const fn new() -> Self {
        Self {
            entries: 0,
            directories: 0,
        }
    }

    fn enter_directory(&mut self) -> Result<(), ZkError> {
        self.directories = self
            .directories
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if self.directories > MAX_EXACT_SOURCE_DIRECTORIES {
            return Err(ZkError::new(ZkErrorReason::ArtifactTooLarge));
        }
        Ok(())
    }

    fn visit_entry(&mut self) -> Result<(), ZkError> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if self.entries > MAX_EXACT_SOURCE_ENTRIES {
            return Err(ZkError::new(ZkErrorReason::ArtifactTooLarge));
        }
        Ok(())
    }
}

#[cfg(feature = "diagnostic-exact-source")]
pub(crate) fn collect_source_files(
    root: &Path,
    relative_dir: &str,
    depth: usize,
    budget: &mut SourceTraversalBudget,
    out: &mut Vec<String>,
) -> Result<(), ZkError> {
    if depth > MAX_EXACT_SOURCE_DEPTH || out.len() > MAX_EXACT_SOURCE_FILES {
        return Err(ZkError::new(ZkErrorReason::ArtifactTooLarge));
    }
    let dir = root.join(relative_dir);
    ensure_directory_not_symlink(&dir)?;
    budget.enter_directory()?;
    for entry in fs::read_dir(dir).map_err(map_filesystem_error)? {
        budget.visit_entry()?;
        let entry = entry.map_err(map_filesystem_error)?;
        let file_type = entry.file_type().map_err(map_filesystem_error)?;
        if file_type.is_symlink() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if out.len() >= MAX_EXACT_SOURCE_FILES {
            return Err(ZkError::new(ZkErrorReason::ArtifactTooLarge));
        }
        let path = entry.path();
        if file_type.is_dir() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?
                .to_str()
                .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
            if !relative.split('/').any(|component| component == "target") {
                collect_source_files(
                    root,
                    relative,
                    depth
                        .checked_add(1)
                        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?,
                    budget,
                    out,
                )?;
            }
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        let include = file_name == "Nargo.toml"
            || path.extension().and_then(|value| value.to_str()) == Some("nr");
        if !include {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?
            .to_str()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        if relative.split('/').any(|component| component == "target") {
            continue;
        }
        out.try_reserve_exact(1)
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        out.push(relative.to_owned());
    }
    Ok(())
}
