// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compatibility validation for upstream Noir program artifact JSON.

use serde_json::Value;

use crate::{ReleaseProcessError, ReleaseProcessErrorReason, ReleaseToolchainProfile};

/// Maximum bytes accepted from one compiled Noir program artifact.
pub const MAX_COMPILED_PROGRAM_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;

/// Proves that two whole-file artifacts have identical execution semantics.
///
/// Noir source comments can alter debug metadata and the upstream artifact
/// `hash` while leaving the ABI and ACIR bytecode unchanged. Release tooling
/// uses this check to admit that metadata-only difference, then packages and
/// hashes the exact artifact bytes distributed for witness generation.
pub fn ensure_compiled_program_execution_compatible(
    freshly_compiled: &[u8],
    packaged_for_witness_generation: &[u8],
) -> Result<(), ReleaseProcessError> {
    ensure_compiled_program_execution_compatible_for_profile(
        freshly_compiled,
        packaged_for_witness_generation,
        ReleaseToolchainProfile::LegacyProduction,
    )
}

pub(crate) fn ensure_compiled_program_execution_compatible_for_profile(
    freshly_compiled: &[u8],
    packaged_for_witness_generation: &[u8],
    profile: ReleaseToolchainProfile,
) -> Result<(), ReleaseProcessError> {
    let fresh = parse_execution_identity(freshly_compiled, profile)?;
    let packaged = parse_execution_identity(packaged_for_witness_generation, profile)?;
    if fresh.abi != packaged.abi || fresh.bytecode != packaged.bytecode {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::CompiledArtifactExecutionMismatch,
        ));
    }
    Ok(())
}

/// Validates one compiled program as a pinned, bounded Noir artifact.
pub fn validate_compiled_program_artifact(bytes: &[u8]) -> Result<(), ReleaseProcessError> {
    validate_compiled_program_artifact_for_profile(bytes, ReleaseToolchainProfile::LegacyProduction)
}

pub(crate) fn validate_compiled_program_artifact_for_profile(
    bytes: &[u8],
    profile: ReleaseToolchainProfile,
) -> Result<(), ReleaseProcessError> {
    let _identity = parse_execution_identity(bytes, profile)?;
    Ok(())
}

/// Produces the deterministic release representation of a pinned Noir
/// artifact while preserving its ABI and bytecode exactly.
///
/// Noirc embeds build-host paths in `file_map`. Those paths are debug metadata,
/// not execution inputs, and would otherwise make package identities depend on
/// the checkout location. Every entry is rewritten to a stable file-id path;
/// malformed or unexpected file-map shapes fail closed.
pub fn normalize_compiled_program_artifact(bytes: &[u8]) -> Result<Vec<u8>, ReleaseProcessError> {
    normalize_compiled_program_artifact_for_profile(
        bytes,
        ReleaseToolchainProfile::LegacyProduction,
    )
}

/// Produces the portable release representation of a modern Noir program.
///
/// The ABI and ACIR bytecode remain unchanged, so witness generation has the
/// same execution identity on every build host. Only source-map paths change.
pub fn normalize_modern_compiled_program_artifact(
    bytes: &[u8],
) -> Result<Vec<u8>, ReleaseProcessError> {
    normalize_compiled_program_artifact_for_profile(bytes, ReleaseToolchainProfile::ModernCandidate)
}

pub(crate) fn normalize_compiled_program_artifact_for_profile(
    bytes: &[u8],
    profile: ReleaseToolchainProfile,
) -> Result<Vec<u8>, ReleaseProcessError> {
    let before = parse_execution_identity(bytes, profile)?;
    let mut artifact: Value = serde_json::from_slice(bytes).map_err(|_| {
        ReleaseProcessError::new(ReleaseProcessErrorReason::MalformedCompiledArtifact)
    })?;
    let root = artifact.as_object_mut().ok_or(ReleaseProcessError::new(
        ReleaseProcessErrorReason::MalformedCompiledArtifact,
    ))?;
    let file_map = root
        .get_mut("file_map")
        .and_then(Value::as_object_mut)
        .ok_or(ReleaseProcessError::new(
            ReleaseProcessErrorReason::MalformedCompiledArtifact,
        ))?;
    for (file_id, entry) in file_map {
        if file_id.is_empty() || !file_id.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ReleaseProcessError::new(
                ReleaseProcessErrorReason::MalformedCompiledArtifact,
            ));
        }
        let entry = entry.as_object_mut().ok_or(ReleaseProcessError::new(
            ReleaseProcessErrorReason::MalformedCompiledArtifact,
        ))?;
        if !entry.get("source").is_some_and(Value::is_string)
            || !entry.get("path").is_some_and(Value::is_string)
        {
            return Err(ReleaseProcessError::new(
                ReleaseProcessErrorReason::MalformedCompiledArtifact,
            ));
        }
        let mut normalized_path = String::from("source/");
        normalized_path.push_str(file_id);
        normalized_path.push_str(".nr");
        entry.insert("path".to_owned(), Value::String(normalized_path));
    }
    let normalized = serde_json::to_vec(&artifact).map_err(|_| {
        ReleaseProcessError::new(ReleaseProcessErrorReason::MalformedCompiledArtifact)
    })?;
    if normalized.len() > MAX_COMPILED_PROGRAM_ARTIFACT_BYTES {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::MalformedCompiledArtifact,
        ));
    }
    let after = parse_execution_identity(&normalized, profile)?;
    if before.abi != after.abi || before.bytecode != after.bytecode {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::CompiledArtifactExecutionMismatch,
        ));
    }
    Ok(normalized)
}

struct CompiledProgramExecutionIdentity {
    abi: Value,
    bytecode: String,
}

/// Typed projection of only the execution-relevant upstream artifact fields.
///
/// Serde's derived map decoder rejects duplicate known fields. Unknown
/// metadata remains deliberately ignored because debug symbols and compiler
/// metadata are outside the execution-identity comparison.
#[derive(serde::Deserialize)]
struct CompiledProgramArtifact {
    noir_version: String,
    abi: Value,
    bytecode: String,
}

fn parse_execution_identity(
    bytes: &[u8],
    profile: ReleaseToolchainProfile,
) -> Result<CompiledProgramExecutionIdentity, ReleaseProcessError> {
    if bytes.is_empty() || bytes.len() > MAX_COMPILED_PROGRAM_ARTIFACT_BYTES {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::MalformedCompiledArtifact,
        ));
    }
    let artifact: CompiledProgramArtifact = serde_json::from_slice(bytes).map_err(|_| {
        ReleaseProcessError::new(ReleaseProcessErrorReason::MalformedCompiledArtifact)
    })?;
    let version_prefix = noirc_version_prefix(profile);
    let git_commit = noirc_git_commit(profile);
    let expected_length =
        version_prefix
            .len()
            .checked_add(git_commit.len())
            .ok_or(ReleaseProcessError::new(
                ReleaseProcessErrorReason::MalformedCompiledArtifact,
            ))?;
    if artifact.noir_version.len() != expected_length
        || !artifact.noir_version.starts_with(version_prefix)
        || !artifact.noir_version.ends_with(git_commit)
    {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::CompiledArtifactToolchainMismatch,
        ));
    }
    if !artifact.abi.is_object() || artifact.bytecode.is_empty() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::MalformedCompiledArtifact,
        ));
    }
    Ok(CompiledProgramExecutionIdentity {
        abi: artifact.abi,
        bytecode: artifact.bytecode,
    })
}

const fn noirc_version_prefix(profile: ReleaseToolchainProfile) -> &'static str {
    match profile {
        ReleaseToolchainProfile::LegacyProduction => PINNED_NOIRC_VERSION_PREFIX,
        ReleaseToolchainProfile::ModernCandidate => MODERN_CANDIDATE_NOIRC_VERSION_PREFIX,
    }
}

const fn noirc_git_commit(profile: ReleaseToolchainProfile) -> &'static str {
    match profile {
        ReleaseToolchainProfile::LegacyProduction | ReleaseToolchainProfile::ModernCandidate => {
            MODERN_NOIRC_GIT_COMMIT
        }
    }
}
const MODERN_NOIRC_GIT_COMMIT: &str = "275d3ab1a5c916c6ea73e8d6b943f685f574500c";
const PINNED_NOIRC_VERSION_PREFIX: &str = "1.0.0+";
const MODERN_CANDIDATE_NOIRC_VERSION_PREFIX: &str = "1.0.0+";
