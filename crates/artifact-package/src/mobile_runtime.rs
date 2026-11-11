// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integrity validation for the public mobile runtime artifact tree.

use std::path::Path;

use reallyme_zk_artifacts::ArtifactVersion;
use reallyme_zk_proto_codec::capability_registry::build_capability_registry;

use crate::{
    candidate_util::package_mismatch,
    common_credential_root_candidate::{
        load_current_index_for_common_credential_root_reseal,
        validate_mobile_public_runtime_tree_against_index,
    },
    promotion::canonical_directory,
    ArtifactPackageError,
};

/// Validate public runtime artifacts against their canonical index and registry.
///
/// This checks every referenced manifest, program, key and source lock and
/// rejects extra files, directories and symlinks. Proof-bearing test vectors
/// are excluded from this distribution. This is an integrity check, not proof
/// verification or approval to publish; complete releases use `SealedRelease`.
pub fn validate_mobile_public_runtime(
    root: &Path,
    version: ArtifactVersion,
) -> Result<(), ArtifactPackageError> {
    canonical_directory(root)?;
    let (index, _) = load_current_index_for_common_credential_root_reseal(root, version)?;
    if index.capability_registry_sha256() != build_capability_registry()?.sha256() {
        return package_mismatch();
    }
    validate_mobile_public_runtime_tree_against_index(root, version, &index)
}
