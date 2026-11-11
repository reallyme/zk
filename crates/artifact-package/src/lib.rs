// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic production artifact package construction and verification.

mod candidate_util;
mod common_credential_root_candidate;
mod error;
mod hash;
mod mobile_runtime;
mod package;
mod persona_credential_evidence_candidate;
mod promotion;
mod recovery;
mod release;
mod release_layout;
mod sealed_release;

pub use common_credential_root_candidate::seal_common_credential_root_candidate;
pub use error::{ArtifactPackageError, ArtifactPackageErrorReason};
pub use mobile_runtime::validate_mobile_public_runtime;
pub use package::{
    noir_source_tree_sha256, ArtifactPackage, ArtifactPackageCoordinates, ArtifactPackageInput,
    ArtifactPackageMaterial, ArtifactSourceFile, ArtifactVectorFile, CanonicalBundleVectorFile,
    SealedArtifactPackage, MAX_CAPABILITY_REGISTRY_BYTES, MAX_NOIR_SOURCE_BYTES,
    MAX_NOIR_SOURCE_FILES, MAX_VECTOR_FILE_BYTES,
};
pub use persona_credential_evidence_candidate::seal_persona_credential_evidence_candidate;
pub use promotion::{promote_sealed_release_new, ReleasePromotionSummary};
pub use reallyme_zk_artifacts::{ArtifactPackageLayout, ARTIFACT_PACKAGE_VERSION};
pub use recovery::{
    quarantine_incomplete_artifact_package, quarantine_incomplete_release,
    IncompleteArtifactPackageQuarantineSummary, IncompleteReleaseQuarantineSummary,
    INCOMPLETE_ARTIFACT_PACKAGE_QUARANTINE_DIRECTORY, INCOMPLETE_RELEASE_QUARANTINE_DIRECTORY,
};
pub use release::{
    assemble_release_index, AssembledReleaseIndex, ReleaseArtifactManifestFile,
    ReleaseVerificationVectorFile,
};
pub use release_layout::{ReleasePackageLayout, RELEASE_PACKAGE_FORMAT};
pub use sealed_release::SealedRelease;
