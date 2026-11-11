// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hash-pinned artifact manifests for ReallyMe ZK providers.

mod bundle_manifest;
mod bytes;
mod common_credential_root_lock;
mod identity;
mod layout;
mod manifest;
#[cfg(test)]
mod tests;

pub use bundle_manifest::ProductionBundleManifest;
pub use bytes::{
    ArtifactBytes, ArtifactKind, VerifiedArtifactBytes, MAX_ACIR_BYTECODE_BYTES,
    MAX_VERIFICATION_KEY_BYTES,
};
pub use common_credential_root_lock::common_credential_root_source_closure_from_lock;
pub use identity::{
    exact_source_artifact_identity, ArtifactToolchain, ArtifactVersion, Digest32,
    MAX_ARTIFACT_VERSION_BYTES, MAX_VECTOR_SET_DIGESTS,
};
pub use layout::{
    ArtifactPackageLayout, CommonCredentialRootArtifactLayout,
    PersonaCredentialEvidenceArtifactLayout, ARTIFACT_MANIFEST_FILE_NAME, ARTIFACT_PACKAGE_VERSION,
    ARTIFACT_PROGRAM_FILE_NAME, ARTIFACT_VECTORS_DIRECTORY_NAME,
    ARTIFACT_VERIFICATION_KEY_FILE_NAME, COMMON_CREDENTIAL_ROOT_ARTIFACT_DIRECTORY_NAME,
    COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_FILE_NAME,
    PERSONA_CREDENTIAL_EVIDENCE_ARTIFACT_DIRECTORY_NAME,
};
pub use manifest::{
    ArtifactDigests, ArtifactManifestPin, ProductionArtifactManifest,
    ProductionArtifactManifestDraft,
};
