// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ZkArtifactIdentity, ZkArtifactManifestDigest, ZkArtifactSetIdentity};
use crate::errors::{ZkError, ZkErrorReason};

#[test]
fn equal_digest_bytes_do_not_conflate_identity_constructions() -> Result<(), ZkError> {
    let manifest = ZkArtifactManifestDigest::from_bytes([7; 32]);
    let artifact_set = ZkArtifactSetIdentity::from_bytes([7; 32]);
    let manifest_identity = ZkArtifactIdentity::from(manifest);
    let set_identity = ZkArtifactIdentity::from(artifact_set);
    assert_ne!(manifest_identity, set_identity);
    assert_eq!(manifest_identity.require_manifest()?, manifest);
    assert_eq!(set_identity.require_artifact_set()?, artifact_set);
    assert_eq!(
        manifest_identity
            .require_artifact_set()
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
    assert_eq!(
        set_identity
            .require_manifest()
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
    Ok(())
}
