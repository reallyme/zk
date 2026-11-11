// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto_codec::{
    capability_registry::build_capability_registry,
    release::{decode_release_index, ReleaseIndex},
};

pub(crate) const RELEASE_INDEX_SHA256_BYTES: usize = 32;
const PINNED_NARGO_VERSION: &[u8] = b"1.0.0";
const PINNED_BARRETENBERG_VERSION: &[u8] = b"6.0.0";

pub(crate) fn decode_pinned_release_index(
    release_index_bytes: &[u8],
    expected_release_index_sha256_bytes: &[u8],
) -> Result<ReleaseIndex, ZkError> {
    let expected_release_index_sha256 =
        digest_from_platform_bytes(expected_release_index_sha256_bytes)?;
    if !expected_release_index_sha256.matches_sha256(release_index_bytes) {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let release_index = decode_release_index(release_index_bytes)?;
    validate_release_index_trust_root(&release_index)?;
    Ok(release_index)
}

fn digest_from_platform_bytes(bytes: &[u8]) -> Result<Digest32, ZkError> {
    let digest = <[u8; RELEASE_INDEX_SHA256_BYTES]>::try_from(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    Ok(Digest32::from_bytes(digest))
}

fn validate_release_index_trust_root(index: &ReleaseIndex) -> Result<(), ZkError> {
    if index.toolchain().nargo_version().as_bytes() != PINNED_NARGO_VERSION
        || index.toolchain().barretenberg_version().as_bytes() != PINNED_BARRETENBERG_VERSION
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let registry = build_capability_registry()?;
    // The caller pins the exact index bytes. The current registry rejects
    // retired circuit families even when a caller retains an older digest.
    if index.capability_registry_sha256() != registry.sha256() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(())
}
