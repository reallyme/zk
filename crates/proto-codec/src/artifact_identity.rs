// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conversion preserves the identity construction as well as its digest bytes.

use buffa::MessageField;
use reallyme_zk_api::{
    artifacts::{ZkArtifactIdentity, ZkArtifactManifestDigest, ZkArtifactSetIdentity},
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

pub(crate) fn manifest_digest_from_proto(
    mut value: MessageField<
        pb::ZkArtifactManifestDigest,
        impl buffa::ProtoBox<pb::ZkArtifactManifestDigest>,
    >,
) -> Result<ZkArtifactManifestDigest, ZkError> {
    let value = value
        .take()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    Ok(ZkArtifactManifestDigest::from_bytes(identity_bytes(
        &value.value,
    )?))
}

pub(crate) fn artifact_set_identity_from_proto(
    mut value: MessageField<
        pb::ZkArtifactSetIdentity,
        impl buffa::ProtoBox<pb::ZkArtifactSetIdentity>,
    >,
) -> Result<ZkArtifactSetIdentity, ZkError> {
    let value = value
        .take()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    Ok(ZkArtifactSetIdentity::from_bytes(identity_bytes(
        &value.value,
    )?))
}

fn identity_bytes(value: &[u8]) -> Result<[u8; 32], ZkError> {
    let bytes =
        <[u8; 32]>::try_from(value).map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(bytes)
}

pub(crate) fn artifact_set_identity_to_proto(
    value: ZkArtifactSetIdentity,
) -> pb::ZkArtifactSetIdentity {
    pb::ZkArtifactSetIdentity {
        value: value.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

pub(crate) fn manifest_digest_to_proto(
    value: ZkArtifactManifestDigest,
) -> pb::ZkArtifactManifestDigest {
    pb::ZkArtifactManifestDigest {
        value: value.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

pub(crate) fn proof_identity_to_proto(
    value: ZkArtifactIdentity,
) -> pb::__buffa::oneof::zk_proof_package::ArtifactIdentity {
    match value {
        ZkArtifactIdentity::Manifest(value) => manifest_digest_to_proto(value).into(),
        ZkArtifactIdentity::ArtifactSet(value) => artifact_set_identity_to_proto(value).into(),
    }
}

pub(crate) fn proof_identity_from_proto(
    value: Option<pb::__buffa::oneof::zk_proof_package::ArtifactIdentity>,
) -> Result<ZkArtifactIdentity, ZkError> {
    use pb::__buffa::oneof::zk_proof_package::ArtifactIdentity;
    match value {
        Some(ArtifactIdentity::ArtifactManifestSha256(value)) => {
            Ok(ZkArtifactManifestDigest::from_bytes(identity_bytes(&value.value)?).into())
        }
        Some(ArtifactIdentity::ArtifactSetIdentitySha256(value)) => {
            Ok(ZkArtifactSetIdentity::from_bytes(identity_bytes(&value.value)?).into())
        }
        None => Err(ZkError::new(ZkErrorReason::ArtifactMismatch)),
    }
}

pub(crate) fn common_root_identity_to_proto(
    value: ZkArtifactIdentity,
) -> pb::__buffa::oneof::zk_common_credential_root_raw_proof_package::ArtifactIdentity {
    match value {
        ZkArtifactIdentity::Manifest(value) => manifest_digest_to_proto(value).into(),
        ZkArtifactIdentity::ArtifactSet(value) => artifact_set_identity_to_proto(value).into(),
    }
}

pub(crate) fn common_root_identity_from_proto(
    value: Option<
        pb::__buffa::oneof::zk_common_credential_root_raw_proof_package::ArtifactIdentity,
    >,
) -> Result<ZkArtifactIdentity, ZkError> {
    use pb::__buffa::oneof::zk_common_credential_root_raw_proof_package::ArtifactIdentity;
    match value {
        Some(ArtifactIdentity::ArtifactManifestSha256(value)) => {
            Ok(ZkArtifactManifestDigest::from_bytes(identity_bytes(&value.value)?).into())
        }
        Some(ArtifactIdentity::ArtifactSetIdentitySha256(value)) => {
            Ok(ZkArtifactSetIdentity::from_bytes(identity_bytes(&value.value)?).into())
        }
        None => Err(ZkError::new(ZkErrorReason::ArtifactMismatch)),
    }
}

#[cfg(test)]
mod tests;
