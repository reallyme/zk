// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    common_root_identity_from_proto, common_root_identity_to_proto, proof_identity_from_proto,
    proof_identity_to_proto,
};
use reallyme_zk_api::{
    artifacts::{ZkArtifactIdentity, ZkArtifactManifestDigest, ZkArtifactSetIdentity},
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

#[test]
fn identity_discriminators_survive_each_transport_boundary() -> Result<(), ZkError> {
    for identity in [
        ZkArtifactIdentity::from(ZkArtifactManifestDigest::from_bytes([9; 32])),
        ZkArtifactIdentity::from(ZkArtifactSetIdentity::from_bytes([9; 32])),
    ] {
        assert_eq!(
            proof_identity_from_proto(Some(proof_identity_to_proto(identity)))?,
            identity
        );
        assert_eq!(
            common_root_identity_from_proto(Some(common_root_identity_to_proto(identity)))?,
            identity
        );
    }
    Ok(())
}

#[test]
fn malformed_and_absent_identities_fail_closed() {
    for value in [Vec::new(), vec![1; 31], vec![1; 33], vec![0; 32]] {
        let manifest = pb::ZkArtifactManifestDigest {
            value: value.clone(),
            __buffa_unknown_fields: Default::default(),
        };
        let artifact_set = pb::ZkArtifactSetIdentity {
            value,
            __buffa_unknown_fields: Default::default(),
        };
        assert_eq!(
            proof_identity_from_proto(Some(manifest.into()))
                .err()
                .map(|error| error.reason()),
            Some(ZkErrorReason::ArtifactMismatch)
        );
        assert_eq!(
            common_root_identity_from_proto(Some(artifact_set.into()))
                .err()
                .map(|error| error.reason()),
            Some(ZkErrorReason::ArtifactMismatch)
        );
    }
    assert_eq!(
        proof_identity_from_proto(None)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
    assert_eq!(
        common_root_identity_from_proto(None)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
}
