// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{pb, success_response, vector_set};
use buffa::Message;
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_proto_codec::verification_vector::decode_verification_vector_set;

#[test]
fn proof_manifest_identity_must_match_the_ordered_artifact_pin() -> Result<(), ZkError> {
    let mut set = vector_set(
        pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE,
        success_response(false),
        false,
    )?;
    let first = set
        .artifact_manifests
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    first.artifact_manifest_sha256.get_or_insert_default().value = vec![99; 32];
    let reason = decode_verification_vector_set(&set.encode_to_vec())
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    Ok(())
}
