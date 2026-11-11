// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::Message;
use reallyme_zk_proto_codec::artifact::decode_artifact_manifest;

use super::{manifest, ZkError, ZkErrorReason};

#[test]
fn artifact_manifest_byte_admission_rejects_unknown_fields() -> Result<(), ZkError> {
    let mut bytes = manifest().encode_to_vec();
    // Unknown field 100, wire type 0, value 1. Generated-message conversion
    // is crate-private, so the public canonical decoder is the only route and
    // must reject the field before any manifest identity is derived.
    bytes.extend_from_slice(&[0xa0, 0x06, 0x01]);
    let error = decode_artifact_manifest(&bytes)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::MalformedProtobuf);
    Ok(())
}
