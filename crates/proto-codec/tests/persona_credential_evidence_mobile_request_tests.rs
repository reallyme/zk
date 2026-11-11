// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The example apps ship only canonical, synthetic proving requests.

use std::{fs, path::PathBuf};

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto_codec::exchange::{decode_operation_request_kind, ZkProviderOperationKind};

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in Digest32::sha256(bytes).as_bytes() {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

#[test]
fn every_prepared_mobile_sample_is_pinned_and_admitted() -> Result<(), ZkError> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("vectors/persona-credential-evidence-mobile-requests-v1");
    let manifest = fs::read_to_string(root.join("sha256.tsv"))
        .map_err(|_| ZkError::new(ZkErrorReason::EmptyInput))?;
    let mut rows = manifest.lines();
    if rows.next() != Some("filename\tsha256") {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    let mut count = 0_usize;
    for line in rows {
        let (name, digest) = line
            .split_once('\t')
            .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
        if !name.ends_with(".pb") || name.contains('/') || name.contains("..") {
            return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
        }
        let bytes =
            fs::read(root.join(name)).map_err(|_| ZkError::new(ZkErrorReason::EmptyInput))?;
        if digest_hex(&bytes) != digest {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        assert_eq!(
            decode_operation_request_kind(&bytes)?,
            ZkProviderOperationKind::ProvePersonaCredentialEvidenceStage
        );
        count += 1;
    }
    // Two persona modes, two hash lanes, and five stage requests per mode.
    assert_eq!(count, 20);
    Ok(())
}
