// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, Message};
use reallyme_zk_api::{
    common_root::ZkRootStatusSnapshot,
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use super::{decode_root_status_snapshot, encode_root_status_snapshot};

fn fixture() -> Result<ZkRootStatusSnapshot, ZkError> {
    ZkRootStatusSnapshot::try_from_parts(
        [1; 32],
        1_700_000_000,
        1_700_000_300,
        42,
        reallyme_zk_api::keys::ZkStatusAuthorityPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(ZkIssuerPublicKey {
                x: [2; 32],
                y: [3; 32],
            }),
        ),
        [1; 64],
    )
    .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

#[test]
fn signed_snapshot_proto_round_trip_preserves_exact_transcript() -> Result<(), ZkError> {
    let source = fixture()?;
    let encoded = encode_root_status_snapshot(&source)?;
    let decoded = decode_root_status_snapshot(&encoded)?;
    assert_eq!(decoded.signing_digest(), source.signing_digest());
    assert_eq!(decoded.signer(), source.signer());
    assert_eq!(decoded.signature(), source.signature());
    assert_eq!(encode_root_status_snapshot(&decoded)?, encoded);
    Ok(())
}

#[test]
fn signed_snapshot_proto_rejects_unknown_version_and_wrong_lengths() -> Result<(), ZkError> {
    let valid = encode_root_status_snapshot(&fixture()?)?;
    assert!(decode_root_status_snapshot(&[]).is_err());
    assert!(decode_root_status_snapshot(&vec![0; 257]).is_err());
    let mut wire = DecodeOptions::new()
        .decode_from_slice::<pb::ZkRootStatusSnapshot>(&valid)
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    wire.format_version = 2;
    assert!(decode_root_status_snapshot(&wire.encode_to_vec()).is_err());
    wire.format_version = 1;
    wire.signature.pop();
    assert!(decode_root_status_snapshot(&wire.encode_to_vec()).is_err());
    Ok(())
}
