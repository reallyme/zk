// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, Message};
use reallyme_zk_api::common_root::COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;

use super::{
    decode_root_active_set_path_assignment, encode_root_active_set_path_assignment,
    ZkRootActiveSetPathAssignmentReason, ZkRootActiveSetPathAssignmentRef,
};

const FEED: [u8; 32] = [0x5a; 32];
const ROOT: [u8; 32] = [0x61; 32];
const ID: [u8; 32] = [0x72; 32];
const PATH: [[u8; 32]; 2] = [[0x11; 32], [0x22; 32]];

#[derive(Debug, Error)]
#[error("active-set path assignment test fixture failed")]
struct TestError;

#[test]
fn canonical_path_assignment_round_trips() -> Result<(), TestError> {
    let encoded = encode_root_active_set_path_assignment(ZkRootActiveSetPathAssignmentRef {
        feed_id: FEED,
        active_status_root: ROOT,
        sequence: 7,
        attestation_id: &ID,
        status_index: 3,
        status_path: &PATH,
    })
    .map_err(|_| TestError)?;
    let decoded = decode_root_active_set_path_assignment(&encoded).map_err(|_| TestError)?;

    assert_eq!(decoded.feed_id(), FEED);
    assert_eq!(decoded.active_status_root(), ROOT);
    assert_eq!(decoded.sequence(), 7);
    assert_eq!(decoded.attestation_id(), &ID);
    assert_eq!(decoded.status_index(), 3);
    assert_eq!(decoded.status_path(), PATH);
    Ok(())
}

#[test]
fn path_assignment_rejects_malformed_or_noncanonical_material() -> Result<(), TestError> {
    assert_eq!(
        encode_root_active_set_path_assignment(ZkRootActiveSetPathAssignmentRef {
            feed_id: [0_u8; 32],
            active_status_root: ROOT,
            sequence: 7,
            attestation_id: &ID,
            status_index: 3,
            status_path: &PATH,
        })
        .err()
        .map(|error| error.reason()),
        Some(ZkRootActiveSetPathAssignmentReason::InvalidEncoding)
    );

    let encoded = encode_root_active_set_path_assignment(ZkRootActiveSetPathAssignmentRef {
        feed_id: FEED,
        active_status_root: ROOT,
        sequence: 7,
        attestation_id: &ID,
        status_index: 3,
        status_path: &PATH,
    })
    .map_err(|_| TestError)?;
    let mut wire = DecodeOptions::new()
        .decode_from_slice::<pb::ZkRootActiveSetPathAssignment>(&encoded)
        .map_err(|_| TestError)?;
    let status_path = wire.status_path.as_option_mut().ok_or(TestError)?;
    status_path.path_length = 1;
    assert_eq!(
        decode_root_active_set_path_assignment(&wire.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkRootActiveSetPathAssignmentReason::InvalidEncoding)
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_root_active_set_path_assignment(&trailing).is_err());
    Ok(())
}

#[test]
fn full_depth_path_assignment_round_trips() -> Result<(), TestError> {
    let path = [[0x33_u8; 32]; COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH];
    let encoded = encode_root_active_set_path_assignment(ZkRootActiveSetPathAssignmentRef {
        feed_id: FEED,
        active_status_root: ROOT,
        sequence: 7,
        attestation_id: &ID,
        status_index: 3,
        status_path: &path,
    })
    .map_err(|_| TestError)?;
    let decoded = decode_root_active_set_path_assignment(&encoded).map_err(|_| TestError)?;

    assert_eq!(decoded.status_path(), path);
    Ok(())
}

#[test]
fn path_assignment_rejects_path_beyond_status_depth() -> Result<(), TestError> {
    let encoded = encode_root_active_set_path_assignment(ZkRootActiveSetPathAssignmentRef {
        feed_id: FEED,
        active_status_root: ROOT,
        sequence: 7,
        attestation_id: &ID,
        status_index: 3,
        status_path: &PATH,
    })
    .map_err(|_| TestError)?;
    let mut wire = DecodeOptions::new()
        .decode_from_slice::<pb::ZkRootActiveSetPathAssignment>(&encoded)
        .map_err(|_| TestError)?;
    let status_path = wire.status_path.as_option_mut().ok_or(TestError)?;
    let surplus_length = COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH
        .checked_add(1)
        .ok_or(TestError)?;
    status_path.siblings.clear();
    for _ in 0..surplus_length {
        let mut sibling = pb::ZkInputBytes32::default();
        sibling.value = vec![0x44_u8; 32];
        status_path.siblings.push(sibling);
    }
    status_path.path_length = u32::try_from(surplus_length).map_err(|_| TestError)?;

    assert_eq!(
        decode_root_active_set_path_assignment(&wire.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkRootActiveSetPathAssignmentReason::InvalidEncoding)
    );
    Ok(())
}
