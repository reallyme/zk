// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admission bounds and canonical-encoding checks, independent of any key.

use buffa::{Message, MessageField};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;

use super::{
    admit_root_active_set_publication, ZkRootActiveSetPublicationReason, FORMAT_VERSION, ID_BYTES,
    MAX_IDS, MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES,
};
use crate::common_credential_root_status_snapshot::MAX_ROOT_STATUS_SNAPSHOT_BYTES;

const SNAPSHOT_FORMAT_VERSION: u32 = 1;
const ISSUED_UNIX: u64 = 1_800_000_000;
const EXPIRES_UNIX: u64 = ISSUED_UNIX + 60;
const SEQUENCE: u64 = 7;
const DUPLICATE_FORMAT_VERSION_FIELD: [u8; 2] = [0x08, 0x01];
const UNKNOWN_VARINT_FIELD: [u8; 3] = [0xa0, 0x06, 0x01];

#[derive(Debug, Error)]
#[error("active-set admission test fixture failed")]
struct TestError;

/// Well-formed snapshot whose signature is never checked by admission.
fn snapshot() -> pb::ZkRootStatusSnapshot {
    let mut signature = vec![0_u8; 64];
    signature[31] = 1;
    signature[63] = 1;
    let mut wire = pb::ZkRootStatusSnapshot::default();
    wire.format_version = SNAPSHOT_FORMAT_VERSION;
    wire.status_root = vec![9; 32];
    wire.issued_unix = ISSUED_UNIX;
    wire.expires_unix = EXPIRES_UNIX;
    wire.sequence = SEQUENCE;
    wire.signer = MessageField::some(pb::ZkP256PublicKey {
        x: vec![2; 32],
        y: vec![3; 32],
        ..Default::default()
    });
    wire.signature = signature;
    wire
}

fn packed_publication(packed_ids: Vec<u8>) -> pb::ZkRootActiveSetPublication {
    let mut wire = pb::ZkRootActiveSetPublication::default();
    wire.format_version = FORMAT_VERSION;
    wire.sorted_attestation_ids = packed_ids;
    wire.snapshot = MessageField::some(snapshot());
    wire
}

fn publication(ids: &[[u8; ID_BYTES]]) -> pb::ZkRootActiveSetPublication {
    packed_publication(ids.concat())
}

fn admission_reason(bytes: &[u8]) -> Option<ZkRootActiveSetPublicationReason> {
    admit_root_active_set_publication(bytes)
        .err()
        .map(|error| error.reason())
}

#[test]
fn admission_exposes_only_unauthenticated_inputs() -> Result<(), TestError> {
    let ids = [[1_u8; ID_BYTES], [2_u8; ID_BYTES]];
    let admitted = admit_root_active_set_publication(&publication(&ids).encode_to_vec())
        .map_err(|_| TestError)?;
    let snapshot = admitted.unauthenticated_snapshot();

    assert_eq!(admitted.identifier_count(), ids.len());
    assert_eq!(snapshot.status_root(), [9; 32]);
    assert_eq!(snapshot.issued_unix(), ISSUED_UNIX);
    assert_eq!(snapshot.expires_unix(), EXPIRES_UNIX);
    assert_eq!(snapshot.sequence(), SEQUENCE);
    assert_eq!(snapshot.signer().x, [2; 32]);
    assert_eq!(snapshot.signer().y, [3; 32]);
    Ok(())
}

#[test]
fn admission_rejects_empty_and_oversized_input() {
    assert_eq!(
        admission_reason(&[]),
        Some(ZkRootActiveSetPublicationReason::Capacity)
    );
    let oversized = vec![0_u8; MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES + 1];
    assert_eq!(
        admission_reason(&oversized),
        Some(ZkRootActiveSetPublicationReason::Capacity)
    );
}

#[test]
fn admission_rejects_more_identifiers_than_the_tree_holds() -> Result<(), TestError> {
    // One identifier over capacity still fits inside the byte bound, so the
    // count needs its own check.
    let count = MAX_IDS.checked_add(1).ok_or(TestError)?;
    let mut packed = Vec::new();
    packed
        .try_reserve_exact(count.checked_mul(ID_BYTES).ok_or(TestError)?)
        .map_err(|_| TestError)?;
    for index in 1..=count {
        let mut id = [0_u8; ID_BYTES];
        let index = u64::try_from(index).map_err(|_| TestError)?;
        id[ID_BYTES - 8..].copy_from_slice(&index.to_be_bytes());
        packed.extend_from_slice(&id);
    }
    let encoded = packed_publication(packed).encode_to_vec();
    assert!(encoded.len() <= MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES);
    assert_eq!(
        admission_reason(&encoded),
        Some(ZkRootActiveSetPublicationReason::Capacity)
    );
    Ok(())
}

#[test]
fn admission_rejects_noncanonical_encoding() {
    let canonical = publication(&[[1_u8; ID_BYTES]]).encode_to_vec();

    let mut duplicate_field = canonical.clone();
    duplicate_field.extend_from_slice(&DUPLICATE_FORMAT_VERSION_FIELD);
    assert_eq!(
        admission_reason(&duplicate_field),
        Some(ZkRootActiveSetPublicationReason::InvalidEncoding)
    );

    let mut unknown_field = canonical.clone();
    unknown_field.extend_from_slice(&UNKNOWN_VARINT_FIELD);
    assert_eq!(
        admission_reason(&unknown_field),
        Some(ZkRootActiveSetPublicationReason::InvalidEncoding)
    );

    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        admission_reason(&trailing),
        Some(ZkRootActiveSetPublicationReason::InvalidEncoding)
    );

    let mut wrong_version = publication(&[[1_u8; ID_BYTES]]);
    wrong_version.format_version = FORMAT_VERSION + 1;
    assert_eq!(
        admission_reason(&wrong_version.encode_to_vec()),
        Some(ZkRootActiveSetPublicationReason::InvalidEncoding)
    );
}

#[test]
fn admission_rejects_noncanonical_identifier_lists() {
    for ids in [
        vec![[2_u8; ID_BYTES], [1_u8; ID_BYTES]],
        vec![[1_u8; ID_BYTES], [1_u8; ID_BYTES]],
        vec![[0_u8; ID_BYTES], [1_u8; ID_BYTES]],
    ] {
        assert_eq!(
            admission_reason(&publication(&ids).encode_to_vec()),
            Some(ZkRootActiveSetPublicationReason::InvalidEncoding)
        );
    }
    let mut ragged = publication(&[[1_u8; ID_BYTES]]);
    ragged.sorted_attestation_ids.pop();
    assert_eq!(
        admission_reason(&ragged.encode_to_vec()),
        Some(ZkRootActiveSetPublicationReason::InvalidEncoding)
    );
}

#[test]
fn admission_rejects_missing_or_oversized_snapshot() {
    let mut missing = publication(&[[1_u8; ID_BYTES]]);
    missing.snapshot = MessageField::none();
    assert_eq!(
        admission_reason(&missing.encode_to_vec()),
        Some(ZkRootActiveSetPublicationReason::InvalidEncoding)
    );

    let mut oversized = publication(&[[1_u8; ID_BYTES]]);
    if let Some(snapshot) = oversized.snapshot.as_option_mut() {
        snapshot.status_root = vec![9; MAX_ROOT_STATUS_SNAPSHOT_BYTES];
    }
    assert_eq!(
        admission_reason(&oversized.encode_to_vec()),
        Some(ZkRootActiveSetPublicationReason::InvalidEncoding)
    );
}
