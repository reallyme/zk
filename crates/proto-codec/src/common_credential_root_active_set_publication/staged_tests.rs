// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authentication must precede materialisation of the active set.
//!
//! `Unauthenticated` is produced only by the signature step, which runs
//! before any Merkle node is hashed, and `RootMismatch` only by the root
//! comparison that follows it. Each case below therefore identifies the stage
//! that rejected the publication by its stable reason.

use buffa::{DecodeOptions, Message};
use reallyme_zk_api::common_root::{
    ZkCommonCredentialRootActiveSet, ZkRootStatusVerificationReason,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use super::{
    admit_root_active_set_publication, encode_root_active_set_publication, signed_snapshot, signer,
    status_trust, TestError, ZkRootActiveSetPublicationReason, NOW, SNAPSHOT_SEQUENCE,
};

const IDS: [[u8; 32]; 3] = [[1; 32], [2; 32], [3; 32]];
const OTHER_SIGNER_SEED: u8 = 53;
const SIGNED_EXPIRY: u64 = NOW + 60;

struct Fixture {
    wire: pb::ZkRootActiveSetPublication,
    signer: reallyme_zk_api::keys::ZkIssuerPublicKey,
}

fn fixture() -> Result<Fixture, TestError> {
    let set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&IDS).map_err(|_| TestError)?;
    let (snapshot, signer) = signed_snapshot(set.root())?;
    let encoded = encode_root_active_set_publication(&set, &snapshot).map_err(|_| TestError)?;
    let wire = DecodeOptions::new()
        .decode_from_slice::<pb::ZkRootActiveSetPublication>(&encoded)
        .map_err(|_| TestError)?;
    Ok(Fixture { wire, signer })
}

fn authentication_reason(
    wire: &pb::ZkRootActiveSetPublication,
    trust_signer: reallyme_zk_api::keys::ZkIssuerPublicKey,
    now_unix: u64,
) -> Result<Option<ZkRootActiveSetPublicationReason>, TestError> {
    // Every tampered case must still pass admission: the rejection under test
    // belongs to the authentication stage, not to canonical decoding.
    let admitted =
        admit_root_active_set_publication(&wire.encode_to_vec()).map_err(|_| TestError)?;
    Ok(admitted
        .authenticate(status_trust(trust_signer, SNAPSHOT_SEQUENCE), now_unix)
        .err()
        .map(|error| error.reason()))
}

const fn unauthenticated(
    reason: ZkRootStatusVerificationReason,
) -> Option<ZkRootActiveSetPublicationReason> {
    Some(ZkRootActiveSetPublicationReason::Unauthenticated(reason))
}

#[test]
fn valid_publication_authenticates_then_materialises() -> Result<(), TestError> {
    let fixture = fixture()?;
    let admitted =
        admit_root_active_set_publication(&fixture.wire.encode_to_vec()).map_err(|_| TestError)?;
    assert_eq!(admitted.identifier_count(), IDS.len());
    let unauthenticated_snapshot = admitted.unauthenticated_snapshot();
    assert_eq!(unauthenticated_snapshot.sequence(), SNAPSHOT_SEQUENCE);

    let authenticated = admitted
        .authenticate(status_trust(fixture.signer, SNAPSHOT_SEQUENCE), NOW)
        .map_err(|_| TestError)?;
    assert_eq!(authenticated.active_set().sorted_ids(), &IDS);
    assert_eq!(
        authenticated.active_set().root(),
        authenticated.verified_snapshot().root()
    );
    assert_eq!(
        authenticated.verified_snapshot().signing_digest(),
        unauthenticated_snapshot.signing_digest()
    );
    assert!(authenticated.snapshot() == unauthenticated_snapshot);
    assert!(authenticated
        .active_set()
        .open_against(authenticated.verified_snapshot(), NOW, &IDS[2])
        .is_ok());
    Ok(())
}

#[test]
fn wrong_pinned_key_is_rejected_before_materialisation() -> Result<(), TestError> {
    let fixture = fixture()?;
    let (_, other) = signer(OTHER_SIGNER_SEED)?;
    assert_eq!(
        authentication_reason(&fixture.wire, other, NOW)?,
        unauthenticated(ZkRootStatusVerificationReason::AuthorityPolicy)
    );
    Ok(())
}

#[test]
fn relabelled_signer_is_rejected_before_materialisation() -> Result<(), TestError> {
    let mut fixture = fixture()?;
    let (_, other) = signer(OTHER_SIGNER_SEED)?;
    // Claim the pinned key while keeping a signature made by a different key.
    let claimed = fixture
        .wire
        .snapshot
        .as_option_mut()
        .and_then(|snapshot| snapshot.signer.as_option_mut())
        .ok_or(TestError)?;
    claimed.x = other.x.to_vec();
    claimed.y = other.y.to_vec();
    assert_eq!(
        authentication_reason(&fixture.wire, other, NOW)?,
        unauthenticated(ZkRootStatusVerificationReason::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn tampered_root_is_rejected_before_materialisation() -> Result<(), TestError> {
    let mut fixture = fixture()?;
    let snapshot = fixture.wire.snapshot.as_option_mut().ok_or(TestError)?;
    snapshot.status_root[0] ^= 1;
    assert_eq!(
        authentication_reason(&fixture.wire, fixture.signer, NOW)?,
        unauthenticated(ZkRootStatusVerificationReason::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn tampered_signature_is_rejected_before_materialisation() -> Result<(), TestError> {
    let mut fixture = fixture()?;
    let snapshot = fixture.wire.snapshot.as_option_mut().ok_or(TestError)?;
    snapshot.signature[0] ^= 1;
    assert_eq!(
        authentication_reason(&fixture.wire, fixture.signer, NOW)?,
        unauthenticated(ZkRootStatusVerificationReason::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn tampered_signed_interval_or_sequence_is_rejected_before_materialisation() -> Result<(), TestError>
{
    let mut fixture = fixture()?;
    let snapshot = fixture.wire.snapshot.as_option_mut().ok_or(TestError)?;
    snapshot.expires_unix = snapshot.expires_unix.checked_add(1).ok_or(TestError)?;
    assert_eq!(
        authentication_reason(&fixture.wire, fixture.signer, NOW)?,
        unauthenticated(ZkRootStatusVerificationReason::SignatureInvalid)
    );
    let mut fixture = self::fixture()?;
    let snapshot = fixture.wire.snapshot.as_option_mut().ok_or(TestError)?;
    snapshot.sequence = snapshot.sequence.checked_add(1).ok_or(TestError)?;
    assert_eq!(
        authentication_reason(&fixture.wire, fixture.signer, NOW)?,
        unauthenticated(ZkRootStatusVerificationReason::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn stale_snapshot_is_rejected_before_materialisation() -> Result<(), TestError> {
    let fixture = fixture()?;
    assert_eq!(
        authentication_reason(&fixture.wire, fixture.signer, SIGNED_EXPIRY)?,
        unauthenticated(ZkRootStatusVerificationReason::Stale)
    );
    Ok(())
}

#[test]
fn tampered_id_list_is_rejected_by_the_signed_root() -> Result<(), TestError> {
    let mut fixture = fixture()?;
    // Keep the list canonical so only the signed root can expose the change.
    fixture.wire.sorted_attestation_ids[2 * 32] = 4;
    assert_eq!(
        authentication_reason(&fixture.wire, fixture.signer, NOW)?,
        Some(ZkRootActiveSetPublicationReason::RootMismatch)
    );
    fixture.wire.sorted_attestation_ids.truncate(2 * 32);
    assert_eq!(
        authentication_reason(&fixture.wire, fixture.signer, NOW)?,
        Some(ZkRootActiveSetPublicationReason::RootMismatch)
    );
    Ok(())
}

#[test]
fn tampered_id_list_without_a_valid_signature_never_reaches_the_tree() -> Result<(), TestError> {
    let mut fixture = fixture()?;
    fixture.wire.sorted_attestation_ids[2 * 32] = 4;
    let snapshot = fixture.wire.snapshot.as_option_mut().ok_or(TestError)?;
    snapshot.signature[0] ^= 1;
    // Both faults are present. The signature reason proves the list was not
    // hashed: a root comparison would have reported `RootMismatch`.
    assert_eq!(
        authentication_reason(&fixture.wire, fixture.signer, NOW)?,
        unauthenticated(ZkRootStatusVerificationReason::SignatureInvalid)
    );
    let (_, other) = signer(OTHER_SIGNER_SEED)?;
    assert_eq!(
        authentication_reason(&fixture.wire, other, NOW)?,
        unauthenticated(ZkRootStatusVerificationReason::AuthorityPolicy)
    );
    Ok(())
}
