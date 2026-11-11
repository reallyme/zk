// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    issuer_status::{
        ZkIssuerStatusAuthority, ZkIssuerStatusFeed, ZkIssuerStatusListPointer,
        ZkIssuerStatusPurpose,
    },
    keys::ZkIssuerPublicKey,
};

use super::SuppliedIssuerStatusAuthority;

const VERIFICATION_TIME_UNIX: u64 = 1_800_000_000;

fn authority() -> SuppliedIssuerStatusAuthority {
    SuppliedIssuerStatusAuthority::new(
        ZkIssuerPublicKey {
            x: [4; 32],
            y: [5; 32],
        },
        ZkIssuerStatusFeed {
            root: [1; 32],
            length: 256,
            list_id: [2; 32],
            url_hash: [3; 32],
            purpose: ZkIssuerStatusPurpose::Revocation,
        },
    )
}

fn pointer(
    list_id: [u8; 32],
    url_hash: [u8; 32],
    purpose: ZkIssuerStatusPurpose,
) -> ZkIssuerStatusListPointer {
    ZkIssuerStatusListPointer {
        list_id,
        url_hash,
        purpose,
    }
}

fn lookup(pointer: &ZkIssuerStatusListPointer) -> Result<ZkIssuerStatusFeed, ZkError> {
    authority().current_feed_for_issuer(
        &ZkIssuerPublicKey {
            x: [4; 32],
            y: [5; 32],
        },
        pointer,
        VERIFICATION_TIME_UNIX,
    )
}

#[test]
fn returns_the_supplied_list_for_its_own_pointer() -> Result<(), ZkError> {
    let feed = lookup(&pointer(
        [2; 32],
        [3; 32],
        ZkIssuerStatusPurpose::Revocation,
    ))?;
    assert_eq!(feed.root, [1; 32]);
    assert_eq!(feed.length, 256);
    assert_eq!(feed.purpose, ZkIssuerStatusPurpose::Revocation);
    Ok(())
}

#[test]
fn refuses_to_answer_for_another_list_url_or_purpose() {
    for other in [
        pointer([9; 32], [3; 32], ZkIssuerStatusPurpose::Revocation),
        pointer([2; 32], [9; 32], ZkIssuerStatusPurpose::Revocation),
        pointer([2; 32], [3; 32], ZkIssuerStatusPurpose::Suspension),
    ] {
        assert_eq!(
            lookup(&other).err().map(|error| error.reason()),
            Some(ZkErrorReason::BindingMismatch)
        );
    }
}

#[test]
fn refuses_another_issuer_even_with_the_same_status_pointer() {
    let authority = authority();
    let same_pointer = pointer([2; 32], [3; 32], ZkIssuerStatusPurpose::Revocation);
    for issuer in [
        ZkIssuerPublicKey {
            x: [9; 32],
            y: [5; 32],
        },
        ZkIssuerPublicKey {
            x: [4; 32],
            y: [9; 32],
        },
    ] {
        assert_eq!(
            authority
                .current_feed_for_issuer(&issuer, &same_pointer, VERIFICATION_TIME_UNIX)
                .err()
                .map(|error| error.reason()),
            Some(ZkErrorReason::BindingMismatch),
        );
    }
}
