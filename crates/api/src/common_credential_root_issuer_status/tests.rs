// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    common_credential_root_issuer_status_opening, common_credential_root_issuer_status_root,
    verify_common_credential_root_issuer_status_opening, ZkCommonCredentialRootIssuerStatusReason,
};

#[test]
fn one_chunk_opening_checks_the_exact_private_status_bit() {
    let list = [0b0000_0010_u8];
    let root = common_credential_root_issuer_status_root(&list, 8).ok();
    let opening = common_credential_root_issuer_status_opening(&list, 8, 0).ok();
    assert!(root.is_some());
    assert!(opening
        .as_ref()
        .is_some_and(|(actual, _)| Some(*actual) == root));
    if let Some((actual, opening)) = opening {
        assert!(
            verify_common_credential_root_issuer_status_opening(&actual, 8, 0, &opening).is_ok()
        );
        assert_eq!(
            verify_common_credential_root_issuer_status_opening(&actual, 8, 1, &opening)
                .err()
                .map(|error| error.reason()),
            Some(ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring)
        );
    }
    assert_eq!(
        common_credential_root_issuer_status_opening(&list, 8, 1)
            .err()
            .map(|error| error.reason()),
        Some(ZkCommonCredentialRootIssuerStatusReason::Inactive)
    );
}

#[test]
fn multi_chunk_path_rejects_wrong_root_length_and_status_index() {
    let mut list = [0_u8; 96];
    list[32] = 0b0000_0001;
    let opened = common_credential_root_issuer_status_opening(&list, 768, 512);
    assert!(opened.is_ok());
    if let Ok((root, opening)) = opened {
        assert_eq!(opening.siblings().len(), 2);
        assert!(
            verify_common_credential_root_issuer_status_opening(&root, 768, 512, &opening).is_ok()
        );
        let mut wrong = root;
        wrong[0] ^= 1;
        assert_eq!(
            verify_common_credential_root_issuer_status_opening(&wrong, 768, 512, &opening)
                .err()
                .map(|error| error.reason()),
            Some(ZkCommonCredentialRootIssuerStatusReason::RootMismatch)
        );
        assert_eq!(
            verify_common_credential_root_issuer_status_opening(&root, 767, 512, &opening)
                .err()
                .map(|error| error.reason()),
            Some(ZkCommonCredentialRootIssuerStatusReason::RootMismatch)
        );
        assert_eq!(
            verify_common_credential_root_issuer_status_opening(&root, 768, 0, &opening)
                .err()
                .map(|error| error.reason()),
            Some(ZkCommonCredentialRootIssuerStatusReason::RootMismatch)
        );
    }
}

#[test]
fn malformed_and_oversized_bitstrings_fail_before_tree_construction() {
    for (encoded, length) in [
        (&[][..], 0_u64),
        (&[][..], 8),
        (&[0_u8, 0][..], 8),
        (&[0b1000_0000][..], 1),
        (&[0_u8][..], 1_000_001),
    ] {
        assert!(common_credential_root_issuer_status_root(encoded, length).is_err());
    }
    assert_eq!(
        common_credential_root_issuer_status_opening(&[0_u8], 8, 8)
            .err()
            .map(|error| error.reason()),
        Some(ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring)
    );
}

#[test]
fn largest_status_list_fits_the_bounded_twelve_level_path() {
    let list = vec![0_u8; 125_000];
    let opened = common_credential_root_issuer_status_opening(&list, 1_000_000, 999_999);
    assert!(opened.is_ok());
    if let Ok((root, opening)) = opened {
        assert_eq!(opening.siblings().len(), 12);
        assert!(verify_common_credential_root_issuer_status_opening(
            &root, 1_000_000, 999_999, &opening
        )
        .is_ok());
    }
}
