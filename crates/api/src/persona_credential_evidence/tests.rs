// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceValidityWindow,
    ZkPersonaCredentialEvidenceValidityWindowError,
    ZkPersonaCredentialEvidenceValidityWindowReason,
};

#[test]
fn evidence_mode_identifiers_round_trip_and_reject_aliases() {
    for mode in [
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
    ] {
        assert_eq!(
            ZkPersonaCredentialEvidenceMode::from_identifier(mode.as_str()),
            Some(mode)
        );
    }
    for alias in [
        "prepared_public_persona",
        "prepared_private_persona_one_time",
        "PREPARED_PUBLIC_PERSONA_V1",
        "",
    ] {
        assert_eq!(
            ZkPersonaCredentialEvidenceMode::from_identifier(alias),
            None
        );
    }
}

#[test]
fn prepared_window_is_separate_from_signed_issuer_validity(
) -> Result<(), ZkPersonaCredentialEvidenceValidityWindowError> {
    let window = ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 200)?;
    assert_eq!(window.valid_from_unix(), 100);
    assert_eq!(window.valid_until_unix(), 200);
    assert!(window.validate_issuer_bounds(50, 250).is_ok());
    // A contained interval may share either endpoint with the issuer interval.
    assert!(window.validate_issuer_bounds(100, 200).is_ok());
    assert!(window.validate_issuer_bounds(50, 200).is_ok());
    assert!(window.validate_at(100).is_ok());
    assert!(window.validate_at(199).is_ok());
    for request_time in [0, 99, 200, 201, u64::MAX] {
        assert_eq!(
            window
                .validate_at(request_time)
                .err()
                .map(|error| error.reason()),
            Some(ZkPersonaCredentialEvidenceValidityWindowReason::NotCurrent)
        );
    }
    assert_eq!(
        window
            .validate_issuer_bounds(101, 250)
            .err()
            .map(|error| error.reason()),
        Some(ZkPersonaCredentialEvidenceValidityWindowReason::OutsideIssuerValidity)
    );
    assert_eq!(
        window
            .validate_issuer_bounds(50, 199)
            .err()
            .map(|error| error.reason()),
        Some(ZkPersonaCredentialEvidenceValidityWindowReason::OutsideIssuerValidity)
    );
    Ok(())
}

#[test]
fn empty_and_reversed_intervals_fail_closed(
) -> Result<(), ZkPersonaCredentialEvidenceValidityWindowError> {
    for (from, until) in [(100, 100), (101, 100)] {
        assert_eq!(
            ZkPersonaCredentialEvidenceValidityWindow::try_new(from, until)
                .err()
                .map(|error| error.reason()),
            Some(ZkPersonaCredentialEvidenceValidityWindowReason::InvalidInterval)
        );
    }
    let window = ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 200)?;
    assert_eq!(
        window
            .validate_issuer_bounds(200, 200)
            .err()
            .map(|error| error.reason()),
        Some(ZkPersonaCredentialEvidenceValidityWindowReason::InvalidInterval)
    );
    Ok(())
}
