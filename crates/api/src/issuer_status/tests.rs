// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::ZkIssuerStatusPurpose;
use crate::errors::{ZkError, ZkErrorReason};

#[test]
fn status_purpose_accepts_only_registered_codes() -> Result<(), ZkError> {
    assert_eq!(
        ZkIssuerStatusPurpose::try_from_wire_value(1)?,
        ZkIssuerStatusPurpose::Revocation
    );
    assert_eq!(
        ZkIssuerStatusPurpose::try_from_wire_value(2)?,
        ZkIssuerStatusPurpose::Suspension
    );
    for code in [0, 3, u8::MAX] {
        assert_eq!(
            ZkIssuerStatusPurpose::try_from_wire_value(code)
                .err()
                .map(|error| error.reason()),
            Some(ZkErrorReason::InvalidProofEncoding)
        );
    }
    Ok(())
}
