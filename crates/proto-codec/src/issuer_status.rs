// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The schema owns the status-purpose vocabulary; reject its default and open values.

use buffa::EnumValue;
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerStatusPurpose,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

/// Validate a generated status purpose before a native witness conversion.
pub fn purpose_from_proto(
    value: EnumValue<pb::ZkIssuerStatusPurpose>,
) -> Result<ZkIssuerStatusPurpose, ZkError> {
    match value.as_known() {
        Some(pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_REVOCATION) => {
            Ok(ZkIssuerStatusPurpose::Revocation)
        }
        Some(pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_SUSPENSION) => {
            Ok(ZkIssuerStatusPurpose::Suspension)
        }
        _ => Err(ZkError::new(ZkErrorReason::InvalidProofEncoding)),
    }
}

pub(crate) fn purpose_to_proto(
    value: ZkIssuerStatusPurpose,
) -> EnumValue<pb::ZkIssuerStatusPurpose> {
    EnumValue::from(match value {
        ZkIssuerStatusPurpose::Revocation => {
            pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_REVOCATION
        }
        ZkIssuerStatusPurpose::Suspension => {
            pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_SUSPENSION
        }
    })
}
