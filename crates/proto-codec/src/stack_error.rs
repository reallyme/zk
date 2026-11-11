// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `IdentityStackError` adapters for ZK-owned reason codes.
//!
//! This optional integration stays in the private codec crate so the public ZK
//! contracts do not acquire an SSI dependency. The adapter consumes the exact
//! published `reallyme-ssi-proto` contract instead of a sibling checkout.

use buffa::EnumValue;
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;
use zeroize::Zeroize;

use crate::error::error_reason_from_proto;

/// The shared stack domain assigned to this repository's ZK error enum.
pub const ZK_STACK_ERROR_DOMAIN: IdentityStackErrorDomain =
    IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_ZK;

/// Maximum ASCII correlation-token length admitted to a shared stack error.
pub const MAX_ZK_CORRELATION_ID_BYTES: usize = 64;

/// Stable reason a correlation token was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkCorrelationIdErrorReason {
    /// The token was empty, oversized, or contained a non-token character.
    InvalidToken,
}

/// Typed, privacy-safe correlation-token admission failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid ZK correlation identifier")]
pub struct ZkCorrelationIdError {
    reason: ZkCorrelationIdErrorReason,
}

impl ZkCorrelationIdError {
    /// Returns the stable failure reason without exposing rejected input.
    #[must_use]
    pub const fn reason(self) -> ZkCorrelationIdErrorReason {
        self.reason
    }
}

/// Bounded non-PII ASCII token for cross-stack diagnostic correlation.
///
/// The accepted alphabet deliberately excludes whitespace, path separators,
/// control characters, and free-form text. Callers must generate an opaque
/// identifier rather than placing user or credential data in this field.
pub struct ZkCorrelationId(String);

impl ZkCorrelationId {
    /// Validates and copies an opaque correlation token.
    pub fn try_from_token(value: &str) -> Result<Self, ZkCorrelationIdError> {
        if value.is_empty()
            || value.len() > MAX_ZK_CORRELATION_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(ZkCorrelationIdError {
                reason: ZkCorrelationIdErrorReason::InvalidToken,
            });
        }
        Ok(Self(value.to_owned()))
    }

    fn into_string(mut self) -> String {
        core::mem::take(&mut self.0)
    }
}

impl Drop for ZkCorrelationId {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Converts a ZK error into the shared stack envelope.
///
/// The envelope preserves only the ZK domain and stable reason code. It must
/// not contain proof bytes, public inputs, backend text, or user context.
#[must_use]
pub fn zk_stack_error(error: ZkError) -> IdentityStackError {
    zk_stack_error_from_reason_without_correlation(error.reason())
}

/// Converts a ZK error into the stack envelope with a caller-supplied,
/// non-PII correlation identifier.
#[must_use]
pub fn zk_stack_error_with_correlation_id(
    error: ZkError,
    correlation_id: ZkCorrelationId,
) -> IdentityStackError {
    zk_stack_error_from_reason_with_correlation_id(error.reason(), correlation_id)
}

/// Converts a known ZK reason into the shared stack envelope.
#[must_use]
pub fn zk_stack_error_from_reason(reason: ZkErrorReason) -> IdentityStackError {
    zk_stack_error_from_reason_without_correlation(reason)
}

/// Converts a known ZK reason into the stack envelope with a caller-supplied,
/// non-PII correlation identifier.
#[must_use]
pub fn zk_stack_error_from_reason_with_correlation_id(
    reason: ZkErrorReason,
    correlation_id: ZkCorrelationId,
) -> IdentityStackError {
    stack_error_from_reason(reason, correlation_id.into_string())
}

fn zk_stack_error_from_reason_without_correlation(reason: ZkErrorReason) -> IdentityStackError {
    stack_error_from_reason(reason, String::new())
}

fn stack_error_from_reason(reason: ZkErrorReason, correlation_id: String) -> IdentityStackError {
    IdentityStackError {
        domain: EnumValue::from(ZK_STACK_ERROR_DOMAIN),
        reason_code: reason.reason_code(),
        correlation_id,
        ..IdentityStackError::default()
    }
}

/// Converts a generated ZK proto reason into the shared stack envelope.
///
/// Unknown or unspecified open-enum values fail closed before an envelope is
/// produced, rather than being represented as supported ZK semantics.
pub fn zk_stack_error_from_proto_reason(
    reason: EnumValue<pb::ZkErrorReason>,
) -> Result<IdentityStackError, ZkError> {
    let reason = error_reason_from_proto(reason)?;
    Ok(zk_stack_error_from_reason_without_correlation(reason))
}

/// Converts a generated ZK proto reason into the stack envelope with a
/// caller-supplied, non-PII correlation identifier.
pub fn zk_stack_error_from_proto_reason_with_correlation_id(
    reason: EnumValue<pb::ZkErrorReason>,
    correlation_id: ZkCorrelationId,
) -> Result<IdentityStackError, ZkError> {
    let reason = error_reason_from_proto(reason)?;
    Ok(zk_stack_error_from_reason_with_correlation_id(
        reason,
        correlation_id,
    ))
}
