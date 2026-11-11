// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable privacy-safe conformance errors.

use reallyme_zk_api::errors::ZkErrorReason;
use thiserror::Error;

/// Exact reason one conformance run failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceErrorReason {
    /// The bundle vector set omitted or reordered a required mutation case.
    IncompleteVectorSet,
    /// The vector set itself failed canonical domain admission.
    InvalidVectorSet(ZkErrorReason),
    /// The release set contained an operation unsupported by this bundle lane.
    UnsupportedOperation,
    /// A case expected a typed failure but the provider reported success.
    UnexpectedSuccess,
    /// A case expected success but the boundary or provider rejected it.
    UnexpectedFailure(ZkErrorReason),
    /// A failure reason differed from the stable vector expectation.
    ErrorMismatch {
        /// Reason required by the canonical vector.
        expected: ZkErrorReason,
        /// Reason returned by the boundary or provider.
        actual: ZkErrorReason,
    },
    /// A successful verification result differed from the canonical result.
    VerificationMismatch,
    /// A bounded conformance count could not be represented.
    LengthOverflow,
}

/// Typed conformance failure without proofs, paths, or backend diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("ReallyMe ZK conformance execution failed")]
pub struct ConformanceError {
    reason: ConformanceErrorReason,
}

impl ConformanceError {
    /// Creates a conformance error from one stable reason.
    #[must_use]
    pub const fn new(reason: ConformanceErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the stable reason.
    #[must_use]
    pub const fn reason(&self) -> ConformanceErrorReason {
        self.reason
    }
}
