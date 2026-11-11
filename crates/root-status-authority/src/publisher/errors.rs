// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed, non-sensitive failures for the status publisher.

use thiserror::Error;

/// Stable, non-sensitive root-status publication failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RootStatusPublisherReason {
    /// The store path, permissions, or expected files are invalid.
    #[error("invalid publisher store")]
    InvalidStore,
    /// Another publisher currently owns this feed's exclusive lock.
    #[error("publisher busy")]
    Busy,
    /// The existing publication or new authority input failed authentication.
    #[error("publisher state or input invalid")]
    InvalidState,
    /// The clock moved behind the last signed publication.
    #[error("publisher clock rollback")]
    ClockRollback,
    /// The signed interval ended before publication or retrieval completed.
    #[error("publisher publication expired")]
    PublicationExpired,
    /// The sequence or expiration calculation exceeded its range.
    #[error("publisher range exhausted")]
    Range,
    /// The injected signer failed or produced an invalid signature.
    #[error("publisher signer failure")]
    Signer,
    /// Filesystem durability could not be established.
    #[error("publisher storage failure")]
    Storage,
    /// The external sequence commitment could not be read or advanced.
    #[error("publisher anchor unavailable")]
    AnchorUnavailable,
    /// Local signed state differs from the external sequence commitment.
    #[error("publisher anchor mismatch")]
    AnchorMismatch,
    /// Another writer advanced the external commitment first.
    #[error("publisher anchor conflict")]
    AnchorConflict,
}

/// Typed publisher error that carries no paths, IDs, or key material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("root status publication failed: {reason}")]
pub struct RootStatusPublisherError {
    reason: RootStatusPublisherReason,
}

impl RootStatusPublisherError {
    /// Return the stable failure reason.
    #[must_use]
    pub const fn reason(self) -> RootStatusPublisherReason {
        self.reason
    }
}

pub(crate) const fn error(reason: RootStatusPublisherReason) -> RootStatusPublisherError {
    RootStatusPublisherError { reason }
}
