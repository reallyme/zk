// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! External monotonic sequence and signing-digest commitment contract.

use crate::publisher::{error, RootStatusPublisherError, RootStatusPublisherReason};

const FIELD_BYTES: usize = 32;

/// Deployment-assigned identity of exactly one root-status feed.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct RootStatusFeedId([u8; FIELD_BYTES]);

impl RootStatusFeedId {
    /// Admit a nonzero fixed-width feed identity.
    pub fn try_from_bytes(bytes: [u8; FIELD_BYTES]) -> Result<Self, RootStatusPublisherError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(error(RootStatusPublisherReason::InvalidState));
        }
        Ok(Self(bytes))
    }

    /// Exact bytes used to scope the deployment's external anchor record.
    #[must_use]
    pub const fn bytes(self) -> [u8; FIELD_BYTES] {
        self.0
    }
}

/// Durable anchor for one signed status transcript.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RootStatusAnchorValue {
    sequence: u64,
    signing_digest: [u8; FIELD_BYTES],
}

impl RootStatusAnchorValue {
    /// Admit a nonzero sequence and fixed signing digest.
    pub fn try_from_parts(
        sequence: u64,
        signing_digest: [u8; FIELD_BYTES],
    ) -> Result<Self, RootStatusPublisherError> {
        if sequence == 0 || signing_digest.iter().all(|byte| *byte == 0) {
            return Err(error(RootStatusPublisherReason::InvalidState));
        }
        Ok(Self {
            sequence,
            signing_digest,
        })
    }

    /// Monotonic status sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Digest of the exact signed root, interval, and sequence.
    #[must_use]
    pub const fn signing_digest(self) -> [u8; FIELD_BYTES] {
        self.signing_digest
    }
}

/// Independently durable, linearizable per-feed compare-and-advance service.
///
/// An implementation must persist `next` before returning success and must
/// reject a mismatch with `expected` without mutating state. It must not share
/// the publisher's local directory or rollback domain. The publisher commits
/// the anchor before asking its signer to sign. If later steps fail, startup
/// completes only the synced intent whose digest matches the anchor. A missing
/// or altered intent makes the feed unavailable; the anchor must never be
/// rolled back to restore availability.
pub trait RootStatusSequenceAnchor: Send + Sync {
    /// Read the latest durable commitment for exactly this feed.
    fn load(
        &self,
        feed_id: RootStatusFeedId,
    ) -> Result<Option<RootStatusAnchorValue>, RootStatusPublisherError>;

    /// Atomically replace `expected` with the next sequence and digest.
    fn compare_and_advance(
        &self,
        feed_id: RootStatusFeedId,
        expected: Option<RootStatusAnchorValue>,
        next: RootStatusAnchorValue,
    ) -> Result<(), RootStatusPublisherError>;
}
