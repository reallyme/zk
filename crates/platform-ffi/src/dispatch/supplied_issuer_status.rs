// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuer status authority backed by one verifier-supplied status list.

use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    issuer_status::{ZkIssuerStatusAuthority, ZkIssuerStatusFeed, ZkIssuerStatusListPointer},
    keys::ZkIssuerPublicKey,
};

/// Answers status lookups with the single list carried in the operation.
///
/// The native provider has no network access and no issuer trust store. The
/// verifier application authenticates the issuer status list (signature,
/// issuer, freshness, and rollback floor) and supplies it with the request.
/// This authority only refuses to substitute that list for a different one:
/// a proof from another credential issuer or pointing at another list
/// identifier, URL, or purpose is
/// rejected, so one authenticated list cannot vouch for a credential that the
/// issuer assigned elsewhere.
pub(super) struct SuppliedIssuerStatusAuthority {
    issuer: ZkIssuerPublicKey,
    feed: ZkIssuerStatusFeed,
}

impl SuppliedIssuerStatusAuthority {
    pub(super) const fn new(issuer: ZkIssuerPublicKey, feed: ZkIssuerStatusFeed) -> Self {
        Self { issuer, feed }
    }
}

impl ZkIssuerStatusAuthority for SuppliedIssuerStatusAuthority {
    fn current_feed_for_issuer(
        &self,
        issuer_key: &ZkIssuerPublicKey,
        status_pointer: &ZkIssuerStatusListPointer,
        _verification_time_unix: u64,
    ) -> Result<ZkIssuerStatusFeed, ZkError> {
        if issuer_key != &self.issuer
            || status_pointer.purpose != self.feed.purpose
            || status_pointer.list_id != self.feed.list_id
            || status_pointer.url_hash != self.feed.url_hash
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(ZkIssuerStatusFeed {
            root: self.feed.root,
            length: self.feed.length,
            list_id: self.feed.list_id,
            url_hash: self.feed.url_hash,
            purpose: self.feed.purpose,
        })
    }
}

#[cfg(test)]
mod tests;
