// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical, unsigned authority intent persisted before anchor advancement.

use buffa::{DecodeOptions, Message};
use reallyme_zk_api::common_root::{
    ZkCommonCredentialRootActiveSet, ZkRootStatusSnapshot, COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::common_credential_root_active_set_publication::MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES;
use zeroize::Zeroizing;

use crate::{
    anchor::{RootStatusAnchorValue, RootStatusFeedId},
    publisher::{error, RootStatusPublisherError, RootStatusPublisherReason, MAX_VALIDITY_SECONDS},
};

const FORMAT_VERSION: u32 = 1;
const ID_BYTES: usize = 32;
const MAX_IDS: usize = 1_usize << COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH;
const RECURSION_LIMIT: u32 = 8;

pub(crate) struct RootStatusIntent {
    active_set: ZkCommonCredentialRootActiveSet,
    issued_unix: u64,
    expires_unix: u64,
    sequence: u64,
    feed_id: RootStatusFeedId,
}

impl RootStatusIntent {
    pub(crate) fn new(
        active_set: ZkCommonCredentialRootActiveSet,
        issued_unix: u64,
        expires_unix: u64,
        sequence: u64,
        feed_id: RootStatusFeedId,
    ) -> Result<Self, RootStatusPublisherError> {
        let validity = expires_unix
            .checked_sub(issued_unix)
            .ok_or_else(|| error(RootStatusPublisherReason::InvalidState))?;
        if issued_unix == 0 || sequence == 0 || validity == 0 || validity > MAX_VALIDITY_SECONDS {
            return Err(error(RootStatusPublisherReason::InvalidState));
        }
        Ok(Self {
            active_set,
            issued_unix,
            expires_unix,
            sequence,
            feed_id,
        })
    }

    pub(crate) fn active_set(&self) -> &ZkCommonCredentialRootActiveSet {
        &self.active_set
    }

    pub(crate) const fn issued_unix(&self) -> u64 {
        self.issued_unix
    }

    pub(crate) const fn expires_unix(&self) -> u64 {
        self.expires_unix
    }

    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn anchor_value(&self) -> Result<RootStatusAnchorValue, RootStatusPublisherError> {
        RootStatusAnchorValue::try_from_parts(
            self.sequence,
            ZkRootStatusSnapshot::signing_digest_for_fields(
                self.active_set.root(),
                self.issued_unix,
                self.expires_unix,
                self.sequence,
            ),
        )
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RootStatusPublisherError> {
        let packed_len = self
            .active_set
            .len()
            .checked_mul(ID_BYTES)
            .ok_or_else(|| error(RootStatusPublisherReason::Range))?;
        let mut packed = Zeroizing::new(Vec::new());
        packed
            .try_reserve_exact(packed_len)
            .map_err(|_| error(RootStatusPublisherReason::Storage))?;
        for id in self.active_set.sorted_ids() {
            packed.extend_from_slice(id);
        }
        // The hardened generated Buffa owner zeroizes the two byte fields.
        let mut wire = pb::ZkRootStatusPublicationIntent::default();
        wire.format_version = FORMAT_VERSION;
        wire.sorted_attestation_ids = core::mem::take(&mut *packed);
        wire.issued_unix = self.issued_unix;
        wire.expires_unix = self.expires_unix;
        wire.sequence = self.sequence;
        wire.feed_id = self.feed_id.bytes().to_vec();
        let encoded = Zeroizing::new(wire.encode_to_vec());
        if encoded.is_empty() || encoded.len() > MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES {
            return Err(error(RootStatusPublisherReason::Range));
        }
        Ok(encoded)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        expected_feed: RootStatusFeedId,
    ) -> Result<Self, RootStatusPublisherError> {
        if bytes.is_empty() || bytes.len() > MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES {
            return Err(error(RootStatusPublisherReason::InvalidState));
        }
        let wire = DecodeOptions::new()
            .with_recursion_limit(RECURSION_LIMIT)
            .with_element_memory_limit(MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES)
            .with_max_message_size(MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES)
            .with_unknown_field_limit(0)
            .decode_from_slice::<pb::ZkRootStatusPublicationIntent>(bytes)
            .map_err(|_| error(RootStatusPublisherReason::InvalidState))?;
        let canonical = Zeroizing::new(wire.encode_to_vec());
        if wire.format_version != FORMAT_VERSION
            || canonical.as_slice() != bytes
            || wire.feed_id.as_slice() != expected_feed.bytes()
            || wire.sorted_attestation_ids.len() % ID_BYTES != 0
        {
            return Err(error(RootStatusPublisherReason::InvalidState));
        }
        let count = wire.sorted_attestation_ids.len() / ID_BYTES;
        if count > MAX_IDS {
            return Err(error(RootStatusPublisherReason::Range));
        }
        let mut ids = Zeroizing::new(Vec::new());
        ids.try_reserve_exact(count)
            .map_err(|_| error(RootStatusPublisherReason::Storage))?;
        for id in wire.sorted_attestation_ids.as_chunks::<ID_BYTES>().0 {
            ids.push(*id);
        }
        let active_set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&ids)
            .map_err(|_| error(RootStatusPublisherReason::InvalidState))?;
        Self::new(
            active_set,
            wire.issued_unix,
            wire.expires_unix,
            wire.sequence,
            expected_feed,
        )
    }
}
