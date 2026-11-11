// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lock, sign, and durably install one canonical public status publication.

use std::{
    fs::{DirBuilder, File},
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::Path,
    sync::Arc,
};

use reallyme_zk_api::{
    common_root::{
        verify_root_status_snapshot, ZkCommonCredentialRootAttestationTrustPolicy,
        ZkRootAssuranceAttestation, ZkRootStatusSnapshot, ZkRootStatusTrustPolicy,
    },
    keys::ZkStatusAuthorityPublicKey,
};
use reallyme_zk_proto_codec::common_credential_root_active_set_publication::{
    admit_root_active_set_publication, build_root_active_set_from_authority,
    encode_root_active_set_publication, ZkRootActiveSetAuthorityInput,
};
use zeroize::Zeroizing;

use crate::anchor::{RootStatusAnchorValue, RootStatusFeedId, RootStatusSequenceAnchor};
use crate::intent::RootStatusIntent;
use crate::secure_files::{self, FileAccess, StoreFile};

#[path = "publisher/filesystem.rs"]
mod filesystem;
use filesystem::{
    current_unix, open_private_directory, read_publication, sync_parent_directory, PublicationLock,
};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
pub(crate) const MAX_VALIDITY_SECONDS: u64 = 86_400;
const FIRST_SEQUENCE: u64 = 1;

/// A deployment-owned P-256 status signer. The secret key stays in the signer.
pub trait RootStatusSigner {
    /// Public key pinned by consumers of this feed.
    fn public_key(&self) -> ZkStatusAuthorityPublicKey;

    /// Sign the fixed 32-byte root-status digest, without hashing it again.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], RootStatusPublisherError>;
}

#[path = "publisher/errors.rs"]
mod errors;
pub(crate) use errors::error;
pub use errors::{RootStatusPublisherError, RootStatusPublisherReason};

/// Single-feed local-disk publisher state.
///
/// Use a deployment-owned local filesystem directory with durable rename and
/// directory sync semantics. `create_new` is an explicit one-time enrollment;
/// `open_existing` reconstructs a missing publication only from an intact
/// intent matching the external anchor. Neither method treats a missing file
/// as sequence zero after a restart.
pub struct RootStatusPublicationStore {
    directory_file: File,
    lock_file: File,
    feed_id: RootStatusFeedId,
    anchor: Arc<dyn RootStatusSequenceAnchor>,
    authority: ZkStatusAuthorityPublicKey,
    fresh: bool,
}

impl RootStatusPublicationStore {
    /// Create a new private feed directory; an existing path is never reset.
    pub fn create_new(
        directory: &Path,
        feed_id: RootStatusFeedId,
        authority: ZkStatusAuthorityPublicKey,
        anchor: Arc<dyn RootStatusSequenceAnchor>,
    ) -> Result<Self, RootStatusPublisherError> {
        if anchor.load(feed_id)?.is_some() {
            return Err(error(RootStatusPublisherReason::AnchorMismatch));
        }
        if !directory.is_absolute() {
            return Err(error(RootStatusPublisherReason::InvalidStore));
        }
        DirBuilder::new()
            .mode(PRIVATE_DIRECTORY_MODE)
            .create(directory)
            .map_err(|_| error(RootStatusPublisherReason::InvalidStore))?;
        let directory_file = open_private_directory(directory)?;
        let lock_file = secure_files::open(
            &directory_file,
            StoreFile::Lock,
            true,
            FileAccess::ReadWrite,
        )?;
        directory_file
            .sync_all()
            .map_err(|_| error(RootStatusPublisherReason::Storage))?;
        // The directory inode sync does not make its name durable in the
        // parent. Losing the whole feed path after an anchor advance would
        // prevent otherwise valid intent recovery.
        sync_parent_directory(directory)?;
        Ok(Self {
            directory_file,
            lock_file,
            feed_id,
            anchor,
            authority,
            fresh: true,
        })
    }

    /// Open an enrolled feed, recovering only the exact externally anchored intent.
    pub fn open_existing(
        directory: &Path,
        feed_id: RootStatusFeedId,
        authority: ZkStatusAuthorityPublicKey,
        anchor: Arc<dyn RootStatusSequenceAnchor>,
        signer: &dyn RootStatusSigner,
    ) -> Result<Self, RootStatusPublisherError> {
        let directory_file = open_private_directory(directory)?;
        let lock_file = secure_files::open(
            &directory_file,
            StoreFile::Lock,
            false,
            FileAccess::ReadWrite,
        )?;
        let mut store = Self {
            directory_file,
            lock_file,
            feed_id,
            anchor,
            authority,
            fresh: false,
        };
        let guard = store.lock()?;
        let fresh = store.reconcile(signer)?;
        drop(guard);
        store.fresh = fresh;
        Ok(store)
    }

    /// Sign and durably install the next complete publication.
    ///
    /// The lock stays held from reading the prior sequence through signing,
    /// atomic replacement, and directory sync. Returned bytes are safe to
    /// distribute only after this method succeeds.
    pub fn publish(
        &mut self,
        active_attestations: &[&ZkRootAssuranceAttestation],
        revoked_attestation_ids: &[[u8; 32]],
        attestation_trust: ZkCommonCredentialRootAttestationTrustPolicy,
        signer: &dyn RootStatusSigner,
        validity_seconds: u64,
    ) -> Result<Zeroizing<Vec<u8>>, RootStatusPublisherError> {
        self.publish_with_clock(
            active_attestations,
            revoked_attestation_ids,
            attestation_trust,
            signer,
            validity_seconds,
            current_unix,
        )
    }

    fn publish_with_clock(
        &mut self,
        active_attestations: &[&ZkRootAssuranceAttestation],
        revoked_attestation_ids: &[[u8; 32]],
        attestation_trust: ZkCommonCredentialRootAttestationTrustPolicy,
        signer: &dyn RootStatusSigner,
        validity_seconds: u64,
        clock: impl Fn() -> Result<u64, RootStatusPublisherError>,
    ) -> Result<Zeroizing<Vec<u8>>, RootStatusPublisherError> {
        if signer.public_key() != self.authority
            || validity_seconds == 0
            || validity_seconds > MAX_VALIDITY_SECONDS
        {
            return Err(error(RootStatusPublisherReason::InvalidState));
        }
        let guard = self.lock()?;
        let previous = if self.fresh {
            if secure_files::exists(&self.directory_file, StoreFile::Publication)? {
                return Err(error(RootStatusPublisherReason::InvalidState));
            }
            None
        } else {
            let (snapshot, _) = self.read_verified_latest()?;
            Some(snapshot)
        };
        let previous_anchor = self.require_anchor(previous)?;
        let issued_unix = clock()?;
        let sequence = match previous {
            Some(snapshot) => {
                if issued_unix < snapshot.issued_unix() {
                    return Err(error(RootStatusPublisherReason::ClockRollback));
                }
                snapshot
                    .sequence()
                    .checked_add(1)
                    .ok_or_else(|| error(RootStatusPublisherReason::Range))?
            }
            None => FIRST_SEQUENCE,
        };
        let expires_unix = issued_unix
            .checked_add(validity_seconds)
            .ok_or_else(|| error(RootStatusPublisherReason::Range))?;
        let active_set = build_root_active_set_from_authority(ZkRootActiveSetAuthorityInput {
            active_attestations,
            revoked_attestation_ids,
            attestation_trust,
            issued_unix,
        })
        .map_err(|_| error(RootStatusPublisherReason::InvalidState))?;
        let intent = RootStatusIntent::new(
            active_set,
            issued_unix,
            expires_unix,
            sequence,
            self.feed_id,
        )?;
        self.clear_intent()?;
        self.save_intent(&intent)?;
        let next_anchor = intent.anchor_value()?;
        self.anchor
            .compare_and_advance(self.feed_id, previous_anchor, next_anchor)?;
        let publication = self.finish_intent(&intent, signer)?;
        // A slow signer or storage sync can finish after the signed interval.
        // Keep the expired publication as the durable sequence predecessor,
        // but never return it as distributable current status.
        let completed_unix = clock();
        drop(guard);
        self.fresh = false;
        let completed_unix = completed_unix?;
        if completed_unix < issued_unix {
            return Err(error(RootStatusPublisherReason::ClockRollback));
        }
        if completed_unix >= expires_unix {
            return Err(error(RootStatusPublisherReason::PublicationExpired));
        }
        Ok(publication)
    }

    fn finish_intent(
        &self,
        intent: &RootStatusIntent,
        signer: &dyn RootStatusSigner,
    ) -> Result<Zeroizing<Vec<u8>>, RootStatusPublisherError> {
        if signer.public_key() != self.authority {
            return Err(error(RootStatusPublisherReason::Signer));
        }
        let digest = intent.anchor_value()?.signing_digest();
        let signature = signer.sign_digest(&digest)?;
        let snapshot = ZkRootStatusSnapshot::try_from_authority_signed_parts(
            intent.active_set().root(),
            intent.issued_unix(),
            intent.expires_unix(),
            intent.sequence(),
            self.authority,
            signature,
        )
        .map_err(|_| error(RootStatusPublisherReason::Signer))?;
        verify_root_status_snapshot(
            snapshot,
            ZkRootStatusTrustPolicy {
                authority: self.authority,
                minimum_sequence: intent.sequence(),
                maximum_age_seconds: MAX_VALIDITY_SECONDS,
            },
            intent.issued_unix(),
        )
        .map_err(|_| error(RootStatusPublisherReason::Signer))?;
        let publication = encode_root_active_set_publication(intent.active_set(), &snapshot)
            .map_err(|_| error(RootStatusPublisherReason::InvalidState))?;
        self.install(&publication)?;
        // A separate writer may have advanced the independent feed anchor
        // while the signer or filesystem was busy. Never return an already
        // stale publication as safe for distribution.
        if self.anchor.load(self.feed_id)? != Some(intent.anchor_value()?) {
            return Err(error(RootStatusPublisherReason::AnchorMismatch));
        }
        self.clear_intent()?;
        Ok(publication)
    }

    /// Read the last durably installed publication under the publisher lock.
    pub fn latest(&self) -> Result<Zeroizing<Vec<u8>>, RootStatusPublisherError> {
        let _guard = self.lock()?;
        let (snapshot, bytes) = self.read_verified_latest()?;
        self.require_anchor(Some(snapshot))?;
        let now_unix = current_unix()?;
        if now_unix < snapshot.issued_unix() {
            return Err(error(RootStatusPublisherReason::ClockRollback));
        }
        if now_unix >= snapshot.expires_unix() {
            return Err(error(RootStatusPublisherReason::PublicationExpired));
        }
        Ok(bytes)
    }

    fn read_verified_latest(
        &self,
    ) -> Result<(ZkRootStatusSnapshot, Zeroizing<Vec<u8>>), RootStatusPublisherError> {
        let bytes = read_publication(&self.directory_file, StoreFile::Publication)?;
        let admitted = admit_root_active_set_publication(&bytes)
            .map_err(|_| error(RootStatusPublisherReason::InvalidState))?;
        let issued_unix = admitted.unauthenticated_snapshot().issued_unix();
        // Existing state may be expired. Verify its signature at its own
        // issuance time to authenticate the durable sequence without treating
        // an old publication as current verifier policy. The active set is
        // rebuilt and matched to the signed root only after that signature
        // is accepted under this store's pinned authority.
        let authenticated = admitted
            .authenticate(
                ZkRootStatusTrustPolicy {
                    authority: self.authority,
                    minimum_sequence: FIRST_SEQUENCE,
                    maximum_age_seconds: u64::MAX,
                },
                issued_unix,
            )
            .map_err(|_| error(RootStatusPublisherReason::InvalidState))?;
        Ok((authenticated.snapshot(), bytes))
    }

    fn require_anchor(
        &self,
        snapshot: Option<ZkRootStatusSnapshot>,
    ) -> Result<Option<RootStatusAnchorValue>, RootStatusPublisherError> {
        let local = snapshot
            .map(|signed| {
                RootStatusAnchorValue::try_from_parts(signed.sequence(), signed.signing_digest())
            })
            .transpose()?;
        let remote = self.anchor.load(self.feed_id)?;
        if local != remote {
            return Err(error(RootStatusPublisherReason::AnchorMismatch));
        }
        Ok(remote)
    }

    fn reconcile(&self, signer: &dyn RootStatusSigner) -> Result<bool, RootStatusPublisherError> {
        if signer.public_key() != self.authority {
            return Err(error(RootStatusPublisherReason::Signer));
        }
        let publication_exists =
            secure_files::exists(&self.directory_file, StoreFile::Publication)?;
        let local = if publication_exists {
            Some(self.read_verified_latest()?.0)
        } else {
            None
        };
        let local_anchor = local
            .map(|snapshot| {
                RootStatusAnchorValue::try_from_parts(
                    snapshot.sequence(),
                    snapshot.signing_digest(),
                )
            })
            .transpose()?;
        let remote = self.anchor.load(self.feed_id)?;
        if local_anchor == remote {
            if local.is_none() && !secure_files::exists(&self.directory_file, StoreFile::Intent)? {
                return Err(error(RootStatusPublisherReason::InvalidStore));
            }
            // The anchor did not advance, or the signed publication is already
            // installed. An unsigned leftover intent is no longer authoritative.
            self.clear_intent()?;
            return Ok(local.is_none());
        }
        if !secure_files::exists(&self.directory_file, StoreFile::Intent)? {
            return Err(error(RootStatusPublisherReason::AnchorMismatch));
        }
        let bytes = read_publication(&self.directory_file, StoreFile::Intent)?;
        let intent = RootStatusIntent::decode(&bytes, self.feed_id)?;
        if Some(intent.anchor_value()?) != remote {
            return Err(error(RootStatusPublisherReason::AnchorMismatch));
        }
        let expected_sequence = local.map_or(Some(FIRST_SEQUENCE), |snapshot| {
            snapshot.sequence().checked_add(1)
        });
        if expected_sequence != Some(intent.sequence())
            || local.is_some_and(|snapshot| intent.issued_unix() < snapshot.issued_unix())
        {
            return Err(error(RootStatusPublisherReason::AnchorMismatch));
        }
        self.finish_intent(&intent, signer)?;
        Ok(false)
    }

    fn save_intent(&self, intent: &RootStatusIntent) -> Result<(), RootStatusPublisherError> {
        let bytes = intent.encode()?;
        let mut file = secure_files::open(
            &self.directory_file,
            StoreFile::Intent,
            true,
            FileAccess::ReadWrite,
        )?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| error(RootStatusPublisherReason::Storage))?;
        self.directory_file
            .sync_all()
            .map_err(|_| error(RootStatusPublisherReason::Storage))
    }

    fn clear_intent(&self) -> Result<(), RootStatusPublisherError> {
        if !secure_files::exists(&self.directory_file, StoreFile::Intent)? {
            return Ok(());
        }
        let file = secure_files::open(
            &self.directory_file,
            StoreFile::Intent,
            false,
            FileAccess::Read,
        )?;
        drop(file);
        secure_files::remove(&self.directory_file, StoreFile::Intent)?;
        self.directory_file
            .sync_all()
            .map_err(|_| error(RootStatusPublisherReason::Storage))
    }

    fn install(&self, publication: &[u8]) -> Result<(), RootStatusPublisherError> {
        if secure_files::exists(&self.directory_file, StoreFile::Pending)? {
            secure_files::remove(&self.directory_file, StoreFile::Pending)?;
        }
        let mut file = secure_files::open(
            &self.directory_file,
            StoreFile::Pending,
            true,
            FileAccess::ReadWrite,
        )?;
        file.write_all(publication)
            .and_then(|()| file.sync_all())
            .map_err(|_| error(RootStatusPublisherReason::Storage))?;
        secure_files::replace(
            &self.directory_file,
            StoreFile::Pending,
            StoreFile::Publication,
        )?;
        self.directory_file
            .sync_all()
            .map_err(|_| error(RootStatusPublisherReason::Storage))
    }

    fn lock(&self) -> Result<PublicationLock<'_>, RootStatusPublisherError> {
        self.lock_file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => self::error(RootStatusPublisherReason::Busy),
            std::fs::TryLockError::Error(_) => self::error(RootStatusPublisherReason::Storage),
        })?;
        Ok(PublicationLock(&self.lock_file))
    }
}

#[cfg(test)]
#[path = "publisher/tests.rs"]
mod tests;
