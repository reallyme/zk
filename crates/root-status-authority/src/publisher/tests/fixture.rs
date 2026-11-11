// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const PUBLICATION_FILE: &str = "publication.pb";
const PENDING_FILE: &str = "publication.pending";
const INTENT_FILE: &str = "publication.intent.pb";

use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder},
    io::Write,
    os::unix::fs::{symlink, DirBuilderExt},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use reallyme_zk_api::{common_root::{common_credential_root_attestation_signing_digest, common_credential_root_root_commitment, ZkCommonCredentialRootActiveSet, ZkRootAssuranceAttestation, ZkRootStatusSnapshot}};
use reallyme_zk_proto_codec::common_credential_root_active_set_publication::{
    encode_root_active_set_publication, ZkAuthenticatedRootActiveSetPublication,
};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    admit_root_active_set_publication, RootStatusAnchorValue, RootStatusFeedId,
    RootStatusPublicationStore, RootStatusPublisherError, RootStatusPublisherReason,
    RootStatusSequenceAnchor, RootStatusSigner, ZkCommonCredentialRootAttestationTrustPolicy,
    ZkStatusAuthorityPublicKey,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const STATUS_SIGNER_SEED: u8 = 29;
const POLICY: [u8; 32] = [0x55; 32];
const FEED_BYTES: [u8; 32] = [0x6a; 32];

#[derive(Debug, Error)]
#[error("root status publisher fixture failed")]
struct TestError;

struct TestDirectory(PathBuf);

struct TestAnchor {
    values: Mutex<BTreeMap<[u8; 32], RootStatusAnchorValue>>,
    available: AtomicBool,
    advance_after_cas: AtomicBool,
}

impl Default for TestAnchor {
    fn default() -> Self {
        Self {
            values: Mutex::new(BTreeMap::new()),
            available: AtomicBool::new(true),
            advance_after_cas: AtomicBool::new(false),
        }
    }
}

impl TestAnchor {
    fn set_fixture(&self, value: RootStatusAnchorValue) -> Result<(), TestError> {
        self.values
            .lock()
            .map_err(|_| TestError)?
            .insert(FEED_BYTES, value);
        Ok(())
    }
}

impl RootStatusSequenceAnchor for TestAnchor {
    fn load(
        &self,
        feed_id: RootStatusFeedId,
    ) -> Result<Option<RootStatusAnchorValue>, RootStatusPublisherError> {
        if !self.available.load(Ordering::SeqCst) {
            return Err(super::error(RootStatusPublisherReason::AnchorUnavailable));
        }
        self.values
            .lock()
            .map(|state| state.get(&feed_id.bytes()).copied())
            .map_err(|_| super::error(RootStatusPublisherReason::AnchorUnavailable))
    }

    fn compare_and_advance(
        &self,
        feed_id: RootStatusFeedId,
        expected: Option<RootStatusAnchorValue>,
        next: RootStatusAnchorValue,
    ) -> Result<(), RootStatusPublisherError> {
        if !self.available.load(Ordering::SeqCst) {
            return Err(super::error(RootStatusPublisherReason::AnchorUnavailable));
        }
        let mut state = self
            .values
            .lock()
            .map_err(|_| super::error(RootStatusPublisherReason::AnchorUnavailable))?;
        let current = state.get(&feed_id.bytes()).copied();
        let expected_sequence = expected.map_or(Some(1), |value| value.sequence().checked_add(1));
        if current != expected || expected_sequence != Some(next.sequence()) {
            return Err(super::error(RootStatusPublisherReason::AnchorConflict));
        }
        state.insert(feed_id.bytes(), next);
        if self.advance_after_cas.swap(false, Ordering::SeqCst) {
            // Model another authority writer committing a later transcript
            // before this store finishes signing and installing its own.
            let later_sequence = next
                .sequence()
                .checked_add(1)
                .ok_or_else(|| super::error(RootStatusPublisherReason::Range))?;
            let later = RootStatusAnchorValue::try_from_parts(later_sequence, [0x77; 32])?;
            state.insert(feed_id.bytes(), later);
        }
        Ok(())
    }
}

/// Admit a publication and authenticate it under the fixture status key.
///
/// Like the store, this checks the signature at the snapshot's own issuance
/// time so tests can inspect publications that have already expired.
fn authenticated_publication(
    bytes: &[u8],
) -> Result<ZkAuthenticatedRootActiveSetPublication, TestError> {
    let admitted = admit_root_active_set_publication(bytes).map_err(|_| TestError)?;
    let issued_unix = admitted.unauthenticated_snapshot().issued_unix();
    admitted
        .authenticate(
            super::ZkRootStatusTrustPolicy {
                authority: TestSigner::new(STATUS_SIGNER_SEED)?.public,
                minimum_sequence: super::FIRST_SEQUENCE,
                maximum_age_seconds: u64::MAX,
            },
            issued_unix,
        )
        .map_err(|_| TestError)
}

fn feed_id() -> Result<RootStatusFeedId, TestError> {
    RootStatusFeedId::try_from_bytes(FEED_BYTES).map_err(|_| TestError)
}

fn create_store(
    directory: &TestDirectory,
    signer: &TestSigner,
    anchor: Arc<TestAnchor>,
) -> Result<RootStatusPublicationStore, TestError> {
    RootStatusPublicationStore::create_new(&directory.0, feed_id()?, signer.public, anchor)
        .map_err(|_| TestError)
}

fn open_store(
    directory: &TestDirectory,
    signer: &TestSigner,
    anchor: Arc<TestAnchor>,
) -> Result<RootStatusPublicationStore, TestError> {
    RootStatusPublicationStore::open_existing(
        &directory.0,
        feed_id()?,
        signer.public,
        anchor,
        signer,
    )
    .map_err(|_| TestError)
}

impl TestDirectory {
    fn new() -> Result<Self, TestError> {
        let count = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TestError)?
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "reallyme-root-status-{}-{nanos}-{count}",
            std::process::id()
        ));
        Ok(Self(directory))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestSigner {
    secret: Zeroizing<[u8; 32]>,
    public: ZkStatusAuthorityPublicKey,
    invalid_signature: bool,
}

impl TestSigner {
    fn new(seed: u8) -> Result<Self, TestError> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        secret[31] = seed;
        let (compressed, _) =
            crypto_p256::generate_p256_keypair_from_secret_key(&secret).map_err(|_| TestError)?;
        let point = crypto_p256::decompress_public_key(&compressed).map_err(|_| TestError)?;
        let public = ZkStatusAuthorityPublicKey {
            x: point[1..33].try_into().map_err(|_| TestError)?,
            y: point[33..65].try_into().map_err(|_| TestError)?,
        };
        Ok(Self {
            secret,
            public,
            invalid_signature: false,
        })
    }

    fn sign(&self, digest: &[u8; 32]) -> Result<[u8; 64], TestError> {
        let digest = crypto_p256::P256Sha256Digest::new(*digest);
        let der = crypto_p256::sign_p256_sha256_digest_low_s_der(
            self.secret.as_slice(),
            &digest,
        )
        .map_err(|_| TestError)?;
        crypto_p256::p256_ecdsa_der_to_jose_signature(&der).map_err(|_| TestError)
    }
}

impl RootStatusSigner for TestSigner {
    fn public_key(&self) -> ZkStatusAuthorityPublicKey {
        self.public
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], RootStatusPublisherError> {
        if self.invalid_signature {
            return Ok([1; 64]);
        }
        self.sign(digest)
            .map_err(|_| super::error(RootStatusPublisherReason::Signer))
    }
}

fn attestation(
    signer: &TestSigner,
    root: &[u8; 32],
) -> Result<ZkRootAssuranceAttestation, TestError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TestError)?
        .as_secs();
    let issued = now.checked_sub(60).ok_or(TestError)?;
    let expires = now.checked_add(3_600).ok_or(TestError)?;
    let commitment = common_credential_root_root_commitment(root).map_err(|_| TestError)?;
    let digest = common_credential_root_attestation_signing_digest(&commitment, POLICY, issued, expires, 1)
        .map_err(|_| TestError)?;
    ZkRootAssuranceAttestation::try_from_authority_signed_parts(
        *commitment,
        POLICY,
        issued,
        expires,
        1,
        reallyme_zk_api::keys::ZkAttestationPublicKey::from(reallyme_zk_api::keys::ZkP256PublicKey::from(signer.public)),
        signer.sign(&digest)?,
    )
    .map_err(|_| TestError)
}

fn trust(signer: &TestSigner) -> ZkCommonCredentialRootAttestationTrustPolicy {
    ZkCommonCredentialRootAttestationTrustPolicy {
        signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(reallyme_zk_api::keys::ZkP256PublicKey::from(signer.public)),
        assurance_policy_id: POLICY,
    }
}
