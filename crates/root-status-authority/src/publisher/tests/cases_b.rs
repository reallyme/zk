// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn stale_pending_file_cannot_replace_the_signed_publication() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor.clone())?;
    store
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    drop(store);
    fs::write(directory.0.join(PENDING_FILE), [0x55; 4]).map_err(|_| TestError)?;
    let mut reopened = open_store(&directory, &status_signer, anchor)?;
    let next = reopened
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    assert_eq!(
        authenticated_publication(&next)
            .map_err(|_| TestError)?
            .snapshot()
            .sequence(),
        2
    );
    assert!(!directory.0.join(PENDING_FILE).exists());
    Ok(())
}

#[test]
fn symlinked_publication_is_not_admitted_after_restart() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor.clone())?;
    let publication = store
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    drop(store);
    fs::write(directory.0.join(PENDING_FILE), publication.as_slice()).map_err(|_| TestError)?;
    fs::remove_file(directory.0.join(PUBLICATION_FILE)).map_err(|_| TestError)?;
    symlink(PENDING_FILE, directory.0.join(PUBLICATION_FILE)).map_err(|_| TestError)?;
    assert_eq!(
        RootStatusPublicationStore::open_existing(
            &directory.0,
            feed_id()?,
            status_signer.public,
            anchor,
            &status_signer,
        )
        .err()
        .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::InvalidStore)
    );
    Ok(())
}

#[test]
fn expired_publication_remains_a_floor_but_is_not_served() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let status_signer = TestSigner::new(29)?;
    let store = create_store(&directory, &status_signer, anchor.clone())?;
    drop(store);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TestError)?
        .as_secs();
    let issued = now.checked_sub(120).ok_or(TestError)?;
    let expires = now.checked_sub(60).ok_or(TestError)?;
    let set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[]).map_err(|_| TestError)?;
    let digest = ZkRootStatusSnapshot::signing_digest_for_fields(set.root(), issued, expires, 4);
    let snapshot = ZkRootStatusSnapshot::try_from_authority_signed_parts(
        set.root(),
        issued,
        expires,
        4,
        status_signer.public,
        status_signer.sign(&digest)?,
    )
    .map_err(|_| TestError)?;
    let bytes = encode_root_active_set_publication(&set, &snapshot).map_err(|_| TestError)?;
    let directory_file = super::open_private_directory(&directory.0).map_err(|_| TestError)?;
    let mut state = super::secure_files::open(
        &directory_file,
        super::StoreFile::Publication,
        true,
        super::FileAccess::ReadWrite,
    )
    .map_err(|_| TestError)?;
    state.write_all(&bytes).map_err(|_| TestError)?;
    state.sync_all().map_err(|_| TestError)?;
    anchor.set_fixture(
        RootStatusAnchorValue::try_from_parts(snapshot.sequence(), snapshot.signing_digest())
            .map_err(|_| TestError)?,
    )?;
    let mut reopened = open_store(&directory, &status_signer, anchor)?;
    assert_eq!(
        reopened
            .latest()
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::PublicationExpired)
    );
    let next = reopened
        .publish(&[], &[], trust(&status_signer), &status_signer, 120)
        .map_err(|_| TestError)?;
    assert_eq!(
        authenticated_publication(&next)
            .map_err(|_| TestError)?
            .snapshot()
            .sequence(),
        5
    );
    Ok(())
}

#[test]
fn restored_older_signed_file_cannot_rollback_external_floor() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor.clone())?;
    let old = store
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    store
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    fs::write(directory.0.join(PUBLICATION_FILE), old.as_slice()).map_err(|_| TestError)?;
    assert_eq!(
        store.latest().err().map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorMismatch)
    );
    drop(store);
    assert_eq!(
        RootStatusPublicationStore::open_existing(
            &directory.0,
            feed_id()?,
            status_signer.public,
            anchor.clone(),
            &status_signer,
        )
        .err()
        .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorMismatch)
    );
    let reset_directory = TestDirectory::new()?;
    assert_eq!(
        RootStatusPublicationStore::create_new(
            &reset_directory.0,
            feed_id()?,
            status_signer.public,
            anchor,
        )
        .err()
        .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorMismatch)
    );
    Ok(())
}

#[test]
fn conflicting_digest_at_the_same_sequence_fails_closed() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor.clone())?;
    let published = store
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    let sequence = authenticated_publication(&published)
        .map_err(|_| TestError)?
        .snapshot()
        .sequence();
    anchor.set_fixture(
        RootStatusAnchorValue::try_from_parts(sequence, [0x77; 32]).map_err(|_| TestError)?,
    )?;
    assert_eq!(
        store.latest().err().map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorMismatch)
    );
    assert_eq!(
        store
            .publish(
                &[&first],
                &[],
                trust(&assurance_signer),
                &status_signer,
                120,
            )
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorMismatch)
    );
    Ok(())
}

#[test]
fn unavailable_external_anchor_stops_serving_and_signing() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor.clone())?;
    store
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    anchor.available.store(false, Ordering::SeqCst);
    assert_eq!(
        store.latest().err().map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorUnavailable)
    );
    assert_eq!(
        store
            .publish(
                &[&first],
                &[],
                trust(&assurance_signer),
                &status_signer,
                120,
            )
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorUnavailable)
    );
    drop(store);
    assert_eq!(
        RootStatusPublicationStore::open_existing(
            &directory.0,
            feed_id()?,
            status_signer.public,
            anchor,
            &status_signer,
        )
        .err()
        .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorUnavailable)
    );
    Ok(())
}

#[test]
fn first_publication_recovers_exact_anchored_intent_after_signer_failure() -> Result<(), TestError>
{
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let mut status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor.clone())?;
    status_signer.invalid_signature = true;
    assert_eq!(
        store
            .publish(
                &[&first],
                &[],
                trust(&assurance_signer),
                &status_signer,
                120,
            )
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::Signer)
    );
    assert!(directory.0.join(INTENT_FILE).exists());
    assert!(!directory.0.join(PUBLICATION_FILE).exists());
    drop(store);
    status_signer.invalid_signature = false;
    let mut recovered = open_store(&directory, &status_signer, anchor)?;
    let publication = recovered.latest().map_err(|_| TestError)?;
    let decoded = authenticated_publication(&publication).map_err(|_| TestError)?;
    assert_eq!(decoded.snapshot().sequence(), 1);
    assert_eq!(decoded.active_set().len(), 1);
    assert!(!directory.0.join(INTENT_FILE).exists());
    let next = recovered
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    assert_eq!(
        authenticated_publication(&next)
            .map_err(|_| TestError)?
            .snapshot()
            .sequence(),
        2
    );
    Ok(())
}

#[test]
fn substituted_canonical_intent_cannot_be_signed_after_restart() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let mut status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor.clone())?;
    status_signer.invalid_signature = true;
    assert_eq!(
        store
            .publish(
                &[&first],
                &[],
                trust(&assurance_signer),
                &status_signer,
                120,
            )
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::Signer)
    );
    drop(store);
    let intent_path = directory.0.join(INTENT_FILE);
    let original = fs::read(&intent_path).map_err(|_| TestError)?;
    let original =
        crate::intent::RootStatusIntent::decode(&original, feed_id()?).map_err(|_| TestError)?;
    let empty_set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[]).map_err(|_| TestError)?;
    let substituted = crate::intent::RootStatusIntent::new(
        empty_set,
        original.issued_unix(),
        original.expires_unix(),
        original.sequence(),
        feed_id()?,
    )
    .map_err(|_| TestError)?
    .encode()
    .map_err(|_| TestError)?;
    fs::write(&intent_path, substituted.as_slice()).map_err(|_| TestError)?;
    status_signer.invalid_signature = false;
    assert_eq!(
        RootStatusPublicationStore::open_existing(
            &directory.0,
            feed_id()?,
            status_signer.public,
            anchor,
            &status_signer,
        )
        .err()
        .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorMismatch)
    );
    assert!(!directory.0.join(PUBLICATION_FILE).exists());
    Ok(())
}

#[test]
fn intent_rejects_wrong_feed_and_unknown_wire_fields() -> Result<(), TestError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TestError)?
        .as_secs();
    let expires = now.checked_add(120).ok_or(TestError)?;
    let empty_set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[]).map_err(|_| TestError)?;
    let intent = crate::intent::RootStatusIntent::new(empty_set, now, expires, 1, feed_id()?)
        .map_err(|_| TestError)?;
    let encoded = intent.encode().map_err(|_| TestError)?;
    let wrong_feed = RootStatusFeedId::try_from_bytes([0x6b; 32]).map_err(|_| TestError)?;
    assert_eq!(
        crate::intent::RootStatusIntent::decode(&encoded, wrong_feed)
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::InvalidState)
    );
    let mut unknown_field = Zeroizing::new(encoded.to_vec());
    unknown_field.extend_from_slice(&[0x38, 0x01]);
    assert_eq!(
        crate::intent::RootStatusIntent::decode(&unknown_field, feed_id()?)
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::InvalidState)
    );
    Ok(())
}
