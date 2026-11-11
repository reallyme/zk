// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn publication_sequence_and_bytes_survive_restart() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let second = attestation(&assurance_signer, &[0x32; 32])?;
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
    let first_snapshot = authenticated_publication(&published)
        .map_err(|_| TestError)?
        .snapshot();
    assert_eq!(first_snapshot.sequence(), 1);
    assert_eq!(
        store.latest().map_err(|_| TestError)?.as_slice(),
        published.as_slice()
    );
    drop(store);

    let wrong_status_signer = TestSigner::new(30)?;
    assert_eq!(
        RootStatusPublicationStore::open_existing(
            &directory.0,
            feed_id()?,
            wrong_status_signer.public,
            anchor.clone(),
            &wrong_status_signer,
        )
        .err()
        .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::InvalidState)
    );

    let mut reopened = open_store(&directory, &status_signer, anchor)?;
    assert_eq!(
        reopened.latest().map_err(|_| TestError)?.as_slice(),
        published.as_slice()
    );
    let next = reopened
        .publish(
            &[&first, &second],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    let decoded = authenticated_publication(&next).map_err(|_| TestError)?;
    assert_eq!(decoded.snapshot().sequence(), 2);
    assert_eq!(decoded.active_set().len(), 2);
    Ok(())
}

#[test]
fn publication_advanced_during_signing_is_not_returned_for_distribution() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor.clone())?;
    anchor.advance_after_cas.store(true, Ordering::SeqCst);

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
            anchor,
            &status_signer,
        )
        .err()
        .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorMismatch)
    );
    Ok(())
}

#[test]
fn publication_expired_before_return_is_not_distributed_or_reused() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor.clone())?;
    let issued_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TestError)?
        .as_secs();
    let clock = AtomicU64::new(issued_unix);

    assert_eq!(
        store
            .publish_with_clock(
                &[&first],
                &[],
                trust(&assurance_signer),
                &status_signer,
                1,
                || Ok(clock.fetch_add(2, Ordering::SeqCst)),
            )
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::PublicationExpired)
    );
    let installed = fs::read(directory.0.join(PUBLICATION_FILE)).map_err(|_| TestError)?;
    let decoded = authenticated_publication(&installed).map_err(|_| TestError)?;
    assert_eq!(decoded.snapshot().sequence(), 1);
    assert_eq!(
        decoded.snapshot().expires_unix(),
        issued_unix.checked_add(1).ok_or(TestError)?
    );

    // The signed but undistributed first sequence remains a predecessor. The
    // next publication must advance the anchor and produce a fresh sequence.
    let next = store
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
    assert_eq!(
        store.latest().map_err(|_| TestError)?.as_slice(),
        next.as_slice()
    );
    Ok(())
}

#[test]
fn clock_rollback_during_signing_rejects_distribution() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor)?;
    let issued_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TestError)?
        .as_secs();
    let rolled_back = issued_unix.checked_sub(1).ok_or(TestError)?;
    let calls = AtomicU64::new(0);

    assert_eq!(
        store
            .publish_with_clock(
                &[&first],
                &[],
                trust(&assurance_signer),
                &status_signer,
                120,
                || {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        Ok(issued_unix)
                    } else {
                        Ok(rolled_back)
                    }
                },
            )
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::ClockRollback)
    );
    let next = store
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
fn replacing_feed_path_cannot_redirect_locked_publication() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let displaced = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor.clone())?;

    fs::rename(&directory.0, &displaced.0).map_err(|_| TestError)?;
    DirBuilder::new()
        .mode(0o700)
        .create(&directory.0)
        .map_err(|_| TestError)?;
    let published = store
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;

    assert_eq!(
        fs::read(displaced.0.join(PUBLICATION_FILE)).map_err(|_| TestError)?,
        published.as_slice()
    );
    assert!(!directory.0.join(PUBLICATION_FILE).exists());
    assert_eq!(
        store.latest().map_err(|_| TestError)?.as_slice(),
        published.as_slice()
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
        Some(RootStatusPublisherReason::InvalidStore)
    );
    let reopened = open_store(&displaced, &status_signer, anchor)?;
    assert_eq!(
        reopened.latest().map_err(|_| TestError)?.as_slice(),
        published.as_slice()
    );
    Ok(())
}

#[test]
fn hardlinked_publication_is_not_read_as_authority_state() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor)?;
    let published = store
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    let alias = directory.0.join("publication-alias.pb");
    fs::hard_link(directory.0.join(PUBLICATION_FILE), &alias).map_err(|_| TestError)?;
    assert_eq!(
        store.latest().err().map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::InvalidStore)
    );
    fs::remove_file(alias).map_err(|_| TestError)?;
    assert_eq!(
        store.latest().map_err(|_| TestError)?.as_slice(),
        published.as_slice()
    );
    Ok(())
}

#[test]
fn invalid_signer_cannot_replace_durable_state() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let mut status_signer = TestSigner::new(29)?;
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
    status_signer.invalid_signature = true;
    assert_eq!(
        store
            .publish(
                &[&first],
                &[],
                trust(&assurance_signer),
                &status_signer,
                120
            )
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::Signer)
    );
    assert_eq!(
        store.latest().err().map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::AnchorMismatch)
    );
    assert_eq!(
        fs::read(directory.0.join(PUBLICATION_FILE)).map_err(|_| TestError)?,
        published.as_slice()
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
        Some(RootStatusPublisherReason::Signer)
    );
    status_signer.invalid_signature = false;
    let reopened = open_store(&directory, &status_signer, anchor)?;
    assert_eq!(
        authenticated_publication(&reopened.latest().map_err(|_| TestError)?)
            .map_err(|_| TestError)?
            .snapshot()
            .sequence(),
        2
    );
    Ok(())
}

#[test]
fn missing_or_corrupt_publication_does_not_reset_sequence() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let signer = TestSigner::new(29)?;
    let fresh = create_store(&directory, &signer, anchor.clone())?;
    drop(fresh);
    assert_eq!(
        RootStatusPublicationStore::open_existing(
            &directory.0,
            feed_id()?,
            signer.public,
            anchor.clone(),
            &signer,
        )
        .err()
        .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::InvalidStore)
    );
    let assurance_signer = TestSigner::new(17)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    // Explicit fresh enrollment is not a recovery path for an existing feed.
    assert!(RootStatusPublicationStore::create_new(
        &directory.0,
        feed_id()?,
        signer.public,
        anchor.clone(),
    )
    .is_err());
    let second_directory = TestDirectory::new()?;
    let mut fresh = create_store(&second_directory, &signer, anchor.clone())?;
    fresh
        .publish(&[&first], &[], trust(&assurance_signer), &signer, 120)
        .map_err(|_| TestError)?;
    drop(fresh);
    fs::write(second_directory.0.join(PUBLICATION_FILE), [0x55; 4]).map_err(|_| TestError)?;
    assert_eq!(
        RootStatusPublicationStore::open_existing(
            &second_directory.0,
            feed_id()?,
            signer.public,
            anchor,
            &signer,
        )
        .err()
        .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::InvalidState)
    );
    Ok(())
}

#[test]
fn concurrent_writer_cannot_reuse_the_next_sequence() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut writer = create_store(&directory, &status_signer, anchor.clone())?;
    writer
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    let mut second = open_store(&directory, &status_signer, anchor)?;
    let guard = writer.lock().map_err(|_| TestError)?;
    assert_eq!(
        second
            .publish(
                &[&first],
                &[],
                trust(&assurance_signer),
                &status_signer,
                120
            )
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::Busy)
    );
    drop(guard);
    let next = second
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
fn invalid_authority_input_does_not_advance_the_sequence() -> Result<(), TestError> {
    let directory = TestDirectory::new()?;
    let anchor = Arc::new(TestAnchor::default());
    let assurance_signer = TestSigner::new(17)?;
    let status_signer = TestSigner::new(29)?;
    let first = attestation(&assurance_signer, &[0x31; 32])?;
    let mut store = create_store(&directory, &status_signer, anchor)?;
    assert_eq!(
        store
            .publish(
                &[&first, &first],
                &[],
                trust(&assurance_signer),
                &status_signer,
                120,
            )
            .err()
            .map(RootStatusPublisherError::reason),
        Some(RootStatusPublisherReason::InvalidState)
    );
    assert!(store.latest().is_err());
    let publication = store
        .publish(
            &[&first],
            &[],
            trust(&assurance_signer),
            &status_signer,
            120,
        )
        .map_err(|_| TestError)?;
    assert_eq!(
        authenticated_publication(&publication)
            .map_err(|_| TestError)?
            .snapshot()
            .sequence(),
        1
    );
    Ok(())
}
