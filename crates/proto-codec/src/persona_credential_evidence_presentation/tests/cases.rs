// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn prepared_wallet_evidence_round_trips_both_profiles() -> Result<(), ZkError> {
    for mode in [
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
    ] {
        let fixture = Fixture::new_for_profile(mode);
        let wire = evidence_wire(&fixture).encode_to_vec();
        let decoded = decode_persona_credential_evidence_proof_set(&wire)?;
        assert_eq!(decoded.mode(), mode);
        assert_eq!(decoded.credential_hash_algorithm(), ZkCredentialHashAlgorithm::Sha256);
        assert_eq!(decoded.selected_claim().proof_bytes().as_bytes(), &[42]);
        assert_eq!(decoded.encode()?.as_slice(), wire);
    }
    Ok(())
}

#[test]
fn prepared_wallet_evidence_rejects_cross_token_and_malformed_records() {
    let fixture = Fixture::new();
    let mut cross_token = evidence_wire(&fixture);
    cross_token.issuer_envelope = Fixture::new_for_token(PROFILE, 8)
        .presentation
        .issuer_envelope
        .clone();
    assert_eq!(
        decode_persona_credential_evidence_proof_set(&cross_token.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut missing = evidence_wire(&fixture);
    missing.claim_root = MessageField::none();
    assert_eq!(
        decode_persona_credential_evidence_proof_set(&missing.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::EmptyInput)
    );

    let mut unknown = evidence_wire(&fixture).encode_to_vec();
    unknown.extend_from_slice(&[0x98, 0x06, 0x01]);
    assert_eq!(
        decode_persona_credential_evidence_proof_set(&unknown)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MalformedProtobuf)
    );

    let oversized = vec![0; MAX_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SET_BYTES + 1];
    assert_eq!(
        decode_persona_credential_evidence_proof_set(&oversized)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MessageTooLarge)
    );
}

#[test]
fn one_hundred_private_presentations_have_distinct_observer_visible_token_transcripts() {
    let verifier = CountingVerifier {
        calls: AtomicUsize::new(0),
        reject: false,
    };
    let nonces = DistinctNonces(Mutex::new(BTreeSet::new()));
    let mut public_joins = BTreeSet::new();
    let mut credential_bindings = BTreeSet::new();
    let mut holder_signatures = BTreeSet::new();
    for token in 1..=100_u8 {
        // Credential and claim facts stay fixed; each private token has a
        // separate authorized key and nonce before its public proof is made.
        let mut fixture = Fixture::new_for_token(PROFILE, token);
        let mut request_nonce = [1_u8; 32];
        request_nonce[0] = token;
        fixture.sign_fresh_request(request_nonce);
        let claim = fixture
            .presentation
            .selected_claim
            .as_option()
            .expect("test claim exists");
        let fields = &claim
            .public_inputs
            .as_option()
            .expect("test public inputs exist")
            .raw_fields;
        assert!(public_joins.insert(fields[..194 * FIELD_BYTES].to_vec()));
        assert!(credential_bindings.insert(fields[162 * FIELD_BYTES..194 * FIELD_BYTES].to_vec()));
        assert!(holder_signatures.insert(fixture.presentation.holder_signature_p256_raw.clone()));
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonces,
            &fixture.presentation.encode_to_vec(),
            &fixture.request,
            fixture.policy(),
        )
        .expect("each complete token transcript is independently accepted");
    }
    assert_eq!(public_joins.len(), 100);
    assert_eq!(credential_bindings.len(), 100);
    assert_eq!(holder_signatures.len(), 100);
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 500);
}

impl ZkIssuerStatusAuthority for Fixture {
    fn current_feed_for_issuer(
        &self,
        issuer_key: &ZkIssuerPublicKey,
        status_pointer: &ZkIssuerStatusListPointer,
        _verification_time_unix: u64,
    ) -> Result<ZkIssuerStatusFeed, ZkError> {
        if issuer_key != &self.status_issuer {
            return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
        }
        if status_pointer.list_id != self.status.list_id
            || status_pointer.url_hash != self.status.url_hash
            || status_pointer.purpose != self.status.purpose
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(ZkIssuerStatusFeed {
            root: self.status.root,
            length: self.status.length,
            list_id: self.status.list_id,
            url_hash: self.status.url_hash,
            purpose: self.status.purpose,
        })
    }
}

#[test]
fn complete_boundary_requires_five_proofs_signature_and_once_nonce() {
    let fixture = Fixture::new();
    let verifier = CountingVerifier {
        calls: AtomicUsize::new(0),
        reject: false,
    };
    let nonce = OnceNonce(AtomicBool::new(false));
    let encoded = fixture.presentation.encode_to_vec();
    let accepted = verify_persona_credential_evidence_presentation_with(
        &verifier,
        &nonce,
        &encoded,
        &fixture.request,
        fixture.policy(),
    )
    .expect("test presentation is valid under injected proof verifier");
    assert_eq!(accepted.evidence().mode(), PROFILE);
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 5);
    assert!(nonce.0.load(Ordering::SeqCst));
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &encoded,
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::NonceReplay),
    );
}

#[test]
fn public_prepared_proofs_support_distinct_live_requests_without_reproving() {
    let mut fixture = Fixture::new_for_profile(ZkPersonaCredentialEvidenceMode::PublicPersonaV1);
    let original_claim = fixture
        .presentation
        .selected_claim
        .as_option()
        .expect("test claim is present")
        .encode_to_vec();
    let original_status = fixture
        .presentation
        .current_state
        .as_option()
        .expect("test status is present")
        .encode_to_vec();
    let verifier = CountingVerifier {
        calls: AtomicUsize::new(0),
        reject: false,
    };
    let nonces = DistinctNonces(Mutex::new(BTreeSet::new()));

    for nonce_prefix in [1_u8, 2, 3] {
        let mut nonce = [1_u8; 32];
        nonce[0] = nonce_prefix;
        fixture.sign_fresh_request(nonce);
        let encoded = fixture.presentation.encode_to_vec();
        let accepted = verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonces,
            &encoded,
            &fixture.request,
            fixture.policy(),
        )
        .expect("a fresh signed request can reuse prepared public evidence");
        assert_eq!(
            accepted.evidence().mode(),
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1
        );
        assert_eq!(
            fixture
                .presentation
                .selected_claim
                .as_option()
                .expect("test claim is present")
                .encode_to_vec(),
            original_claim
        );
        assert_eq!(
            fixture
                .presentation
                .current_state
                .as_option()
                .expect("test status is present")
                .encode_to_vec(),
            original_status
        );
    }
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 15);
    let mut next_nonce = [1_u8; 32];
    next_nonce[0] = 4;
    fixture.sign_fresh_request(next_nonce);
    fixture.status.root[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonces,
            &fixture.presentation.encode_to_vec(),
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected),
    );
    fixture.status.root[0] ^= 1;
    verify_persona_credential_evidence_presentation_with(
        &verifier,
        &nonces,
        &fixture.presentation.encode_to_vec(),
        &fixture.request,
        fixture.policy(),
    )
    .expect("an unconsumed challenge succeeds while the signed status root remains current");
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonces,
            &fixture.presentation.encode_to_vec(),
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::NonceReplay),
    );
}

#[test]
fn complete_evidence_fails_closed_when_durable_replay_store_is_unavailable() {
    let fixture = Fixture::new();
    let verifier = CountingVerifier {
        calls: AtomicUsize::new(0),
        reject: false,
    };
    let result = verify_persona_credential_evidence_presentation_with(
        &verifier,
        &UnavailableNonce,
        &fixture.presentation.encode_to_vec(),
        &fixture.request,
        fixture.policy(),
    );
    assert_eq!(
        result.err().map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::ReplayStoreUnavailable)
    );
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 5);
}

#[test]
fn substituted_request_status_and_holder_signature_cannot_consume_nonce() {
    let mut fixture = Fixture::new();
    let verifier = CountingVerifier {
        calls: AtomicUsize::new(0),
        reject: false,
    };
    let nonce = OnceNonce(AtomicBool::new(false));
    fixture.request.nonce[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &fixture.presentation.encode_to_vec(),
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::PolicyMismatch),
    );
    fixture.request.nonce[0] ^= 1;
    fixture.status.root[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &fixture.presentation.encode_to_vec(),
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected),
    );
    fixture.status.root[0] ^= 1;
    fixture.presentation.holder_signature_p256_raw[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &fixture.presentation.encode_to_vec(),
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::HolderAuthenticationFailed),
    );
    assert!(!nonce.0.load(Ordering::SeqCst));
}

#[test]
fn builder_round_trips_both_persona_credential_evidence_modes() {
    for mode in [
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
    ] {
        let fixture = Fixture::new_for_profile(mode);
        let mut wire = fixture.presentation.clone();
        let issuer = persona_credential_evidence_stage_proof_from_proto(
            wire.issuer_envelope
                .take()
                .expect("fixture has issuer envelope"),
        )
        .expect("fixture issuer package is valid");
        let root = persona_credential_evidence_stage_proof_from_proto(
            wire.claim_root.take().expect("fixture has claim root"),
        )
        .expect("fixture root package is valid");
        let validity = persona_credential_evidence_stage_proof_from_proto(
            wire.signed_validity
                .take()
                .expect("fixture has signed validity"),
        )
        .expect("fixture validity package is valid");
        let claim = persona_credential_evidence_stage_proof_from_proto(
            wire.selected_claim
                .take()
                .expect("fixture has a selected claim"),
        )
        .expect("fixture claim package is valid");
        let status = persona_credential_evidence_stage_proof_from_proto(
            wire.current_state
                .take()
                .expect("fixture has current status"),
        )
        .expect("fixture status package is valid");
        let encoded = build_persona_credential_evidence_presentation(
            ZkPersonaCredentialEvidenceProofSetRef {
                issuer_envelope: &issuer,
                claim_root: &root,
                signed_validity: &validity,
                selected_claim: &claim,
            },
            &status,
            &fixture.request,
            150,
            &FixtureSigner(7),
        )
        .expect("fixture signer matches the proof key");
        let verifier = CountingVerifier {
            calls: AtomicUsize::new(0),
            reject: false,
        };
        let nonce = OnceNonce(AtomicBool::new(false));
        let accepted = verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &encoded,
            &fixture.request,
            fixture.policy(),
        );
        assert!(accepted.is_ok(), "built presentation must verify");
        let signing_digest = persona_credential_evidence_signing_digest(
            ZkPersonaCredentialEvidenceProofSetRef {
                issuer_envelope: &issuer,
                claim_root: &root,
                signed_validity: &validity,
                selected_claim: &claim,
            },
            &status,
            &fixture.request,
            150,
        )
        .expect("platform signing challenge uses the joined evidence");
        let platform_signature = FixtureSigner(7)
            .sign_digest(&signing_digest)
            .expect("fixture key signs the exact challenge");
        let externally_signed = build_persona_credential_evidence_presentation_with_signature(
            ZkPersonaCredentialEvidenceProofSetRef {
                issuer_envelope: &issuer,
                claim_root: &root,
                signed_validity: &validity,
                selected_claim: &claim,
            },
            &status,
            &fixture.request,
            150,
            platform_signature,
        )
        .expect("the same platform signature assembles a complete presentation");
        let external_nonce = OnceNonce(AtomicBool::new(false));
        assert!(verify_persona_credential_evidence_presentation_with(
            &verifier,
            &external_nonce,
            &externally_signed,
            &fixture.request,
            fixture.policy(),
        )
        .is_ok());
        assert_eq!(
            build_persona_credential_evidence_presentation_with_signature(
                ZkPersonaCredentialEvidenceProofSetRef {
                    issuer_envelope: &issuer,
                    claim_root: &root,
                    signed_validity: &validity,
                    selected_claim: &claim,
                },
                &status,
                &fixture.request,
                150,
                [0_u8; 64],
            )
            .err()
            .map(ZkPersonaCredentialEvidencePresentationError::reason),
            Some(ZkPersonaCredentialEvidencePresentationReason::HolderAuthenticationFailed),
        );
        assert_eq!(
            build_persona_credential_evidence_presentation(
                ZkPersonaCredentialEvidenceProofSetRef {
                    issuer_envelope: &issuer,
                    claim_root: &root,
                    signed_validity: &validity,
                    selected_claim: &claim
                },
                &status,
                &fixture.request,
                150,
                &FixtureSigner(8),
            )
            .err()
            .map(ZkPersonaCredentialEvidencePresentationError::reason),
            Some(ZkPersonaCredentialEvidencePresentationReason::HolderAuthenticationFailed),
        );
        assert_eq!(
            build_persona_credential_evidence_presentation(
                ZkPersonaCredentialEvidenceProofSetRef {
                    issuer_envelope: &issuer,
                    claim_root: &root,
                    signed_validity: &validity,
                    selected_claim: &claim
                },
                &status,
                &fixture.request,
                200,
                &FixtureSigner(7),
            )
            .err()
            .map(ZkPersonaCredentialEvidencePresentationError::reason),
            Some(ZkPersonaCredentialEvidencePresentationReason::RequestRejected),
        );
    }
}

#[test]
fn invalid_proof_or_noncanonical_wire_fails_closed() {
    let fixture = Fixture::new();
    let verifier = CountingVerifier {
        calls: AtomicUsize::new(0),
        reject: true,
    };
    let nonce = OnceNonce(AtomicBool::new(false));
    let encoded = fixture.presentation.encode_to_vec();
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &encoded,
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected),
    );
    assert!(!nonce.0.load(Ordering::SeqCst));
    let mut unknown = encoded;
    unknown.extend_from_slice(&[0x98, 0x06, 0x01]);
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &unknown,
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding),
    );
}

#[test]
fn policy_and_evidence_substitutions_fail_before_nonce_consumption() {
    let mut fixture = Fixture::new();
    let verifier = CountingVerifier {
        calls: AtomicUsize::new(0),
        reject: false,
    };
    let nonce = OnceNonce(AtomicBool::new(false));
    let encoded = fixture.presentation.encode_to_vec();
    fixture.issuers[0].x[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &encoded,
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected),
    );
    fixture.issuers[0].x[0] ^= 1;
    fixture.status_issuer.x[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &encoded,
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected),
    );
    fixture.status_issuer.x[0] ^= 1;
    fixture.claim_name_hash[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &encoded,
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected),
    );
    fixture.claim_name_hash[0] ^= 1;
    fixture.presentation.mode =
        EnumValue::from(pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1);
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &fixture.presentation.encode_to_vec(),
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::PolicyMismatch),
    );
    fixture.presentation.mode = EnumValue::from(
        pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1,
    );
    fixture.presentation.credential_hash_algorithm =
        EnumValue::from(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2);
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &fixture.presentation.encode_to_vec(),
            &fixture.request,
            fixture.policy(),
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::PolicyMismatch),
    );
    fixture.presentation.credential_hash_algorithm =
        EnumValue::from(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256);
    let mut expired_policy = fixture.policy();
    expired_policy.now_unix = 200;
    assert_eq!(
        verify_persona_credential_evidence_presentation_with(
            &verifier,
            &nonce,
            &encoded,
            &fixture.request,
            expired_policy,
        )
        .err()
        .map(ZkPersonaCredentialEvidencePresentationError::reason),
        Some(ZkPersonaCredentialEvidencePresentationReason::RequestRejected),
    );
    assert!(!nonce.0.load(Ordering::SeqCst));
}
