// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::sync::atomic::{AtomicUsize, Ordering};

use super::{
    verify_persona_credential_evidence_with, ZkPersonaCredentialEvidenceStageProof,
    ZkPersonaCredentialEvidenceStageVerifier, ZkPersonaCredentialEvidenceVerifyRequest,
};
use crate::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    issuer_status::{ZkIssuerStatusAuthority, ZkIssuerStatusFeed, ZkIssuerStatusListPointer},
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceRawPublicInputs,
        ZkPersonaCredentialEvidenceSourceStage,
    },
    proofs::{ZkProofBytes, ZkProofSuite},
};

const FIELD_BYTES: usize = 32;
const SIGNED_EDGE_FIELDS: usize = 194;
const SIGNED_VALIDITY_FIELDS: usize = 259;
const CLAIM_FIELDS: usize = 291;
const STATUS_FIELDS: usize = 292;
const PROFILE: ZkPersonaCredentialEvidenceMode =
    ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1;
const LANE: ZkCredentialHashAlgorithm = ZkCredentialHashAlgorithm::Sha256;

fn put_byte(bytes: &mut [u8], field: usize, value: u8) {
    bytes[field * FIELD_BYTES + FIELD_BYTES - 1] = value;
}

fn put_u64(bytes: &mut [u8], field: usize, value: u64) {
    let start = field * FIELD_BYTES + FIELD_BYTES - 8;
    bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn claim_bytes() -> Vec<u8> {
    let mut bytes = vec![0_u8; CLAIM_FIELDS * FIELD_BYTES];
    for (field, value) in [(0, 1), (32, 2), (64, 3), (96, 4), (128, 5), (162, 6)] {
        put_byte(&mut bytes, field, value);
    }
    put_u64(&mut bytes, 160, 100);
    put_u64(&mut bytes, 161, 200);
    put_byte(&mut bytes, 194, 1);
    put_byte(&mut bytes, 195, 18);
    put_byte(&mut bytes, 259, 7);
    bytes
}

fn status_bytes() -> Vec<u8> {
    let claim = claim_bytes();
    let mut bytes = vec![0_u8; STATUS_FIELDS * FIELD_BYTES];
    bytes[..194 * FIELD_BYTES].copy_from_slice(&claim[..194 * FIELD_BYTES]);
    put_byte(&mut bytes, 194, 8);
    put_u64(&mut bytes, 226, 1_000);
    put_byte(&mut bytes, 227, 9);
    put_byte(&mut bytes, 259, 10);
    put_byte(&mut bytes, 291, 1);
    bytes
}

fn signed_edge_bytes() -> Vec<u8> {
    claim_bytes()[..SIGNED_EDGE_FIELDS * FIELD_BYTES].to_vec()
}

fn signed_validity_bytes() -> Vec<u8> {
    let mut bytes = vec![0_u8; SIGNED_VALIDITY_FIELDS * FIELD_BYTES];
    bytes[..SIGNED_EDGE_FIELDS * FIELD_BYTES].copy_from_slice(&signed_edge_bytes());
    put_byte(&mut bytes, 194, 9);
    put_byte(&mut bytes, 226, 10);
    put_byte(&mut bytes, 258, 1);
    bytes
}

fn proof(
    stage: ZkPersonaCredentialEvidenceSourceStage,
    inputs: Vec<u8>,
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    let artifact_digest = match stage {
        ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope => [13; 32],
        ZkPersonaCredentialEvidenceSourceStage::ClaimRoot => [14; 32],
        ZkPersonaCredentialEvidenceSourceStage::SignedValidity => [15; 32],
        ZkPersonaCredentialEvidenceSourceStage::PublicClaim => [10; 32],
        ZkPersonaCredentialEvidenceSourceStage::PrivateClaim => [11; 32],
        ZkPersonaCredentialEvidenceSourceStage::CurrentState => [12; 32],
    };
    ZkPersonaCredentialEvidenceStageProof::try_from_parts(
        PROFILE,
        ZkProofSuite::PRODUCTION,
        crate::artifacts::ZkArtifactSetIdentity::from_bytes(
            *(ZkArtifactManifestDigest::from_bytes(artifact_digest)).as_bytes(),
        ),
        ZkProofBytes::try_from_bytes(vec![42])?,
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(stage.source_ref(LANE), inputs)?,
    )
}

struct Fixture {
    issuer_envelope: ZkPersonaCredentialEvidenceStageProof,
    claim_root: ZkPersonaCredentialEvidenceStageProof,
    signed_validity: ZkPersonaCredentialEvidenceStageProof,
    claim: ZkPersonaCredentialEvidenceStageProof,
    status: ZkPersonaCredentialEvidenceStageProof,
    trusted_feed: ZkIssuerStatusFeed,
    trusted_issuers: [ZkIssuerPublicKey; 1],
    status_issuer: ZkIssuerPublicKey,
    name_hash: [u8; 32],
}

impl Fixture {
    fn new() -> Result<Self, ZkError> {
        let issuer_envelope = proof(
            ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope,
            signed_edge_bytes(),
        )?;
        let claim_root = proof(
            ZkPersonaCredentialEvidenceSourceStage::ClaimRoot,
            signed_edge_bytes(),
        )?;
        let signed_validity = proof(
            ZkPersonaCredentialEvidenceSourceStage::SignedValidity,
            signed_validity_bytes(),
        )?;
        let claim = proof(
            ZkPersonaCredentialEvidenceSourceStage::PrivateClaim,
            claim_bytes(),
        )?;
        let status = proof(
            ZkPersonaCredentialEvidenceSourceStage::CurrentState,
            status_bytes(),
        )?;
        let trusted_feed = status.public_inputs().status_feed()?;
        let trusted_issuers = [claim
            .public_inputs()
            .join(ZkProofSuite::PRODUCTION)?
            .issuer_key];
        let mut name_hash = [0_u8; 32];
        name_hash[0] = 7;
        Ok(Self {
            issuer_envelope,
            claim_root,
            signed_validity,
            claim,
            status,
            trusted_feed,
            status_issuer: trusted_issuers[0],
            trusted_issuers,
            name_hash,
        })
    }

    fn request(&self, time: u64) -> Result<ZkPersonaCredentialEvidenceVerifyRequest<'_>, ZkError> {
        ZkPersonaCredentialEvidenceVerifyRequest::try_new(
            PROFILE,
            LANE,
            ZkProofSuite::PRODUCTION,
            &self.issuer_envelope,
            &self.claim_root,
            &self.signed_validity,
            &self.claim,
            &self.status,
            &self.trusted_issuers,
            self,
            &self.name_hash,
            &[18],
            time,
        )
    }
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
        if status_pointer.list_id != self.trusted_feed.list_id
            || status_pointer.url_hash != self.trusted_feed.url_hash
            || status_pointer.purpose != self.trusted_feed.purpose
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(ZkIssuerStatusFeed {
            root: self.trusted_feed.root,
            length: self.trusted_feed.length,
            list_id: self.trusted_feed.list_id,
            url_hash: self.trusted_feed.url_hash,
            purpose: self.trusted_feed.purpose,
        })
    }
}

struct CountingVerifier {
    calls: AtomicUsize,
    reject_at: Option<usize>,
}

impl CountingVerifier {
    fn new(reject_at: Option<usize>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            reject_at,
        }
    }
}

impl ZkPersonaCredentialEvidenceStageVerifier for CountingVerifier {
    fn verify_persona_credential_evidence_stage_proof(
        &self,
        proof: &ZkPersonaCredentialEvidenceStageProof,
    ) -> Result<(), ZkError> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        if self.reject_at == Some(call) {
            return Err(ZkError::new(ZkErrorReason::InvalidProof));
        }
        let expected_digest = match proof.public_inputs().stage() {
            ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope => [13; 32],
            ZkPersonaCredentialEvidenceSourceStage::ClaimRoot => [14; 32],
            ZkPersonaCredentialEvidenceSourceStage::SignedValidity => [15; 32],
            ZkPersonaCredentialEvidenceSourceStage::PublicClaim => [10; 32],
            ZkPersonaCredentialEvidenceSourceStage::PrivateClaim => [11; 32],
            ZkPersonaCredentialEvidenceSourceStage::CurrentState => [12; 32],
        };
        if proof.artifact_set_identity_sha256()
            != crate::artifacts::ZkArtifactSetIdentity::from_bytes(
                *(ZkArtifactManifestDigest::from_bytes(expected_digest)).as_bytes(),
            )
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(())
    }
}

#[test]
fn verified_evidence_requires_all_five_backend_proofs() -> Result<(), ZkError> {
    let fixture = Fixture::new()?;
    let backend = CountingVerifier::new(None);
    let result = verify_persona_credential_evidence_with(&backend, fixture.request(150)?)?;
    assert_eq!(backend.calls.load(Ordering::Relaxed), 5);
    assert_eq!(result.holder_key().x[0], 3);
    assert_eq!(result.mode(), PROFILE);
    assert_eq!(result.credential_hash_algorithm(), LANE);
    assert_eq!(result.proof_window().valid_until_unix(), 200);
    Ok(())
}

#[test]
fn rejected_backend_proof_cannot_produce_verified_evidence() -> Result<(), ZkError> {
    let fixture = Fixture::new()?;
    for rejected_call in [1, 2, 3, 4, 5] {
        let backend = CountingVerifier::new(Some(rejected_call));
        assert_eq!(
            verify_persona_credential_evidence_with(&backend, fixture.request(150)?)
                .err()
                .map(|error| error.reason()),
            Some(ZkErrorReason::InvalidProof)
        );
        assert_eq!(backend.calls.load(Ordering::Relaxed), rejected_call);
    }
    Ok(())
}

#[test]
fn stale_or_wrong_status_and_untrusted_issuer_fail_closed() -> Result<(), ZkError> {
    let mut fixture = Fixture::new()?;
    let backend = CountingVerifier::new(None);
    fixture.trusted_feed.root[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_with(&backend, fixture.request(150)?)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );
    fixture.trusted_feed.root[0] ^= 1;
    fixture.trusted_issuers[0].x[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_with(&backend, fixture.request(150)?)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::UntrustedIssuer)
    );
    fixture.trusted_issuers[0].x[0] ^= 1;
    fixture.status_issuer.x[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_with(&backend, fixture.request(150)?)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::UntrustedIssuer)
    );
    fixture.status_issuer.x[0] ^= 1;
    assert_eq!(
        verify_persona_credential_evidence_with(&backend, fixture.request(200)?)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );
    assert_eq!(backend.calls.load(Ordering::Relaxed), 15);
    Ok(())
}

#[test]
fn mismatched_profile_or_zero_artifact_identity_is_rejected() -> Result<(), ZkError> {
    let fixture = Fixture::new()?;
    assert_eq!(
        ZkPersonaCredentialEvidenceVerifyRequest::try_new(
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
            LANE,
            ZkProofSuite::PRODUCTION,
            &fixture.issuer_envelope,
            &fixture.claim_root,
            &fixture.signed_validity,
            &fixture.claim,
            &fixture.status,
            &fixture.trusted_issuers,
            &fixture,
            &fixture.name_hash,
            &[18],
            150,
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::StageMismatch)
    );
    assert_eq!(
        ZkPersonaCredentialEvidenceStageProof::try_from_parts(
            PROFILE,
            ZkProofSuite::PRODUCTION,
            crate::artifacts::ZkArtifactSetIdentity::from_bytes(
                *(ZkArtifactManifestDigest::from_bytes([0; 32])).as_bytes()
            ),
            ZkProofBytes::try_from_bytes(vec![42])?,
            ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
                ZkPersonaCredentialEvidenceSourceStage::PrivateClaim.source_ref(LANE),
                claim_bytes(),
            )?,
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
    // Each circuit has its own compiled program and artifact identity. A
    // different nonzero digest is valid at this boundary; the injected
    // verifier must resolve and authenticate each circuit independently.
    assert_ne!(
        fixture.claim.artifact_set_identity_sha256(),
        fixture.status.artifact_set_identity_sha256()
    );
    assert!(fixture.request(150).is_ok());
    Ok(())
}

#[test]
fn wrong_current_state_artifact_identity_fails_at_backend_boundary() -> Result<(), ZkError> {
    let mut fixture = Fixture::new()?;
    fixture.status.artifact_set_identity_sha256 =
        crate::artifacts::ZkArtifactSetIdentity::from_bytes(
            *(ZkArtifactManifestDigest::from_bytes([13; 32])).as_bytes(),
        );
    let backend = CountingVerifier::new(None);
    assert_eq!(
        verify_persona_credential_evidence_with(&backend, fixture.request(150)?)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
    assert_eq!(backend.calls.load(Ordering::Relaxed), 5);
    Ok(())
}
