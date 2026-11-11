// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opt-in verification of fresh prepared proofs with the linked BBAPI library.

#![cfg(feature = "native")]

use std::{
    env, fs,
    io::{self, Read},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    issuer_status::{ZkIssuerStatusAuthority, ZkIssuerStatusFeed, ZkIssuerStatusListPointer},
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        verify_persona_credential_evidence_with, ZkPersonaCredentialEvidenceMode,
        ZkPersonaCredentialEvidenceRawPublicInputs, ZkPersonaCredentialEvidenceReplayChallenge,
        ZkPersonaCredentialEvidenceReplayError, ZkPersonaCredentialEvidenceReplayStore,
        ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceStageProof,
        ZkPersonaCredentialEvidenceStageVerifier, ZkPersonaCredentialEvidenceVerifyRequest,
    },
    proofs::{ZkProofBytes, ZkProofSuite, ZkWitness},
};
use reallyme_zk_artifacts::{
    exact_source_artifact_identity, ArtifactKind, Digest32, VerifiedArtifactBytes,
};
use reallyme_zk_backend_bb::{
    BarretenbergProverCrs, BbExactCircuitArtifacts, BbPersonaCredentialEvidenceStageProveRequest,
    NativeBarretenbergBackend,
};
use reallyme_zk_proto_codec::{
    persona_credential_evidence_auth::{
        ZkPersonaCredentialEvidenceRequestProtocol, ZkPersonaCredentialEvidenceResponseMode,
        ZkPersonaCredentialEvidenceVerifierRequest,
    },
    persona_credential_evidence_presentation::{
        build_persona_credential_evidence_presentation,
        verify_persona_credential_evidence_presentation_with,
        ZkPersonaCredentialEvidenceHolderSigner, ZkPersonaCredentialEvidencePresentationPolicy,
        ZkPersonaCredentialEvidencePresentationReason, ZkPersonaCredentialEvidenceProofSetRef,
        ZkPersonaCredentialEvidenceSignerError,
    },
};
use thiserror::Error;
use zeroize::Zeroizing;

const EVIDENCE_ENV: &str = "REALLYME_PREPARED_LINKED_EVIDENCE";
const CRS_ENV: &str = "BB_CRS_DIR";
const EXPECTED_PROOFS: usize = 20;
const PROVER_G1_BYTES: usize = 67_108_928;
const VERIFIER_G2_BYTES: usize = 128;

#[derive(Debug, Error)]
enum PreparedLinkedTestError {
    #[error("prepared linked evidence layout invalid")]
    Layout,
    #[error("prepared linked evidence did not reject tampering")]
    TamperingAccepted,
    #[error("prepared linked evidence I/O failed")]
    Io(#[from] io::Error),
    #[error("prepared linked evidence verification failed")]
    Zk(#[from] ZkError),
    #[error("prepared signed presentation failed")]
    Presentation,
}

/// The test-only signing keys match the deterministic Noir fixture generator.
struct FixtureHolderSigner(u8);

impl ZkPersonaCredentialEvidenceHolderSigner for FixtureHolderSigner {
    fn sign_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], ZkPersonaCredentialEvidenceSignerError> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        secret[31] = self.0;
        let digest = crypto_p256::P256Sha256Digest::new(*digest);
        let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)
            .map_err(|_| ZkPersonaCredentialEvidenceSignerError)?;
        crypto_p256::p256_ecdsa_der_to_jose_signature(&der)
            .map_err(|_| ZkPersonaCredentialEvidenceSignerError)
    }
}

struct OnceReplay(AtomicBool);

impl ZkPersonaCredentialEvidenceReplayStore for OnceReplay {
    fn consume(
        &self,
        _challenge: &ZkPersonaCredentialEvidenceReplayChallenge,
        _now_unix: u64,
    ) -> Result<(), ZkPersonaCredentialEvidenceReplayError> {
        if self.0.swap(true, Ordering::SeqCst) {
            Err(ZkPersonaCredentialEvidenceReplayError::already_consumed())
        } else {
            Ok(())
        }
    }
}

fn authenticated_request() -> ZkPersonaCredentialEvidenceVerifierRequest {
    ZkPersonaCredentialEvidenceVerifierRequest {
        protocol: ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp,
        response_mode: ZkPersonaCredentialEvidenceResponseMode::DirectPostJwt,
        nonce: [51; 32],
        audience_sha256: [52; 32],
        transaction_data_sha256: [53; 32],
        requested_claims_sha256: [54; 32],
        verifier_policy_sha256: [55; 32],
        transport_context_sha256: [56; 32],
        issued_at_unix: 1_800_000_000,
        expires_at_unix: 1_800_000_100,
    }
}

struct PreparedEvidence {
    lane: ZkCredentialHashAlgorithm,
    mode: ZkPersonaCredentialEvidenceMode,
    stage: ZkPersonaCredentialEvidenceSourceStage,
    proof: ZkPersonaCredentialEvidenceStageProof,
    artifacts: BbExactCircuitArtifacts,
}

struct PreparedTestVerifier<'a> {
    backend: &'a NativeBarretenbergBackend,
    evidence: &'a [PreparedEvidence],
}

struct SyntheticStatusAuthority {
    feed: ZkIssuerStatusFeed,
    issuer: ZkIssuerPublicKey,
}

impl ZkIssuerStatusAuthority for SyntheticStatusAuthority {
    fn current_feed_for_issuer(
        &self,
        issuer_key: &ZkIssuerPublicKey,
        status_pointer: &ZkIssuerStatusListPointer,
        _verification_time_unix: u64,
    ) -> Result<ZkIssuerStatusFeed, ZkError> {
        if issuer_key != &self.issuer {
            return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
        }
        if status_pointer.list_id != self.feed.list_id
            || status_pointer.url_hash != self.feed.url_hash
            || status_pointer.purpose != self.feed.purpose
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

impl ZkPersonaCredentialEvidenceStageVerifier for PreparedTestVerifier<'_> {
    fn verify_persona_credential_evidence_stage_proof(
        &self,
        proof: &ZkPersonaCredentialEvidenceStageProof,
    ) -> Result<(), ZkError> {
        let artifacts = self
            .evidence
            .iter()
            .find(|entry| {
                entry.mode == proof.mode()
                    && entry.proof.public_inputs().circuit_ref()
                        == proof.public_inputs().circuit_ref()
            })
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        self.backend
            .verify_persona_credential_evidence_stage_exact_circuit(proof, &artifacts.artifacts)
    }
}

#[test]
#[ignore = "requires freshly generated prepared proofs and pinned native CRS"]
fn fresh_prepared_proofs_verify_through_linked_library() -> Result<(), PreparedLinkedTestError> {
    let evidence_path = env::var_os(EVIDENCE_ENV).ok_or(PreparedLinkedTestError::Layout)?;
    let crs_dir = env::var_os(CRS_ENV).ok_or(PreparedLinkedTestError::Layout)?;
    let mut g1 = vec![0_u8; PROVER_G1_BYTES];
    fs::File::open(Path::new(&crs_dir).join("bn254_g1.dat"))?.read_exact(&mut g1)?;
    let g2_bytes = fs::read(Path::new(&crs_dir).join("bn254_g2.dat"))?;
    let g2 = <[u8; VERIFIER_G2_BYTES]>::try_from(g2_bytes)
        .map_err(|_| PreparedLinkedTestError::Layout)?;
    let backend = NativeBarretenbergBackend::try_new()?;
    backend.initialize_prover_crs(BarretenbergProverCrs::try_from_pinned_slices(&g1, &g2)?)?;

    let evidence = fs::read_to_string(evidence_path)?;
    let diagnostic_source_digest = Digest32::sha256(evidence.as_bytes());
    let mut count = 0_usize;
    let mut verified = Vec::new();
    for line in evidence.lines() {
        let mut parts = line.split('\t');
        let lane = match parts.next() {
            Some("sha256") => ZkCredentialHashAlgorithm::Sha256,
            Some("poseidon2") => ZkCredentialHashAlgorithm::Poseidon2,
            _ => return Err(PreparedLinkedTestError::Layout),
        };
        let mode = match parts.next() {
            Some("public") => ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
            Some("private") => ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
            _ => return Err(PreparedLinkedTestError::Layout),
        };
        let stage = match parts.next() {
            Some("issuer_envelope") => ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope,
            Some("claim_root") => ZkPersonaCredentialEvidenceSourceStage::ClaimRoot,
            Some("signed_validity") => ZkPersonaCredentialEvidenceSourceStage::SignedValidity,
            Some("public_claim") => ZkPersonaCredentialEvidenceSourceStage::PublicClaim,
            Some("private_claim") => ZkPersonaCredentialEvidenceSourceStage::PrivateClaim,
            Some("current_state") => ZkPersonaCredentialEvidenceSourceStage::CurrentState,
            _ => return Err(PreparedLinkedTestError::Layout),
        };
        let artifact_path = parts.next().ok_or(PreparedLinkedTestError::Layout)?;
        let vk_path = parts.next().ok_or(PreparedLinkedTestError::Layout)?;
        let proof_path = parts.next().ok_or(PreparedLinkedTestError::Layout)?;
        let public_inputs_path = parts.next().ok_or(PreparedLinkedTestError::Layout)?;
        let witness_path = parts.next().ok_or(PreparedLinkedTestError::Layout)?;
        if parts.next().is_some() {
            return Err(PreparedLinkedTestError::Layout);
        }
        let artifact_bytes = fs::read(artifact_path)?;
        let vk_bytes = fs::read(vk_path)?;
        let bytecode_digest = Digest32::sha256(&artifact_bytes);
        let vk_digest = Digest32::sha256(&vk_bytes);
        // This test uses an untrusted diagnostic source digest, but derives a
        // separate artifact identity from each circuit and binary pair. The
        // release resolver must instead use the sealed source lock and index.
        let circuit_ref = stage.source_ref(lane);
        let identity = exact_source_artifact_identity(
            circuit_ref,
            diagnostic_source_digest,
            bytecode_digest,
            vk_digest,
        )?;
        let artifacts = BbExactCircuitArtifacts::try_new(
            circuit_ref,
            identity,
            VerifiedArtifactBytes::try_from_bytes(
                ArtifactKind::AcirBytecode,
                artifact_bytes,
                bytecode_digest,
            )?,
            VerifiedArtifactBytes::try_from_bytes(
                ArtifactKind::VerificationKey,
                vk_bytes,
                vk_digest,
            )?,
        )?;
        let proof_bytes = fs::read(proof_path)?;
        let public_inputs_bytes = fs::read(public_inputs_path)?;
        let proof = ZkPersonaCredentialEvidenceStageProof::try_from_parts(
            mode,
            ZkProofSuite::PRODUCTION,
            identity,
            ZkProofBytes::try_copy_from_slice(&proof_bytes)?,
            ZkPersonaCredentialEvidenceRawPublicInputs::try_copy_from_slice(
                circuit_ref,
                &public_inputs_bytes,
            )?,
        )?;
        backend.verify_persona_credential_evidence_stage_exact_circuit(&proof, &artifacts)?;
        let witness = ZkWitness::try_from_noir_witness_stack_v1_zeroizing(
            circuit_ref,
            Zeroizing::new(fs::read(witness_path)?),
        )?;
        let linked = backend.prove_persona_credential_evidence_stage_exact_circuit(
            BbPersonaCredentialEvidenceStageProveRequest {
                mode,
                circuit_ref,
                proof_suite: ZkProofSuite::PRODUCTION,
                artifact_identity: identity.into(),
                artifacts: &artifacts,
                witness: &witness,
            },
        )?;
        if linked.public_inputs().as_bytes() != public_inputs_bytes {
            return Err(PreparedLinkedTestError::Layout);
        }
        let mut tampered_bytes = proof_bytes;
        let first = tampered_bytes
            .first_mut()
            .ok_or(PreparedLinkedTestError::Layout)?;
        *first ^= 1;
        let tampered = ZkPersonaCredentialEvidenceStageProof::try_from_parts(
            mode,
            ZkProofSuite::PRODUCTION,
            identity,
            ZkProofBytes::try_from_bytes(tampered_bytes)?,
            ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
                circuit_ref,
                public_inputs_bytes,
            )?,
        )?;
        let reason = backend
            .verify_persona_credential_evidence_stage_exact_circuit(&tampered, &artifacts)
            .err()
            .map(|error| error.reason());
        if !matches!(
            reason,
            Some(ZkErrorReason::InvalidProof | ZkErrorReason::InvalidProofEncoding)
        ) {
            return Err(PreparedLinkedTestError::TamperingAccepted);
        }
        verified.push(PreparedEvidence {
            lane,
            mode,
            stage,
            proof,
            artifacts,
        });
        count = count
            .checked_add(1)
            .ok_or(PreparedLinkedTestError::Layout)?;
    }
    if count != EXPECTED_PROOFS {
        return Err(PreparedLinkedTestError::Layout);
    }
    let verifier = PreparedTestVerifier {
        backend: &backend,
        evidence: &verified,
    };
    for lane in [
        ZkCredentialHashAlgorithm::Sha256,
        ZkCredentialHashAlgorithm::Poseidon2,
    ] {
        for mode in [
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
        ] {
            let claim_stage = match mode {
                ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
                    ZkPersonaCredentialEvidenceSourceStage::PublicClaim
                }
                ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
                    ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
                }
            };
            let claim = verified
                .iter()
                .find(|entry| {
                    entry.lane == lane && entry.mode == mode && entry.stage == claim_stage
                })
                .ok_or(PreparedLinkedTestError::Layout)?;
            let issuer_envelope = verified
                .iter()
                .find(|entry| {
                    entry.lane == lane
                        && entry.mode == mode
                        && entry.stage == ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
                })
                .ok_or(PreparedLinkedTestError::Layout)?;
            let claim_root = verified
                .iter()
                .find(|entry| {
                    entry.lane == lane
                        && entry.mode == mode
                        && entry.stage == ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
                })
                .ok_or(PreparedLinkedTestError::Layout)?;
            let signed_validity = verified
                .iter()
                .find(|entry| {
                    entry.lane == lane
                        && entry.mode == mode
                        && entry.stage == ZkPersonaCredentialEvidenceSourceStage::SignedValidity
                })
                .ok_or(PreparedLinkedTestError::Layout)?;
            let status = verified
                .iter()
                .find(|entry| {
                    entry.lane == lane
                        && entry.mode == mode
                        && entry.stage == ZkPersonaCredentialEvidenceSourceStage::CurrentState
                })
                .ok_or(PreparedLinkedTestError::Layout)?;
            if claim.proof.artifact_set_identity_sha256()
                == status.proof.artifact_set_identity_sha256()
            {
                return Err(PreparedLinkedTestError::Layout);
            }
            // Synthetic fixture policy: real callers authenticate this feed
            // independently and enforce a durable freshness/rollback floor.
            let issuer = claim
                .proof
                .public_inputs()
                .join(ZkProofSuite::PRODUCTION)?
                .issuer_key;
            let issuers = [issuer];
            let authority = SyntheticStatusAuthority {
                feed: status.proof.public_inputs().status_feed()?,
                issuer,
            };
            let name_hash = *Digest32::sha256(b"over_18").as_bytes();
            let request = ZkPersonaCredentialEvidenceVerifyRequest::try_new(
                mode,
                lane,
                ZkProofSuite::PRODUCTION,
                &issuer_envelope.proof,
                &claim_root.proof,
                &signed_validity.proof,
                &claim.proof,
                &status.proof,
                &issuers,
                &authority,
                &name_hash,
                b"true",
                1_800_000_001,
            )?;
            let result = verify_persona_credential_evidence_with(&verifier, request)?;
            if result.mode() != mode || result.credential_hash_algorithm() != lane {
                return Err(PreparedLinkedTestError::Layout);
            }
            let mut wrong_feed = status.proof.public_inputs().status_feed()?;
            wrong_feed.root[0] ^= 1;
            let wrong_authority = SyntheticStatusAuthority {
                feed: wrong_feed,
                issuer,
            };
            let wrong_status = ZkPersonaCredentialEvidenceVerifyRequest::try_new(
                mode,
                lane,
                ZkProofSuite::PRODUCTION,
                &issuer_envelope.proof,
                &claim_root.proof,
                &signed_validity.proof,
                &claim.proof,
                &status.proof,
                &issuers,
                &wrong_authority,
                &name_hash,
                b"true",
                1_800_000_001,
            )?;
            if verify_persona_credential_evidence_with(&verifier, wrong_status)
                .err()
                .map(|error| error.reason())
                != Some(ZkErrorReason::BindingMismatch)
            {
                return Err(PreparedLinkedTestError::TamperingAccepted);
            }

            // Exercise the entire acceptance boundary with actual linked
            // proofs. The signer uses the exact public or one-time holder key
            // from the deterministic fixture, and the verifier supplies its
            // own request, issuer policy, current feed, and replay store.
            let signer = FixtureHolderSigner(match mode {
                ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => 17,
                ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => 19,
            });
            let authenticated = authenticated_request();
            let presentation = build_persona_credential_evidence_presentation(
                ZkPersonaCredentialEvidenceProofSetRef {
                    issuer_envelope: &issuer_envelope.proof,
                    claim_root: &claim_root.proof,
                    signed_validity: &signed_validity.proof,
                    selected_claim: &claim.proof,
                },
                &status.proof,
                &authenticated,
                1_800_000_001,
                &signer,
            )
            .map_err(|_| PreparedLinkedTestError::Presentation)?;
            let replay = OnceReplay(AtomicBool::new(false));
            let accepted = verify_persona_credential_evidence_presentation_with(
                &verifier,
                &replay,
                &presentation,
                &authenticated,
                ZkPersonaCredentialEvidencePresentationPolicy {
                    mode,
                    credential_hash_algorithm: lane,
                    trusted_issuers: &issuers,
                    status_authority: &authority,
                    expected_claim_name_hash: &name_hash,
                    expected_claim_value: b"true",
                    now_unix: 1_800_000_001,
                },
            )
            .map_err(|_| PreparedLinkedTestError::Presentation)?;
            if accepted.evidence().mode() != mode {
                return Err(PreparedLinkedTestError::Presentation);
            }
            let replay_reason = verify_persona_credential_evidence_presentation_with(
                &verifier,
                &replay,
                &presentation,
                &authenticated,
                ZkPersonaCredentialEvidencePresentationPolicy {
                    mode,
                    credential_hash_algorithm: lane,
                    trusted_issuers: &issuers,
                    status_authority: &authority,
                    expected_claim_name_hash: &name_hash,
                    expected_claim_value: b"true",
                    now_unix: 1_800_000_001,
                },
            )
            .err()
            .map(|error| error.reason());
            if replay_reason != Some(ZkPersonaCredentialEvidencePresentationReason::NonceReplay) {
                return Err(PreparedLinkedTestError::TamperingAccepted);
            }
            let mut wrong_request = authenticated_request();
            wrong_request.requested_claims_sha256[0] ^= 1;
            let wrong_binding = verify_persona_credential_evidence_presentation_with(
                &verifier,
                &OnceReplay(AtomicBool::new(false)),
                &presentation,
                &wrong_request,
                ZkPersonaCredentialEvidencePresentationPolicy {
                    mode,
                    credential_hash_algorithm: lane,
                    trusted_issuers: &issuers,
                    status_authority: &authority,
                    expected_claim_name_hash: &name_hash,
                    expected_claim_value: b"true",
                    now_unix: 1_800_000_001,
                },
            )
            .err()
            .map(|error| error.reason());
            if wrong_binding != Some(ZkPersonaCredentialEvidencePresentationReason::PolicyMismatch)
            {
                return Err(PreparedLinkedTestError::TamperingAccepted);
            }
            let mut revoked_feed = status.proof.public_inputs().status_feed()?;
            revoked_feed.root[0] ^= 1;
            let revoked_authority = SyntheticStatusAuthority {
                feed: revoked_feed,
                issuer,
            };
            let stale_status = verify_persona_credential_evidence_presentation_with(
                &verifier,
                &OnceReplay(AtomicBool::new(false)),
                &presentation,
                &authenticated,
                ZkPersonaCredentialEvidencePresentationPolicy {
                    mode,
                    credential_hash_algorithm: lane,
                    trusted_issuers: &issuers,
                    status_authority: &revoked_authority,
                    expected_claim_name_hash: &name_hash,
                    expected_claim_value: b"true",
                    now_unix: 1_800_000_001,
                },
            )
            .err()
            .map(|error| error.reason());
            if stale_status != Some(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected)
            {
                return Err(PreparedLinkedTestError::TamperingAccepted);
            }
            let wrong_signer = FixtureHolderSigner(23);
            let wrong_key_result = build_persona_credential_evidence_presentation(
                ZkPersonaCredentialEvidenceProofSetRef {
                    issuer_envelope: &issuer_envelope.proof,
                    claim_root: &claim_root.proof,
                    signed_validity: &signed_validity.proof,
                    selected_claim: &claim.proof,
                },
                &status.proof,
                &authenticated,
                1_800_000_001,
                &wrong_signer,
            )
            .err()
            .map(|error| error.reason());
            if wrong_key_result
                != Some(ZkPersonaCredentialEvidencePresentationReason::HolderAuthenticationFailed)
            {
                return Err(PreparedLinkedTestError::TamperingAccepted);
            }
        }
    }
    Ok(())
}
