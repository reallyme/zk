// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::{collections::BTreeSet, sync::Mutex};

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{persona_evidence::{derive_persona_credential_evidence_binding, ZkPersonaCredentialEvidenceBindingInputs, ZkPersonaCredentialEvidenceStageVerifier, ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceStageProof, ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceValidityWindow, ZkPersonaCredentialEvidenceReplayChallenge, ZkPersonaCredentialEvidenceReplayError, ZkPersonaCredentialEvidenceReplayStore, ZkPersonaCredentialEvidenceSubjectPublicKey}, errors::{ZkError, ZkErrorReason}, circuits::{ZkCredentialHashAlgorithm}, keys::{ZkIssuerPublicKey}, issuer_status::{ZkIssuerStatusAuthority, ZkIssuerStatusFeed, ZkIssuerStatusListPointer}, proofs::{ZkProofSuite}};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

use super::{
    build_persona_credential_evidence_presentation, build_persona_credential_evidence_presentation_with_signature,
    canonical_credential_evidence_bytes, persona_credential_evidence_signing_digest,
    verify_persona_credential_evidence_presentation_with, ZkPersonaCredentialEvidenceProofSetRef, ZkPersonaCredentialEvidenceHolderSigner,
    ZkPersonaCredentialEvidencePresentationError, ZkPersonaCredentialEvidencePresentationPolicy, ZkPersonaCredentialEvidencePresentationReason,
    ZkPersonaCredentialEvidenceSignerError,
};
use crate::{
    artifact::{circuit_ref_to_proto, proof_suite_to_proto},
    persona_credential_evidence_auth::{
        decode_persona_credential_evidence_verifier_request, ZkPersonaCredentialEvidencePresentationAuth, ZkPersonaCredentialEvidenceRequestProtocol,
        ZkPersonaCredentialEvidenceResponseMode, ZkPersonaCredentialEvidenceVerifierRequest,
    },
    persona_credential_evidence_proof_set::{
        decode_persona_credential_evidence_proof_set, MAX_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SET_BYTES,
    },
    persona_credential_evidence_stage_proof::persona_credential_evidence_stage_proof_from_proto,
};

struct FixtureSigner(u8);

impl ZkPersonaCredentialEvidenceHolderSigner for FixtureSigner {
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], ZkPersonaCredentialEvidenceSignerError> {
        let secret = Zeroizing::new([self.0; 32]);
        let digest = crypto_p256::P256Sha256Digest::new(*digest);
        let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)
            .map_err(|_| ZkPersonaCredentialEvidenceSignerError)?;
        crypto_p256::p256_ecdsa_der_to_jose_signature(&der).map_err(|_| ZkPersonaCredentialEvidenceSignerError)
    }
}

const FIELD_BYTES: usize = 32;
const PROFILE: ZkPersonaCredentialEvidenceMode = ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1;

fn put_bytes(bytes: &mut [u8], start: usize, value: &[u8; 32]) {
    for (offset, byte) in value.iter().enumerate() {
        bytes[(start + offset) * FIELD_BYTES + FIELD_BYTES - 1] = *byte;
    }
}

fn put_u64(bytes: &mut [u8], field: usize, value: u64) {
    let start = field * FIELD_BYTES + FIELD_BYTES - 8;
    bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_byte(bytes: &mut [u8], field: usize, value: u8) {
    bytes[field * FIELD_BYTES + FIELD_BYTES - 1] = value;
}

fn package(
    stage: ZkPersonaCredentialEvidenceSourceStage,
    mode: ZkPersonaCredentialEvidenceMode,
    fields: Vec<u8>,
) -> pb::ZkPersonaCredentialEvidenceStageProof {
    let mode = match mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
        }
    };
    let slot = match stage {
        ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE
        }
        ZkPersonaCredentialEvidenceSourceStage::ClaimRoot => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT
        }
        ZkPersonaCredentialEvidenceSourceStage::SignedValidity => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY
        }
        ZkPersonaCredentialEvidenceSourceStage::PrivateClaim => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM
        }
        ZkPersonaCredentialEvidenceSourceStage::CurrentState => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE
        }
        ZkPersonaCredentialEvidenceSourceStage::PublicClaim => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM
        }
    };
    let circuit_ref = circuit_ref_to_proto(stage.source_ref(ZkCredentialHashAlgorithm::Sha256));
    pb::ZkPersonaCredentialEvidenceStageProof {
        mode: EnumValue::from(mode),
        proof_slot: EnumValue::from(slot),
        circuit_ref: MessageField::some(circuit_ref.clone()),
        proof: vec![42],
        public_inputs: MessageField::some(pb::ZkPersonaCredentialEvidenceRawPublicInputs {
            mode: EnumValue::from(mode),
            proof_slot: EnumValue::from(slot),
            circuit_ref: MessageField::some(circuit_ref),
            raw_fields: fields,
            __buffa_unknown_fields: Default::default(),
        }),
        artifact_set_identity_sha256: MessageField::some(pb::ZkArtifactSetIdentity {
            value: vec![11; 32],
            __buffa_unknown_fields: Default::default(),
        }),
        proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
        __buffa_unknown_fields: Default::default(),
    }
}

fn request() -> ZkPersonaCredentialEvidenceVerifierRequest {
    ZkPersonaCredentialEvidenceVerifierRequest {
        protocol: ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp,
        response_mode: ZkPersonaCredentialEvidenceResponseMode::DirectPostJwt,
        nonce: [1; 32],
        audience_sha256: [2; 32],
        transaction_data_sha256: [3; 32],
        requested_claims_sha256: [4; 32],
        verifier_policy_sha256: [5; 32],
        transport_context_sha256: [6; 32],
        issued_at_unix: 100,
        expires_at_unix: 200,
    }
}

struct CountingVerifier {
    calls: AtomicUsize,
    reject: bool,
}

impl ZkPersonaCredentialEvidenceStageVerifier for CountingVerifier {
    fn verify_persona_credential_evidence_stage_proof(&self, _proof: &ZkPersonaCredentialEvidenceStageProof) -> Result<(), ZkError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.reject {
            Err(ZkError::new(ZkErrorReason::InvalidProof))
        } else {
            Ok(())
        }
    }
}

struct OnceNonce(AtomicBool);

impl ZkPersonaCredentialEvidenceReplayStore for OnceNonce {
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

struct UnavailableNonce;

struct DistinctNonces(Mutex<BTreeSet<[u8; 32]>>);

impl ZkPersonaCredentialEvidenceReplayStore for DistinctNonces {
    fn consume(
        &self,
        challenge: &ZkPersonaCredentialEvidenceReplayChallenge,
        _now_unix: u64,
    ) -> Result<(), ZkPersonaCredentialEvidenceReplayError> {
        let mut seen = self.0.lock().expect("test replay store lock is available");
        if seen.insert(*challenge.nonce()) {
            Ok(())
        } else {
            Err(ZkPersonaCredentialEvidenceReplayError::already_consumed())
        }
    }
}

impl ZkPersonaCredentialEvidenceReplayStore for UnavailableNonce {
    fn consume(
        &self,
        _challenge: &ZkPersonaCredentialEvidenceReplayChallenge,
        _now_unix: u64,
    ) -> Result<(), ZkPersonaCredentialEvidenceReplayError> {
        Err(ZkPersonaCredentialEvidenceReplayError::store_unavailable())
    }
}

struct Fixture {
    mode: ZkPersonaCredentialEvidenceMode,
    holder_secret: u8,
    presentation: pb::ZkPersonaCredentialEvidencePresentation,
    request: ZkPersonaCredentialEvidenceVerifierRequest,
    status: ZkIssuerStatusFeed,
    issuers: [ZkIssuerPublicKey; 1],
    status_issuer: ZkIssuerPublicKey,
    claim_name_hash: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        Self::new_for_profile(PROFILE)
    }

    fn new_for_profile(mode: ZkPersonaCredentialEvidenceMode) -> Self {
        Self::new_for_token(mode, 7)
    }

    fn new_for_token(mode: ZkPersonaCredentialEvidenceMode, holder_secret: u8) -> Self {
        let secret = Zeroizing::new([holder_secret; 32]);
        let (compressed, _) = crypto_p256::generate_p256_keypair_from_secret_key(&secret)
            .expect("test P-256 secret is valid");
        let key = crypto_p256::decompress_public_key(&compressed).expect("test P-256 key is valid");
        let x: [u8; 32] = key[1..33].try_into().expect("P-256 x is 32 bytes");
        let y: [u8; 32] = key[33..65].try_into().expect("P-256 y is 32 bytes");
        let mut claim = vec![0_u8; 291 * FIELD_BYTES];
        put_bytes(&mut claim, 0, &[1; 32]);
        put_bytes(&mut claim, 32, &[2; 32]);
        put_bytes(&mut claim, 64, &x);
        put_bytes(&mut claim, 96, &y);
        put_bytes(&mut claim, 128, &[holder_secret; 32]);
        put_u64(&mut claim, 160, 100);
        put_u64(&mut claim, 161, 200);
        // Derive the exact PRECB2 join used by the circuits. A whole-proof
        // uniqueness test could otherwise hide a stable credential binding.
        let credential_binding = derive_persona_credential_evidence_binding(
            ZkCredentialHashAlgorithm::Sha256,
            ZkPersonaCredentialEvidenceBindingInputs {
                issuer_key: ZkIssuerPublicKey {
                    x: [1; 32],
                    y: [2; 32],
                },
                envelope_hash: [11; 32],
                claims_root: [12; 32],
                subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
                    x: [13; 32],
                    y: [14; 32],
                },
                holder_key: ZkPersonaCredentialEvidenceHolderPublicKey { x, y },
                token_nonce: [holder_secret; 32],
                proof_window: ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 200)
                    .expect("test proof interval is valid"),
            },
        )
        .expect("test credential join derives");
        put_bytes(&mut claim, 162, &credential_binding);
        put_byte(&mut claim, 194, 1);
        put_byte(&mut claim, 195, 18);
        put_bytes(&mut claim, 259, &[7; 32]);
        let mut status_inputs = vec![0_u8; 292 * FIELD_BYTES];
        status_inputs[..194 * FIELD_BYTES].copy_from_slice(&claim[..194 * FIELD_BYTES]);
        put_bytes(&mut status_inputs, 194, &[8; 32]);
        put_u64(&mut status_inputs, 226, 1_000);
        put_bytes(&mut status_inputs, 227, &[9; 32]);
        put_bytes(&mut status_inputs, 259, &[10; 32]);
        put_byte(&mut status_inputs, 291, 1);
        let claim_stage = match mode {
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => ZkPersonaCredentialEvidenceSourceStage::PublicClaim,
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => ZkPersonaCredentialEvidenceSourceStage::PrivateClaim,
        };
        let claim_package = package(claim_stage, mode, claim);
        let status_package = package(ZkPersonaCredentialEvidenceSourceStage::CurrentState, mode, status_inputs);
        let signed_edge = claim_package
            .public_inputs
            .as_option()
            .expect("test claim public inputs exist")
            .raw_fields[..194 * FIELD_BYTES]
            .to_vec();
        let issuer_package = package(
            ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope,
            mode,
            signed_edge.clone(),
        );
        let root_package = package(
            ZkPersonaCredentialEvidenceSourceStage::ClaimRoot,
            mode,
            signed_edge.clone(),
        );
        let mut validity_inputs = vec![0_u8; 259 * FIELD_BYTES];
        validity_inputs[..194 * FIELD_BYTES].copy_from_slice(&signed_edge);
        put_bytes(&mut validity_inputs, 194, &[9; 32]);
        put_bytes(&mut validity_inputs, 226, &[10; 32]);
        put_byte(&mut validity_inputs, 258, 1);
        let validity_package = package(
            ZkPersonaCredentialEvidenceSourceStage::SignedValidity,
            mode,
            validity_inputs,
        );
        let request = request();
        let evidence = canonical_credential_evidence_bytes(
            &issuer_package,
            &root_package,
            &validity_package,
            &claim_package,
        );
        let auth = ZkPersonaCredentialEvidencePresentationAuth::from_canonical_packages(
            mode,
            &evidence,
            &status_package.encode_to_vec(),
            &request,
        )
        .expect("test authentication transcript is valid");
        let digest = auth.signing_digest().expect("test digest is valid");
        let digest = crypto_p256::P256Sha256Digest::new(*digest.as_bytes());
        let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)
            .expect("test signature succeeds");
        let signature =
            crypto_p256::p256_ecdsa_der_to_jose_signature(&der).expect("test signature converts");
        let verifier_request =
            decode_persona_credential_evidence_verifier_request(&request.encode().expect("test request encodes"))
                .expect("test request decodes");
        let auth_wire = buffa::DecodeOptions::new()
            .decode_from_slice::<pb::ZkPersonaCredentialEvidencePresentationAuthV1>(
                &auth.encode().expect("test auth encodes"),
            )
            .expect("test auth decodes");
        Self {
            mode,
            holder_secret,
            presentation: pb::ZkPersonaCredentialEvidencePresentation {
                mode: EnumValue::from(match mode {
                    ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1,
                    ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1,
                }),
                credential_hash_algorithm: EnumValue::from(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256),
                proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
                issuer_envelope: MessageField::some(issuer_package),
                claim_root: MessageField::some(root_package),
                signed_validity: MessageField::some(validity_package),
                selected_claim: MessageField::some(claim_package),
                current_state: MessageField::some(status_package),
                verifier_request: MessageField::some(
                    buffa::DecodeOptions::new()
                        .decode_from_slice(&verifier_request.encode().expect("test request encodes"))
                        .expect("test request decodes"),
                ),
                auth: MessageField::some(auth_wire),
                holder_signature_p256_raw: signature.to_vec(),
                __buffa_unknown_fields: Default::default(),
            },
            request,
            status: ZkIssuerStatusFeed {
                root: [8; 32],
                length: 1_000,
                list_id: [9; 32],
                url_hash: [10; 32],
                purpose: reallyme_zk_api::issuer_status::ZkIssuerStatusPurpose::Revocation,
            },
            issuers: [ZkIssuerPublicKey { x: [1; 32], y: [2; 32] }],
            status_issuer: ZkIssuerPublicKey { x: [1; 32], y: [2; 32] },
            claim_name_hash: [7; 32],
        }
    }

    fn policy(&self) -> ZkPersonaCredentialEvidencePresentationPolicy<'_> {
        ZkPersonaCredentialEvidencePresentationPolicy {
            mode: self.mode,
            credential_hash_algorithm: ZkCredentialHashAlgorithm::Sha256,
            trusted_issuers: &self.issuers,
            status_authority: self,
            expected_claim_name_hash: &self.claim_name_hash,
            expected_claim_value: &[18],
            now_unix: 150,
        }
    }

    fn sign_fresh_request(&mut self, nonce: [u8; 32]) {
        self.request.nonce = nonce;
        let issuer = self
            .presentation
            .issuer_envelope
            .as_option()
            .expect("test issuer proof is present");
        let root = self
            .presentation
            .claim_root
            .as_option()
            .expect("test root proof is present");
        let validity = self
            .presentation
            .signed_validity
            .as_option()
            .expect("test validity proof is present");
        let claim = self
            .presentation
            .selected_claim
            .as_option()
            .expect("test claim is present");
        let status = self
            .presentation
            .current_state
            .as_option()
            .expect("test status is present");
        let evidence = canonical_credential_evidence_bytes(issuer, root, validity, claim);
        let auth = ZkPersonaCredentialEvidencePresentationAuth::from_canonical_packages(
            self.mode,
            &evidence,
            &status.encode_to_vec(),
            &self.request,
        )
        .expect("test authentication transcript is valid");
        let digest = auth.signing_digest().expect("test digest is valid");
        let secret = Zeroizing::new([self.holder_secret; 32]);
        let digest = crypto_p256::P256Sha256Digest::new(*digest.as_bytes());
        let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)
            .expect("test signature succeeds");
        let signature =
            crypto_p256::p256_ecdsa_der_to_jose_signature(&der).expect("test signature converts");
        self.presentation.verifier_request = MessageField::some(
            buffa::DecodeOptions::new()
                .decode_from_slice(&self.request.encode().expect("test request encodes"))
                .expect("test request decodes"),
        );
        self.presentation.auth = MessageField::some(
            buffa::DecodeOptions::new()
                .decode_from_slice(&auth.encode().expect("test auth encodes"))
                .expect("test auth decodes"),
        );
        self.presentation.holder_signature_p256_raw = signature.to_vec();
    }
}

fn evidence_wire(fixture: &Fixture) -> pb::ZkPersonaCredentialEvidenceProofSet {
    pb::ZkPersonaCredentialEvidenceProofSet {
        issuer_envelope: fixture.presentation.issuer_envelope.clone(),
        claim_root: fixture.presentation.claim_root.clone(),
        signed_validity: fixture.presentation.signed_validity.clone(),
        selected_claim: fixture.presentation.selected_claim.clone(),
        __buffa_unknown_fields: Default::default(),
    }
}
