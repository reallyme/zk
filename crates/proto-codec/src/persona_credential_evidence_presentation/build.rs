// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet-side construction of the canonical prepared presentation transcript.
//!
//! Construction checks the two public-input joins and the holder signature.
//! The verifier must independently verify both proofs, issuer trust, current
//! status, policy, and nonce consumption before accepting the presentation.

use buffa::{DecodeOptions, EnumValue, Message, MessageField};
use reallyme_zk_api::{
    persona_evidence::{
        check_persona_credential_evidence_v1_joins, ZkPersonaCredentialEvidenceMode,
        ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceStageJoin,
        ZkPersonaCredentialEvidenceStageProof,
    },
    proofs::ZkProofSuite,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    artifact::{credential_hash_algorithm_to_proto, proof_suite_to_proto},
    persona_credential_evidence_auth::{
        ZkPersonaCredentialEvidencePresentationAuth, ZkPersonaCredentialEvidenceVerifierRequest,
        AUTH_WIRE_LIMIT, RECURSION_LIMIT, REQUEST_WIRE_LIMIT,
    },
    persona_credential_evidence_stage_proof::persona_credential_evidence_stage_proof_to_proto,
};

use super::{
    canonical_credential_evidence_bytes, rejected, ZkPersonaCredentialEvidencePresentationError,
    ZkPersonaCredentialEvidencePresentationReason, MAX_PREPARED_PRESENTATION_BYTES,
};

const SIGNATURE_BYTES: usize = 64;

struct ProofPackageGuard(pb::ZkPersonaCredentialEvidenceStageProof);

impl Drop for ProofPackageGuard {
    fn drop(&mut self) {
        wipe_proof_package(&mut self.0);
    }
}

fn wipe_proof_package(package: &mut pb::ZkPersonaCredentialEvidenceStageProof) {
    package.proof.zeroize();
    if let Some(mut inputs) = package.public_inputs.take() {
        inputs.raw_fields.zeroize();
    }
}

/// A non-sensitive failure from the wallet's protected P-256 signing provider.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("prepared holder signing provider unavailable")]
pub struct ZkPersonaCredentialEvidenceSignerError;

/// Signs one canonical prepared-presentation digest with the selected key.
///
/// A private-mode implementation must receive a token only after the wallet
/// durably reserves it. The signer must never silently substitute another key.
pub trait ZkPersonaCredentialEvidenceHolderSigner {
    /// Return a fixed-width, low-S P-256 signature over the supplied digest.
    fn sign_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<[u8; SIGNATURE_BYTES], ZkPersonaCredentialEvidenceSignerError>;
}

/// Assemble four prepared credential proofs, current status, and live holder authentication.
///
/// The caller obtains `selected_claim` from its public cache or from an
/// atomically reserved private token. A private token must be burned before
/// invoking this function, even if construction or transport later fails.
/// Proofs remain transport data until a verifier authenticates them.
pub struct ZkPersonaCredentialEvidenceProofSetRef<'a> {
    /// Issuer-authenticated envelope and hidden subject.
    pub issuer_envelope: &'a ZkPersonaCredentialEvidenceStageProof,
    /// Issuer-authenticated envelope-to-claim-root link.
    pub claim_root: &'a ZkPersonaCredentialEvidenceStageProof,
    /// Issuer-signed validity and status locator.
    pub signed_validity: &'a ZkPersonaCredentialEvidenceStageProof,
    /// Persona-authorized selected claim.
    pub selected_claim: &'a ZkPersonaCredentialEvidenceStageProof,
}

fn validate_prepared_inputs(
    evidence: &ZkPersonaCredentialEvidenceProofSetRef<'_>,
    current_state: &ZkPersonaCredentialEvidenceStageProof,
    request: &ZkPersonaCredentialEvidenceVerifierRequest,
    now_unix: u64,
) -> Result<
    (
        ZkPersonaCredentialEvidenceMode,
        ZkPersonaCredentialEvidenceStageJoin,
    ),
    ZkPersonaCredentialEvidencePresentationError,
> {
    let ZkPersonaCredentialEvidenceProofSetRef {
        issuer_envelope,
        claim_root,
        signed_validity,
        selected_claim,
    } = evidence;
    request
        .validate_at(now_unix)
        .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::RequestRejected))?;
    let mode = selected_claim.mode();
    let required_stage = match mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            ZkPersonaCredentialEvidenceSourceStage::PublicClaim
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        }
    };
    if issuer_envelope.public_inputs().stage()
        != ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
        || claim_root.public_inputs().stage() != ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
        || signed_validity.public_inputs().stage()
            != ZkPersonaCredentialEvidenceSourceStage::SignedValidity
        || issuer_envelope.mode() != mode
        || claim_root.mode() != mode
        || signed_validity.mode() != mode
        || issuer_envelope.proof_suite() != ZkProofSuite::PRODUCTION
        || claim_root.proof_suite() != ZkProofSuite::PRODUCTION
        || signed_validity.proof_suite() != ZkProofSuite::PRODUCTION
        || selected_claim.public_inputs().stage() != required_stage
        || current_state.public_inputs().stage()
            != ZkPersonaCredentialEvidenceSourceStage::CurrentState
        || current_state.mode() != mode
        || selected_claim.proof_suite() != ZkProofSuite::PRODUCTION
        || current_state.proof_suite() != ZkProofSuite::PRODUCTION
    {
        return Err(rejected(
            ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected,
        ));
    }
    let claim_join = selected_claim
        .public_inputs()
        .join(selected_claim.proof_suite())
        .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected))?;
    for proof in [
        *issuer_envelope,
        *claim_root,
        *signed_validity,
        current_state,
    ] {
        let joined = proof
            .public_inputs()
            .join(proof.proof_suite())
            .map_err(|_| {
                rejected(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected)
            })?;
        check_persona_credential_evidence_v1_joins(&claim_join, &joined, now_unix).map_err(
            |_| rejected(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected),
        )?;
    }
    if signed_validity
        .public_inputs()
        .status_list_pointer()
        .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected))?
        != current_state
            .public_inputs()
            .status_list_pointer()
            .map_err(|_| {
                rejected(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected)
            })?
    {
        return Err(rejected(
            ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected,
        ));
    }
    Ok((mode, claim_join))
}

/// Compute the exact digest that a platform protected key must sign.
///
/// The same joins and request checks are applied again when the returned
/// signature is assembled into a presentation. A private caller must durably
/// reserve its one-time token before invoking this function.
pub fn persona_credential_evidence_signing_digest(
    evidence: ZkPersonaCredentialEvidenceProofSetRef<'_>,
    current_state: &ZkPersonaCredentialEvidenceStageProof,
    request: &ZkPersonaCredentialEvidenceVerifierRequest,
    now_unix: u64,
) -> Result<[u8; 32], ZkPersonaCredentialEvidencePresentationError> {
    let (mode, _claim_join) =
        validate_prepared_inputs(&evidence, current_state, request, now_unix)?;
    let issuer_wire = ProofPackageGuard(persona_credential_evidence_stage_proof_to_proto(
        evidence.issuer_envelope,
    ));
    let root_wire = ProofPackageGuard(persona_credential_evidence_stage_proof_to_proto(
        evidence.claim_root,
    ));
    let validity_wire = ProofPackageGuard(persona_credential_evidence_stage_proof_to_proto(
        evidence.signed_validity,
    ));
    let claim_wire = ProofPackageGuard(persona_credential_evidence_stage_proof_to_proto(
        evidence.selected_claim,
    ));
    let status_wire = ProofPackageGuard(persona_credential_evidence_stage_proof_to_proto(
        current_state,
    ));
    let evidence_bytes = canonical_credential_evidence_bytes(
        &issuer_wire.0,
        &root_wire.0,
        &validity_wire.0,
        &claim_wire.0,
    );
    let status_bytes = Zeroizing::new(status_wire.0.encode_to_vec());
    let auth = ZkPersonaCredentialEvidencePresentationAuth::from_canonical_packages(
        mode,
        &evidence_bytes,
        &status_bytes,
        request,
    )
    .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let digest = auth
        .signing_digest()
        .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    Ok(*digest.as_bytes())
}

struct SuppliedSignatureSigner(Zeroizing<[u8; SIGNATURE_BYTES]>);

impl ZkPersonaCredentialEvidenceHolderSigner for SuppliedSignatureSigner {
    fn sign_digest(
        &self,
        _digest: &[u8; 32],
    ) -> Result<[u8; SIGNATURE_BYTES], ZkPersonaCredentialEvidenceSignerError> {
        Ok(*self.0)
    }
}

/// Assemble a presentation after its exact digest was signed by a platform key.
///
/// The builder recomputes the digest and checks the supplied signature against
/// the holder key constrained by the selected claim proof. A different request
/// or status package therefore cannot be substituted between the two calls.
pub fn build_persona_credential_evidence_presentation_with_signature(
    evidence: ZkPersonaCredentialEvidenceProofSetRef<'_>,
    current_state: &ZkPersonaCredentialEvidenceStageProof,
    request: &ZkPersonaCredentialEvidenceVerifierRequest,
    now_unix: u64,
    signature: [u8; SIGNATURE_BYTES],
) -> Result<Zeroizing<Vec<u8>>, ZkPersonaCredentialEvidencePresentationError> {
    let signer = SuppliedSignatureSigner(Zeroizing::new(signature));
    build_persona_credential_evidence_presentation(
        evidence,
        current_state,
        request,
        now_unix,
        &signer,
    )
}

/// Sign a canonical presentation after checking all exact proof joins.
pub fn build_persona_credential_evidence_presentation(
    evidence: ZkPersonaCredentialEvidenceProofSetRef<'_>,
    current_state: &ZkPersonaCredentialEvidenceStageProof,
    request: &ZkPersonaCredentialEvidenceVerifierRequest,
    now_unix: u64,
    signer: &dyn ZkPersonaCredentialEvidenceHolderSigner,
) -> Result<Zeroizing<Vec<u8>>, ZkPersonaCredentialEvidencePresentationError> {
    let (mode, claim_join) = validate_prepared_inputs(&evidence, current_state, request, now_unix)?;
    let ZkPersonaCredentialEvidenceProofSetRef {
        issuer_envelope,
        claim_root,
        signed_validity,
        selected_claim,
    } = evidence;

    let mut issuer_wire = ProofPackageGuard(persona_credential_evidence_stage_proof_to_proto(
        issuer_envelope,
    ));
    let mut root_wire =
        ProofPackageGuard(persona_credential_evidence_stage_proof_to_proto(claim_root));
    let mut validity_wire = ProofPackageGuard(persona_credential_evidence_stage_proof_to_proto(
        signed_validity,
    ));
    let mut claim_wire = ProofPackageGuard(persona_credential_evidence_stage_proof_to_proto(
        selected_claim,
    ));
    let mut status_wire = ProofPackageGuard(persona_credential_evidence_stage_proof_to_proto(
        current_state,
    ));
    let evidence_bytes = canonical_credential_evidence_bytes(
        &issuer_wire.0,
        &root_wire.0,
        &validity_wire.0,
        &claim_wire.0,
    );
    let status_bytes = Zeroizing::new(status_wire.0.encode_to_vec());
    let auth = ZkPersonaCredentialEvidencePresentationAuth::from_canonical_packages(
        mode,
        &evidence_bytes,
        &status_bytes,
        request,
    )
    .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let digest = auth
        .signing_digest()
        .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let signature = Zeroizing::new(signer.sign_digest(digest.as_bytes()).map_err(|_| {
        rejected(ZkPersonaCredentialEvidencePresentationReason::HolderSigningFailed)
    })?);
    auth.verify_holder_signature(
        &claim_join.holder_key.x,
        &claim_join.holder_key.y,
        &signature,
    )
    .map_err(|_| {
        rejected(ZkPersonaCredentialEvidencePresentationReason::HolderAuthenticationFailed)
    })?;
    let request_bytes = request
        .encode()
        .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::RequestRejected))?;
    let auth_bytes = auth
        .encode()
        .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let request_wire = DecodeOptions::new()
        .with_recursion_limit(RECURSION_LIMIT)
        .with_unknown_field_limit(0)
        .with_element_memory_limit(REQUEST_WIRE_LIMIT)
        .with_max_message_size(REQUEST_WIRE_LIMIT)
        .decode_from_slice::<pb::ZkPersonaCredentialEvidenceVerifierRequestV1>(&request_bytes)
        .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let auth_wire = DecodeOptions::new()
        .with_recursion_limit(RECURSION_LIMIT)
        .with_unknown_field_limit(0)
        .with_element_memory_limit(AUTH_WIRE_LIMIT)
        .with_max_message_size(AUTH_WIRE_LIMIT)
        .decode_from_slice::<pb::ZkPersonaCredentialEvidencePresentationAuthV1>(&auth_bytes)
        .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let profile_wire = match mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
        }
    };
    let mut presentation = pb::ZkPersonaCredentialEvidencePresentation {
        mode: EnumValue::from(profile_wire),
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm_to_proto(
            claim_join.credential_hash_algorithm,
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
        issuer_envelope: MessageField::some(core::mem::take(&mut issuer_wire.0)),
        claim_root: MessageField::some(core::mem::take(&mut root_wire.0)),
        signed_validity: MessageField::some(core::mem::take(&mut validity_wire.0)),
        selected_claim: MessageField::some(core::mem::take(&mut claim_wire.0)),
        current_state: MessageField::some(core::mem::take(&mut status_wire.0)),
        verifier_request: MessageField::some(request_wire),
        auth: MessageField::some(auth_wire),
        holder_signature_p256_raw: signature.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let encoded = Zeroizing::new(presentation.encode_to_vec());
    presentation.holder_signature_p256_raw.zeroize();
    for slot in [
        &mut presentation.issuer_envelope,
        &mut presentation.claim_root,
        &mut presentation.signed_validity,
        &mut presentation.selected_claim,
        &mut presentation.current_state,
    ] {
        if let Some(mut package) = slot.take() {
            wipe_proof_package(&mut package);
        }
    }
    if let Some(mut request) = presentation.verifier_request.take() {
        request.nonce.zeroize();
        request.audience_sha256.zeroize();
        request.transaction_data_sha256.zeroize();
        request.requested_claims_sha256.zeroize();
        request.verifier_policy_sha256.zeroize();
        request.transport_context_sha256.zeroize();
    }
    if let Some(mut auth) = presentation.auth.take() {
        auth.evidence_proof_set_sha256.zeroize();
        auth.current_state_sha256.zeroize();
        auth.verifier_request_sha256.zeroize();
    }
    if encoded.len() > MAX_PREPARED_PRESENTATION_BYTES {
        return Err(rejected(
            ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding,
        ));
    }
    Ok(encoded)
}
