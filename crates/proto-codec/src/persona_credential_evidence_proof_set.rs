// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical four-proof credential evidence for protected Wallet inventory.
//!
//! These proofs can be prepared before a verifier request. This codec checks
//! their structure and shared token context; only the injected backend and
//! issuer-status authority can authenticate them. Current status and the live
//! holder signature are deliberately outside this reusable record.

use buffa::{DecodeOptions, Message, MessageField};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{
        check_persona_credential_evidence_v1_joins, ZkPersonaCredentialEvidenceMode,
        ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceStageProof,
    },
    proofs::ZkProofSuite,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
#[cfg(any(feature = "native", feature = "wasm"))]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::persona_credential_evidence_stage_proof::{
    persona_credential_evidence_stage_proof_from_proto,
    persona_credential_evidence_stage_proof_to_proto,
};

/// Bound for four individually bounded proofs, their public inputs, and
/// protobuf metadata. It is applied before Buffa allocates an owned message.
pub const MAX_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SET_BYTES: usize = 2 * 1024 * 1024;
const PREPARED_CREDENTIAL_EVIDENCE_RECURSION_LIMIT: u32 = 8;

/// Four joined source proofs for one token and selected claim.
///
/// This owner is suitable only as plaintext inside authenticated Wallet
/// encryption. Decoding does not establish proof validity or issuer trust.
pub struct ZkPersonaCredentialEvidenceProofSet {
    issuer_envelope: ZkPersonaCredentialEvidenceStageProof,
    claim_root: ZkPersonaCredentialEvidenceStageProof,
    signed_validity: ZkPersonaCredentialEvidenceStageProof,
    selected_claim: ZkPersonaCredentialEvidenceStageProof,
    mode: ZkPersonaCredentialEvidenceMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
}

impl ZkPersonaCredentialEvidenceProofSet {
    /// Admit exactly the four production stages under one token context.
    pub fn try_from_parts(
        issuer_envelope: ZkPersonaCredentialEvidenceStageProof,
        claim_root: ZkPersonaCredentialEvidenceStageProof,
        signed_validity: ZkPersonaCredentialEvidenceStageProof,
        selected_claim: ZkPersonaCredentialEvidenceStageProof,
    ) -> Result<Self, ZkError> {
        let mode = selected_claim.mode();
        let selected_stage = match mode {
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
                ZkPersonaCredentialEvidenceSourceStage::PublicClaim
            }
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
                ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
            }
        };
        let credential_hash_algorithm = selected_claim
            .public_inputs()
            .circuit_ref()
            .credential_hash_algorithm;
        for (proof, stage) in [
            (
                &issuer_envelope,
                ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope,
            ),
            (
                &claim_root,
                ZkPersonaCredentialEvidenceSourceStage::ClaimRoot,
            ),
            (
                &signed_validity,
                ZkPersonaCredentialEvidenceSourceStage::SignedValidity,
            ),
            (&selected_claim, selected_stage),
        ] {
            proof.proof_suite().require_production()?;
            if proof.mode() != mode
                || proof.public_inputs().circuit_ref()
                    != stage.source_ref(credential_hash_algorithm)
            {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
        }
        let selected_join = selected_claim
            .public_inputs()
            .join(ZkProofSuite::PRODUCTION)?;
        let proof_start = selected_join.proof_window.valid_from_unix();
        for proof in [&issuer_envelope, &claim_root, &signed_validity] {
            let join = proof.public_inputs().join(ZkProofSuite::PRODUCTION)?;
            check_persona_credential_evidence_v1_joins(&selected_join, &join, proof_start)
                .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
        }
        Ok(Self {
            issuer_envelope,
            claim_root,
            signed_validity,
            selected_claim,
            mode,
            credential_hash_algorithm,
        })
    }

    /// Persona disclosure mode fixed by the selected claim circuit.
    #[must_use]
    pub const fn mode(&self) -> ZkPersonaCredentialEvidenceMode {
        self.mode
    }

    /// Credential commitment lane shared by all source proofs.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Borrow the issuer envelope proof for pinned backend verification.
    #[must_use]
    pub const fn issuer_envelope(&self) -> &ZkPersonaCredentialEvidenceStageProof {
        &self.issuer_envelope
    }

    /// Borrow the signed claim-root proof for pinned backend verification.
    #[must_use]
    pub const fn claim_root(&self) -> &ZkPersonaCredentialEvidenceStageProof {
        &self.claim_root
    }

    /// Borrow the signed validity and status-pointer proof.
    #[must_use]
    pub const fn signed_validity(&self) -> &ZkPersonaCredentialEvidenceStageProof {
        &self.signed_validity
    }

    /// Borrow the exact selected claim proof.
    #[must_use]
    pub const fn selected_claim(&self) -> &ZkPersonaCredentialEvidenceStageProof {
        &self.selected_claim
    }

    /// Produce the canonical protobuf plaintext for Wallet AEAD storage.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ZkError> {
        let wire = pb::ZkPersonaCredentialEvidenceProofSet {
            issuer_envelope: MessageField::some(persona_credential_evidence_stage_proof_to_proto(
                &self.issuer_envelope,
            )),
            claim_root: MessageField::some(persona_credential_evidence_stage_proof_to_proto(
                &self.claim_root,
            )),
            signed_validity: MessageField::some(persona_credential_evidence_stage_proof_to_proto(
                &self.signed_validity,
            )),
            selected_claim: MessageField::some(persona_credential_evidence_stage_proof_to_proto(
                &self.selected_claim,
            )),
            __buffa_unknown_fields: Default::default(),
        };
        let encoded = Zeroizing::new(wire.encode_to_vec());
        if encoded.len() > MAX_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SET_BYTES {
            return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
        }
        Ok(encoded)
    }
}

/// Strictly decode Wallet-decrypted prepared credential evidence.
///
/// The caller must still verify every proof under its pinned VK and check a
/// fresh authenticated current-status proof before presenting this evidence.
pub fn decode_persona_credential_evidence_proof_set(
    bytes: &[u8],
) -> Result<ZkPersonaCredentialEvidenceProofSet, ZkError> {
    if bytes.is_empty() || bytes.len() > MAX_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SET_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let wire = DecodeOptions::new()
        .with_recursion_limit(PREPARED_CREDENTIAL_EVIDENCE_RECURSION_LIMIT)
        .with_unknown_field_limit(0)
        .with_element_memory_limit(MAX_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SET_BYTES)
        .with_max_message_size(MAX_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SET_BYTES)
        .decode_from_slice::<pb::ZkPersonaCredentialEvidenceProofSet>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    if Zeroizing::new(wire.encode_to_vec()).as_slice() != bytes {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    persona_credential_evidence_proof_set_from_proto(wire)
}

pub(crate) fn persona_credential_evidence_proof_set_from_proto(
    mut wire: pb::ZkPersonaCredentialEvidenceProofSet,
) -> Result<ZkPersonaCredentialEvidenceProofSet, ZkError> {
    let issuer_envelope = persona_credential_evidence_stage_proof_from_proto(
        wire.issuer_envelope
            .take()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    let claim_root = persona_credential_evidence_stage_proof_from_proto(
        wire.claim_root
            .take()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    let signed_validity = persona_credential_evidence_stage_proof_from_proto(
        wire.signed_validity
            .take()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    let selected_claim = persona_credential_evidence_stage_proof_from_proto(
        wire.selected_claim
            .take()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    ZkPersonaCredentialEvidenceProofSet::try_from_parts(
        issuer_envelope,
        claim_root,
        signed_validity,
        selected_claim,
    )
}

/// Canonical evidence transcript shared by the holder and verifier.
#[cfg(any(feature = "native", feature = "wasm"))]
pub(crate) fn canonical_credential_evidence_bytes(
    issuer_envelope: &pb::ZkPersonaCredentialEvidenceStageProof,
    claim_root: &pb::ZkPersonaCredentialEvidenceStageProof,
    signed_validity: &pb::ZkPersonaCredentialEvidenceStageProof,
    selected_claim: &pb::ZkPersonaCredentialEvidenceStageProof,
) -> Zeroizing<Vec<u8>> {
    let mut wire = pb::ZkPersonaCredentialEvidenceProofSet {
        issuer_envelope: MessageField::some(issuer_envelope.clone()),
        claim_root: MessageField::some(claim_root.clone()),
        signed_validity: MessageField::some(signed_validity.clone()),
        selected_claim: MessageField::some(selected_claim.clone()),
        __buffa_unknown_fields: Default::default(),
    };
    let encoded = Zeroizing::new(wire.encode_to_vec());
    for slot in [
        &mut wire.issuer_envelope,
        &mut wire.claim_root,
        &mut wire.signed_validity,
        &mut wire.selected_claim,
    ] {
        if let Some(mut package) = slot.take() {
            package.proof.zeroize();
            if let Some(mut inputs) = package.public_inputs.take() {
                inputs.raw_fields.zeroize();
            }
        }
    }
    encoded
}

#[cfg(test)]
#[path = "persona_credential_evidence_proof_set/tests.rs"]
mod tests;
