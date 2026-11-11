// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::Message;
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    persona_evidence::ZkPersonaCredentialEvidenceStageProof,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::persona_credential_evidence_auth::{
    decode_persona_credential_evidence_verifier_request, ZkPersonaCredentialEvidenceVerifierRequest,
};
use crate::persona_credential_evidence_proof_set::persona_credential_evidence_proof_set_from_proto;
use crate::persona_credential_evidence_proof_set::ZkPersonaCredentialEvidenceProofSet;
use crate::persona_credential_evidence_stage_proof::persona_credential_evidence_stage_proof_from_proto;

use super::{
    secret_cleanup::{
        zeroize_prepared_current_state_credential_proto, zeroize_prepared_current_status_proto,
    },
    ZkProviderOperation,
};

const PREPARED_DIGEST_BYTES: usize = 32;
const PREPARED_SIGNATURE_BYTES: usize = 64;
const MAX_PREPARED_STATUS_INDEX: u64 = 1_000_000;

/// Typed current-status proving request admitted at the provider boundary.
///
/// The stored evidence proofs are public to the verifier after presentation,
/// but this request also owns hidden credential fields and a private status
/// opening. The enum variant that carries it intentionally has no `Debug`.
pub struct ZkPersonaCredentialEvidenceCurrentStateProveRequest {
    /// Already joined durable four-proof credential evidence.
    pub evidence: ZkPersonaCredentialEvidenceProofSet,
    /// Hidden issuer credential material for the fresh status proof.
    pub credential: pb::ZkPersonaCredentialEvidenceCurrentStateCredentialInput,
    /// Current issuer status snapshot opening for the hidden credential index.
    pub current_status: pb::ZkPersonaCredentialEvidenceCurrentStatusInput,
    /// Trusted verifier time used to reject stale feeds and expired tokens.
    pub verification_time_unix: u64,
}

/// Owned issuer-envelope preparation input. The generated message is kept
/// private to this boundary and wiped even when later admission fails.
pub struct ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest {
    /// Secret-bearing canonical operation, wiped when this owner is dropped.
    pub operation: pb::ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation,
}

/// Owned claim-root preparation input. The generated message is wiped on drop.
pub struct ZkPersonaCredentialEvidenceClaimRootProveRequest {
    /// Exact hidden claim-root edge and token context.
    pub operation: pb::ZkPersonaCredentialEvidenceClaimRootProveOperation,
}

/// Owned issuer-signed validity input, including the hidden status index.
pub struct ZkPersonaCredentialEvidenceSignedValidityProveRequest {
    /// Secret-bearing canonical operation, wiped after admission or rejection.
    pub operation: pb::ZkPersonaCredentialEvidenceSignedValidityProveOperation,
}

/// Owned selected claim opening and persona authorizations for one token.
pub struct ZkPersonaCredentialEvidenceSelectedClaimProveRequest {
    /// Secret-bearing canonical operation, wiped after admission or rejection.
    pub operation: pb::ZkPersonaCredentialEvidenceSelectedClaimProveOperation,
}

impl ZkPersonaCredentialEvidenceSelectedClaimProveRequest {
    /// Correlate a provider result with the selected token and exact disclosure.
    pub(crate) fn matches_proof(
        &self,
        proof: &ZkPersonaCredentialEvidenceStageProof,
    ) -> Result<bool, ZkError> {
        let disclosure = self
            .operation
            .disclosure
            .as_option()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
        if !matches_token_join(
            &self.operation.issuer_public_key,
            &self.operation.holder_public_key,
            &self.operation.token_nonce,
            &disclosure.credential_binding,
            self.operation.evidence_valid_from_unix,
            self.operation.evidence_valid_until_unix,
            proof,
        )? {
            return Ok(false);
        }
        let name = disclosure
            .claim_name_hash
            .as_option()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
        let value = disclosure
            .value
            .as_option()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
        let length = usize::try_from(disclosure.value_length)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        proof.public_inputs().validate_claim(
            &name
                .value
                .as_slice()
                .try_into()
                .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
            value
                .value
                .get(..length)
                .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
        )?;
        Ok(true)
    }
}

impl Zeroize for ZkPersonaCredentialEvidenceSelectedClaimProveRequest {
    fn zeroize(&mut self) {
        super::secret_cleanup::zeroize_prepared_selected_claim_prove_operation_proto(
            &mut self.operation,
        );
    }
}

impl Drop for ZkPersonaCredentialEvidenceSelectedClaimProveRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceSelectedClaimProveRequest {}

impl ZkPersonaCredentialEvidenceSignedValidityProveRequest {
    /// Correlate both the token join and signed public status pointer.
    pub(crate) fn matches_proof(
        &self,
        proof: &ZkPersonaCredentialEvidenceStageProof,
    ) -> Result<bool, ZkError> {
        if !matches_token_join(
            &self.operation.issuer_public_key,
            &self.operation.holder_public_key,
            &self.operation.token_nonce,
            &self.operation.credential_binding,
            self.operation.evidence_valid_from_unix,
            self.operation.evidence_valid_until_unix,
            proof,
        )? {
            return Ok(false);
        }
        let pointer = proof.public_inputs().status_list_pointer()?;
        let list_id = self
            .operation
            .status_list_id
            .as_option()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
        let url_hash = self
            .operation
            .status_url_hash
            .as_option()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
        Ok(pointer.list_id.as_slice() == list_id.value.as_slice()
            && pointer.url_hash.as_slice() == url_hash.value.as_slice()
            && pointer.purpose
                == crate::issuer_status::purpose_from_proto(self.operation.status_purpose)?)
    }
}

impl Zeroize for ZkPersonaCredentialEvidenceSignedValidityProveRequest {
    fn zeroize(&mut self) {
        super::secret_cleanup::zeroize_prepared_signed_validity_prove_operation_proto(
            &mut self.operation,
        );
    }
}

impl Drop for ZkPersonaCredentialEvidenceSignedValidityProveRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceSignedValidityProveRequest {}

impl ZkPersonaCredentialEvidenceClaimRootProveRequest {
    /// Reject a proof for another selected credential or prepared token.
    pub(crate) fn matches_proof(
        &self,
        proof: &ZkPersonaCredentialEvidenceStageProof,
    ) -> Result<bool, ZkError> {
        matches_token_join(
            &self.operation.issuer_public_key,
            &self.operation.holder_public_key,
            &self.operation.token_nonce,
            &self.operation.credential_binding,
            self.operation.evidence_valid_from_unix,
            self.operation.evidence_valid_until_unix,
            proof,
        )
    }
}

impl Zeroize for ZkPersonaCredentialEvidenceClaimRootProveRequest {
    fn zeroize(&mut self) {
        super::secret_cleanup::zeroize_prepared_claim_root_prove_operation_proto(
            &mut self.operation,
        );
    }
}

impl Drop for ZkPersonaCredentialEvidenceClaimRootProveRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceClaimRootProveRequest {}

impl ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest {
    /// Correlate the provider's returned public statement with this exact
    /// token request. Circuit/mode checks alone permit a different token's
    /// proof to be substituted by a faulty or hostile provider.
    pub(crate) fn matches_proof(
        &self,
        proof: &ZkPersonaCredentialEvidenceStageProof,
    ) -> Result<bool, ZkError> {
        matches_token_join(
            &self.operation.issuer_public_key,
            &self.operation.holder_public_key,
            &self.operation.token_nonce,
            &self.operation.credential_binding,
            self.operation.evidence_valid_from_unix,
            self.operation.evidence_valid_until_unix,
            proof,
        )
    }
}

fn matches_token_join(
    issuer_public_key: &buffa::MessageField<
        pb::ZkInputP256PublicKey,
        buffa::Inline<pb::ZkInputP256PublicKey>,
    >,
    holder_public_key: &buffa::MessageField<
        pb::ZkInputP256PublicKey,
        buffa::Inline<pb::ZkInputP256PublicKey>,
    >,
    token_nonce: &buffa::MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
    credential_binding: &buffa::MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
    evidence_valid_from_unix: u64,
    evidence_valid_until_unix: u64,
    proof: &ZkPersonaCredentialEvidenceStageProof,
) -> Result<bool, ZkError> {
    let join = proof.public_inputs().join(proof.proof_suite())?;
    let issuer = issuer_public_key
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let holder = holder_public_key
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let nonce = token_nonce
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let binding = credential_binding
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let issuer_x = issuer
        .x
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let issuer_y = issuer
        .y
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let holder_x = holder
        .x
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let holder_y = holder
        .y
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(join.issuer_key.x.as_slice() == issuer_x.value.as_slice()
        && join.issuer_key.y.as_slice() == issuer_y.value.as_slice()
        && join.holder_key.x.as_slice() == holder_x.value.as_slice()
        && join.holder_key.y.as_slice() == holder_y.value.as_slice()
        && join.token_nonce.as_slice() == nonce.value.as_slice()
        && join.proof_window.valid_from_unix() == evidence_valid_from_unix
        && join.proof_window.valid_until_unix() == evidence_valid_until_unix
        && join.credential_binding.as_slice() == binding.value.as_slice())
}

impl Zeroize for ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest {
    fn zeroize(&mut self) {
        super::secret_cleanup::zeroize_prepared_issuer_envelope_prove_operation_proto(
            &mut self.operation,
        );
    }
}

impl Drop for ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest {}

/// Owned canonical input shared by platform signing and final assembly.
/// The verifier request must originate from a verified protocol adapter.
pub struct ZkPersonaCredentialEvidencePresentationInput {
    /// Four joined prepared credential proofs.
    pub evidence: ZkPersonaCredentialEvidenceProofSet,
    /// Fresh current-status proof supplied by the wallet.
    pub current_state: ZkPersonaCredentialEvidenceStageProof,
    /// Authenticated live request projected by the protocol adapter.
    pub request: ZkPersonaCredentialEvidenceVerifierRequest,
    /// Wallet clock, checked again by the receiving verifier.
    pub now_unix: u64,
}

fn presentation_input_from_proto(
    evidence: Option<pb::ZkPersonaCredentialEvidenceProofSet>,
    current_state: Option<pb::ZkPersonaCredentialEvidenceStageProof>,
    request: Option<pb::ZkPersonaCredentialEvidenceVerifierRequestV1>,
    now_unix: u64,
) -> Result<Box<ZkPersonaCredentialEvidencePresentationInput>, ZkError> {
    let evidence = persona_credential_evidence_proof_set_from_proto(
        evidence.ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    let current_state = persona_credential_evidence_stage_proof_from_proto(
        current_state.ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    let request_wire = request.ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let request_bytes = Zeroizing::new(request_wire.encode_to_vec());
    let request = decode_persona_credential_evidence_verifier_request(&request_bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    Ok(Box::new(ZkPersonaCredentialEvidencePresentationInput {
        evidence,
        current_state,
        request,
        now_unix,
    }))
}

pub(super) fn prepare_persona_credential_evidence_presentation_signing_from_proto(
    mut operation: pb::ZkPersonaCredentialEvidencePresentationSigningOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let input = presentation_input_from_proto(
        operation.evidence_proof_set.take(),
        operation.current_state.take(),
        operation.verifier_request.take(),
        operation.now_unix,
    )?;
    Ok(ZkProviderOperation::PreparePersonaCredentialEvidencePresentationSigning { input })
}

pub(super) fn assemble_persona_credential_evidence_presentation_from_proto(
    mut operation: pb::ZkPersonaCredentialEvidencePresentationAssembleOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let signature: [u8; 64] = operation
        .holder_signature_p256_raw
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    operation.holder_signature_p256_raw.zeroize();
    let input = presentation_input_from_proto(
        operation.evidence_proof_set.take(),
        operation.current_state.take(),
        operation.verifier_request.take(),
        operation.now_unix,
    )?;
    Ok(
        ZkProviderOperation::AssemblePersonaCredentialEvidencePresentation {
            input,
            signature: Zeroizing::new(signature),
        },
    )
}

impl Zeroize for ZkPersonaCredentialEvidenceCurrentStateProveRequest {
    fn zeroize(&mut self) {
        zeroize_prepared_current_state_credential_proto(&mut self.credential);
        zeroize_prepared_current_status_proto(&mut self.current_status);
        self.verification_time_unix = 0;
    }
}

impl Drop for ZkPersonaCredentialEvidenceCurrentStateProveRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceCurrentStateProveRequest {}

#[path = "persona_credential_evidence/admission.rs"]
mod admission;
pub(super) use admission::{
    prove_persona_credential_evidence_claim_root_from_proto,
    prove_persona_credential_evidence_current_state_from_proto,
    prove_persona_credential_evidence_issuer_envelope_from_proto,
    prove_persona_credential_evidence_selected_claim_from_proto,
    prove_persona_credential_evidence_signed_validity_from_proto,
    prove_persona_credential_evidence_stage_from_proto,
    verify_persona_credential_evidence_stage_from_proto,
};

#[cfg(test)]
#[path = "persona_credential_evidence/issuer_envelope_tests.rs"]
mod issuer_envelope_tests;
