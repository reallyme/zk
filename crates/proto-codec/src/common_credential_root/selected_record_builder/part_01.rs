// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, MessageField};
use crypto_csprng::SecureRandom;
use reallyme_zk_api::{common_root::{common_credential_root_poseidon2_persona_session_binding, common_credential_root_sha256_persona_session_binding, derive_common_credential_root_credential_binding, derive_common_credential_root_presentation_material, normalize_common_credential_root_p256_signature_low_s, verify_common_credential_root_active_status_membership, verify_common_credential_root_issuer_status_opening, ZkCommonCredentialRootClaimOpening, ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootCredentialBindingInputs, ZkCommonCredentialRootHolderAssurance, ZkCommonCredentialRootIssuerStatusOpening, ZkCommonCredentialRootJoinDerivationInputs, ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot, ZkCommonCredentialRootRequestJoinContext, ZkCommonCredentialRootStageInputMaterial, ZkCommonCredentialRootSubjectPublicKey, ZkVerifiedRootStatusSnapshot}, circuits::{ZkCredentialHashAlgorithm}, errors::{ZkError, ZkErrorReason}, keys::{ZkIssuerPublicKey}, issuer_status::{ZkIssuerStatusPurpose}, proofs::{ZkProofSuite, ZkSessionBinding}, claim_bundle::{MAX_PRESENTATION_LIFETIME_SECONDS}};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    artifact::{circuit_ref_to_proto, proof_suite_to_proto},
    binding::session_binding_to_proto_message,
    common_credential_root::{
        common_credential_root_persona_mode_to_proto, common_credential_root_slot_to_proto,
    },
    operation::{
        decode_operation_request, encode_sensitive_operation_request,
        zeroize_common_credential_root_presentation_prove_operation_proto,
        zeroize_common_credential_root_stage_prove_operation_proto, ZkSensitiveProviderRequest,
    },
};

const CLAIM_VALUE_BYTES: usize = 64;
const SIGNATURE_BYTES: usize = 64;

/// Session authorization supplied by the wallet's persona-key boundary.
///
/// The builder deliberately accepts signatures rather than secret keys. Hardware
/// key handles and signing prompts remain SDK responsibilities; ZK only checks
/// deterministic binding and transports the resulting fixed-width signature to
/// the stage witness.
pub enum ZkCommonCredentialRootPresenterAuthorization<'a> {
    /// Private persona proof: persona key is hidden from the verifier.
    Private {
        /// Public key corresponding to the signing handle.
        persona_public_key: ZkIssuerPublicKey,
        /// Signature over the API-defined private-persona authorization digest.
        persona_signature: &'a [u8; SIGNATURE_BYTES],
    },
    /// Public persona proof: persona key is intentionally disclosed.
    Public {
        /// Disclosed persona key corresponding to the signing handle.
        persona_public_key: ZkIssuerPublicKey,
        /// Signature over the API-defined public-persona authorization digest.
        persona_fresh_signature: &'a [u8; SIGNATURE_BYTES],
    },
}

/// One credential selected by wallet policy from an issuer-authenticated store.
///
/// The builder expects the SDK to perform envelope/signature receipt validation
/// before constructing this value. This layer binds the validated fields into
/// canonical stage witnesses; it does not replace the wallet trust policy.
pub struct ZkCommonCredentialRootSelectedCredentialRecord<'a> {
    /// Issuer key authenticated by the credential envelope.
    pub issuer_public_key: ZkIssuerPublicKey,
    /// Hidden root claimed by this credential's private lineage material.
    pub lineage_root: [u8; 32],
    /// Issuer-authenticated envelope digest.
    pub envelope_hash: [u8; 32],
    /// Issuer signature binding envelope digest to claims root.
    pub issuer_root_binding_signature: &'a [u8; SIGNATURE_BYTES],
    /// Private claim openings decrypted from wallet storage.
    pub claims: &'a ZkCommonCredentialRootClaimsCommitment,
    /// Index of the requested disclosed claim in `claims.openings()`.
    pub selected_claim_index: usize,
    /// Subject key authenticated by the issuer-subject binding.
    pub subject_public_key: ZkIssuerPublicKey,
    /// Private relationship DID hash used by the lineage circuit.
    pub relationship_did_hash: [u8; 32],
    /// Private relationship nonce used by the lineage circuit.
    pub relationship_nonce: [u8; 32],
    /// Issuer signature binding issuer, envelope, and subject key.
    pub issuer_subject_binding_signature: &'a [u8; SIGNATURE_BYTES],
    /// Subject signature linking the selected persona to this credential.
    pub subject_link_signature: &'a [u8; SIGNATURE_BYTES],
    /// Current issuer-status opening authenticated by wallet policy.
    pub issuer_status: ZkCommonCredentialRootSelectedIssuerStatus<'a>,
}

impl Drop for ZkCommonCredentialRootSelectedCredentialRecord<'_> {
    fn drop(&mut self) {
        self.lineage_root.zeroize();
        self.relationship_did_hash.zeroize();
        self.relationship_nonce.zeroize();
    }
}

impl ZeroizeOnDrop for ZkCommonCredentialRootSelectedCredentialRecord<'_> {}

/// Issuer status material for one selected credential.
///
/// `root`, `length`, `list_id`, `url_hash`, and `purpose` must come from the
/// verifier/status trust boundary for the active request. The builder checks
/// Merkle membership and circuit binding only; it intentionally does not treat
/// an arbitrary caller-supplied root as fresh revocation authority.
pub struct ZkCommonCredentialRootSelectedIssuerStatus<'a> {
    /// Status-list root admitted by verifier/status policy.
    pub root: [u8; 32],
    /// Status-list length admitted by verifier/status policy.
    pub length: u64,
    /// Status-list identifier admitted by verifier/status policy.
    pub list_id: [u8; 32],
    /// SHA-256 of the status-list URL admitted by verifier/status policy.
    pub url_hash: [u8; 32],
    /// Exact status purpose requested by verifier/status policy.
    pub purpose: ZkIssuerStatusPurpose,
    /// Issuer signature over validity, credential binding, and status tuple.
    pub issuer_validity_status_signature: &'a [u8; SIGNATURE_BYTES],
    /// Inclusive credential validity start.
    pub valid_from: u64,
    /// Exclusive credential validity end.
    pub valid_until: u64,
    /// Private status index for this credential.
    pub status_index: u64,
    /// Private opening into the authenticated issuer status root.
    pub opening: &'a ZkCommonCredentialRootIssuerStatusOpening,
}

/// Trusted inputs for a complete selected-record common-credential-root presentation.
pub struct ZkCommonCredentialRootSelectedRecordPresentationInput<'a> {
    /// Common-credential-root persona_mode selected by wallet and verifier policy.
    pub persona_mode: ZkCommonCredentialRootPersonaMode,
    /// Exact hash lane authenticated by both selected credential receipts.
    pub credential_hash_algorithm: ZkCredentialHashAlgorithm,
    /// Production proof suite requested by the SDK.
    pub proof_suite: ZkProofSuite,
    /// Active OpenID4VP/session binding.
    pub expected_binding: ZkSessionBinding,
    /// Verifier request time committed into the circuit transcript.
    pub request_time_unix: u64,
    /// Current authenticated status/assurance validation time.
    pub status_validation_time_unix: u64,
    /// Presentation expiry used by every stage.
    pub presentation_expiry_unix: u64,
    /// Authority-verified active root snapshot.
    pub active_status_snapshot: ZkVerifiedRootStatusSnapshot,
    /// Holder-private assurance admitted against the active status snapshot.
    pub holder_assurance: &'a ZkCommonCredentialRootHolderAssurance,
    /// Persona-key authorization from the wallet signing boundary.
    pub presenter_authorization: ZkCommonCredentialRootPresenterAuthorization<'a>,
    /// Two selected credentials in verifier-requested role order.
    pub records: [ZkCommonCredentialRootSelectedCredentialRecord<'a>; 2],
}

struct BuildContext<'a> {
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    expected_binding: ZkSessionBinding,
    request_time_unix: u64,
    status_validation_time_unix: u64,
    presentation_expiry_unix: u64,
    active_status_snapshot: ZkVerifiedRootStatusSnapshot,
    holder_assurance: &'a ZkCommonCredentialRootHolderAssurance,
    presenter_authorization: ZkCommonCredentialRootPresenterAuthorization<'a>,
    records: [ZkCommonCredentialRootSelectedCredentialRecord<'a>; 2],
}

/// Owns a generated complete-presentation prove operation until transport
/// ownership can take over.
///
/// Selected-record construction assembles private witness material stage by
/// stage. Keeping the generated Buffa operation behind this owner from the
/// first inserted stage ensures early build errors still scrub already-built
/// private inputs instead of relying on callers to remember a cleanup step.
pub struct ZkCommonCredentialRootSelectedRecordPresentationOperationOwner {
    operation: pb::ZkCommonCredentialRootPresentationProveOperation,
}

impl ZkCommonCredentialRootSelectedRecordPresentationOperationOwner {
    fn new(input: &BuildContext<'_>) -> Self {
        Self {
            operation: pb::ZkCommonCredentialRootPresentationProveOperation {
                persona_mode: EnumValue::from(common_credential_root_persona_mode_to_proto(
                    input.persona_mode,
                )),
                proof_suite: EnumValue::from(proof_suite_to_proto(input.proof_suite)),
                expected_binding: MessageField::some(session_binding_to_proto_message(
                    input.expected_binding,
                )),
                root_attestation: MessageField::none(),
                root_status: MessageField::none(),
                lineage_0: MessageField::none(),
                lineage_1: MessageField::none(),
                selected_claim_0: MessageField::none(),
                selected_claim_1: MessageField::none(),
                session: MessageField::none(),
                issuer_credential_status_0: MessageField::none(),
                issuer_credential_status_1: MessageField::none(),
                __buffa_unknown_fields: Default::default(),
            },
        }
    }

    /// Borrows the generated operation while the owner retains cleanup
    /// responsibility.
    #[must_use]
    pub const fn operation(&self) -> &pb::ZkCommonCredentialRootPresentationProveOperation {
        &self.operation
    }

    /// Transfers the operation into a provider-request owner that continues
    /// clearing nested private inputs after encoding or dispatch.
    #[must_use]
    pub fn into_sensitive_provider_request(mut self) -> ZkSensitiveProviderRequest {
        let operation = core::mem::take(&mut self.operation);
        ZkSensitiveProviderRequest::new(pb::ZkProviderOperationRequest {
            operation: Some(
                pb::__buffa::oneof::zk_provider_operation_request::Operation::ProveCommonCredentialRootPresentation(
                    Box::new(operation),
                ),
            ),
            __buffa_unknown_fields: Default::default(),
        })
    }

    fn set_stage(
        &mut self,
        slot: ZkCommonCredentialRootProofSlot,
        mut stage: pb::ZkCommonCredentialRootStageProveOperation,
    ) -> Result<(), ZkError> {
        match slot {
            ZkCommonCredentialRootProofSlot::RootAttestation => {
                self.operation.root_attestation = MessageField::some(stage);
            }
            ZkCommonCredentialRootProofSlot::RootStatus => {
                self.operation.root_status = MessageField::some(stage);
            }
            ZkCommonCredentialRootProofSlot::Lineage0 => {
                self.operation.lineage_0 = MessageField::some(stage);
            }
            ZkCommonCredentialRootProofSlot::Lineage1 => {
                self.operation.lineage_1 = MessageField::some(stage);
            }
            ZkCommonCredentialRootProofSlot::SelectedClaim0 => {
                self.operation.selected_claim_0 = MessageField::some(stage);
            }
            ZkCommonCredentialRootProofSlot::SelectedClaim1 => {
                self.operation.selected_claim_1 = MessageField::some(stage);
            }
            ZkCommonCredentialRootProofSlot::Session => {
                self.operation.session = MessageField::some(stage);
            }
            ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 => {
                self.operation.issuer_credential_status_0 = MessageField::some(stage);
            }
            ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => {
                self.operation.issuer_credential_status_1 = MessageField::some(stage);
            }
            _ => {
                zeroize_common_credential_root_stage_prove_operation_proto(&mut stage);
                return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
            }
        }
        Ok(())
    }
}

impl Drop for ZkCommonCredentialRootSelectedRecordPresentationOperationOwner {
    fn drop(&mut self) {
        zeroize_common_credential_root_presentation_prove_operation_proto(&mut self.operation);
    }
}

impl ZeroizeOnDrop for ZkCommonCredentialRootSelectedRecordPresentationOperationOwner {}

/// Build canonical provider-operation bytes for the linked common-credential-root prover.
pub fn encode_common_credential_root_selected_record_presentation_request(
    input: ZkCommonCredentialRootSelectedRecordPresentationInput<'_>,
    rng: &mut impl SecureRandom,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let operation =
        build_common_credential_root_selected_record_presentation_operation(input, rng)?;
    let request = operation.into_sensitive_provider_request();
    let bytes = encode_sensitive_operation_request(request)?;
    let _validated = decode_operation_request(bytes.as_slice())?;
    Ok(bytes)
}

/// Build the generated Buffa operation owner for callers that already own transport.
pub fn build_common_credential_root_selected_record_presentation_operation(
    input: ZkCommonCredentialRootSelectedRecordPresentationInput<'_>,
    rng: &mut impl SecureRandom,
) -> Result<ZkCommonCredentialRootSelectedRecordPresentationOperationOwner, ZkError> {
    let ZkCommonCredentialRootSelectedRecordPresentationInput {
        persona_mode,
        credential_hash_algorithm,
        proof_suite,
        expected_binding,
        request_time_unix,
        status_validation_time_unix,
        presentation_expiry_unix,
        active_status_snapshot,
        holder_assurance,
        presenter_authorization,
        records,
    } = input;
    let input = BuildContext {
        persona_mode,
        credential_hash_algorithm,
        proof_suite,
        expected_binding,
        request_time_unix,
        status_validation_time_unix,
        presentation_expiry_unix,
        active_status_snapshot,
        holder_assurance,
        presenter_authorization,
        records,
    };
    let persona_mode = input.persona_mode;
    let persona_key = input.presenter_authorization.persona_key();
    input
        .expected_binding
        .validate_for_circuit(input.persona_mode.source_ref(
            input.credential_hash_algorithm,
            ZkCommonCredentialRootProofSlot::Session,
        ))?;
    if input.request_time_unix == 0 || input.presentation_expiry_unix <= input.request_time_unix {
        return Err(ZkError::new(ZkErrorReason::PresentationExpired));
    }
    if input.status_validation_time_unix < input.request_time_unix
        || input.status_validation_time_unix >= input.presentation_expiry_unix
    {
        return Err(ZkError::new(ZkErrorReason::PresentationExpired));
    }
    let proof_lifetime = input
        .presentation_expiry_unix
        .checked_sub(input.request_time_unix)
        .ok_or(ZkError::new(ZkErrorReason::PresentationExpired))?;
    if proof_lifetime > MAX_PRESENTATION_LIFETIME_SECONDS {
        return Err(ZkError::new(ZkErrorReason::PresentationExpiryTooFar));
    }
    if input.presentation_expiry_unix >= input.holder_assurance.expires_unix() {
        return Err(ZkError::new(ZkErrorReason::PresentationExpired));
    }
    for record in &input.records {
        if input.presentation_expiry_unix >= record.issuer_status.valid_until {
            return Err(ZkError::new(ZkErrorReason::PresentationExpired));
        }
    }
    input
        .active_status_snapshot
        .validate_at(input.status_validation_time_unix)
        .map_err(|_| ZkError::new(ZkErrorReason::PresentationExpired))?;
    input
        .holder_assurance
        .validate_at(input.status_validation_time_unix)
        .map_err(|_| ZkError::new(ZkErrorReason::PresentationExpired))?;
    verify_common_credential_root_active_status_membership(
        input.active_status_snapshot,
        input.status_validation_time_unix,
        input.holder_assurance.attestation_id(),
        input.holder_assurance.status_index(),
        input.holder_assurance.siblings(),
    )
    .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    input
        .holder_assurance
        .require_lineage_roots(
            &input.records[0].lineage_root,
            &input.records[1].lineage_root,
        )
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;

    let request = request_context(input.expected_binding);
    let presentation_material = derive_common_credential_root_presentation_material(
        rng,
        ZkCommonCredentialRootJoinDerivationInputs {
            request,
            root: input.holder_assurance.root(),
            attestation_id: input.holder_assurance.attestation_id(),
            subject_public_keys: [
                subject_key(input.records[0].subject_public_key),
                subject_key(input.records[1].subject_public_key),
            ],
        },
    )
    .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    let session_binding = persona_session_binding(
        input.credential_hash_algorithm,
        persona_mode,
        persona_key,
        request,
        input.presentation_expiry_unix,
    )?;
    let mut composer = presentation_material.into_stage_input_composer();
    let mut operation = ZkCommonCredentialRootSelectedRecordPresentationOperationOwner::new(&input);
    operation.set_stage(
        ZkCommonCredentialRootProofSlot::RootAttestation,
        root_attestation_operation(&input, &mut composer)?,
    )?;
    operation.set_stage(
        ZkCommonCredentialRootProofSlot::RootStatus,
        root_status_operation(&input, &mut composer)?,
    )?;
    operation.set_stage(
        ZkCommonCredentialRootProofSlot::Lineage0,
        lineage_operation(&input, &mut composer, 0)?,
    )?;
    operation.set_stage(
        ZkCommonCredentialRootProofSlot::Lineage1,
        lineage_operation(&input, &mut composer, 1)?,
    )?;
    operation.set_stage(
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
        selected_claim_operation(&input, &mut composer, session_binding, 0)?,
    )?;
    operation.set_stage(
        ZkCommonCredentialRootProofSlot::SelectedClaim1,
        selected_claim_operation(&input, &mut composer, session_binding, 1)?,
    )?;
    operation.set_stage(
        ZkCommonCredentialRootProofSlot::Session,
        session_operation(&input, &mut composer, persona_mode, session_binding)?,
    )?;
    operation.set_stage(
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0,
        issuer_status_operation(&input, &mut composer, 0)?,
    )?;
    operation.set_stage(
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1,
        issuer_status_operation(&input, &mut composer, 1)?,
    )?;
    composer
        .finish()
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;

    Ok(operation)
}

impl ZkCommonCredentialRootPresenterAuthorization<'_> {
    fn persona_key(&self) -> ZkIssuerPublicKey {
        match self {
            Self::Private {
                persona_public_key, ..
            }
            | Self::Public {
                persona_public_key, ..
            } => *persona_public_key,
        }
    }
}
