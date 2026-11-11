// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, EnumValue, MessageField};
use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    claim_bundle::{
        ZkClaimProofBundle, ZkPresentationBoundClaimBundleVerification,
        ZkStatusQualifiedClaimProofBundleVerification,
    },
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceSourceStage,
        ZkPersonaCredentialEvidenceStageProof,
    },
    proofs::ZkProof,
};
use reallyme_zk_artifacts::{Digest32, ProductionArtifactManifest};
use zeroize::Zeroizing;

use crate::artifact::{
    artifact_manifest_to_proto, circuit_id_to_proto, circuit_ref_to_proto, proof_suite_to_proto,
};
use crate::common_credential_root::{
    common_credential_root_persona_mode_to_proto_public,
    common_credential_root_presentation_to_proto,
    common_credential_root_raw_proof_package_to_proto, ZkCommonCredentialRootPresentation,
    ZkCommonCredentialRootRawProofPackage,
};
use crate::domain::bundle_kind_from_family;
use crate::error::error_to_proto;
use crate::issuer_status::purpose_to_proto;
use crate::operation::{ZkNativeStageWitnessHandle, MAX_ZK_PROTO_OPERATION_BYTES};
use crate::persona_credential_evidence_stage_proof::persona_credential_evidence_stage_proof_to_proto;
use crate::proof::{claim_proof_bundle_to_proto, proof_to_proto};
use crate::release::bundle_kind_to_proto;

use super::{
    encode_canonical_response, pb, scrub_claim_proof_bundle_verification_response,
    scrub_status_qualified_verification_response, session_binding_to_proto,
    status_qualified_proof_count, status_qualified_statement_to_proto, verified_statement_to_proto,
};

fn common_credential_root_verification_to_proto(
    persona_mode: reallyme_zk_api::common_root::ZkCommonCredentialRootPersonaMode,
    verified_proof_count: u8,
    proof_suite: reallyme_zk_api::proofs::ZkProofSuite,
) -> pb::ZkCommonCredentialRootVerification {
    pb::ZkCommonCredentialRootVerification {
        persona_mode: EnumValue::from(common_credential_root_persona_mode_to_proto_public(
            persona_mode,
        )),
        verified_proof_count: u32::from(verified_proof_count),
        proof_suite: EnumValue::from(proof_suite_to_proto(proof_suite)),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Encodes a canonical typed failure response for one exact request payload.
///
/// Platform FFI/JNI/Swift adapters use this helper after request admission or
/// dispatch fails so every lane emits the same protobuf error envelope instead
/// of re-implementing error encoding near native pointers. The request bytes
/// are used only for the stable response binding hash; malformed request bytes
/// can still receive a privacy-safe typed failure as long as they satisfy the
/// operation transport size bound.
pub fn encode_operation_failure_response(
    request_bytes: &[u8],
    error: ZkError,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    if request_bytes.len() > MAX_ZK_PROTO_OPERATION_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let response = pb::ZkProviderOperationResponse {
        request_sha256: Digest32::sha256(request_bytes).as_bytes().to_vec(),
        outcome: Some(
            pb::__buffa::oneof::zk_provider_operation_response::Outcome::Error(Box::new(
                error_to_proto(error),
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    };
    encode_canonical_response(&response)
}

/// Encodes a canonical successful exact-stage proof response.
pub fn encode_stage_proof_response(
    request_bytes: &[u8],
    proof: &ZkProof,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::StageProof(Box::new(
            proof_to_proto(proof)?,
        )),
    )
}

/// Encodes a canonical successful complete-bundle proof response.
pub fn encode_claim_proof_bundle_response(
    request_bytes: &[u8],
    bundle: &ZkClaimProofBundle,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::ClaimProofBundle(Box::new(
            claim_proof_bundle_to_proto(bundle)?,
        )),
    )
}

/// Encodes a canonical successful five-proof status-qualified verification
/// response.
///
/// This encoder accepts only the API-owned value minted after both proof
/// verifiers, every join, and the current issuer status check succeeded. It
/// cannot be built from four-proof evidence or from decoded transport bytes.
pub fn encode_status_qualified_claim_proof_bundle_verification_response(
    request_bytes: &[u8],
    verification: &ZkStatusQualifiedClaimProofBundleVerification,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    if request_bytes.len() > MAX_ZK_PROTO_OPERATION_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let verified_proof_count = u32::from(status_qualified_proof_count()?);
    let mut response = pb::ZkProviderOperationResponse {
        request_sha256: Digest32::sha256(request_bytes).as_bytes().to_vec(),
        outcome: Some(
            pb::__buffa::oneof::zk_provider_operation_response::Outcome::Result(Box::new(
                pb::ZkProviderOperationResult {
                    result: Some(
                        pb::__buffa::oneof::zk_provider_operation_result::Result::StatusQualifiedClaimProofBundleVerification(
                            Box::new(pb::ZkStatusQualifiedClaimProofBundleVerification {
                                bundle_kind: EnumValue::from(bundle_kind_to_proto(
                                    verification.bundle_kind(),
                                )),
                                verified_proof_count,
                                proof_suite: EnumValue::from(proof_suite_to_proto(
                                    verification.proof_suite(),
                                )),
                                statement: MessageField::some(
                                    status_qualified_statement_to_proto(verification.statement())?,
                                ),
                                status_purpose: purpose_to_proto(verification.status_purpose()),
                                __buffa_unknown_fields: Default::default(),
                            }),
                        ),
                    ),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    };
    let encoded = encode_canonical_response(&response);
    scrub_status_qualified_verification_response(&mut response);
    encoded
}

/// Encodes a canonical successful complete-bundle verification response.
///
/// This encoder accepts only the API-owned verified domain value. Callers that
/// merely decoded transport bytes must not use it to mint trusted state.
pub fn encode_claim_proof_bundle_verification_response(
    request_bytes: &[u8],
    verification: &ZkPresentationBoundClaimBundleVerification,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let verified_stage_count = u32::from(verification.verified_stage_count());
    if request_bytes.len() > MAX_ZK_PROTO_OPERATION_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let mut response = pb::ZkProviderOperationResponse {
        request_sha256: Digest32::sha256(request_bytes).as_bytes().to_vec(),
        outcome: Some(
            pb::__buffa::oneof::zk_provider_operation_response::Outcome::Result(Box::new(
                pb::ZkProviderOperationResult {
                    result: Some(pb::__buffa::oneof::zk_provider_operation_result::Result::ClaimProofBundleVerification(
                        Box::new(pb::ZkPresentationBoundClaimBundleVerification {
                            bundle_kind: EnumValue::from(bundle_kind_to_proto(
                                verification.bundle_kind(),
                            )),
                            verified_stage_count,
                            proof_suite: EnumValue::from(proof_suite_to_proto(
                                verification.proof_suite(),
                            )),
                            statement: MessageField::some(verified_statement_to_proto(
                                verification.statement(),
                            )?),
                            __buffa_unknown_fields: Default::default(),
                        }),
                    ),
                    ),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    };
    let encoded = encode_canonical_response(&response);
    scrub_claim_proof_bundle_verification_response(&mut response);
    encoded
}

/// Encodes a canonical successful exact-stage verification response.
pub fn encode_stage_verification_response(
    request_bytes: &[u8],
    proof: &ZkProof,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let circuit_ref = proof.circuit_ref();
    let bundle_kind = bundle_kind_from_family(circuit_ref.family)?;
    let verification = pb::ZkVerification {
        circuit_id: EnumValue::from(circuit_id_to_proto(proof.circuit_id())),
        circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
        bundle_kind: EnumValue::from(bundle_kind_to_proto(bundle_kind)),
        proof_suite: EnumValue::from(proof_suite_to_proto(proof.proof_suite())),
        __buffa_unknown_fields: Default::default(),
    };
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::StageVerification(Box::new(
            verification,
        )),
    )
}

/// Report one backend-verified prepared proof. This report authenticates only
/// one source stage; application acceptance requires the full joined persona_mode.
pub fn encode_persona_credential_evidence_stage_verification_response(
    request_bytes: &[u8],
    proof: &ZkPersonaCredentialEvidenceStageProof,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let persona_mode = match proof.mode() {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
        }
    };
    let slot = match proof.public_inputs().stage() {
        ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE
        }
        ZkPersonaCredentialEvidenceSourceStage::ClaimRoot => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT
        }
        ZkPersonaCredentialEvidenceSourceStage::SignedValidity => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY
        }
        ZkPersonaCredentialEvidenceSourceStage::PublicClaim
        | ZkPersonaCredentialEvidenceSourceStage::PrivateClaim => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM
        }
        ZkPersonaCredentialEvidenceSourceStage::CurrentState => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE
        }
    };
    let report = pb::ZkPersonaCredentialEvidenceStageVerification {
        mode: EnumValue::from(persona_mode),
        proof_slot: EnumValue::from(slot),
        circuit_ref: MessageField::some(circuit_ref_to_proto(proof.public_inputs().circuit_ref())),
        proof_suite: EnumValue::from(proof_suite_to_proto(proof.proof_suite())),
        __buffa_unknown_fields: Default::default(),
    };
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::PersonaCredentialEvidenceStageVerification(
            Box::new(report),
        ),
    )
}

/// Encode one newly proved and backend-verified prepared stage.
pub fn encode_persona_credential_evidence_stage_proof_response(
    request_bytes: &[u8],
    proof: &ZkPersonaCredentialEvidenceStageProof,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::PersonaCredentialEvidenceStageProof(Box::new(
            persona_credential_evidence_stage_proof_to_proto(proof),
        )),
    )
}

/// Return the digest for the exact validated prepared evidence and request.
pub fn encode_persona_credential_evidence_presentation_signing_challenge_response(
    request_bytes: &[u8],
    digest_sha256: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::PersonaCredentialEvidencePresentationSigningChallenge(
            Box::new(pb::ZkPersonaCredentialEvidencePresentationSigningChallenge {
                digest_sha256: digest_sha256.to_vec(),
                __buffa_unknown_fields: Default::default(),
            }),
        ),
    )
}

/// Return the complete holder-signed protobuf presentation after native checks.
pub fn encode_persona_credential_evidence_presentation_response(
    request_bytes: &[u8],
    presentation_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let presentation = DecodeOptions::new()
        .with_recursion_limit(10)
        .with_unknown_field_limit(0)
        .with_element_memory_limit(MAX_ZK_PROTO_OPERATION_BYTES)
        .with_max_message_size(MAX_ZK_PROTO_OPERATION_BYTES)
        .decode_from_slice::<pb::ZkPersonaCredentialEvidencePresentation>(presentation_bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::PersonaCredentialEvidencePresentation(
            Box::new(presentation),
        ),
    )
}

/// Encodes a canonical successful common-credential-root verification response.
pub fn encode_common_credential_root_verification_response(
    request_bytes: &[u8],
    persona_mode: reallyme_zk_api::common_root::ZkCommonCredentialRootPersonaMode,
    proof_suite: reallyme_zk_api::proofs::ZkProofSuite,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let verified_proof_count =
        u8::try_from(reallyme_zk_api::common_root::COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::CommonCredentialRootVerification(
            Box::new(common_credential_root_verification_to_proto(
                persona_mode,
                verified_proof_count,
                proof_suite,
            )),
        ),
    )
}

/// Encodes a canonical successful common-credential-root stage proof response.
pub fn encode_common_credential_root_stage_proof_response(
    request_bytes: &[u8],
    proof: &ZkCommonCredentialRootRawProofPackage,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::CommonCredentialRootStageProof(
            Box::new(common_credential_root_raw_proof_package_to_proto(proof)?),
        ),
    )
}

/// Encodes a canonical successful complete common-credential-root presentation response.
pub fn encode_common_credential_root_presentation_response(
    request_bytes: &[u8],
    presentation: &ZkCommonCredentialRootPresentation,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::CommonCredentialRootPresentation(
            Box::new(common_credential_root_presentation_to_proto(presentation)?),
        ),
    )
}

/// Encodes a canonical successful artifact-manifest lookup response.
pub fn encode_artifact_manifest_response(
    request_bytes: &[u8],
    manifest: &ProductionArtifactManifest,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::ArtifactManifest(Box::new(
            artifact_manifest_to_proto(manifest)?,
        )),
    )
}

/// Encodes a canonical successful stage-witness response.
pub fn encode_stage_witness_response(
    request_bytes: &[u8],
    handle: ZkNativeStageWitnessHandle,
    public_inputs: &reallyme_zk_api::proofs::ZkPublicInputs,
    session_binding: reallyme_zk_api::proofs::ZkSessionBinding,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::StageWitness(Box::new(
            pb::ZkStageWitness {
                witness_handle: MessageField::some(pb::ZkStageWitnessHandle {
                    native_handle_id: handle.native_handle_id,
                    circuit_ref: MessageField::some(circuit_ref_to_proto(handle.circuit_ref)),
                    encoding: EnumValue::from(
                        pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1,
                    ),
                    __buffa_unknown_fields: Default::default(),
                }),
                public_inputs: MessageField::some(pb::ZkPublicInputs {
                    encoded: public_inputs.as_bytes().to_vec(),
                    __buffa_unknown_fields: Default::default(),
                }),
                session_binding: MessageField::some(session_binding_to_proto(session_binding)),
                __buffa_unknown_fields: Default::default(),
            },
        )),
    )
}

/// Encodes a canonical successful stage-witness release response.
pub fn encode_stage_witness_release_response(
    request_bytes: &[u8],
    circuit_ref: ZkCircuitRef,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_success_response(
        request_bytes,
        pb::__buffa::oneof::zk_provider_operation_result::Result::StageWitnessRelease(Box::new(
            pb::ZkStageWitnessRelease {
                circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
                __buffa_unknown_fields: Default::default(),
            },
        )),
    )
}

fn encode_success_response(
    request_bytes: &[u8],
    result: pb::__buffa::oneof::zk_provider_operation_result::Result,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    if request_bytes.len() > MAX_ZK_PROTO_OPERATION_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let response = pb::ZkProviderOperationResponse {
        request_sha256: Digest32::sha256(request_bytes).as_bytes().to_vec(),
        outcome: Some(
            pb::__buffa::oneof::zk_provider_operation_response::Outcome::Result(Box::new(
                pb::ZkProviderOperationResult {
                    result: Some(result),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    };
    encode_canonical_response(&response)
}
