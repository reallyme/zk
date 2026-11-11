// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict canonical provider-result decoding and conversion.
//!
//! Canonical response encoders live in the sibling module but remain part of
//! this proto-first boundary: exported helpers return `Zeroizing<Vec<u8>>` so
//! platform adapters do not leave response envelopes in unmanaged scratch
//! buffers longer than necessary.

use buffa::{DecodeOptions, Message, MessageField};
use reallyme_zk_api::{
    claim_bundle::{
        ZkClaimProofBundleStage, ZkClaimedStatement, ZkPresentationBoundClaimStatement,
    },
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, Zeroizing};

use crate::artifact::artifact_manifest_from_proto;
use crate::common_credential_root::{
    common_credential_root_persona_mode_from_proto, common_credential_root_presentation_from_proto,
    common_credential_root_raw_proof_package_from_proto,
};
use crate::domain::{
    bundle_kind_from_family, bundle_kind_from_proto, circuit_id_from_proto,
    circuit_ref_from_proto_message, proof_suite_from_proto,
};
use crate::error::error_from_proto;
use crate::operation::MAX_ZK_PROTO_OPERATION_BYTES;
use crate::persona_credential_evidence_stage_proof::{
    persona_credential_evidence_stage_proof_from_proto,
    persona_credential_evidence_stage_verification_from_proto,
};
use crate::proof::{claim_proof_bundle_from_proto, exact_proof_from_proto};

mod encoding;
mod native_witness;
mod reports;
mod status_qualified;

pub use encoding::{
    encode_artifact_manifest_response, encode_claim_proof_bundle_response,
    encode_claim_proof_bundle_verification_response,
    encode_common_credential_root_presentation_response,
    encode_common_credential_root_stage_proof_response,
    encode_common_credential_root_verification_response, encode_operation_failure_response,
    encode_persona_credential_evidence_presentation_response,
    encode_persona_credential_evidence_presentation_signing_challenge_response,
    encode_persona_credential_evidence_stage_proof_response,
    encode_persona_credential_evidence_stage_verification_response, encode_stage_proof_response,
    encode_stage_verification_response, encode_stage_witness_release_response,
    encode_stage_witness_response,
    encode_status_qualified_claim_proof_bundle_verification_response,
};
pub use native_witness::{ZkStageWitnessReleaseReport, ZkStageWitnessReport};
pub use reports::{
    DecodedOperationResponse, ZkClaimProofBundleVerificationReport,
    ZkCommonCredentialRootVerificationReport, ZkProviderOperationOutcome,
    ZkProviderOperationResult, ZkStageVerificationReport,
    ZkStatusQualifiedClaimProofBundleVerificationReport,
};

use native_witness::{stage_witness_from_proto, stage_witness_release_from_proto};
use status_qualified::{
    scrub_status_qualified_verification_response,
    status_qualified_claim_proof_bundle_verification_from_proto, status_qualified_proof_count,
    status_qualified_statement_to_proto,
};

const ZK_PROTO_RESPONSE_RECURSION_LIMIT: u32 = 32;
const ZK_PROTO_RESPONSE_UNKNOWN_FIELD_LIMIT: usize = 0;
const ZK_PROTO_RESPONSE_ELEMENT_MEMORY_LIMIT: usize = MAX_ZK_PROTO_OPERATION_BYTES;

/// Decodes and converts an untrusted binary canonical provider response.
///
/// Neither the response envelope converter nor the converters for the
/// payload messages it carries (proof bundles, artifact manifests, structured
/// errors, common-credential-root proofs and presentations, prepared stage
/// proofs) are public, so a caller cannot treat a response or payload that
/// skipped the size, unknown-field, and canonical-encoding checks applied
/// here as decoded:
///
/// ```compile_fail
/// let _ = reallyme_zk_proto_codec::result::operation_response_from_proto;
/// ```
///
/// ```compile_fail
/// let _ = reallyme_zk_proto_codec::proof::claim_proof_bundle_from_proto;
/// ```
///
/// ```compile_fail
/// let _ = reallyme_zk_proto_codec::error::error_from_proto;
/// ```
pub fn decode_operation_response(bytes: &[u8]) -> Result<DecodedOperationResponse, ZkError> {
    if bytes.len() > MAX_ZK_PROTO_OPERATION_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let response = DecodeOptions::new()
        .with_recursion_limit(ZK_PROTO_RESPONSE_RECURSION_LIMIT)
        .with_unknown_field_limit(ZK_PROTO_RESPONSE_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(ZK_PROTO_RESPONSE_ELEMENT_MEMORY_LIMIT)
        .with_max_message_size(MAX_ZK_PROTO_OPERATION_BYTES)
        .decode_from_slice::<pb::ZkProviderOperationResponse>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let canonical = encode_canonical_response(&response)?;
    if canonical.as_slice() != bytes {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    operation_response_from_proto(response)
}

fn encode_canonical_response(
    response: &pb::ZkProviderOperationResponse,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let maximum = u32::try_from(MAX_ZK_PROTO_OPERATION_BYTES)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let encoded_len = response
        .try_encoded_len()
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    if encoded_len > maximum {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let encoded_len =
        usize::try_from(encoded_len).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    response
        .try_encode_bounded(maximum, &mut *encoded)
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    Ok(encoded)
}

/// Converts a canonical generated response and rejects a missing outcome.
pub(crate) fn operation_response_from_proto(
    mut response: pb::ZkProviderOperationResponse,
) -> Result<DecodedOperationResponse, ZkError> {
    use pb::zk_provider_operation_response::Outcome;

    let request_sha256 = <[u8; 32]>::try_from(response.request_sha256.as_slice())
        .map(Digest32::from_bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let outcome = match response
        .outcome
        .take()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?
    {
        Outcome::Result(result) => operation_result_from_proto(*result)
            .map(Box::new)
            .map(ZkProviderOperationOutcome::Success),
        Outcome::Error(error) => error_from_proto(*error).map(ZkProviderOperationOutcome::Failure),
    }?;
    Ok(DecodedOperationResponse {
        request_sha256,
        outcome,
    })
}

/// Converts one generated canonical success result into a domain value.
pub(crate) fn operation_result_from_proto(
    result: pb::ZkProviderOperationResult,
) -> Result<ZkProviderOperationResult, ZkError> {
    use pb::zk_provider_operation_result::Result as ProtoResult;

    match result
        .result
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?
    {
        ProtoResult::ClaimProofBundle(bundle) => {
            claim_proof_bundle_from_proto(*bundle).map(ZkProviderOperationResult::ClaimProofBundle)
        }
        ProtoResult::ClaimProofBundleVerification(verification) => {
            claim_proof_bundle_verification_from_proto(*verification)
                .map(Box::new)
                .map(ZkProviderOperationResult::ClaimProofBundleVerification)
        }
        ProtoResult::StatusQualifiedClaimProofBundleVerification(verification) => {
            status_qualified_claim_proof_bundle_verification_from_proto(*verification)
                .map(Box::new)
                .map(ZkProviderOperationResult::StatusQualifiedClaimProofBundleVerification)
        }
        ProtoResult::StageProof(proof) => {
            exact_proof_from_proto(*proof).map(ZkProviderOperationResult::StageProof)
        }
        ProtoResult::StageVerification(verification) => {
            stage_verification_from_proto(*verification)
                .map(ZkProviderOperationResult::StageVerification)
        }
        ProtoResult::ArtifactManifest(manifest) => artifact_manifest_from_proto(*manifest)
            .map(Box::new)
            .map(ZkProviderOperationResult::ArtifactManifest),
        ProtoResult::StageWitness(witness) => stage_witness_from_proto(*witness)
            .map(Box::new)
            .map(ZkProviderOperationResult::StageWitness),
        ProtoResult::StageWitnessRelease(release) => stage_witness_release_from_proto(*release)
            .map(ZkProviderOperationResult::StageWitnessRelease),
        ProtoResult::CommonCredentialRootVerification(verification) => {
            common_credential_root_verification_from_proto(*verification)
                .map(ZkProviderOperationResult::CommonCredentialRootVerification)
        }
        ProtoResult::CommonCredentialRootStageProof(proof) => {
            common_credential_root_raw_proof_package_from_proto(*proof)
                .map(ZkProviderOperationResult::CommonCredentialRootStageProof)
        }
        ProtoResult::CommonCredentialRootPresentation(presentation) => {
            common_credential_root_presentation_from_proto(*presentation)
                .map(Box::new)
                .map(ZkProviderOperationResult::CommonCredentialRootPresentation)
        }
        ProtoResult::PersonaCredentialEvidenceStageVerification(verification) => {
            persona_credential_evidence_stage_verification_from_proto(*verification)
                .map(ZkProviderOperationResult::PersonaCredentialEvidenceStageVerification)
        }
        ProtoResult::PersonaCredentialEvidenceStageProof(proof) => {
            persona_credential_evidence_stage_proof_from_proto(*proof)
                .map(ZkProviderOperationResult::PersonaCredentialEvidenceStageProof)
        }
        ProtoResult::PersonaCredentialEvidencePresentationSigningChallenge(challenge) => {
            let digest: [u8; 32] = challenge
                .digest_sha256
                .as_slice()
                .try_into()
                .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
            Ok(
                ZkProviderOperationResult::PersonaCredentialEvidencePresentationSigningChallenge(
                    Zeroizing::new(digest),
                ),
            )
        }
        ProtoResult::PersonaCredentialEvidencePresentation(presentation) => Ok(
            ZkProviderOperationResult::PersonaCredentialEvidencePresentation(Zeroizing::new(
                presentation.encode_to_vec(),
            )),
        ),
    }
}

fn session_binding_to_proto(
    binding: reallyme_zk_api::proofs::ZkSessionBinding,
) -> pb::ZkSessionBinding {
    pb::ZkSessionBinding {
        nonce_hash: binding.nonce_hash.to_vec(),
        audience_hash: binding.audience_hash.to_vec(),
        transaction_data_hash: binding
            .transaction_data_hash
            .map(|hash| hash.to_vec())
            .unwrap_or_default(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn verified_statement_to_proto(
    statement: &ZkPresentationBoundClaimStatement,
) -> Result<pb::ZkPresentationBoundClaimStatement, ZkError> {
    let disclosed_value = statement.claim_value();
    if disclosed_value.len() > 64 {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let claim_value_length = u32::try_from(disclosed_value.len())
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut claim_value = vec![0_u8; 64];
    claim_value[..disclosed_value.len()].copy_from_slice(disclosed_value);
    let persona = match statement.persona() {
        Some(persona) => MessageField::some(issuer_public_key_to_proto(persona)),
        None => MessageField::none(),
    };
    Ok(pb::ZkPresentationBoundClaimStatement {
        issuer: MessageField::some(issuer_public_key_to_proto(statement.issuer())),
        persona,
        claim_name_hash: statement.claim_name_hash().to_vec(),
        claim_value,
        claim_value_length,
        presentation_expiry_unix: statement.presentation_expiry_unix(),
        session_link_commitment: statement.session_link_commitment().to_vec(),
        credential_binding: statement.credential_binding().to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn issuer_public_key_to_proto(
    key: impl Into<reallyme_zk_api::keys::ZkP256PublicKey>,
) -> pb::ZkP256PublicKey {
    let key = key.into();
    pb::ZkP256PublicKey {
        x: key.x.to_vec(),
        y: key.y.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn scrub_claim_proof_bundle_verification_response(response: &mut pb::ZkProviderOperationResponse) {
    let Some(pb::zk_provider_operation_response::Outcome::Result(result)) =
        response.outcome.as_mut()
    else {
        return;
    };
    let Some(pb::zk_provider_operation_result::Result::ClaimProofBundleVerification(verification)) =
        result.result.as_mut()
    else {
        return;
    };
    if let Some(statement) = verification.statement.as_option_mut() {
        statement.claim_name_hash.as_mut_slice().zeroize();
        statement.claim_value.as_mut_slice().zeroize();
        statement.claim_value_length.zeroize();
        statement.session_link_commitment.as_mut_slice().zeroize();
        statement.credential_binding.as_mut_slice().zeroize();
    }
}

fn claim_proof_bundle_verification_from_proto(
    verification: pb::ZkPresentationBoundClaimBundleVerification,
) -> Result<ZkClaimProofBundleVerificationReport, ZkError> {
    let profile = bundle_kind_from_proto(verification.bundle_kind)?;
    let verified_stage_count = u8::try_from(verification.verified_stage_count)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let required_stage_count = u8::try_from(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if verified_stage_count != required_stage_count {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }
    let proof_suite = proof_suite_from_proto(verification.proof_suite)?;
    let statement = verification
        .statement
        .into_option()
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let session_link_commitment = statement
        .session_link_commitment
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let statement = statement_from_proto(statement)?;
    Ok(ZkClaimProofBundleVerificationReport {
        bundle_kind: profile,
        verified_stage_count,
        proof_suite,
        statement,
        session_link_commitment,
    })
}

fn common_credential_root_verification_from_proto(
    verification: pb::ZkCommonCredentialRootVerification,
) -> Result<ZkCommonCredentialRootVerificationReport, ZkError> {
    let profile = common_credential_root_persona_mode_from_proto(verification.persona_mode)?;
    let verified_proof_count = u8::try_from(verification.verified_proof_count)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let required_count =
        u8::try_from(reallyme_zk_api::common_root::COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if verified_proof_count != required_count {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }
    let proof_suite = proof_suite_from_proto(verification.proof_suite)?;
    Ok(ZkCommonCredentialRootVerificationReport {
        persona_mode: profile,
        verified_proof_count,
        proof_suite,
    })
}

fn statement_from_proto(
    mut statement: pb::ZkPresentationBoundClaimStatement,
) -> Result<ZkClaimedStatement, ZkError> {
    let issuer = issuer_public_key_from_proto(
        statement
            .issuer
            .take()
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
    )?;
    let persona = statement
        .persona
        .take()
        .map(issuer_public_key_from_proto)
        .transpose()?;
    let credential_binding = statement
        .credential_binding
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let claim_name_hash = statement
        .claim_name_hash
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let claim_value = statement
        .claim_value
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    ZkClaimedStatement::try_from_parts(
        issuer,
        persona.map(|key| {
            reallyme_zk_api::keys::ZkPersonaPublicKey::from(
                reallyme_zk_api::keys::ZkP256PublicKey::from(key),
            )
        }),
        credential_binding,
        claim_name_hash,
        claim_value,
        statement.claim_value_length,
        statement.presentation_expiry_unix,
    )
}

fn issuer_public_key_from_proto(key: pb::ZkP256PublicKey) -> Result<ZkIssuerPublicKey, ZkError> {
    let x = key
        .x
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let y = key
        .y
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    Ok(ZkIssuerPublicKey { x, y })
}

fn stage_verification_from_proto(
    verification: pb::ZkVerification,
) -> Result<ZkStageVerificationReport, ZkError> {
    let circuit_id = circuit_id_from_proto(verification.circuit_id)?;
    let circuit_ref = circuit_ref_from_proto_message(verification.circuit_ref)?;
    let profile = bundle_kind_from_proto(verification.bundle_kind)?;
    let proof_suite = proof_suite_from_proto(verification.proof_suite)?;
    if circuit_ref.circuit_id() != circuit_id
        || bundle_kind_from_family(circuit_ref.family)? != profile
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }

    Ok(ZkStageVerificationReport {
        circuit_id,
        circuit_ref: Some(circuit_ref),
        proof_suite,
    })
}

#[cfg(test)]
mod tests;
