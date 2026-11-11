// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical protobuf boundary for a direct/private claim and its issuer
//! validity/current-status proof.

use buffa::{DecodeOptions, EnumValue, Message, MessageField};
use reallyme_zk_api::{
    claim_bundle::ZkStatusQualifiedClaimProofBundle,
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerCredentialStatusProof,
    proofs::ZkProofBytes,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

use crate::artifact::{circuit_ref_to_proto, proof_suite_to_proto};
use crate::common_credential_root::{
    common_credential_root_raw_public_inputs_from_proto,
    common_credential_root_raw_public_inputs_to_proto,
};
use crate::domain::{circuit_ref_from_proto_message, proof_suite_from_proto};
use crate::proof::{claim_proof_bundle_from_proto, claim_proof_bundle_to_proto};

const MAX_STATUS_QUALIFIED_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const STATUS_QUALIFIED_RECURSION_LIMIT: u32 = 16;
const STATUS_QUALIFIED_UNKNOWN_FIELD_LIMIT: usize = 0;
const STATUS_SLOT: ZkCommonCredentialRootProofSlot =
    ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0;
const STATUS_PROFILE: ZkCommonCredentialRootPersonaMode =
    ZkCommonCredentialRootPersonaMode::PrivatePersona;

/// Encode one complete status-qualified bundle as bounded canonical Buffa.
pub fn encode_status_qualified_claim_proof_bundle(
    bundle: &ZkStatusQualifiedClaimProofBundle,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let proof = bundle.issuer_credential_status();
    let message = pb::ZkStatusQualifiedClaimProofBundle {
        claim_proof_bundle: MessageField::some(claim_proof_bundle_to_proto(
            bundle.claim_proof_bundle(),
        )?),
        issuer_credential_status: MessageField::some(pb::ZkCredentialStatusProofPackage {
            circuit_ref: MessageField::some(circuit_ref_to_proto(
                proof.public_inputs().circuit_ref(),
            )),
            proof_suite: EnumValue::from(proof_suite_to_proto(proof.proof_suite())),
            artifact_set_identity_sha256: MessageField::some(
                crate::artifact_identity::artifact_set_identity_to_proto(
                    proof.artifact_set_identity_sha256(),
                ),
            ),
            proof: proof.proof_bytes().as_bytes().to_vec(),
            public_inputs: MessageField::some(common_credential_root_raw_public_inputs_to_proto(
                STATUS_PROFILE,
                STATUS_SLOT,
                proof.public_inputs(),
            )?),
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    };
    encode_canonical(&message)
}

/// Decode only canonical bounded protobuf, then check exact source identities
/// and the active request join before returning an owned bundle.
pub fn decode_status_qualified_claim_proof_bundle(
    bytes: &[u8],
) -> Result<ZkStatusQualifiedClaimProofBundle, ZkError> {
    if bytes.len() > MAX_STATUS_QUALIFIED_MESSAGE_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let message = DecodeOptions::new()
        .with_recursion_limit(STATUS_QUALIFIED_RECURSION_LIMIT)
        .with_unknown_field_limit(STATUS_QUALIFIED_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(MAX_STATUS_QUALIFIED_MESSAGE_BYTES)
        .with_max_message_size(MAX_STATUS_QUALIFIED_MESSAGE_BYTES)
        .decode_from_slice::<pb::ZkStatusQualifiedClaimProofBundle>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let canonical = encode_canonical(&message)?;
    if canonical.as_slice() != bytes {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    status_qualified_claim_proof_bundle_from_proto(message)
}

/// Converts an already admitted generated message into the joined domain
/// bundle. The caller is responsible for canonical byte admission.
pub(crate) fn status_qualified_claim_proof_bundle_from_proto(
    mut message: pb::ZkStatusQualifiedClaimProofBundle,
) -> Result<ZkStatusQualifiedClaimProofBundle, ZkError> {
    let claim_proof_bundle = claim_proof_bundle_from_proto(
        message
            .claim_proof_bundle
            .take()
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))?,
    )?;
    let mut status = message
        .issuer_credential_status
        .take()
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    let circuit_ref = circuit_ref_from_proto_message(core::mem::take(&mut status.circuit_ref))?;
    let proof_suite = proof_suite_from_proto(status.proof_suite)?;
    let artifact_set_identity_sha256 = crate::artifact_identity::artifact_set_identity_from_proto(
        core::mem::take(&mut status.artifact_set_identity_sha256),
    )?;
    let raw_inputs = common_credential_root_raw_public_inputs_from_proto(
        status
            .public_inputs
            .take()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    if raw_inputs.persona_mode() != STATUS_PROFILE
        || raw_inputs.slot() != STATUS_SLOT
        || raw_inputs.public_inputs().circuit_ref() != circuit_ref
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let proof = ZkIssuerCredentialStatusProof::try_from_parts(
        proof_suite,
        artifact_set_identity_sha256,
        ZkProofBytes::try_from_bytes(core::mem::take(&mut status.proof))?,
        raw_inputs.into_public_inputs(),
    )?;
    ZkStatusQualifiedClaimProofBundle::try_from_parts(claim_proof_bundle, proof)
}

fn encode_canonical(
    message: &pb::ZkStatusQualifiedClaimProofBundle,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let maximum = u32::try_from(MAX_STATUS_QUALIFIED_MESSAGE_BYTES)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let encoded_len = message
        .try_encoded_len()
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    if encoded_len > maximum {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let capacity =
        usize::try_from(encoded_len).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    message
        .try_encode_bounded(maximum, &mut *encoded)
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    Ok(encoded)
}
