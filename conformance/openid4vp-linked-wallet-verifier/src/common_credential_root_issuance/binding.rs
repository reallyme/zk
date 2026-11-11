// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_credential::committed::proof_binding::CredentialProofBinding;
use reallyme_credential_status::StatusPurpose;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        common_credential_root_issuer_status_opening,
        derive_common_credential_root_credential_binding, ZkCommonCredentialRootClaimOpening,
        ZkCommonCredentialRootCredentialBindingInputs, ZkCommonCredentialRootRequestJoinContext,
    },
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::ZkSensitiveProviderRequest;

use crate::error::HarnessError;

use super::{
    crypto::{coordinates_from_proto, hash_parts, input32, replace32, replace64, stage, stage_mut},
    VerifiedZkStoredCredential, STATUS_PATH_SLOTS,
};

pub(super) fn bind_lineage(
    request: &mut ZkSensitiveProviderRequest,
    binding: &CredentialProofBinding,
    openings: &[ZkCommonCredentialRootClaimOpening],
) -> Result<(), HarnessError> {
    let credential_hash_algorithm = stage_credential_hash_algorithm(stage(request)?)?;
    let stage = stage_mut(request)?;
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::Lineage(input)) =
        stage.input.as_mut()
    else {
        return Err(HarnessError::MissingField);
    };
    let witness = input
        .witness
        .as_option_mut()
        .ok_or(HarnessError::MissingField)?;
    let slot = input
        .slot
        .as_option_mut()
        .ok_or(HarnessError::MissingField)?;
    if input32(&witness.merkle_root)? != binding.claims_root
        || coordinates_from_proto(
            witness
                .subject_public_key
                .as_option()
                .ok_or(HarnessError::MissingField)?,
        )? != (binding.subject_public_key_x, binding.subject_public_key_y)
        || coordinates_from_proto(
            slot.issuer_public_key
                .as_option()
                .ok_or(HarnessError::MissingField)?,
        )? != (binding.issuer_public_key_x, binding.issuer_public_key_y)
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let presentation = input
        .presentation
        .as_option()
        .ok_or(HarnessError::MissingField)?;
    let credential_binding = credential_binding(
        credential_hash_algorithm,
        binding,
        input32(&presentation.challenge)?,
        input32(&presentation.audience_hash)?,
        input32(&presentation.transaction_data_hash)?,
        slot.expiry_unix,
    );
    replace32(&mut witness.envelope_hash, &binding.envelope_hash)?;
    replace64(
        &mut witness.issuer_root_binding_signature,
        &binding.issuer_root_binding_signature,
    )?;
    let lineage_opening = openings.first().ok_or(HarnessError::MissingField)?;
    if lineage_opening.leaf_index() != 0 {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    apply_opening(
        lineage_opening,
        &mut witness.claim_salt,
        &mut witness.merkle_leaf_index,
        &mut witness.merkle_path,
    )?;
    replace32(&mut slot.credential_binding, &credential_binding?)
}

pub(super) fn bind_selected_claim(
    request: &mut ZkSensitiveProviderRequest,
    binding: &CredentialProofBinding,
    openings: &[ZkCommonCredentialRootClaimOpening],
) -> Result<(), HarnessError> {
    let credential_hash_algorithm = stage_credential_hash_algorithm(stage(request)?)?;
    let stage = stage_mut(request)?;
    match stage.input.as_mut() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(
            input,
        )) => {
            let proof = input
                .proof
                .as_option_mut()
                .ok_or(HarnessError::MissingField)?;
            let link = input
                .link
                .as_option_mut()
                .ok_or(HarnessError::MissingField)?;
            let issuer = input
                .issuer_context
                .as_option()
                .ok_or(HarnessError::MissingField)?;
            if input32(&proof.merkle_root)? != binding.claims_root
                || coordinates_from_proto(
                    link.subject_public_key
                        .as_option()
                        .ok_or(HarnessError::MissingField)?,
                )? != (binding.subject_public_key_x, binding.subject_public_key_y)
                || coordinates_from_proto(
                    issuer
                        .issuer_public_key
                        .as_option()
                        .ok_or(HarnessError::MissingField)?,
                )? != (binding.issuer_public_key_x, binding.issuer_public_key_y)
            {
                return Err(HarnessError::InvalidPresentationAccepted);
            }
            let credential_binding = credential_binding(
                credential_hash_algorithm,
                binding,
                input32(&issuer.challenge)?,
                input32(&issuer.audience_hash)?,
                input32(&issuer.transaction_data_hash)?,
                issuer.expiry_unix,
            )?;
            replace32(&mut proof.envelope_hash, &binding.envelope_hash)?;
            replace64(
                &mut link.issuer_subject_binding_signature,
                &binding.issuer_subject_binding_signature,
            )?;
            bind_selected_claim_opening(
                proof,
                input.disclosure.get_or_insert_default(),
                openings,
                &credential_binding,
            )
        }
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PublicPersonaClaim(
            input,
        )) => {
            let proof = input
                .proof
                .as_option_mut()
                .ok_or(HarnessError::MissingField)?;
            let link = input
                .link
                .as_option_mut()
                .ok_or(HarnessError::MissingField)?;
            let issuer = input
                .issuer_context
                .as_option()
                .ok_or(HarnessError::MissingField)?;
            if input32(&proof.merkle_root)? != binding.claims_root
                || coordinates_from_proto(
                    link.subject_public_key
                        .as_option()
                        .ok_or(HarnessError::MissingField)?,
                )? != (binding.subject_public_key_x, binding.subject_public_key_y)
                || coordinates_from_proto(
                    issuer
                        .issuer_public_key
                        .as_option()
                        .ok_or(HarnessError::MissingField)?,
                )? != (binding.issuer_public_key_x, binding.issuer_public_key_y)
            {
                return Err(HarnessError::InvalidPresentationAccepted);
            }
            let credential_binding = credential_binding(
                credential_hash_algorithm,
                binding,
                input32(&issuer.challenge)?,
                input32(&issuer.audience_hash)?,
                input32(&issuer.transaction_data_hash)?,
                issuer.expiry_unix,
            )?;
            replace32(&mut proof.envelope_hash, &binding.envelope_hash)?;
            replace64(
                &mut link.issuer_subject_binding_signature,
                &binding.issuer_subject_binding_signature,
            )?;
            bind_selected_claim_opening(
                proof,
                input.disclosure.get_or_insert_default(),
                openings,
                &credential_binding,
            )
        }
        _ => Err(HarnessError::MissingField),
    }
}

fn bind_selected_claim_opening(
    proof: &mut pb::ZkInputMerkleClaimProof,
    disclosure: &mut pb::ZkInputClaimDisclosure,
    openings: &[ZkCommonCredentialRootClaimOpening],
    credential_binding: &[u8; 32],
) -> Result<(), HarnessError> {
    let selected = openings.get(1).ok_or(HarnessError::MissingField)?;
    apply_opening(
        selected,
        &mut proof.claim_salt,
        &mut proof.leaf_index,
        &mut proof.path,
    )?;
    let mut padded_value = [0_u8; 64];
    let value_len = selected.value().len();
    let target = padded_value
        .get_mut(..value_len)
        .ok_or(HarnessError::InvalidLength)?;
    target.copy_from_slice(selected.value());
    disclosure.value_length = u32::try_from(value_len).map_err(|_| HarnessError::InvalidLength)?;
    replace64(&mut disclosure.value, &padded_value)?;
    replace32(&mut disclosure.claim_name_hash, &selected.name_hash())?;
    replace32(&mut disclosure.credential_binding, credential_binding)
}

pub(super) fn bind_issuer_status(
    request: &mut ZkSensitiveProviderRequest,
    issued: &VerifiedZkStoredCredential,
    request_time: u64,
) -> Result<(), HarnessError> {
    let credential_hash_algorithm = stage_credential_hash_algorithm(stage(request)?)?;
    let stage = stage_mut(request)?;
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::IssuerCredentialStatus(
        input,
    )) = stage.input.as_mut()
    else {
        return Err(HarnessError::MissingField);
    };
    let envelope = &issued.envelope;
    let binding = &issued.binding;
    let status = &issued.status_list;
    if status.issuer != envelope.status.status_list_url
        || status.list_id != Some(envelope.status.status_list_id)
        || status.purpose != envelope.status.purpose
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let issuer_key = input
        .issuer_public_key
        .as_option_mut()
        .ok_or(HarnessError::MissingField)?;
    replace32(&mut issuer_key.x, &binding.issuer_public_key_x)?;
    replace32(&mut issuer_key.y, &binding.issuer_public_key_y)?;
    let presentation = input
        .presentation
        .as_option()
        .ok_or(HarnessError::MissingField)?;
    let credential_binding = credential_binding(
        credential_hash_algorithm,
        binding,
        input32(&presentation.challenge)?,
        input32(&presentation.audience_hash)?,
        input32(&presentation.transaction_data_hash)?,
        input.presentation_expiry,
    );
    let (status_root, opening) = common_credential_root_issuer_status_opening(
        &status.encoded_list,
        status.length,
        envelope.status.status_list_index,
    )
    .map_err(|_| HarnessError::InvalidPresentationAccepted)?;
    if opening.siblings().len() > STATUS_PATH_SLOTS {
        return Err(HarnessError::InvalidLength);
    }
    let valid_from = u64::try_from(envelope.valid_from).map_err(|_| HarnessError::InvalidLength)?;
    let valid_until =
        u64::try_from(envelope.valid_until).map_err(|_| HarnessError::InvalidLength)?;
    let purpose = match status.purpose {
        StatusPurpose::Revocation => pb::ZkIssuerStatusPurpose::Revocation,
        StatusPurpose::Suspension => pb::ZkIssuerStatusPurpose::Suspension,
        _ => return Err(HarnessError::InvalidPresentationAccepted),
    };
    replace32(&mut input.credential_binding, &credential_binding?)?;
    replace32(&mut input.status_root, &status_root)?;
    input.status_length = status.length;
    replace32(&mut input.status_list_id, &envelope.status.status_list_id)?;
    replace32(
        &mut input.status_url_hash,
        &hash_parts(&[envelope.status.status_list_url.as_bytes()]),
    )?;
    input.status_purpose = purpose.into();
    input.verifier_now = request_time;
    replace32(&mut input.envelope_hash, &binding.envelope_hash)?;
    replace32(&mut input.claims_root, &binding.claims_root)?;
    replace64(
        &mut input.issuer_validity_status_signature,
        &binding.issuer_validity_status_signature,
    )?;
    input.valid_from = valid_from;
    input.valid_until = valid_until;
    input.status_index = envelope.status.status_list_index;
    replace32(&mut input.status_chunk, opening.chunk())?;
    input.path_length =
        u32::try_from(opening.siblings().len()).map_err(|_| HarnessError::InvalidLength)?;
    input.path.clear();
    input
        .path
        .try_reserve_exact(opening.siblings().len())
        .map_err(|_| HarnessError::InvalidLength)?;
    for sibling in opening.siblings() {
        input.path.push(pb::ZkInputBytes32 {
            value: sibling.to_vec(),
            __buffa_unknown_fields: Default::default(),
        });
    }
    Ok(())
}

fn apply_opening(
    opening: &ZkCommonCredentialRootClaimOpening,
    salt: &mut buffa::MessageField<pb::ZkInputBytes16, buffa::Inline<pb::ZkInputBytes16>>,
    leaf_index: &mut u32,
    path_field: &mut buffa::MessageField<
        pb::ZkInputMerklePath,
        buffa::Inline<pb::ZkInputMerklePath>,
    >,
) -> Result<(), HarnessError> {
    salt.get_or_insert_default().value = opening.salt().to_vec();
    *leaf_index = opening.leaf_index();
    let path = path_field
        .as_option_mut()
        .ok_or(HarnessError::MissingField)?;
    if opening.siblings().len() > path.siblings.len() {
        return Err(HarnessError::InvalidLength);
    }
    path.path_length =
        u32::try_from(opening.siblings().len()).map_err(|_| HarnessError::InvalidLength)?;
    for (index, sibling) in path.siblings.iter_mut().enumerate() {
        sibling.value = opening
            .siblings()
            .get(index)
            .copied()
            .unwrap_or([0_u8; 32])
            .to_vec();
    }
    Ok(())
}

fn stage_credential_hash_algorithm(
    stage: &pb::ZkCommonCredentialRootStageProveOperation,
) -> Result<ZkCredentialHashAlgorithm, HarnessError> {
    let circuit_ref = stage
        .circuit_ref
        .as_option()
        .ok_or(HarnessError::MissingField)?;
    match circuit_ref.credential_hash_algorithm.as_known() {
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256) => {
            Ok(ZkCredentialHashAlgorithm::Sha256)
        }
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2) => {
            Ok(ZkCredentialHashAlgorithm::Poseidon2)
        }
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_UNSPECIFIED) | None => {
            Err(HarnessError::InvalidPresentationAccepted)
        }
    }
}

fn credential_binding(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    binding: &CredentialProofBinding,
    challenge: [u8; 32],
    audience: [u8; 32],
    transaction: [u8; 32],
    expiry_unix: u64,
) -> Result<[u8; 32], HarnessError> {
    let derived = derive_common_credential_root_credential_binding(
        credential_hash_algorithm,
        ZkCommonCredentialRootCredentialBindingInputs {
            issuer_key: ZkIssuerPublicKey {
                x: binding.issuer_public_key_x,
                y: binding.issuer_public_key_y,
            },
            envelope_hash: binding.envelope_hash,
            claims_root: binding.claims_root,
            request: ZkCommonCredentialRootRequestJoinContext {
                challenge,
                audience_hash: audience,
                transaction_data_hash: transaction,
            },
            expiry_unix,
        },
    )
    .map_err(HarnessError::from)?;
    if credential_hash_algorithm == ZkCredentialHashAlgorithm::Sha256
        && binding.credential_binding(challenge, audience, transaction, expiry_unix)? != derived
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    Ok(derived)
}
