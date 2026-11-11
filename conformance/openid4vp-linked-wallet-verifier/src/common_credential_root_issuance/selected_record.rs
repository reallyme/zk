// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::DecodeOptions;
use crypto_csprng::OsSecureRandom;
use reallyme_credential_status::{StatusList, StatusPurpose};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        common_credential_root_issuer_status_opening,
        common_credential_root_poseidon2_persona_session_authorization,
        common_credential_root_poseidon2_subject_persona_link,
        common_credential_root_sha256_persona_session_authorization,
        common_credential_root_sha256_subject_persona_link, ZkCommonCredentialRootPersonaMode,
        ZkCommonCredentialRootRequestJoinContext, ZkCommonCredentialRootSubjectPublicKey,
        ZkVerifiedRootStatusSnapshot,
    },
    issuer_status::ZkIssuerStatusPurpose,
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofSuite, ZkSessionBinding, ABSENT_TRANSACTION_DATA_HASH},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::{
    common_credential_root::{
        encode_common_credential_root_selected_record_presentation_request,
        ZkCommonCredentialRootPresenterAuthorization,
        ZkCommonCredentialRootSelectedCredentialRecord, ZkCommonCredentialRootSelectedIssuerStatus,
        ZkCommonCredentialRootSelectedRecordPresentationInput,
    },
    operation::ZkSensitiveProviderRequest,
};

use crate::error::HarnessError;

use super::{
    crypto::{self, hash_parts, issuer_key, public_key, scalar, sign_digest},
    validation::{reject_revoked_and_stale_wallet_receipts, validate_wallet_receipt},
    TrustedCommonCredentialRootSource, VerifiedZkStoredCredential, ISSUER_SCALARS, PERSONA_SCALAR,
    SUBJECT_SCALARS,
};

pub(crate) struct SelectedRecordPresentationClock {
    pub(crate) request_time_unix: u64,
    pub(crate) status_validation_time_unix: u64,
    pub(crate) presentation_expiry_unix: u64,
}

pub(crate) fn selected_record_presentation_request_from_verified_records(
    selected: [VerifiedZkStoredCredential; 2],
    trusted_source: &TrustedCommonCredentialRootSource,
    active_status_snapshot: ZkVerifiedRootStatusSnapshot,
    binding: ZkSessionBinding,
    clock: SelectedRecordPresentationClock,
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<(ZkSensitiveProviderRequest, [StatusList; 2]), HarnessError> {
    let SelectedRecordPresentationClock {
        request_time_unix,
        status_validation_time_unix,
        presentation_expiry_unix,
    } = clock;
    validate_wallet_receipt(
        &selected[0],
        ISSUER_SCALARS[0],
        SUBJECT_SCALARS[0],
        status_validation_time_unix,
    )?;
    validate_wallet_receipt(
        &selected[1],
        ISSUER_SCALARS[1],
        SUBJECT_SCALARS[1],
        status_validation_time_unix,
    )?;
    reject_revoked_and_stale_wallet_receipts(
        &selected[0],
        ISSUER_SCALARS[0],
        SUBJECT_SCALARS[0],
        status_validation_time_unix,
    )?;
    reject_revoked_and_stale_wallet_receipts(
        &selected[1],
        ISSUER_SCALARS[1],
        SUBJECT_SCALARS[1],
        status_validation_time_unix,
    )?;
    trusted_source
        .holder()
        .require_lineage_roots(
            &selected[0].private_lineage_root,
            &selected[1].private_lineage_root,
        )
        .map_err(HarnessError::from)?;
    let [first_opening, second_opening] = [
        issuer_status_opening(&selected[0])?,
        issuer_status_opening(&selected[1])?,
    ];
    let persona_secret = scalar(PERSONA_SCALAR);
    let persona_public = public_key(&persona_secret)?;
    let (persona_x, persona_y) = crypto::coordinates(&persona_public)?;
    let persona_key = ZkIssuerPublicKey {
        x: persona_x,
        y: persona_y,
    };
    let persona_subject = ZkCommonCredentialRootSubjectPublicKey {
        x: persona_x,
        y: persona_y,
    };
    let request = ZkCommonCredentialRootRequestJoinContext {
        challenge: binding.nonce_hash,
        audience_hash: binding.audience_hash,
        transaction_data_hash: binding
            .transaction_data_hash
            .unwrap_or(ABSENT_TRANSACTION_DATA_HASH),
    };
    let persona_digest = persona_session_authorization(
        credential_hash_algorithm,
        persona_mode,
        request,
        presentation_expiry_unix,
    )?;
    let persona_signature = sign_digest(&persona_secret, &persona_digest)?;
    let subject_link_digest = subject_persona_link(credential_hash_algorithm, persona_subject)?;
    let first_subject_signature = sign_digest(&scalar(SUBJECT_SCALARS[0]), &subject_link_digest)?;
    let second_subject_signature = sign_digest(&scalar(SUBJECT_SCALARS[1]), &subject_link_digest)?;
    let first_status_root = first_opening.0;
    let second_status_root = second_opening.0;
    let mut rng = OsSecureRandom;
    let bytes = encode_common_credential_root_selected_record_presentation_request(
        ZkCommonCredentialRootSelectedRecordPresentationInput {
            persona_mode,
            credential_hash_algorithm,
            proof_suite: ZkProofSuite::PRODUCTION,
            expected_binding: binding,
            request_time_unix,
            status_validation_time_unix,
            presentation_expiry_unix,
            active_status_snapshot,
            holder_assurance: trusted_source.holder(),
            presenter_authorization: presenter_authorization(
                persona_mode,
                persona_key,
                &persona_signature,
            )?,
            records: [
                selected_record(
                    &selected[0],
                    &first_opening.1,
                    first_status_root,
                    &first_subject_signature,
                )?,
                selected_record(
                    &selected[1],
                    &second_opening.1,
                    second_status_root,
                    &second_subject_signature,
                )?,
            ],
        },
        &mut rng,
    )?;
    let request = DecodeOptions::new()
        .decode_from_slice::<pb::ZkProviderOperationRequest>(bytes.as_slice())
        .map_err(|_| HarnessError::InvalidLength)?;
    let [first, second] = selected;
    Ok((
        ZkSensitiveProviderRequest::new(request),
        [first.status_list, second.status_list],
    ))
}

fn persona_session_authorization(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    persona_mode: ZkCommonCredentialRootPersonaMode,
    request: ZkCommonCredentialRootRequestJoinContext,
    presentation_expiry_unix: u64,
) -> Result<[u8; 32], HarnessError> {
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => {
            Ok(common_credential_root_sha256_persona_session_authorization(
                persona_mode,
                request,
                presentation_expiry_unix,
            ))
        }
        ZkCredentialHashAlgorithm::Poseidon2 => {
            common_credential_root_poseidon2_persona_session_authorization(
                persona_mode,
                request,
                presentation_expiry_unix,
            )
            .map_err(HarnessError::from)
        }
        _ => Err(HarnessError::InvalidPresentationAccepted),
    }
}

fn subject_persona_link(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    persona_subject: ZkCommonCredentialRootSubjectPublicKey,
) -> Result<[u8; 32], HarnessError> {
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => Ok(
            common_credential_root_sha256_subject_persona_link(persona_subject),
        ),
        ZkCredentialHashAlgorithm::Poseidon2 => {
            common_credential_root_poseidon2_subject_persona_link(persona_subject)
                .map_err(HarnessError::from)
        }
        _ => Err(HarnessError::InvalidPresentationAccepted),
    }
}

fn presenter_authorization<'a>(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    persona_public_key: ZkIssuerPublicKey,
    persona_signature: &'a [u8; 64],
) -> Result<ZkCommonCredentialRootPresenterAuthorization<'a>, HarnessError> {
    match persona_mode {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => {
            Ok(ZkCommonCredentialRootPresenterAuthorization::Private {
                persona_public_key,
                persona_signature,
            })
        }
        ZkCommonCredentialRootPersonaMode::PublicPersona => {
            Ok(ZkCommonCredentialRootPresenterAuthorization::Public {
                persona_public_key,
                persona_fresh_signature: persona_signature,
            })
        }
    }
}

fn issuer_status_opening(
    selected: &VerifiedZkStoredCredential,
) -> Result<
    (
        [u8; 32],
        reallyme_zk_api::common_root::ZkCommonCredentialRootIssuerStatusOpening,
    ),
    HarnessError,
> {
    common_credential_root_issuer_status_opening(
        &selected.status_list.encoded_list,
        selected.status_list.length,
        selected.envelope.status.status_list_index,
    )
    .map_err(|_| HarnessError::InvalidPresentationAccepted)
}

fn selected_record<'a>(
    selected: &'a VerifiedZkStoredCredential,
    opening: &'a reallyme_zk_api::common_root::ZkCommonCredentialRootIssuerStatusOpening,
    status_root: [u8; 32],
    subject_link_signature: &'a [u8; 64],
) -> Result<ZkCommonCredentialRootSelectedCredentialRecord<'a>, HarnessError> {
    if selected.status_list.issuer != selected.envelope.status.status_list_url
        || selected.status_list.list_id != Some(selected.envelope.status.status_list_id)
        || selected.status_list.purpose != selected.envelope.status.purpose
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let valid_from =
        u64::try_from(selected.envelope.valid_from).map_err(|_| HarnessError::InvalidLength)?;
    let valid_until =
        u64::try_from(selected.envelope.valid_until).map_err(|_| HarnessError::InvalidLength)?;
    Ok(ZkCommonCredentialRootSelectedCredentialRecord {
        issuer_public_key: issuer_key(&selected.binding),
        lineage_root: *selected.private_lineage_root,
        envelope_hash: selected.binding.envelope_hash,
        issuer_root_binding_signature: &selected.binding.issuer_root_binding_signature,
        claims: &selected.private_claims,
        selected_claim_index: 1,
        subject_public_key: ZkIssuerPublicKey {
            x: selected.binding.subject_public_key_x,
            y: selected.binding.subject_public_key_y,
        },
        relationship_did_hash: *selected.relationship_did_hash,
        relationship_nonce: *selected.relationship_nonce,
        issuer_subject_binding_signature: &selected.binding.issuer_subject_binding_signature,
        subject_link_signature,
        issuer_status: ZkCommonCredentialRootSelectedIssuerStatus {
            root: status_root,
            length: selected.status_list.length,
            list_id: selected.envelope.status.status_list_id,
            url_hash: hash_parts(&[selected.envelope.status.status_list_url.as_bytes()]),
            purpose: status_purpose(selected.envelope.status.purpose)?,
            issuer_validity_status_signature: &selected.binding.issuer_validity_status_signature,
            valid_from,
            valid_until,
            status_index: selected.envelope.status.status_list_index,
            opening,
        },
    })
}

fn status_purpose(purpose: StatusPurpose) -> Result<ZkIssuerStatusPurpose, HarnessError> {
    match purpose {
        StatusPurpose::Revocation => Ok(ZkIssuerStatusPurpose::Revocation),
        StatusPurpose::Suspension => Ok(ZkIssuerStatusPurpose::Suspension),
        _ => Err(HarnessError::InvalidPresentationAccepted),
    }
}
