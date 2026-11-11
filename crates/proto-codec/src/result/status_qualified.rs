// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Status-qualified wire reports stay separate from verified domain capabilities.

use buffa::MessageField;
use reallyme_zk_api::{
    claim_bundle::{ZkClaimProofBundleStage, ZkVerifiedClaimStatement},
    errors::{ZkError, ZkErrorReason},
};
use zeroize::Zeroize;

use super::{
    issuer_public_key_to_proto, pb, statement_from_proto,
    ZkStatusQualifiedClaimProofBundleVerificationReport,
};
use crate::{
    domain::{bundle_kind_from_proto, proof_suite_from_proto},
    issuer_status::purpose_from_proto,
};

/// Proofs covered by a status-qualified verification: the four claim stages
/// and the issuer validity and current-status proof.
const STATUS_QUALIFIED_STATUS_PROOF_COUNT: usize = 1;
const MAX_CLAIM_VALUE_BYTES: usize = 64;

pub(super) fn status_qualified_proof_count() -> Result<u8, ZkError> {
    ZkClaimProofBundleStage::ALL
        .len()
        .checked_add(STATUS_QUALIFIED_STATUS_PROOF_COUNT)
        .and_then(|count| u8::try_from(count).ok())
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))
}

pub(super) fn status_qualified_statement_to_proto(
    statement: &ZkVerifiedClaimStatement,
) -> Result<pb::ZkStatusQualifiedClaimStatement, ZkError> {
    let disclosed_value = statement.claim_value();
    if disclosed_value.len() > MAX_CLAIM_VALUE_BYTES {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let claim_value_length = u32::try_from(disclosed_value.len())
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut claim_value = vec![0_u8; MAX_CLAIM_VALUE_BYTES];
    claim_value[..disclosed_value.len()].copy_from_slice(disclosed_value);
    let persona = match statement.persona() {
        Some(persona) => MessageField::some(issuer_public_key_to_proto(persona)),
        None => MessageField::none(),
    };
    Ok(pb::ZkStatusQualifiedClaimStatement {
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

pub(super) fn scrub_status_qualified_verification_response(
    response: &mut pb::ZkProviderOperationResponse,
) {
    let Some(pb::zk_provider_operation_response::Outcome::Result(result)) =
        response.outcome.as_mut()
    else {
        return;
    };
    let Some(
        pb::zk_provider_operation_result::Result::StatusQualifiedClaimProofBundleVerification(
            verification,
        ),
    ) = result.result.as_mut()
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

pub(super) fn status_qualified_claim_proof_bundle_verification_from_proto(
    verification: pb::ZkStatusQualifiedClaimProofBundleVerification,
) -> Result<ZkStatusQualifiedClaimProofBundleVerificationReport, ZkError> {
    let bundle_kind = bundle_kind_from_proto(verification.bundle_kind)?;
    let verified_proof_count = u8::try_from(verification.verified_proof_count)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if verified_proof_count != status_qualified_proof_count()? {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }
    let proof_suite = proof_suite_from_proto(verification.proof_suite)?;
    // The fifth proof exists only for the production suite.
    proof_suite.require_production()?;
    let status_purpose = purpose_from_proto(verification.status_purpose)?;
    let mut statement = verification
        .statement
        .into_option()
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let session_link_commitment = statement
        .session_link_commitment
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    // Both statement messages carry the same fields; reuse one strict
    // conversion so the two reports cannot drift apart.
    let statement = statement_from_proto(pb::ZkPresentationBoundClaimStatement {
        issuer: core::mem::take(&mut statement.issuer),
        persona: core::mem::take(&mut statement.persona),
        claim_name_hash: core::mem::take(&mut statement.claim_name_hash),
        claim_value: core::mem::take(&mut statement.claim_value),
        claim_value_length: statement.claim_value_length,
        presentation_expiry_unix: statement.presentation_expiry_unix,
        session_link_commitment: core::mem::take(&mut statement.session_link_commitment),
        credential_binding: core::mem::take(&mut statement.credential_binding),
        __buffa_unknown_fields: Default::default(),
    })?;
    Ok(ZkStatusQualifiedClaimProofBundleVerificationReport {
        bundle_kind,
        verified_proof_count,
        proof_suite,
        status_purpose,
        statement,
        session_link_commitment,
    })
}
