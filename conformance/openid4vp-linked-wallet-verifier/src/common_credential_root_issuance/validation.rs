// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_credential::AssuranceLevel;
use reallyme_credential_status::{
    status_list_signing_payload, StatusList, StatusListAlgorithm, StatusListSignature,
};
use reallyme_identity::zk::{validate_zk_common_root_wallet_receipt, ZkWalletReceiptPolicy};
use reallyme_zk_api::keys::ZkIssuerPublicKey;

use crate::error::HarnessError;

use super::{
    crypto::{coordinates, public_key, scalar, sign_raw},
    VerifiedZkStoredCredential, PROFILE_ID,
};

pub(super) fn validate_wallet_receipt(
    issued: &VerifiedZkStoredCredential,
    issuer_scalar: u8,
    subject_scalar: u8,
    now_unix: u64,
) -> Result<(), HarnessError> {
    validate_wallet_receipt_with_status(
        issued,
        &issued.status_list,
        issuer_scalar,
        subject_scalar,
        now_unix,
    )
}

fn validate_wallet_receipt_with_status(
    issued: &VerifiedZkStoredCredential,
    status_list: &StatusList,
    issuer_scalar: u8,
    subject_scalar: u8,
    now_unix: u64,
) -> Result<(), HarnessError> {
    let issuer_public = public_key(&scalar(issuer_scalar))?;
    let (x, y) = coordinates(&issuer_public)?;
    let trusted_issuer = ZkIssuerPublicKey { x, y };
    let holder_public = public_key(&scalar(subject_scalar))?;
    let receipt = validate_zk_common_root_wallet_receipt(
        &issued.envelope,
        &issued.binding,
        status_list,
        trusted_issuer,
        trusted_issuer,
        &holder_public,
        now_unix,
        ZkWalletReceiptPolicy {
            profile_id: PROFILE_ID,
            minimum_assurance: AssuranceLevel::High,
            status_issuer: &issued.envelope.status.status_list_url,
            max_status_age_seconds: 3_600,
        },
    )?;
    issued
        .private_claims
        .verify_issuer_root(&receipt.root.merkle_root)
        .map_err(|_| HarnessError::InvalidPresentationAccepted)?;
    Ok(())
}

pub(super) fn reject_revoked_and_stale_wallet_receipts(
    issued: &VerifiedZkStoredCredential,
    issuer_scalar: u8,
    subject_scalar: u8,
    now_unix: u64,
) -> Result<(), HarnessError> {
    let original = &issued.status_list;
    let mut revoked = StatusList {
        issuer: original.issuer.clone(),
        purpose: original.purpose,
        issued_at: original.issued_at,
        next_update: original.next_update,
        encoded_list: vec![0, 0b0000_0010],
        length: original.length,
        list_id: original.list_id,
        signature: StatusListSignature {
            alg: StatusListAlgorithm::P256,
            sig_bytes: Vec::new(),
        },
    };
    sign_test_status_list(&mut revoked, issuer_scalar)?;
    if validate_wallet_receipt_with_status(
        issued,
        &revoked,
        issuer_scalar,
        subject_scalar,
        now_unix,
    )
    .is_ok()
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }

    let mut stale = StatusList {
        issuer: original.issuer.clone(),
        purpose: original.purpose,
        issued_at: original.issued_at,
        next_update: original.issued_at,
        encoded_list: original.encoded_list.clone(),
        length: original.length,
        list_id: original.list_id,
        signature: StatusListSignature {
            alg: StatusListAlgorithm::P256,
            sig_bytes: Vec::new(),
        },
    };
    sign_test_status_list(&mut stale, issuer_scalar)?;
    if validate_wallet_receipt_with_status(issued, &stale, issuer_scalar, subject_scalar, now_unix)
        .is_ok()
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    Ok(())
}

pub(crate) fn sign_test_status_list(
    status_list: &mut StatusList,
    issuer_scalar: u8,
) -> Result<(), HarnessError> {
    let payload = status_list_signing_payload(status_list)?;
    status_list.signature.sig_bytes = sign_raw(&scalar(issuer_scalar), &payload)?.to_vec();
    Ok(())
}
