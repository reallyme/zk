// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Convert verifier-owned common-credential-root join policy while clearing private claims.

use reallyme_zk_api::{
    common_root::{
        ZkCommonCredentialRootClaimExpectation, ZkCommonCredentialRootIssuerStatusExpectation,
        ZkCommonCredentialRootJoinPolicy, ZkCommonCredentialRootPersonaMode,
    },
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_STATUS_VALIDATION_MAX_AGE_SECONDS: u64 = 120;

/// One verifier-owned common-credential-root claim expectation.
pub struct ZkCommonCredentialRootClaimExpectationOwner {
    issuer: ZkIssuerPublicKey,
    claim_name_hash: [u8; 32],
    value: Zeroizing<Vec<u8>>,
}

impl ZkCommonCredentialRootClaimExpectationOwner {
    /// Borrows the API-domain expectation without exposing ownership.
    #[must_use]
    pub fn as_borrowed(&self) -> ZkCommonCredentialRootClaimExpectation<'_> {
        ZkCommonCredentialRootClaimExpectation {
            issuer: self.issuer,
            claim_name_hash: self.claim_name_hash,
            value: self.value.as_slice(),
        }
    }
}

impl Drop for ZkCommonCredentialRootClaimExpectationOwner {
    fn drop(&mut self) {
        // Claim names can themselves be sensitive when they identify a
        // credential category. The plaintext value is held by Zeroizing.
        self.claim_name_hash.zeroize();
    }
}

/// Verifier-owned common-credential-root join policy.
pub struct ZkCommonCredentialRootJoinPolicyOwner {
    challenge: [u8; 32],
    audience_hash: [u8; 32],
    transaction_data_hash: [u8; 32],
    request_time_unix: u64,
    status_validation_time_unix: u64,
    status_validation_max_age_seconds: u64,
    attestation_signer: reallyme_zk_api::keys::ZkAttestationPublicKey,
    assurance_policy_id: [u8; 32],
    status_root: [u8; 32],
    claims: [ZkCommonCredentialRootClaimExpectationOwner; 2],
    issuer_status: [ZkCommonCredentialRootIssuerStatusExpectation; 2],
}

impl ZkCommonCredentialRootJoinPolicyOwner {
    /// Borrows the API-domain join policy for one persona mode.
    #[must_use]
    pub fn as_borrowed(
        &self,
        persona_mode: ZkCommonCredentialRootPersonaMode,
    ) -> ZkCommonCredentialRootJoinPolicy<'_> {
        ZkCommonCredentialRootJoinPolicy {
            challenge: self.challenge,
            audience_hash: self.audience_hash,
            transaction_data_hash: self.transaction_data_hash,
            request_time_unix: self.request_time_unix,
            status_validation_time_unix: self.status_validation_time_unix,
            status_validation_max_age_seconds: self.status_validation_max_age_seconds,
            attestation_signer: self.attestation_signer,
            assurance_policy_id: self.assurance_policy_id,
            status_root: self.status_root,
            claims: [self.claims[0].as_borrowed(), self.claims[1].as_borrowed()],
            issuer_status: self.issuer_status,
            persona_mode,
        }
    }
}

/// Converts a generated verifier-owned join policy into a zeroizing owner.
pub(crate) fn common_credential_root_join_policy_from_proto(
    policy: pb::ZkCommonCredentialRootJoinPolicy,
) -> Result<ZkCommonCredentialRootJoinPolicyOwner, ZkError> {
    // The generated policy carries plaintext verifier claim expectations.
    // Own it before validation so every early error clears unconverted claims.
    let mut policy = JoinPolicyInputGuard(policy);
    if policy.claims.len() != 2 || policy.issuer_status.len() != 2 {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }
    let first_input = policy
        .claims
        .get_mut(0)
        .map(core::mem::take)
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    let first = common_credential_root_claim_expectation_from_proto(first_input)?;
    let second_input = policy
        .claims
        .get_mut(1)
        .map(core::mem::take)
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    let second = common_credential_root_claim_expectation_from_proto(second_input)?;
    let first_status = policy
        .issuer_status
        .get_mut(0)
        .map(core::mem::take)
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    let second_status = policy
        .issuer_status
        .get_mut(1)
        .map(core::mem::take)
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    let issuer_status = [
        issuer_status_expectation_from_proto(first_status)?,
        issuer_status_expectation_from_proto(second_status)?,
    ];
    let attestation_signer = issuer_public_key_from_proto(
        policy
            .attestation_signer
            .take()
            .ok_or(ZkError::new(ZkErrorReason::UntrustedIssuer))?,
    )?;
    if policy.status_validation_time_unix == 0 {
        return Err(ZkError::new(ZkErrorReason::PresentationExpired));
    }
    Ok(ZkCommonCredentialRootJoinPolicyOwner {
        challenge: bytes32_from_vec(&mut policy.challenge, ZkErrorReason::BindingMismatch)?,
        audience_hash: bytes32_from_vec(&mut policy.audience_hash, ZkErrorReason::BindingMismatch)?,
        transaction_data_hash: bytes32_from_vec(
            &mut policy.transaction_data_hash,
            ZkErrorReason::BindingMismatch,
        )?,
        request_time_unix: policy.request_time_unix,
        status_validation_time_unix: policy.status_validation_time_unix,
        status_validation_max_age_seconds: if policy.status_validation_max_age_seconds == 0 {
            DEFAULT_STATUS_VALIDATION_MAX_AGE_SECONDS
        } else {
            policy.status_validation_max_age_seconds
        },
        attestation_signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(attestation_signer),
        ),
        assurance_policy_id: bytes32_from_vec(
            &mut policy.assurance_policy_id,
            ZkErrorReason::BindingMismatch,
        )?,
        status_root: bytes32_from_vec(&mut policy.status_root, ZkErrorReason::BindingMismatch)?,
        claims: [first, second],
        issuer_status,
    })
}

fn issuer_status_expectation_from_proto(
    mut status: pb::ZkCommonCredentialRootIssuerStatusExpectation,
) -> Result<ZkCommonCredentialRootIssuerStatusExpectation, ZkError> {
    let purpose = crate::issuer_status::purpose_from_proto(status.purpose)?;
    if status.length == 0 || status.length > 1_000_000 {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(ZkCommonCredentialRootIssuerStatusExpectation {
        root: bytes32_from_vec(&mut status.root, ZkErrorReason::InvalidProofEncoding)?,
        length: status.length,
        list_id: bytes32_from_vec(&mut status.list_id, ZkErrorReason::InvalidProofEncoding)?,
        url_hash: bytes32_from_vec(&mut status.url_hash, ZkErrorReason::InvalidProofEncoding)?,
        purpose,
    })
}

fn common_credential_root_claim_expectation_from_proto(
    mut claim: pb::ZkCommonCredentialRootClaimExpectation,
) -> Result<ZkCommonCredentialRootClaimExpectationOwner, ZkError> {
    // Take the plaintext before any fallible issuer or length check. This
    // avoids a second allocation and clears it if conversion fails.
    let value = Zeroizing::new(core::mem::take(&mut claim.claim_value));
    let mut claim_name_hash = Zeroizing::new(core::mem::take(&mut claim.claim_name_hash));
    let issuer = issuer_public_key_from_proto(
        claim
            .issuer
            .take()
            .ok_or(ZkError::new(ZkErrorReason::UntrustedIssuer))?,
    )?;
    let value_len = usize::try_from(claim.claim_value_length)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if value_len == 0 || value_len > 64 || value.len() != value_len {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    Ok(ZkCommonCredentialRootClaimExpectationOwner {
        issuer,
        claim_name_hash: bytes32_from_vec(
            &mut claim_name_hash,
            ZkErrorReason::InvalidProofEncoding,
        )?,
        value,
    })
}

struct JoinPolicyInputGuard(pb::ZkCommonCredentialRootJoinPolicy);

impl core::ops::Deref for JoinPolicyInputGuard {
    type Target = pb::ZkCommonCredentialRootJoinPolicy;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for JoinPolicyInputGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for JoinPolicyInputGuard {
    fn drop(&mut self) {
        zeroize_common_credential_root_join_policy_proto(&mut self.0);
    }
}

pub(crate) fn zeroize_common_credential_root_join_policy_proto(
    policy: &mut pb::ZkCommonCredentialRootJoinPolicy,
) {
    policy.challenge.zeroize();
    policy.audience_hash.zeroize();
    policy.transaction_data_hash.zeroize();
    policy.assurance_policy_id.zeroize();
    policy.status_root.zeroize();
    for claim in &mut policy.claims {
        claim.claim_name_hash.zeroize();
        claim.claim_value.zeroize();
    }
    for status in &mut policy.issuer_status {
        status.root.zeroize();
        status.list_id.zeroize();
        status.url_hash.zeroize();
    }
}

fn issuer_public_key_from_proto(
    mut key: pb::ZkP256PublicKey,
) -> Result<ZkIssuerPublicKey, ZkError> {
    let x = bytes32_from_vec(&mut key.x, ZkErrorReason::InvalidProofEncoding)?;
    let y = bytes32_from_vec(&mut key.y, ZkErrorReason::InvalidProofEncoding)?;
    if x == [0_u8; 32] && y == [0_u8; 32] {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(ZkIssuerPublicKey { x, y })
}

fn bytes32_from_vec(bytes: &mut Vec<u8>, reason: ZkErrorReason) -> Result<[u8; 32], ZkError> {
    let value = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ZkError::new(reason))?;
    bytes.zeroize();
    Ok(value)
}
