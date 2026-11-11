// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Versioned ReallyMe root-assurance attestation carried privately by wallets.

#[cfg(any(feature = "native", feature = "wasm"))]
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[cfg(any(feature = "native", feature = "wasm"))]
use crate::common_root::{
    common_credential_root_root_commitment,
    derive_common_credential_root_attestation_id_from_commitment,
    ZkCommonCredentialRootAttestationTrustPolicy,
};
use crate::{
    common_root::{
        normalize_common_credential_root_p256_signature_low_s,
        ZkCommonCredentialRootAttestationCommitmentMaterial,
        ZkCommonCredentialRootAttestationMaterial,
    },
    keys::ZkAttestationPublicKey,
};

const HASH_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// Stable reason for rejecting an authority-issued attestation record.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkRootAssuranceAttestationReason {
    /// A required fixed-width field is zero or the time interval is invalid.
    #[error("invalid root assurance field")]
    InvalidField,
    /// The holder's secret root does not open the signed commitment.
    #[error("root assurance commitment mismatch")]
    RootMismatch,
    /// The authority signature, policy, or validity interval failed admission.
    #[error("root assurance trust check failed")]
    TrustRejected,
}

/// Typed attestation error without a root, identifier, or signature value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("root assurance attestation rejected: {reason}")]
pub struct ZkRootAssuranceAttestationError {
    reason: ZkRootAssuranceAttestationReason,
}

impl ZkRootAssuranceAttestationError {
    /// Return a stable, non-sensitive failure reason.
    #[must_use]
    pub const fn reason(self) -> ZkRootAssuranceAttestationReason {
        self.reason
    }
}

/// Authority-signed assertion about one hidden wallet root commitment.
///
/// This record is stored in the encrypted wallet. A verifier sees its
/// attestation proof, not the record or its reusable commitment. Construction
/// checks shape; `verify_for_root` authenticates the exact signer and policy.
pub struct ZkRootAssuranceAttestation {
    root_commitment: Zeroizing<[u8; HASH_BYTES]>,
    assurance_policy_id: Zeroizing<[u8; HASH_BYTES]>,
    issued_unix: u64,
    expires_unix: u64,
    epoch: u32,
    signer: ZkAttestationPublicKey,
    signature: Zeroizing<[u8; SIGNATURE_BYTES]>,
}

impl ZeroizeOnDrop for ZkRootAssuranceAttestation {}

impl ZkRootAssuranceAttestation {
    /// Admit exact fixed fields from a decoded or stored attestation artifact.
    pub fn try_from_signed_parts(
        root_commitment: [u8; HASH_BYTES],
        assurance_policy_id: [u8; HASH_BYTES],
        issued_unix: u64,
        expires_unix: u64,
        epoch: u32,
        signer: ZkAttestationPublicKey,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Result<Self, ZkRootAssuranceAttestationError> {
        let normalized = normalize_common_credential_root_p256_signature_low_s(signature)
            .map_err(|_| error(ZkRootAssuranceAttestationReason::InvalidField))?;
        if normalized != signature {
            return Err(error(ZkRootAssuranceAttestationReason::InvalidField));
        }
        Self::try_from_canonical_signed_parts(
            root_commitment,
            assurance_policy_id,
            issued_unix,
            expires_unix,
            epoch,
            signer,
            signature,
        )
    }

    /// Admit private attestation authority signer output by canonicalizing low-S.
    ///
    /// Use this only before publishing or storing a newly signed authority
    /// artifact. Decoded wallet records must use `try_from_signed_parts` so
    /// non-canonical high-S artifacts are rejected instead of rewritten.
    pub fn try_from_authority_signed_parts(
        root_commitment: [u8; HASH_BYTES],
        assurance_policy_id: [u8; HASH_BYTES],
        issued_unix: u64,
        expires_unix: u64,
        epoch: u32,
        signer: ZkAttestationPublicKey,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Result<Self, ZkRootAssuranceAttestationError> {
        let signature = normalize_common_credential_root_p256_signature_low_s(signature)
            .map_err(|_| error(ZkRootAssuranceAttestationReason::InvalidField))?;
        Self::try_from_canonical_signed_parts(
            root_commitment,
            assurance_policy_id,
            issued_unix,
            expires_unix,
            epoch,
            signer,
            signature,
        )
    }

    fn try_from_canonical_signed_parts(
        root_commitment: [u8; HASH_BYTES],
        assurance_policy_id: [u8; HASH_BYTES],
        issued_unix: u64,
        expires_unix: u64,
        epoch: u32,
        signer: ZkAttestationPublicKey,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Result<Self, ZkRootAssuranceAttestationError> {
        let root_commitment = Zeroizing::new(root_commitment);
        let assurance_policy_id = Zeroizing::new(assurance_policy_id);
        let signature = Zeroizing::new(signature);
        if root_commitment.iter().all(|byte| *byte == 0)
            || assurance_policy_id.iter().all(|byte| *byte == 0)
            || (signer.x.iter().all(|byte| *byte == 0) && signer.y.iter().all(|byte| *byte == 0))
            || signature.iter().all(|byte| *byte == 0)
            || issued_unix == 0
            || expires_unix <= issued_unix
        {
            return Err(error(ZkRootAssuranceAttestationReason::InvalidField));
        }
        Ok(Self {
            root_commitment,
            assurance_policy_id,
            issued_unix,
            expires_unix,
            epoch,
            signer,
            signature,
        })
    }

    /// Commit to this exact root without exposing it to the authority.
    #[must_use]
    pub fn root_commitment(&self) -> &[u8; HASH_BYTES] {
        &self.root_commitment
    }

    /// Assurance policy signed by the authority.
    #[must_use]
    pub fn assurance_policy_id(&self) -> &[u8; HASH_BYTES] {
        &self.assurance_policy_id
    }

    /// Signed issuance time.
    #[must_use]
    pub const fn issued_unix(&self) -> u64 {
        self.issued_unix
    }

    /// Exclusive signed expiration time.
    #[must_use]
    pub const fn expires_unix(&self) -> u64 {
        self.expires_unix
    }

    /// Signed root epoch.
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Claimed authority key; the caller must compare it to pinned policy.
    #[must_use]
    pub const fn signer(&self) -> ZkAttestationPublicKey {
        self.signer
    }

    /// Fixed-width P-256 signature in `r || s` form.
    #[must_use]
    pub fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// Borrow exact verification inputs without copying the hidden root.
    #[must_use]
    pub fn material<'a>(
        &'a self,
        root: &'a [u8; HASH_BYTES],
        request_time_unix: u64,
    ) -> ZkCommonCredentialRootAttestationMaterial<'a> {
        ZkCommonCredentialRootAttestationMaterial {
            reallyme_public_key: self.signer,
            assurance_policy_id: *self.assurance_policy_id,
            request_time_unix,
            root,
            attestation_issued_unix: self.issued_unix,
            attestation_expires_unix: self.expires_unix,
            attestation_epoch: self.epoch,
            attestation_signature: &self.signature,
        }
    }

    /// Borrow authority-visible ID inputs without holder root material.
    #[must_use]
    pub fn commitment_material(&self) -> ZkCommonCredentialRootAttestationCommitmentMaterial<'_> {
        ZkCommonCredentialRootAttestationCommitmentMaterial {
            reallyme_public_key: self.signer,
            assurance_policy_id: *self.assurance_policy_id,
            root_commitment: &self.root_commitment,
            attestation_issued_unix: self.issued_unix,
            attestation_expires_unix: self.expires_unix,
            attestation_epoch: self.epoch,
            attestation_signature: &self.signature,
        }
    }

    /// Verify the public commitment signature and derive the active-set ID.
    ///
    /// This is the authority/status-publication path. It never receives the
    /// holder root `R`; it derives the same identifier from the signed
    /// commitment `C` that wallets later reproduce from `R` privately. Callers
    /// must pass deployment-pinned trust policy so a self-signed or wrong-policy
    /// record cannot accidentally enter a published active set.
    #[cfg(any(feature = "native", feature = "wasm"))]
    pub fn attestation_id_for_status_publication(
        &self,
        trust: ZkCommonCredentialRootAttestationTrustPolicy,
        publication_time_unix: u64,
    ) -> Result<Zeroizing<[u8; HASH_BYTES]>, ZkRootAssuranceAttestationError> {
        if self.signer != trust.signer || *self.assurance_policy_id != trust.assurance_policy_id {
            return Err(error(ZkRootAssuranceAttestationReason::TrustRejected));
        }
        if publication_time_unix < self.issued_unix || publication_time_unix >= self.expires_unix {
            return Err(error(ZkRootAssuranceAttestationReason::TrustRejected));
        }
        let id = Zeroizing::new(
            derive_common_credential_root_attestation_id_from_commitment(
                self.commitment_material(),
            )
            .map_err(|_| error(ZkRootAssuranceAttestationReason::InvalidField))?,
        );
        // Keep the already-computed SHA-256 value in the crypto crate's typed,
        // zeroizing owner so it cannot be confused with original message bytes.
        let digest = crypto_p256::P256Sha256Digest::new(
            crate::common_root::common_credential_root_attestation_signing_digest(
                &self.root_commitment,
                *self.assurance_policy_id,
                self.issued_unix,
                self.expires_unix,
                self.epoch,
            )
            .map_err(|_| error(ZkRootAssuranceAttestationReason::InvalidField))?,
        );
        let mut public_key = [0_u8; 65];
        public_key[0] = 0x04;
        public_key[1..33].copy_from_slice(&self.signer.x);
        public_key[33..65].copy_from_slice(&self.signer.y);
        let signature_der = Zeroizing::new(
            crypto_p256::p256_ecdsa_jose_signature_to_der(self.signature.as_ref())
                .map_err(|_| error(ZkRootAssuranceAttestationReason::TrustRejected))?,
        );
        crypto_p256::verify_p256_sha256_digest_low_s_der(
            signature_der.as_slice(),
            &digest,
            &public_key,
        )
        .map_err(|_| error(ZkRootAssuranceAttestationReason::TrustRejected))?;
        Ok(id)
    }

    /// Verify the hidden root, pinned authority, policy, and exact signature.
    ///
    /// The returned attestation ID is private witness material. Callers must
    /// keep it inside a zeroizing owner and must not use it in a network query.
    #[cfg(any(feature = "native", feature = "wasm"))]
    pub fn verify_for_root(
        &self,
        root: &[u8; HASH_BYTES],
        trust: ZkCommonCredentialRootAttestationTrustPolicy,
        request_time_unix: u64,
    ) -> Result<Zeroizing<[u8; HASH_BYTES]>, ZkRootAssuranceAttestationError> {
        let commitment = common_credential_root_root_commitment(root)
            .map_err(|_| error(ZkRootAssuranceAttestationReason::RootMismatch))?;
        if !bool::from(commitment.as_slice().ct_eq(self.root_commitment.as_slice())) {
            return Err(error(ZkRootAssuranceAttestationReason::RootMismatch));
        }
        let id = crate::common_root::verify_common_credential_root_attestation_material(
            self.material(root, request_time_unix),
            trust,
        )
        .map_err(|_| error(ZkRootAssuranceAttestationReason::TrustRejected))?;
        Ok(Zeroizing::new(id))
    }
}

const fn error(reason: ZkRootAssuranceAttestationReason) -> ZkRootAssuranceAttestationError {
    ZkRootAssuranceAttestationError { reason }
}

#[cfg(test)]
#[path = "common_credential_root_attestation/tests.rs"]
mod tests;
