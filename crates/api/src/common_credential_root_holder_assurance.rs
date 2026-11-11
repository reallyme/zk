// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One checked owner for holder-private assurance and its current active path.

use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    common_root::{
        normalize_common_credential_root_p256_signature_low_s,
        verify_common_credential_root_active_status_membership,
        verify_common_credential_root_attestation_material,
        ZkCommonCredentialRootAttestationMaterial, ZkCommonCredentialRootAttestationTrustPolicy,
        ZkVerifiedRootStatusSnapshot, COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH,
    },
    keys::ZkAttestationPublicKey,
};

/// Stable reason for rejecting a holder-private assurance package.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootHolderAssuranceReason {
    /// The signed attestation failed the deployment's pinned trust policy.
    #[error("root attestation invalid")]
    InvalidAttestation,
    /// The private path did not open that attestation in the current active set.
    #[error("active status opening invalid")]
    InvalidStatusOpening,
    /// The supplied path exceeds the circuit's bounded capacity.
    #[error("active status path too long")]
    PathTooLong,
    /// The selected credentials do not share the assured hidden root.
    #[error("credential lineage root mismatch")]
    LineageRootMismatch,
    /// The attestation or signed active-root snapshot expired before use.
    #[error("holder assurance stale")]
    Stale,
}

/// Typed failure without root, attestation ID, or path contents.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("holder assurance admission failed: {reason}")]
pub struct ZkCommonCredentialRootHolderAssuranceError {
    reason: ZkCommonCredentialRootHolderAssuranceReason,
}

impl ZkCommonCredentialRootHolderAssuranceError {
    /// Return a stable reason for protocol and FFI mapping.
    #[must_use]
    pub const fn reason(self) -> ZkCommonCredentialRootHolderAssuranceReason {
        self.reason
    }
}

/// Attestation and current membership path bound to the same hidden root.
///
/// The wallet owns this value only while building a presentation. Its root,
/// signature, identifier, and path are erased on drop. The verifier still
/// checks the corresponding circuit proofs against independently trusted
/// authority inputs; admission here is a wallet-side preflight.
pub struct ZkCommonCredentialRootHolderAssurance {
    root: Zeroizing<[u8; 32]>,
    attestation_id: Zeroizing<[u8; 32]>,
    signature: Zeroizing<[u8; 64]>,
    status_index: u32,
    siblings: Zeroizing<Vec<[u8; 32]>>,
    issued_unix: u64,
    expires_unix: u64,
    epoch: u32,
    signer: ZkAttestationPublicKey,
    assurance_policy_id: [u8; 32],
    snapshot: ZkVerifiedRootStatusSnapshot,
}

impl ZkCommonCredentialRootHolderAssurance {
    /// Authenticate the exact attestation and its opening under caller-owned trust.
    ///
    /// `now_unix` comes from the wallet's trusted clock; the attestation's
    /// request time is separately bound to the verifier's active session.
    pub fn admit(
        material: ZkCommonCredentialRootAttestationMaterial<'_>,
        trust: ZkCommonCredentialRootAttestationTrustPolicy,
        snapshot: ZkVerifiedRootStatusSnapshot,
        now_unix: u64,
        status_index: u32,
        siblings: &[[u8; 32]],
    ) -> Result<Self, ZkCommonCredentialRootHolderAssuranceError> {
        if siblings.len() > COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH {
            return Err(error(
                ZkCommonCredentialRootHolderAssuranceReason::PathTooLong,
            ));
        }
        let signature = Zeroizing::new(
            normalize_common_credential_root_p256_signature_low_s(*material.attestation_signature)
                .map_err(|_| {
                    error(ZkCommonCredentialRootHolderAssuranceReason::InvalidAttestation)
                })?,
        );
        let normalized_material = ZkCommonCredentialRootAttestationMaterial {
            reallyme_public_key: material.reallyme_public_key,
            assurance_policy_id: material.assurance_policy_id,
            request_time_unix: material.request_time_unix,
            root: material.root,
            attestation_issued_unix: material.attestation_issued_unix,
            attestation_expires_unix: material.attestation_expires_unix,
            attestation_epoch: material.attestation_epoch,
            attestation_signature: &signature,
        };
        let root = Zeroizing::new(*normalized_material.root);
        let request_time_unix = material.request_time_unix;
        let issued_unix = material.attestation_issued_unix;
        let expires_unix = material.attestation_expires_unix;
        let epoch = material.attestation_epoch;
        let signer = trust.signer;
        let assurance_policy_id = trust.assurance_policy_id;
        let attestation_id = Zeroizing::new(
            verify_common_credential_root_attestation_material(normalized_material, trust)
                .map_err(|_| {
                    error(ZkCommonCredentialRootHolderAssuranceReason::InvalidAttestation)
                })?,
        );
        verify_common_credential_root_active_status_membership(
            snapshot,
            now_unix,
            &attestation_id,
            status_index,
            siblings,
        )
        .map_err(|_| error(ZkCommonCredentialRootHolderAssuranceReason::InvalidStatusOpening))?;
        let mut owned_path = Vec::new();
        owned_path
            .try_reserve_exact(siblings.len())
            .map_err(|_| error(ZkCommonCredentialRootHolderAssuranceReason::PathTooLong))?;
        owned_path.extend_from_slice(siblings);
        let admitted = Self {
            root,
            attestation_id,
            signature,
            status_index,
            siblings: Zeroizing::new(owned_path),
            issued_unix,
            expires_unix,
            epoch,
            signer,
            assurance_policy_id,
            snapshot,
        };
        admitted.validate_at(now_unix)?;
        if request_time_unix > now_unix {
            return Err(error(ZkCommonCredentialRootHolderAssuranceReason::Stale));
        }
        Ok(admitted)
    }

    /// Recheck the exact signed time bounds immediately before witness creation.
    pub fn validate_at(
        &self,
        now_unix: u64,
    ) -> Result<(), ZkCommonCredentialRootHolderAssuranceError> {
        if now_unix < self.issued_unix || now_unix >= self.expires_unix {
            return Err(error(ZkCommonCredentialRootHolderAssuranceReason::Stale));
        }
        self.snapshot
            .validate_at(now_unix)
            .map_err(|_| error(ZkCommonCredentialRootHolderAssuranceReason::Stale))
    }

    /// Require both storage-authenticated credential lineages to use this root.
    ///
    /// The caller must first verify each encrypted credential record against
    /// its exact issuer receipt. This check prevents cross-record composition
    /// after those independent receipt checks have succeeded.
    pub fn require_lineage_roots(
        &self,
        first: &[u8; 32],
        second: &[u8; 32],
    ) -> Result<(), ZkCommonCredentialRootHolderAssuranceError> {
        let first_matches = self.root.as_slice().ct_eq(first);
        let second_matches = self.root.as_slice().ct_eq(second);
        if !bool::from(first_matches & second_matches) {
            return Err(error(
                ZkCommonCredentialRootHolderAssuranceReason::LineageRootMismatch,
            ));
        }
        Ok(())
    }

    /// Borrow the hidden root while composing stage witnesses.
    #[must_use]
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Borrow the attestation identifier committed by the status stage.
    #[must_use]
    pub fn attestation_id(&self) -> &[u8; 32] {
        &self.attestation_id
    }

    /// Borrow the authority signature for the attestation stage.
    #[must_use]
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Index of this attestation in the authenticated active set.
    #[must_use]
    pub const fn status_index(&self) -> u32 {
        self.status_index
    }

    /// Borrow the bounded Merkle path for the status stage.
    #[must_use]
    pub fn siblings(&self) -> &[[u8; 32]] {
        self.siblings.as_slice()
    }

    /// Root-attestation issuance time signed by ReallyMe.
    #[must_use]
    pub const fn issued_unix(&self) -> u64 {
        self.issued_unix
    }

    /// Exclusive root-attestation expiry signed by ReallyMe.
    #[must_use]
    pub const fn expires_unix(&self) -> u64 {
        self.expires_unix
    }

    /// Root-attestation epoch signed by ReallyMe.
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Deployment-pinned signer checked at admission.
    #[must_use]
    pub const fn signer(&self) -> ZkAttestationPublicKey {
        self.signer
    }

    /// Deployment-pinned assurance policy checked at admission.
    #[must_use]
    pub const fn assurance_policy_id(&self) -> [u8; 32] {
        self.assurance_policy_id
    }
}

impl ZeroizeOnDrop for ZkCommonCredentialRootHolderAssurance {}

const fn error(
    reason: ZkCommonCredentialRootHolderAssuranceReason,
) -> ZkCommonCredentialRootHolderAssuranceError {
    ZkCommonCredentialRootHolderAssuranceError { reason }
}

#[cfg(test)]
#[path = "common_credential_root_holder_assurance/tests.rs"]
mod tests;
