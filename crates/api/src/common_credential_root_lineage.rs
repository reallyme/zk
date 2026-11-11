// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuance relationship derivation shared by common-credential-root v1 hash lanes.

use crypto_hkdf::{DeriveRequest, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt, HkdfSuite};
use crypto_sha2_256::digest as sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    common_root::{ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootSubjectPublicKey},
    keys::ZkIssuerPublicKey,
};

const CONTEXT_DOMAIN: &[u8; 6] = b"RMCTX1";
const EXTRACT_DOMAIN: &[u8] = b"ReallyMe/common-credential-root/v1/HKDF-Extract";
const FIELD_BYTES: usize = 32;
const CONTEXT_PREIMAGE_BYTES: usize = CONTEXT_DOMAIN.len() + (6 * FIELD_BYTES);
/// Maximum canonical relationship DID admitted by common-credential-root v1.
pub const MAX_COMMON_CREDENTIAL_ROOT_RELATIONSHIP_DID_BYTES: usize = 2048;
const DID_ME_PREFIX: &str = "did:me:";

/// Stable, non-sensitive reason for a rejected lineage derivation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootLineageReason {
    /// The supplied relationship DID does not meet this persona_mode's bounds.
    #[error("invalid relationship identifier")]
    InvalidRelationship,
    /// A root or relationship nonce used a reserved all-zero value.
    #[error("invalid derivation material")]
    InvalidMaterial,
    /// The approved HKDF provider rejected the derivation.
    #[error("lineage derivation failed")]
    DerivationFailed,
    /// The retained private root, nonce, or relationship differs from the committed opening.
    #[error("private lineage opening mismatch")]
    OpeningMismatch,
}

/// Typed failure from the v1 relationship-specific lineage transcript.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("common-credential-root lineage failed: {reason}")]
pub struct ZkCommonCredentialRootLineageError {
    reason: ZkCommonCredentialRootLineageReason,
}

impl ZkCommonCredentialRootLineageError {
    /// Return the stable reason without exposing DID or secret root material.
    #[must_use]
    pub const fn reason(self) -> ZkCommonCredentialRootLineageReason {
        self.reason
    }
}

/// Issuer-visible context digest and holder-private derived lineage value.
pub struct ZkCommonCredentialRootDerivedLineage {
    context_hash: [u8; FIELD_BYTES],
    tag: Zeroizing<[u8; FIELD_BYTES]>,
}

/// Private derivation inputs retained only inside wallet-encrypted storage.
///
/// Construction verifies the exact reserved leaf committed by the issuer.
/// Keeping these inputs permits a later proof to reconstruct the lineage
/// transcript without trusting unvalidated storage bytes or fixture data.
pub struct ZkCommonCredentialRootPrivateLineageMaterial {
    root: Zeroizing<[u8; FIELD_BYTES]>,
    relationship_did: Zeroizing<String>,
    nonce: Zeroizing<[u8; FIELD_BYTES]>,
}

impl ZkCommonCredentialRootPrivateLineageMaterial {
    /// Admit private lineage inputs only when they reconstruct the prepared tree.
    pub fn new(
        root: [u8; FIELD_BYTES],
        relationship_did: String,
        nonce: [u8; FIELD_BYTES],
        issuer_key: ZkIssuerPublicKey,
        subject_key: ZkCommonCredentialRootSubjectPublicKey,
        claims: &ZkCommonCredentialRootClaimsCommitment,
    ) -> Result<Self, ZkCommonCredentialRootLineageError> {
        let material = Self {
            root: Zeroizing::new(root),
            relationship_did: Zeroizing::new(relationship_did),
            nonce: Zeroizing::new(nonce),
        };
        material.validate_against(issuer_key, subject_key, claims)?;
        Ok(material)
    }

    /// Recheck after decryption using the authenticated issuer and holder keys.
    pub fn validate_against(
        &self,
        issuer_key: ZkIssuerPublicKey,
        subject_key: ZkCommonCredentialRootSubjectPublicKey,
        claims: &ZkCommonCredentialRootClaimsCommitment,
    ) -> Result<(), ZkCommonCredentialRootLineageError> {
        let derived = derive_common_credential_root_v1_lineage(
            &self.root,
            issuer_key,
            &self.relationship_did,
            subject_key,
            &self.nonce,
        )?;
        let opening = claims
            .openings()
            .first()
            .ok_or(ZkCommonCredentialRootLineageError {
                reason: ZkCommonCredentialRootLineageReason::OpeningMismatch,
            })?;
        let value = opening.value();
        let mut expected = Zeroizing::new([0_u8; 2 * FIELD_BYTES]);
        expected[..FIELD_BYTES].copy_from_slice(&derived.context_hash());
        expected[FIELD_BYTES..].copy_from_slice(derived.tag());
        if value.len() != expected.len() || !bool::from(expected.as_slice().ct_eq(value)) {
            return Err(ZkCommonCredentialRootLineageError {
                reason: ZkCommonCredentialRootLineageReason::OpeningMismatch,
            });
        }
        Ok(())
    }

    /// Borrow the common secret root only while constructing a private witness.
    #[must_use]
    pub fn root(&self) -> &[u8; FIELD_BYTES] {
        &self.root
    }

    /// Borrow the canonical relationship identifier within the protected owner.
    #[must_use]
    pub fn relationship_did(&self) -> &str {
        &self.relationship_did
    }

    /// Borrow the relationship nonce only while constructing a private witness.
    #[must_use]
    pub fn nonce(&self) -> &[u8; FIELD_BYTES] {
        &self.nonce
    }
}

impl ZkCommonCredentialRootDerivedLineage {
    /// SHA-256 of the exact relationship context consumed by the circuit.
    #[must_use]
    pub const fn context_hash(&self) -> [u8; FIELD_BYTES] {
        self.context_hash
    }

    /// Holder-private HKDF output committed in the reserved lineage leaf.
    #[must_use]
    pub fn tag(&self) -> &[u8; FIELD_BYTES] {
        &self.tag
    }
}

/// Derive the issuer-specific lineage value from a private random root.
///
/// The caller supplies a canonical relationship DID, independently generated
/// P-256 issuer and subject keys, and a fresh relationship nonce. Reusing a
/// context is an application-level issuance error; callers must track nonce
/// use across issuances. The derivation does not reveal the root to the issuer.
pub fn derive_common_credential_root_v1_lineage(
    root: &[u8; FIELD_BYTES],
    issuer_key: ZkIssuerPublicKey,
    relationship_did: &str,
    subject_key: ZkCommonCredentialRootSubjectPublicKey,
    nonce: &[u8; FIELD_BYTES],
) -> Result<ZkCommonCredentialRootDerivedLineage, ZkCommonCredentialRootLineageError> {
    if !relationship_did.starts_with(DID_ME_PREFIX)
        || relationship_did.len() <= DID_ME_PREFIX.len()
        || relationship_did.len() > MAX_COMMON_CREDENTIAL_ROOT_RELATIONSHIP_DID_BYTES
    {
        return Err(ZkCommonCredentialRootLineageError {
            reason: ZkCommonCredentialRootLineageReason::InvalidRelationship,
        });
    }
    if root.iter().all(|byte| *byte == 0) || nonce.iter().all(|byte| *byte == 0) {
        return Err(ZkCommonCredentialRootLineageError {
            reason: ZkCommonCredentialRootLineageReason::InvalidMaterial,
        });
    }
    let did_hash = sha256(relationship_did.as_bytes()).into_bytes();
    let mut context = Zeroizing::new([0_u8; CONTEXT_PREIMAGE_BYTES]);
    context[..CONTEXT_DOMAIN.len()].copy_from_slice(CONTEXT_DOMAIN);
    let fields = Zeroizing::new([
        issuer_key.x,
        issuer_key.y,
        did_hash,
        subject_key.x,
        subject_key.y,
        *nonce,
    ]);
    for (chunk, field) in context[CONTEXT_DOMAIN.len()..]
        .as_chunks_mut::<FIELD_BYTES>()
        .0
        .iter_mut()
        .zip(fields.iter())
    {
        chunk.copy_from_slice(field);
    }
    let context_hash = sha256(context.as_slice()).into_bytes();
    let mut extract_salt = Zeroizing::new(sha256(EXTRACT_DOMAIN).into_bytes());
    let ikm = HkdfInputKeyMaterial::from_slice(root);
    let salt = HkdfSalt::from_slice(extract_salt.as_slice());
    let info = HkdfInfo::from_slice(&context_hash);
    let output = crypto_hkdf::derive::<FIELD_BYTES>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    })
    .map_err(|_| ZkCommonCredentialRootLineageError {
        reason: ZkCommonCredentialRootLineageReason::DerivationFailed,
    })?;
    extract_salt.zeroize();
    Ok(ZkCommonCredentialRootDerivedLineage {
        context_hash,
        tag: output.into_zeroizing(),
    })
}

#[cfg(test)]
#[path = "common_credential_root_lineage/tests.rs"]
mod tests;
