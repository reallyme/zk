// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Exact public-input joins for the nine-proof common-credential-root v1 persona_mode.
//
// This module checks statements only after a provider has verified each
// proof against its pinned circuit artifact and verification key. A matching
// set of public inputs alone is never evidence of a valid proof.

use crypto_core::{CryptoError, RngOutputKind};
use crypto_csprng::{generate_bytes, RandomBytes, SecureRandom};
use crypto_sha2_256::digest as sha2_256_digest;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{keys::{ZkAttestationPublicKey, ZkIssuerPublicKey, ZkP256PublicKey}, common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot}, errors::{ZkError, ZkErrorReason}, issuer_status::{ZkIssuerStatusPurpose}, claim_bundle::{MAX_PRESENTATION_LIFETIME_SECONDS}};

const FIELD_BYTES: usize = 32;
const JOIN_SALT_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const P256_CURVE_ORDER: [u8; FIELD_BYTES] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const P256_HALF_CURVE_ORDER: [u8; FIELD_BYTES] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];
const ATTESTATION_FIELDS: usize = 258;
const STATUS_FIELDS: usize = 192;
const LINEAGE_FIELDS: usize = 257;
const ISSUER_CREDENTIAL_STATUS_FIELDS: usize = 292;
const CREDENTIAL_SUBJECT_CLAIM_FIELDS: usize = 354;
const PUBLIC_CLAIM_FIELDS: usize = 418;
const PRIVATE_SESSION_FIELDS: usize = 129;
const PUBLIC_SESSION_FIELDS: usize = 193;
const CLAIM_VALUE_BYTES: usize = 64;
const SALT_SLOT_ROOT_ATTESTATION: u8 = 1 << 0;
const SALT_SLOT_ROOT_STATUS: u8 = 1 << 1;
const SALT_SLOT_LINEAGE_0: u8 = 1 << 2;
const SALT_SLOT_LINEAGE_1: u8 = 1 << 3;
const SALT_SLOT_SELECTED_CLAIM_0: u8 = 1 << 4;
const SALT_SLOT_SELECTED_CLAIM_1: u8 = 1 << 5;
const ALL_SALT_SLOT_MASK: u8 = SALT_SLOT_ROOT_ATTESTATION
    | SALT_SLOT_ROOT_STATUS
    | SALT_SLOT_LINEAGE_0
    | SALT_SLOT_LINEAGE_1
    | SALT_SLOT_SELECTED_CLAIM_0
    | SALT_SLOT_SELECTED_CLAIM_1;
const ROOT_COMMITMENT_DOMAIN: &[u8; 7] = b"RMROOT1";
const ROOT_ATTESTATION_DOMAIN: &[u8; 5] = b"RMRA1";
const ROOT_ATTESTATION_ID_DOMAIN: &[u8; 7] = b"RMRAID1";
const ROOT_JOIN_DOMAIN: &[u8; 8] = b"RMRJOIN1";
const ATTESTATION_JOIN_DOMAIN: &[u8; 9] = b"RMATJOIN1";
const SUBJECT_JOIN_DOMAIN: &[u8; 8] = b"RMSJOIN1";
const RESERVED_LINEAGE_NAME_HASH: [u8; 32] = [
    0xa0, 0x0e, 0x5f, 0x5f, 0x55, 0xfa, 0x10, 0x52, 0x66, 0x8a, 0x6f, 0x10, 0x71, 0x98, 0xe8, 0x48,
    0x58, 0x90, 0x42, 0x51, 0x19, 0xb4, 0xca, 0x1a, 0xe1, 0xe8, 0x28, 0x7a, 0x77, 0x08, 0x46, 0xdd,
];

/// Failure to generate one-use common-credential-root presentation salt.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootJoinGenerationError {
    /// The injected secure RNG failed to return entropy.
    #[error("secure random generation failed")]
    Random {
        /// Non-sensitive typed cause from the crypto layer.
        #[source]
        source: CryptoError,
    },
    /// The RNG returned the reserved all-zero salt value.
    #[error("degenerate common-credential-root presentation salt")]
    DegenerateSalt,
    /// The supplied join derivation input was invalid.
    #[error("invalid common-credential-root join derivation input")]
    InvalidInput {
        /// Stable non-sensitive ZK reason.
        reason: ZkErrorReason,
    },
}

/// Failure while dispensing the one-use common-credential-root presentation salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootStageSaltError {
    /// The caller tried to put join salt into a proof slot that does not carry it.
    #[error("common-credential-root proof slot does not carry presentation salt")]
    UnsaltedSlot,
    /// The caller tried to reuse salt for a stage witness that was already filled.
    #[error("common-credential-root stage salt was already used")]
    ReusedSlot,
    /// The caller tried to use a salt owner for a different authenticated request.
    #[error("common-credential-root stage binding does not match salt owner")]
    BindingMismatch,
    /// The owner was finished before every salt-bearing stage received the salt once.
    #[error("common-credential-root stage salt owner is incomplete")]
    Incomplete,
}

/// Failure while composing typed common-credential-root stage input material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootStageInputError {
    /// The underlying one-use salt owner rejected the requested slot.
    #[error("common-credential-root stage salt owner rejected stage input")]
    Salt {
        /// Stable non-sensitive salt-owner reason.
        reason: ZkCommonCredentialRootStageSaltError,
    },
    /// The caller requested a credential-role join for a non-credential slot.
    #[error("common-credential-root stage slot has no credential index")]
    MissingCredentialSlot,
}

impl From<ZkCommonCredentialRootStageSaltError> for ZkCommonCredentialRootStageInputError {
    fn from(reason: ZkCommonCredentialRootStageSaltError) -> Self {
        Self::Salt { reason }
    }
}

/// One-use common-credential-root presentation salt.
///
/// The salt is private holder material. Callers generate or import it, then
/// consume it exactly once to derive the complete join set. There is no public
/// raw-byte accessor because replacing only `join_salt` without recomputing all
/// public joins would break the circuit contract.
pub struct ZkCommonCredentialRootPresentationSalt {
    bytes: RandomBytes<JOIN_SALT_BYTES>,
}

impl ZkCommonCredentialRootPresentationSalt {
    /// Generates a non-zero common-credential-root presentation salt from an injected CSPRNG.
    pub fn generate(
        rng: &mut impl SecureRandom,
    ) -> Result<Self, ZkCommonCredentialRootJoinGenerationError> {
        let bytes = generate_bytes::<JOIN_SALT_BYTES>(rng, RngOutputKind::Generic)
            .map_err(|source| ZkCommonCredentialRootJoinGenerationError::Random { source })?;
        Self::from_random_bytes(bytes)
    }

    /// Imports RNG-owned salt bytes while preserving zeroization ownership.
    pub fn from_random_bytes(
        bytes: RandomBytes<JOIN_SALT_BYTES>,
    ) -> Result<Self, ZkCommonCredentialRootJoinGenerationError> {
        if bytes.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(ZkCommonCredentialRootJoinGenerationError::DegenerateSalt);
        }
        Ok(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8; JOIN_SALT_BYTES] {
        self.bytes.as_bytes()
    }
}

/// Verifier-owned request binding fields used in common-credential-root joins.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootRequestJoinContext {
    /// OpenID4VP challenge computed from the active nonce.
    pub challenge: [u8; 32],
    /// Hash of the active verifier identity.
    pub audience_hash: [u8; 32],
    /// Active transaction-data hash or the canonical absence sentinel.
    pub transaction_data_hash: [u8; 32],
}

/// Public subject key committed by common-credential-root subject joins.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootSubjectPublicKey {
    /// Subject public-key x-coordinate.
    pub x: [u8; 32],
    /// Subject public-key y-coordinate.
    pub y: [u8; 32],
}

/// Inputs needed to derive the stable root-attestation identifier.
pub struct ZkCommonCredentialRootAttestationMaterial<'a> {
    /// Claimed ReallyMe root-attestation signing key.
    pub reallyme_public_key: ZkAttestationPublicKey,
    /// Claimed root-assurance policy identifier.
    pub assurance_policy_id: [u8; 32],
    /// Trusted verifier request time.
    pub request_time_unix: u64,
    /// Hidden credential root.
    ///
    /// This helper only borrows the root and zeroizes its transcript buffers.
    /// The caller remains responsible for owning and erasing the root itself.
    pub root: &'a [u8; 32],
    /// Root-attestation issued-at time.
    pub attestation_issued_unix: u64,
    /// Root-attestation expiry time.
    pub attestation_expires_unix: u64,
    /// Root-attestation epoch.
    pub attestation_epoch: u32,
    /// Root-attestation signature bytes.
    pub attestation_signature: &'a [u8; SIGNATURE_BYTES],
}

/// Public authority-side inputs for deriving an active attestation identifier.
///
/// This is the status-publication counterpart to
/// [`ZkCommonCredentialRootAttestationMaterial`]. It carries the holder's root commitment
/// `C = H(domain || R)`, never the holder root `R`, so the attestation
/// authority can publish active IDs without learning wallet-private root
/// material.
pub struct ZkCommonCredentialRootAttestationCommitmentMaterial<'a> {
    /// Claimed ReallyMe root-attestation signing key.
    pub reallyme_public_key: ZkAttestationPublicKey,
    /// Claimed root-assurance policy identifier.
    pub assurance_policy_id: [u8; 32],
    /// Public commitment to the hidden holder root.
    pub root_commitment: &'a [u8; 32],
    /// Root-attestation issued-at time.
    pub attestation_issued_unix: u64,
    /// Root-attestation expiry time.
    pub attestation_expires_unix: u64,
    /// Root-attestation epoch.
    pub attestation_epoch: u32,
    /// Root-attestation signature bytes.
    pub attestation_signature: &'a [u8; SIGNATURE_BYTES],
}

/// Deployment-owned authority and assurance policy for a root attestation.
/// Neither field may be inferred from holder-supplied attestation material.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootAttestationTrustPolicy {
    /// Pinned ReallyMe attestation signing key.
    pub signer: ZkAttestationPublicKey,
    /// Exact accepted assurance policy identifier.
    pub assurance_policy_id: [u8; 32],
}

/// Inputs needed to derive all presentation joins from one private salt.
pub struct ZkCommonCredentialRootJoinDerivationInputs<'a> {
    /// Active request binding context.
    pub request: ZkCommonCredentialRootRequestJoinContext,
    /// Hidden credential root.
    ///
    /// This helper only borrows the root and zeroizes its transcript buffers.
    /// The caller remains responsible for owning and erasing the root itself.
    pub root: &'a [u8; 32],
    /// Stable root-attestation identifier.
    pub attestation_id: &'a [u8; 32],
    /// Subject keys for the two requested credential slots.
    pub subject_public_keys: [ZkCommonCredentialRootSubjectPublicKey; 2],
}

/// Complete common-credential-root public join set derived from one private salt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootPresentationJoins {
    /// Join binding root assurance, active status, and lineage proofs.
    pub root_join: [u8; 32],
    /// Join binding root attestation and active status proofs.
    pub attestation_join: [u8; 32],
    /// Slot-ordered subject joins binding lineage and selected-claim proofs.
    pub subject_joins: [[u8; 32]; 2],
}

/// Private salt plus derived public joins for one common-credential-root presentation.
///
/// This owner exists so wallet/prover orchestration can fill every salt-bearing
/// stage witness with the same private salt while also carrying the matching
/// public joins. It still avoids a raw salt accessor; callers may only copy the
/// salt into fixed-size witness destinations.
pub struct ZkCommonCredentialRootPresentationMaterial {
    salt: ZkCommonCredentialRootPresentationSalt,
    request: ZkCommonCredentialRootRequestJoinContext,
    joins: ZkCommonCredentialRootPresentationJoins,
}

impl ZkCommonCredentialRootPresentationMaterial {
    /// Returns the public joins derived from this material's private salt.
    #[must_use]
    pub const fn joins(&self) -> ZkCommonCredentialRootPresentationJoins {
        self.joins
    }

    /// Consumes this material into a one-use salt owner.
    ///
    /// The returned owner dispenses the private salt exactly once for each of
    /// the six salt-bearing proof slots. The session proof deliberately has no
    /// join-salt witness, and attempting to request one fails closed.
    #[must_use]
    pub fn into_stage_salt_owner(self) -> ZkCommonCredentialRootStageSaltOwner {
        ZkCommonCredentialRootStageSaltOwner {
            salt: self.salt,
            request: self.request,
            used_mask: 0,
        }
    }

    /// Consumes this material into a typed stage-input composer.
    ///
    /// The composer owns the private salt and derived joins for one active
    /// presentation. It deliberately does not own issuer credentials, status
    /// snapshots, or holder persona keys; those are Identity/OpenID wallet
    /// inputs that must be supplied by the caller's authenticated credential
    /// store before platform encoding.
    #[must_use]
    pub fn into_stage_input_composer(self) -> ZkCommonCredentialRootStageInputComposer {
        let request = self.request;
        let joins = self.joins;
        ZkCommonCredentialRootStageInputComposer {
            request,
            joins,
            salt_owner: self.into_stage_salt_owner(),
        }
    }
}

/// One-use owner for the private common-credential-root presentation salt.
///
/// Wallet/prover orchestration should create one owner per authenticated
/// presentation and pass it through the six salt-bearing stage witnesses. The
/// owner refuses mismatched request bindings and slot reuse, so a later stage
/// cannot accidentally replay a salt from another request or overwrite a stage
/// that has already been populated.
pub struct ZkCommonCredentialRootStageSaltOwner {
    salt: ZkCommonCredentialRootPresentationSalt,
    request: ZkCommonCredentialRootRequestJoinContext,
    used_mask: u8,
}

impl ZkCommonCredentialRootStageSaltOwner {
    /// Copies the private salt into the requested salt-bearing stage witness.
    pub fn copy_for_stage_witness(
        &mut self,
        slot: ZkCommonCredentialRootProofSlot,
        request: ZkCommonCredentialRootRequestJoinContext,
        destination: &mut [u8; 32],
    ) -> Result<(), ZkCommonCredentialRootStageSaltError> {
        if request != self.request {
            return Err(ZkCommonCredentialRootStageSaltError::BindingMismatch);
        }
        let bit = salt_slot_bit(slot)?;
        if self.used_mask & bit != 0 {
            return Err(ZkCommonCredentialRootStageSaltError::ReusedSlot);
        }
        destination.copy_from_slice(self.salt.as_bytes());
        self.used_mask |= bit;
        Ok(())
    }

    /// Finishes the owner after all salt-bearing stage witnesses have been filled.
    pub fn finish(self) -> Result<(), ZkCommonCredentialRootStageSaltError> {
        if self.used_mask == ALL_SALT_SLOT_MASK {
            Ok(())
        } else {
            Err(ZkCommonCredentialRootStageSaltError::Incomplete)
        }
    }
}
