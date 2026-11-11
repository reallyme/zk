// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact raw public-input ABI for prepared credential and status stages.
//!
//! Decoding is independent of proof verification. Callers must select the
//! matching pinned verification key and verify each proof before trusting a
//! decoded value or composing the stages.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::{ZkError, ZkErrorReason},
    issuer_status::{ZkIssuerStatusFeed, ZkIssuerStatusListPointer},
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceStageJoin,
        ZkPersonaCredentialEvidenceValidityWindow,
    },
    proofs::ZkProofSuite,
};

const FIELD_BYTES: usize = 32;
const SIGNED_EDGE_FIELDS: usize = 194;
const SIGNED_VALIDITY_FIELDS: usize = 259;
const CLAIM_FIELDS: usize = 291;
const STATUS_FIELDS: usize = 292;
const MAX_CLAIM_VALUE_BYTES: usize = 64;
const MAX_STATUS_LENGTH: u64 = 1_000_000;

/// Maximum accepted raw prepared public-input stream at an FFI boundary.
pub const PERSONA_CREDENTIAL_EVIDENCE_V1_MAX_RAW_PUBLIC_INPUT_BYTES: usize =
    STATUS_FIELDS * FIELD_BYTES;

/// Exact persona-credential-evidence Noir stage represented by this field stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZkPersonaCredentialEvidenceSourceStage {
    /// Issuer signature over the exact canonical envelope and hidden subject.
    IssuerEnvelope,
    /// Issuer signature joining the exact envelope and claim root.
    ClaimRoot,
    /// Issuer signature over credential validity and the status pointer.
    SignedValidity,
    /// Claim linked to an intentionally public persona.
    PublicClaim,
    /// Claim linked to a hidden persona authorizing a one-time token key.
    PrivateClaim,
    /// Hidden credential validity and active status at a public status root.
    CurrentState,
}

impl ZkPersonaCredentialEvidenceSourceStage {
    /// Exact v1 source circuit for the chosen hash lane.
    #[must_use]
    pub const fn source_ref(
        self,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
    ) -> ZkCircuitRef {
        let stage = match self {
            Self::IssuerEnvelope => ZkCircuitStage::EvidenceIssuerEnvelope,
            Self::ClaimRoot => ZkCircuitStage::EvidenceClaimRoot,
            Self::SignedValidity => ZkCircuitStage::EvidenceSignedValidity,
            Self::PublicClaim => ZkCircuitStage::EvidencePublicClaim,
            Self::PrivateClaim => ZkCircuitStage::EvidencePrivateClaim,
            Self::CurrentState => ZkCircuitStage::EvidenceCurrentState,
        };
        ZkCircuitRef::new(
            credential_hash_algorithm,
            ZkCircuitFamily::PersonaCredentialEvidenceV1,
            stage,
        )
    }
}

/// Owned raw Barretenberg public inputs for one prepared proof.
#[derive(PartialEq, Eq)]
pub struct ZkPersonaCredentialEvidenceRawPublicInputs {
    circuit_ref: ZkCircuitRef,
    stage: ZkPersonaCredentialEvidenceSourceStage,
    bytes: Vec<u8>,
}

impl ZkPersonaCredentialEvidenceRawPublicInputs {
    /// Validate exact length, scalar widths, interval, and stage fields.
    pub fn try_from_bytes(circuit_ref: ZkCircuitRef, bytes: Vec<u8>) -> Result<Self, ZkError> {
        let mut bytes = Zeroizing::new(bytes);
        // Circuit rejection must also erase the token-specific public join.
        let stage = stage_from_ref(circuit_ref)?;
        validate(stage, bytes.as_slice())?;
        Ok(Self {
            circuit_ref,
            stage,
            bytes: core::mem::take(&mut *bytes),
        })
    }

    /// Validate a borrowed platform buffer before allocating its owner.
    pub fn try_copy_from_slice(circuit_ref: ZkCircuitRef, bytes: &[u8]) -> Result<Self, ZkError> {
        let stage = stage_from_ref(circuit_ref)?;
        validate(stage, bytes)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        owned.extend_from_slice(bytes);
        Ok(Self {
            circuit_ref,
            stage,
            bytes: owned,
        })
    }

    /// Borrow the unmodified public-input bytes for backend verification.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact source stage; the verifier must use its matching pinned key.
    #[must_use]
    pub const fn stage(&self) -> ZkPersonaCredentialEvidenceSourceStage {
        self.stage
    }

    /// Exact registered source circuit whose compiled ABI produced the bytes.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Extract the public values that all verified proof stages must share.
    /// This does not authenticate the bytes until the proof has been verified.
    pub fn join(
        &self,
        proof_suite: ZkProofSuite,
    ) -> Result<ZkPersonaCredentialEvidenceStageJoin, ZkError> {
        Ok(ZkPersonaCredentialEvidenceStageJoin {
            credential_hash_algorithm: self.circuit_ref.credential_hash_algorithm,
            proof_suite,
            issuer_key: ZkIssuerPublicKey {
                x: read_bytes::<32>(&self.bytes, 0)?,
                y: read_bytes::<32>(&self.bytes, 32)?,
            },
            holder_key: ZkPersonaCredentialEvidenceHolderPublicKey {
                x: read_bytes::<32>(&self.bytes, 64)?,
                y: read_bytes::<32>(&self.bytes, 96)?,
            },
            token_nonce: read_bytes::<32>(&self.bytes, 128)?,
            proof_window: ZkPersonaCredentialEvidenceValidityWindow::try_new(
                read_u64(&self.bytes, 160)?,
                read_u64(&self.bytes, 161)?,
            )
            .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
            credential_binding: read_bytes::<32>(&self.bytes, 162)?,
        })
    }

    /// Require the selected public claim to match the verifier's requested
    /// claim name and value. The claim value is a public disclosure here.
    pub fn validate_claim(
        &self,
        expected_name_hash: &[u8; 32],
        expected_value: &[u8],
    ) -> Result<(), ZkError> {
        if !matches!(
            self.stage,
            ZkPersonaCredentialEvidenceSourceStage::PublicClaim
                | ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        ) {
            return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
        }
        let length = usize::try_from(read_u32(&self.bytes, 194)?)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        if length != expected_value.len() {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        let value = Zeroizing::new(read_bytes::<64>(&self.bytes, 195)?);
        let name_hash = read_bytes::<32>(&self.bytes, 259)?;
        if !bool::from(name_hash.ct_eq(expected_name_hash))
            || !bool::from(value[..length].ct_eq(expected_value))
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }

    /// Derive the local Wallet selector from the exact claim encoded by this
    /// stage. Proof authentication remains the caller's responsibility.
    pub fn claim_selector_digest(&self, copy_id: &str) -> Result<[u8; 32], ZkError> {
        if !matches!(
            self.stage,
            ZkPersonaCredentialEvidenceSourceStage::PublicClaim
                | ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        ) {
            return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
        }
        let length = usize::try_from(read_u32(&self.bytes, 194)?)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        let value = Zeroizing::new(read_bytes::<64>(&self.bytes, 195)?);
        let name_hash = read_bytes::<32>(&self.bytes, 259)?;
        crate::persona_evidence::persona_credential_evidence_claim_selector_digest(
            copy_id,
            self.circuit_ref.credential_hash_algorithm,
            &name_hash,
            &value[..length],
        )
    }

    /// Read status fields for comparison with the trusted issuer feed.
    pub fn status_feed(&self) -> Result<ZkIssuerStatusFeed, ZkError> {
        if self.stage != ZkPersonaCredentialEvidenceSourceStage::CurrentState {
            return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
        }
        Ok(ZkIssuerStatusFeed {
            root: read_bytes::<32>(&self.bytes, 194)?,
            length: read_u64(&self.bytes, 226)?,
            list_id: read_bytes::<32>(&self.bytes, 227)?,
            url_hash: read_bytes::<32>(&self.bytes, 259)?,
            purpose: crate::issuer_status::ZkIssuerStatusPurpose::try_from_wire_value(read_u8(
                &self.bytes,
                291,
            )?)?,
        })
    }

    /// Extract only the issuer-signed list locator for trusted status lookup.
    pub fn status_list_pointer(&self) -> Result<ZkIssuerStatusListPointer, ZkError> {
        let (list, url, purpose) = match self.stage {
            ZkPersonaCredentialEvidenceSourceStage::SignedValidity => (194, 226, 258),
            ZkPersonaCredentialEvidenceSourceStage::CurrentState => (227, 259, 291),
            _ => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
        };
        Ok(ZkIssuerStatusListPointer {
            list_id: read_bytes::<32>(&self.bytes, list)?,
            url_hash: read_bytes::<32>(&self.bytes, url)?,
            purpose: crate::issuer_status::ZkIssuerStatusPurpose::try_from_wire_value(read_u8(
                &self.bytes,
                purpose,
            )?)?,
        })
    }

    /// Match every public status field to an independently authenticated
    /// current issuer snapshot. The caller must also enforce snapshot age,
    /// rollback protection, and the issuer's shared-feed privacy policy.
    pub fn validate_status_feed(&self, expected: &ZkIssuerStatusFeed) -> Result<(), ZkError> {
        let actual = self.status_feed()?;
        if actual.length != expected.length
            || actual.purpose != expected.purpose
            || !bool::from(actual.root.ct_eq(&expected.root))
            || !bool::from(actual.list_id.ct_eq(&expected.list_id))
            || !bool::from(actual.url_hash.ct_eq(&expected.url_hash))
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }
}

fn stage_from_ref(
    circuit_ref: ZkCircuitRef,
) -> Result<ZkPersonaCredentialEvidenceSourceStage, ZkError> {
    if circuit_ref.revision != ZkCircuitRef::CURRENT_REVISION
        || circuit_ref.family != ZkCircuitFamily::PersonaCredentialEvidenceV1
        || !ZkCircuitRef::ALL.contains(&circuit_ref)
    {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }
    match circuit_ref.stage {
        ZkCircuitStage::EvidenceIssuerEnvelope => {
            Ok(ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope)
        }
        ZkCircuitStage::EvidenceClaimRoot => Ok(ZkPersonaCredentialEvidenceSourceStage::ClaimRoot),
        ZkCircuitStage::EvidenceSignedValidity => {
            Ok(ZkPersonaCredentialEvidenceSourceStage::SignedValidity)
        }
        ZkCircuitStage::EvidencePublicClaim => {
            Ok(ZkPersonaCredentialEvidenceSourceStage::PublicClaim)
        }
        ZkCircuitStage::EvidencePrivateClaim => {
            Ok(ZkPersonaCredentialEvidenceSourceStage::PrivateClaim)
        }
        ZkCircuitStage::EvidenceCurrentState => {
            Ok(ZkPersonaCredentialEvidenceSourceStage::CurrentState)
        }
        _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    }
}

impl Drop for ZkPersonaCredentialEvidenceRawPublicInputs {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

fn validate(stage: ZkPersonaCredentialEvidenceSourceStage, bytes: &[u8]) -> Result<(), ZkError> {
    let count = match stage {
        ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
        | ZkPersonaCredentialEvidenceSourceStage::ClaimRoot => SIGNED_EDGE_FIELDS,
        ZkPersonaCredentialEvidenceSourceStage::SignedValidity => SIGNED_VALIDITY_FIELDS,
        ZkPersonaCredentialEvidenceSourceStage::PublicClaim
        | ZkPersonaCredentialEvidenceSourceStage::PrivateClaim => CLAIM_FIELDS,
        ZkPersonaCredentialEvidenceSourceStage::CurrentState => STATUS_FIELDS,
    };
    if bytes.len()
        != count
            .checked_mul(FIELD_BYTES)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    for field in 0..count {
        let width = match (stage, field) {
            (_, 160 | 161) => 8,
            (ZkPersonaCredentialEvidenceSourceStage::CurrentState, 226) => 8,
            (ZkPersonaCredentialEvidenceSourceStage::CurrentState, 291) => 1,
            (
                ZkPersonaCredentialEvidenceSourceStage::PublicClaim
                | ZkPersonaCredentialEvidenceSourceStage::PrivateClaim,
                194,
            ) => 4,
            _ => 1,
        };
        let encoded = field_at(bytes, field)?;
        if encoded[..FIELD_BYTES - width]
            .iter()
            .any(|value| *value != 0)
        {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
    }
    if read_u64(bytes, 160)? >= read_u64(bytes, 161)? {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    if stage == ZkPersonaCredentialEvidenceSourceStage::CurrentState {
        let length = read_u64(bytes, 226)?;
        if !(1..=MAX_STATUS_LENGTH).contains(&length) || !matches!(read_u8(bytes, 291)?, 1 | 2) {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
    } else if stage == ZkPersonaCredentialEvidenceSourceStage::SignedValidity {
        if !matches!(read_u8(bytes, 258)?, 1 | 2) {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
    } else if matches!(
        stage,
        ZkPersonaCredentialEvidenceSourceStage::PublicClaim
            | ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
    ) {
        let length = usize::try_from(read_u32(bytes, 194)?)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        if !(1..=MAX_CLAIM_VALUE_BYTES).contains(&length) {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        let value = read_bytes::<64>(bytes, 195)?;
        if value[length..].iter().any(|byte| *byte != 0) {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
    }
    Ok(())
}

fn field_at(bytes: &[u8], index: usize) -> Result<&[u8], ZkError> {
    let start = index
        .checked_mul(FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let end = start
        .checked_add(FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    bytes
        .get(start..end)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

fn read_bytes<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], ZkError> {
    let mut result = [0_u8; N];
    for (offset, byte) in result.iter_mut().enumerate() {
        let index = start
            .checked_add(offset)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        *byte = *field_at(bytes, index)?
            .last()
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    }
    Ok(result)
}

fn read_u8(bytes: &[u8], index: usize) -> Result<u8, ZkError> {
    field_at(bytes, index)?
        .last()
        .copied()
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

fn read_u32(bytes: &[u8], index: usize) -> Result<u32, ZkError> {
    let field = field_at(bytes, index)?;
    let tail = field
        .get(FIELD_BYTES - 4..)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let value =
        <[u8; 4]>::try_from(tail).map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    Ok(u32::from_be_bytes(value))
}

fn read_u64(bytes: &[u8], index: usize) -> Result<u64, ZkError> {
    let field = field_at(bytes, index)?;
    let tail = field
        .get(FIELD_BYTES - 8..)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let value =
        <[u8; 8]>::try_from(tail).map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    Ok(u64::from_be_bytes(value))
}

#[cfg(test)]
#[path = "persona_credential_evidence_public_inputs/tests.rs"]
mod tests;
