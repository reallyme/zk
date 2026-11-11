// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Raw public-input owner for common-credential-root verification.

use crate::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage},
    errors::{ZkError, ZkErrorReason},
    issuer_status::{ZkIssuerCredentialStatusStatement, ZkIssuerStatusFeed},
    keys::ZkIssuerPublicKey,
    proofs::{ZkSessionBinding, ABSENT_TRANSACTION_DATA_HASH},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

mod validation;

use validation::{
    read_public_byte, read_public_bytes32, read_public_u64, session_field_start, u32_from_field,
    validate_raw_public_inputs,
};

pub(super) const RAW_FIELD_BYTES: usize = 32;
const ROOT_ATTESTATION_FIELDS: usize = 258;
const ROOT_STATUS_FIELDS: usize = 192;
const LINEAGE_FIELDS: usize = 257;
const ISSUER_CREDENTIAL_STATUS_FIELDS: usize = 292;
const PRIVATE_PERSONA_CLAIM_FIELDS: usize = 354;
const PUBLIC_PERSONA_CLAIM_FIELDS: usize = 418;
const PRIVATE_PERSONA_SESSION_FIELDS: usize = 129;
const PUBLIC_PERSONA_SESSION_FIELDS: usize = 193;
pub(super) const CLAIM_VALUE_BYTES_MAX_U32: u32 = 64;
const LINEAGE_EXPIRY_FIELD: usize = 192;
const LINEAGE_CREDENTIAL_BINDING_FIELD: usize = 193;
const ISSUER_STATUS_VALIDATION_TIME_FIELD: usize = 291;

/// Largest raw Barretenberg public-input stream accepted by common-credential-root v1.
pub const COMMON_CREDENTIAL_ROOT_V1_MAX_RAW_PUBLIC_INPUT_BYTES: usize =
    PUBLIC_PERSONA_CLAIM_FIELDS * RAW_FIELD_BYTES;

/// Raw Barretenberg public-input stream for one common-credential-root v1 proof slot.
///
/// The existing compact `ZkPublicInputs` owner intentionally remains capped at
/// four KiB for production bundles. Common-credential-root verification needs the exact
/// raw field stream because the join checker composes values at field indexes
/// that are not represented by the compact stage ABI.
#[derive(PartialEq, Eq)]
pub struct ZkCommonCredentialRootRawPublicInputs {
    circuit_ref: ZkCircuitRef,
    bytes: Vec<u8>,
}

impl ZkCommonCredentialRootRawPublicInputs {
    /// Admits one raw field stream after exact circuit, length, and ABI validation.
    pub fn try_from_bytes(circuit_ref: ZkCircuitRef, bytes: Vec<u8>) -> Result<Self, ZkError> {
        let mut bytes = Zeroizing::new(bytes);
        validate_raw_public_inputs(circuit_ref, bytes.as_slice())?;
        Ok(Self {
            circuit_ref,
            bytes: core::mem::take(&mut *bytes),
        })
    }

    /// Checks a borrowed FFI/JNI/Swift buffer before allocating its owner.
    pub fn try_copy_from_slice(circuit_ref: ZkCircuitRef, bytes: &[u8]) -> Result<Self, ZkError> {
        validate_raw_public_inputs(circuit_ref, bytes)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        owned.extend_from_slice(bytes);
        Ok(Self {
            circuit_ref,
            bytes: owned,
        })
    }

    /// Exact circuit ABI that produced the raw stream.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Borrows raw field bytes in Barretenberg public-input order.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Requires the exact verifier request in the public inputs returned by
    /// a prover. A witness supplied by the wallet cannot choose a different
    /// challenge, audience, or transaction while satisfying this check.
    pub fn validate_session_binding(&self, expected: ZkSessionBinding) -> Result<(), ZkError> {
        if bool::from(expected.nonce_hash.ct_eq(&[0_u8; 32]))
            || bool::from(expected.audience_hash.ct_eq(&[0_u8; 32]))
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        if let Some(transaction_hash) = expected.transaction_data_hash {
            if bool::from(transaction_hash.ct_eq(&[0_u8; 32]))
                || bool::from(transaction_hash.ct_eq(&ABSENT_TRANSACTION_DATA_HASH))
            {
                return Err(ZkError::new(ZkErrorReason::BindingMismatch));
            }
        }
        let start = session_field_start(self.circuit_ref)?;
        let challenge = read_public_bytes32(self.bytes.as_slice(), start)?;
        let audience = read_public_bytes32(
            self.bytes.as_slice(),
            start
                .checked_add(32)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?,
        )?;
        let transaction = read_public_bytes32(
            self.bytes.as_slice(),
            start
                .checked_add(64)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?,
        )?;
        if !bool::from(challenge.ct_eq(&expected.nonce_hash))
            || !bool::from(audience.ct_eq(&expected.audience_hash))
            || !bool::from(transaction.ct_eq(&expected.transaction_data_public_input()))
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }

    /// Match the status proof's public root to an independently verified,
    /// current authority snapshot. The prover must not choose the active set
    /// against which it proves membership.
    pub fn validate_active_status_root(&self, expected: &[u8; 32]) -> Result<(), ZkError> {
        if (self.circuit_ref.family, self.circuit_ref.stage)
            != (
                ZkCircuitFamily::CommonCredentialRootV1,
                ZkCircuitStage::RootStatus,
            )
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
        }
        let actual = read_public_bytes32(self.bytes.as_slice(), 96)?;
        if !bool::from(actual.ct_eq(expected)) {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }

    /// Decodes the selected credential's presentation expiry from a lineage proof.
    ///
    /// The field location is part of the common-credential-root public-input ABI and stays
    /// owned by the ZK API so wallet and OpenID4VP code do not duplicate circuit
    /// offsets.
    pub fn lineage_expiry_unix(&self) -> Result<u64, ZkError> {
        self.require_lineage()?;
        read_public_u64(self.bytes.as_slice(), LINEAGE_EXPIRY_FIELD)
    }

    /// Decode the time asserted by an issuer-status proof.
    ///
    /// A verifier must accept this only within its retained request and
    /// independently authenticated current-status windows. The proof field
    /// alone does not establish that a clock or status source is trusted.
    pub fn issuer_status_validation_time_unix(&self) -> Result<u64, ZkError> {
        self.require_issuer_credential_status()?;
        read_public_u64(self.bytes.as_slice(), ISSUER_STATUS_VALIDATION_TIME_FIELD)
    }

    /// Decode the public claim of a status proof. The returned fields are
    /// untrusted until the exact proof and verification key have been checked.
    pub fn issuer_credential_status_statement(
        &self,
    ) -> Result<ZkIssuerCredentialStatusStatement, ZkError> {
        self.require_issuer_credential_status()?;
        let bytes = self.bytes.as_slice();
        let issuer = ZkIssuerPublicKey {
            x: read_public_bytes32(bytes, 96)?,
            y: read_public_bytes32(bytes, 128)?,
        };
        let expiry_unix = read_public_u64(bytes, 160)?;
        let credential_binding = read_public_bytes32(bytes, 161)?;
        let status_feed = ZkIssuerStatusFeed {
            root: read_public_bytes32(bytes, 193)?,
            length: read_public_u64(bytes, 225)?,
            list_id: read_public_bytes32(bytes, 226)?,
            url_hash: read_public_bytes32(bytes, 258)?,
            purpose: crate::issuer_status::ZkIssuerStatusPurpose::try_from_wire_value(
                read_public_byte(bytes, 290)?,
            )?,
        };
        let status_validation_time_unix = read_public_u64(bytes, 291)?;
        Ok(ZkIssuerCredentialStatusStatement::from_parts(
            issuer,
            expiry_unix,
            credential_binding,
            status_feed,
            status_validation_time_unix,
        ))
    }

    /// Decodes the selected credential binding from a lineage proof.
    ///
    /// Callers should compare this value with the consent-selected stored
    /// credential before preparing a wallet response. This check complements,
    /// but does not replace, remote verifier proof validation.
    pub fn lineage_credential_binding(&self) -> Result<[u8; 32], ZkError> {
        self.require_lineage()?;
        read_public_bytes32(self.bytes.as_slice(), LINEAGE_CREDENTIAL_BINDING_FIELD)
    }

    /// Requires a lineage proof to describe the exact selected credential record.
    pub fn validate_lineage_credential_binding(
        &self,
        expected_binding: &[u8; 32],
        expected_expiry_unix: u64,
    ) -> Result<(), ZkError> {
        let actual_binding = self.lineage_credential_binding()?;
        let actual_expiry = self.lineage_expiry_unix()?;
        if actual_expiry != expected_expiry_unix
            || !bool::from(actual_binding.ct_eq(expected_binding))
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }

    /// Match a selected common-credential-root claim's public statement to the exact
    /// verifier request. The proof's circuit and slot were already validated
    /// when this owner was constructed; this check does not substitute for
    /// backend proof verification or the complete common-credential-root join policy.
    pub fn validate_claim_disclosure(
        &self,
        expected_name_hash: &[u8; 32],
        expected_value: &[u8],
    ) -> Result<(), ZkError> {
        let offset: usize = match (self.circuit_ref.family, self.circuit_ref.stage) {
            (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim) => 0,
            (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicPersonaClaim) => 64,
            _ => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
        };
        if expected_value.is_empty() || expected_value.len() > 64 {
            return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
        }
        let length_field = offset
            .checked_add(257)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let length_start = length_field
            .checked_mul(RAW_FIELD_BYTES)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let length_end = length_start
            .checked_add(RAW_FIELD_BYTES)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let length = u32_from_field(
            self.bytes
                .get(length_start..length_end)
                .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
        )?;
        let length =
            usize::try_from(length).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        if length != expected_value.len() {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        let value_start = offset
            .checked_add(258)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let name_start = offset
            .checked_add(322)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let mut value = Zeroizing::new([0_u8; 64]);
        for (index, byte) in value.iter_mut().enumerate() {
            let field = value_start
                .checked_add(index)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            let position = field
                .checked_mul(RAW_FIELD_BYTES)
                .and_then(|start| start.checked_add(RAW_FIELD_BYTES - 1))
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            *byte = *self
                .bytes
                .get(position)
                .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        }
        let name = read_public_bytes32(&self.bytes, name_start)?;
        if !bool::from(name.ct_eq(expected_name_hash))
            || !bool::from(value[..length].ct_eq(expected_value))
            || value[length..].iter().any(|byte| *byte != 0)
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }

    /// Consumes the owner without copying.
    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }

    fn require_lineage(&self) -> Result<(), ZkError> {
        if (self.circuit_ref.family, self.circuit_ref.stage)
            != (
                ZkCircuitFamily::CommonCredentialRootV1,
                ZkCircuitStage::Lineage,
            )
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
        }
        Ok(())
    }

    fn require_issuer_credential_status(&self) -> Result<(), ZkError> {
        if (self.circuit_ref.family, self.circuit_ref.stage)
            != (
                ZkCircuitFamily::CommonCredentialRootV1,
                ZkCircuitStage::IssuerCredentialStatus,
            )
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
        }
        Ok(())
    }
}

impl Drop for ZkCommonCredentialRootRawPublicInputs {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl core::fmt::Debug for ZkCommonCredentialRootRawPublicInputs {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkCommonCredentialRootRawPublicInputs")
            .field("circuit_ref", &self.circuit_ref)
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

pub(super) fn expected_raw_len(circuit_ref: ZkCircuitRef) -> Result<usize, ZkError> {
    if !ZkCircuitRef::ALL.contains(&circuit_ref) {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }
    let fields = match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => {
            ROOT_ATTESTATION_FIELDS
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus) => ROOT_STATUS_FIELDS,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage) => LINEAGE_FIELDS,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::IssuerCredentialStatus) => {
            ISSUER_CREDENTIAL_STATUS_FIELDS
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim) => {
            PRIVATE_PERSONA_CLAIM_FIELDS
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicPersonaClaim) => {
            PUBLIC_PERSONA_CLAIM_FIELDS
        }
        (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => {
            PRIVATE_PERSONA_SESSION_FIELDS
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicSession) => {
            PUBLIC_PERSONA_SESSION_FIELDS
        }
        _ => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    };
    fields
        .checked_mul(RAW_FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))
}
