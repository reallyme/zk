// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ZkPublicInputName, ZkPublicInputType, ZkPublicInputs};
use crate::{
    capabilities::circuit_ref_capabilities,
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage},
    errors::{ZkError, ZkErrorReason},
};
use core::ops::Range;

/// One ordered field in the canonical public-input ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkPublicInputField {
    /// Semantic field name.
    pub name: ZkPublicInputName,
    /// Compact wire representation used between provider adapters.
    pub input_type: ZkPublicInputType,
}

const fn field(name: ZkPublicInputName, input_type: ZkPublicInputType) -> ZkPublicInputField {
    ZkPublicInputField { name, input_type }
}

const PRIVATE_SESSION_FIELDS: &[ZkPublicInputField] = &[
    field(ZkPublicInputName::Challenge, ZkPublicInputType::Bytes32),
    field(ZkPublicInputName::AudienceHash, ZkPublicInputType::Bytes32),
    field(
        ZkPublicInputName::TransactionDataHash,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::ExpiryUnix, ZkPublicInputType::U64),
    field(
        ZkPublicInputName::SessionBinding,
        ZkPublicInputType::Bytes32,
    ),
];

const CREDENTIAL_ENVELOPE_FIELDS: &[ZkPublicInputField] = &[
    field(
        ZkPublicInputName::IssuerPublicKeyX,
        ZkPublicInputType::Bytes32,
    ),
    field(
        ZkPublicInputName::IssuerPublicKeyY,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::Challenge, ZkPublicInputType::Bytes32),
    field(ZkPublicInputName::AudienceHash, ZkPublicInputType::Bytes32),
    field(
        ZkPublicInputName::TransactionDataHash,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::ExpiryUnix, ZkPublicInputType::U64),
    field(
        ZkPublicInputName::EnvelopeBinding,
        ZkPublicInputType::Bytes32,
    ),
];

const CREDENTIAL_ROOT_FIELDS: &[ZkPublicInputField] = &[
    field(
        ZkPublicInputName::IssuerPublicKeyX,
        ZkPublicInputType::Bytes32,
    ),
    field(
        ZkPublicInputName::IssuerPublicKeyY,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::Challenge, ZkPublicInputType::Bytes32),
    field(ZkPublicInputName::AudienceHash, ZkPublicInputType::Bytes32),
    field(
        ZkPublicInputName::TransactionDataHash,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::ExpiryUnix, ZkPublicInputType::U64),
    field(
        ZkPublicInputName::EnvelopeBinding,
        ZkPublicInputType::Bytes32,
    ),
    field(
        ZkPublicInputName::CredentialBinding,
        ZkPublicInputType::Bytes32,
    ),
];

const CREDENTIAL_SUBJECT_CLAIM_FIELDS: &[ZkPublicInputField] = &[
    field(
        ZkPublicInputName::IssuerPublicKeyX,
        ZkPublicInputType::Bytes32,
    ),
    field(
        ZkPublicInputName::IssuerPublicKeyY,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::Challenge, ZkPublicInputType::Bytes32),
    field(ZkPublicInputName::AudienceHash, ZkPublicInputType::Bytes32),
    field(
        ZkPublicInputName::TransactionDataHash,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::ExpiryUnix, ZkPublicInputType::U64),
    field(
        ZkPublicInputName::SessionBinding,
        ZkPublicInputType::Bytes32,
    ),
    field(
        ZkPublicInputName::CredentialBinding,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::ValueLength, ZkPublicInputType::U32),
    field(ZkPublicInputName::Value, ZkPublicInputType::Bytes64),
    field(ZkPublicInputName::ClaimNameHash, ZkPublicInputType::Bytes32),
];

const CREDENTIAL_SUBJECT_CLAIM_PROOF_BUNDLE_FIELDS: &[ZkPublicInputField] = &[
    field(
        ZkPublicInputName::IssuerPublicKeyX,
        ZkPublicInputType::Bytes32,
    ),
    field(
        ZkPublicInputName::IssuerPublicKeyY,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::Challenge, ZkPublicInputType::Bytes32),
    field(ZkPublicInputName::AudienceHash, ZkPublicInputType::Bytes32),
    field(
        ZkPublicInputName::TransactionDataHash,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::ExpiryUnix, ZkPublicInputType::U64),
    field(
        ZkPublicInputName::SessionBinding,
        ZkPublicInputType::Bytes32,
    ),
    field(
        ZkPublicInputName::CredentialBinding,
        ZkPublicInputType::Bytes32,
    ),
    field(ZkPublicInputName::BundleCount, ZkPublicInputType::U32),
    field(ZkPublicInputName::BundleHash, ZkPublicInputType::Bytes32),
];

/// Exact compact public-input ABI for one imported circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkPublicInputDescriptor {
    circuit_ref: ZkCircuitRef,
    fields: &'static [ZkPublicInputField],
}

impl ZkPublicInputDescriptor {
    /// Returns the descriptor for a supported exact circuit version.
    pub fn for_circuit(circuit_ref: ZkCircuitRef) -> Result<Self, ZkError> {
        circuit_ref_capabilities(circuit_ref)?;
        let fields = match circuit_ref.stage {
            ZkCircuitStage::Session => match circuit_ref.family {
                ZkCircuitFamily::CredentialSubjectClaimV1
                | ZkCircuitFamily::PrivatePersonaClaimV1 => PRIVATE_SESSION_FIELDS,
                ZkCircuitFamily::CommonCredentialRootV1
                | ZkCircuitFamily::PersonaCredentialEvidenceV1 => {
                    return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
                }
            },
            ZkCircuitStage::CredentialEnvelope => {
                if matches!(
                    circuit_ref.family,
                    ZkCircuitFamily::CommonCredentialRootV1
                        | ZkCircuitFamily::PersonaCredentialEvidenceV1
                ) {
                    return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
                }
                CREDENTIAL_ENVELOPE_FIELDS
            }
            ZkCircuitStage::CredentialRoot => {
                if matches!(
                    circuit_ref.family,
                    ZkCircuitFamily::CommonCredentialRootV1
                        | ZkCircuitFamily::PersonaCredentialEvidenceV1
                ) {
                    return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
                }
                CREDENTIAL_ROOT_FIELDS
            }
            ZkCircuitStage::Claim => match circuit_ref.family {
                ZkCircuitFamily::CredentialSubjectClaimV1
                | ZkCircuitFamily::PrivatePersonaClaimV1 => CREDENTIAL_SUBJECT_CLAIM_FIELDS,
                ZkCircuitFamily::CommonCredentialRootV1
                | ZkCircuitFamily::PersonaCredentialEvidenceV1 => {
                    return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
                }
            },
            ZkCircuitStage::ClaimBundle4 => match circuit_ref.family {
                ZkCircuitFamily::CredentialSubjectClaimV1
                | ZkCircuitFamily::PrivatePersonaClaimV1 => {
                    CREDENTIAL_SUBJECT_CLAIM_PROOF_BUNDLE_FIELDS
                }
                ZkCircuitFamily::CommonCredentialRootV1
                | ZkCircuitFamily::PersonaCredentialEvidenceV1 => {
                    return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
                }
            },
            ZkCircuitStage::RootAttestation
            | ZkCircuitStage::RootStatus
            | ZkCircuitStage::Lineage
            | ZkCircuitStage::IssuerCredentialStatus
            | ZkCircuitStage::PrivatePersonaClaim
            | ZkCircuitStage::PublicPersonaClaim
            | ZkCircuitStage::PublicSession
            | ZkCircuitStage::EvidenceIssuerEnvelope
            | ZkCircuitStage::EvidenceClaimRoot
            | ZkCircuitStage::EvidenceSignedValidity
            | ZkCircuitStage::EvidencePublicClaim
            | ZkCircuitStage::EvidencePrivateClaim
            | ZkCircuitStage::EvidenceCurrentState => {
                return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
            }
        };

        Ok(Self {
            circuit_ref,
            fields,
        })
    }

    /// Exact circuit described by this ABI.
    #[must_use]
    pub const fn circuit_ref(self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Ordered public fields in Noir source order.
    #[must_use]
    pub const fn fields(self) -> &'static [ZkPublicInputField] {
        self.fields
    }

    /// Exact byte length of the compact provider encoding.
    pub fn encoded_len(self) -> Result<usize, ZkError> {
        let mut length = 0_usize;
        for field in self.fields {
            length = length
                .checked_add(field.input_type.encoded_len())
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
        Ok(length)
    }

    /// Exact flattened Noir field-element count in compiler ABI order.
    pub fn flattened_element_count(self) -> Result<usize, ZkError> {
        let mut count = 0_usize;
        for field in self.fields {
            count = count
                .checked_add(field.input_type.flattened_element_count())
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
        Ok(count)
    }

    /// Byte range occupied by a named field.
    pub fn field_range(self, name: ZkPublicInputName) -> Result<Range<usize>, ZkError> {
        let mut offset = 0_usize;
        for field in self.fields {
            let end = offset
                .checked_add(field.input_type.encoded_len())
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            if field.name == name {
                return Ok(offset..end);
            }
            offset = end;
        }

        Err(ZkError::new(ZkErrorReason::InvalidPublicInputName))
    }

    pub(crate) fn validate(self, public_inputs: &ZkPublicInputs) -> Result<(), ZkError> {
        if public_inputs.as_bytes().len() != self.encoded_len()? {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        Ok(())
    }
}
