// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed decoding of canonical circuit public inputs.

use super::{
    read_hash, read_optional_hash, read_optional_public_key, read_optional_u32,
    read_optional_value, read_u64, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs,
    ZkPublicKeyCoordinates, HASH_BYTES, VALUE_BYTES,
};
use crate::{circuits::ZkCircuitRef, errors::ZkError};
use zeroize::Zeroize;

/// Session and cross-stage commitments decoded from exact circuit public inputs.
///
/// PII-bearing decoded values are deliberately neither `Copy` nor `Clone`:
///
/// ```compile_fail
/// use reallyme_zk_api::proofs::ZkDecodedPublicInputs;
/// fn require_copy<T: Copy>() {}
/// require_copy::<ZkDecodedPublicInputs>();
/// ```
#[derive(PartialEq, Eq)]
pub struct ZkDecodedPublicInputs {
    /// OpenID4VP challenge hash.
    challenge: [u8; HASH_BYTES],
    /// Verifier/audience hash.
    audience_hash: [u8; HASH_BYTES],
    /// Transaction-data hash when exposed by the circuit ABI.
    transaction_data_hash: Option<[u8; HASH_BYTES]>,
    /// Presentation expiry timestamp.
    expiry_unix: u64,
    /// Session commitment when this stage exposes one.
    session_binding: Option<[u8; HASH_BYTES]>,
    /// Envelope commitment when this stage exposes one.
    envelope_binding: Option<[u8; HASH_BYTES]>,
    /// Credential commitment when this stage exposes one.
    credential_binding: Option<[u8; HASH_BYTES]>,
    /// Issuer P-256 public-key coordinates when exposed by this stage.
    pub(crate) issuer_key: Option<ZkPublicKeyCoordinates>,
    /// Persona P-256 public-key coordinates when exposed by this stage.
    pub(crate) persona_key: Option<ZkPublicKeyCoordinates>,
    /// Revealed claim value length when exposed by this stage.
    value_length: Option<u32>,
    /// Revealed, fixed-width claim value when exposed by this stage.
    value: Option<[u8; VALUE_BYTES]>,
    /// Revealed claim-name hash when exposed by this stage.
    claim_name_hash: Option<[u8; HASH_BYTES]>,
}

impl core::fmt::Debug for ZkDecodedPublicInputs {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkDecodedPublicInputs")
            .field("expiry_unix", &self.expiry_unix)
            .field("challenge", &"<redacted>")
            .field("audience_hash", &"<redacted>")
            .field("commitments", &"<redacted>")
            .field("keys", &"<redacted>")
            .field("claim", &"<redacted>")
            .finish()
    }
}

impl Drop for ZkDecodedPublicInputs {
    fn drop(&mut self) {
        self.challenge.zeroize();
        self.audience_hash.zeroize();
        self.transaction_data_hash.zeroize();
        self.expiry_unix.zeroize();
        self.session_binding.zeroize();
        self.envelope_binding.zeroize();
        self.credential_binding.zeroize();
        if let Some(key) = &mut self.issuer_key {
            key.x.zeroize();
            key.y.zeroize();
        }
        self.issuer_key = None;
        if let Some(key) = &mut self.persona_key {
            key.x.zeroize();
            key.y.zeroize();
        }
        self.persona_key = None;
        self.value_length.zeroize();
        self.value.zeroize();
        self.claim_name_hash.zeroize();
    }
}

impl ZkDecodedPublicInputs {
    /// OpenID4VP challenge hash decoded from the public inputs.
    #[must_use]
    pub const fn challenge(&self) -> [u8; HASH_BYTES] {
        self.challenge
    }

    /// Verifier/audience hash decoded from the public inputs.
    #[must_use]
    pub const fn audience_hash(&self) -> [u8; HASH_BYTES] {
        self.audience_hash
    }

    /// Transaction-data hash decoded from the public inputs.
    #[must_use]
    pub const fn transaction_data_hash(&self) -> Option<[u8; HASH_BYTES]> {
        self.transaction_data_hash
    }

    /// Presentation expiry timestamp decoded from the public inputs.
    #[must_use]
    pub const fn expiry_unix(&self) -> u64 {
        self.expiry_unix
    }

    /// Session commitment decoded from the public inputs.
    #[must_use]
    pub const fn session_binding(&self) -> Option<[u8; HASH_BYTES]> {
        self.session_binding
    }

    /// Envelope commitment decoded from the public inputs.
    #[must_use]
    pub const fn envelope_binding(&self) -> Option<[u8; HASH_BYTES]> {
        self.envelope_binding
    }

    /// Credential commitment decoded from the public inputs.
    #[must_use]
    pub const fn credential_binding(&self) -> Option<[u8; HASH_BYTES]> {
        self.credential_binding
    }

    /// Revealed claim value length decoded from the public inputs.
    #[must_use]
    pub const fn value_length(&self) -> Option<u32> {
        self.value_length
    }

    /// Revealed, fixed-width claim value decoded from the public inputs.
    #[must_use]
    pub const fn value(&self) -> Option<[u8; VALUE_BYTES]> {
        self.value
    }

    /// Revealed claim-name hash decoded from the public inputs.
    #[must_use]
    pub const fn claim_name_hash(&self) -> Option<[u8; HASH_BYTES]> {
        self.claim_name_hash
    }

    /// Decodes the stage-specific compact ABI and rejects wrong length/order.
    pub fn try_decode(
        circuit_ref: ZkCircuitRef,
        public_inputs: &ZkPublicInputs,
    ) -> Result<Self, ZkError> {
        let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
        descriptor.validate(public_inputs)?;

        Ok(Self {
            challenge: read_hash(descriptor, public_inputs, ZkPublicInputName::Challenge)?,
            audience_hash: read_hash(descriptor, public_inputs, ZkPublicInputName::AudienceHash)?,
            transaction_data_hash: read_optional_hash(
                descriptor,
                public_inputs,
                ZkPublicInputName::TransactionDataHash,
            )?,
            expiry_unix: read_u64(descriptor, public_inputs, ZkPublicInputName::ExpiryUnix)?,
            session_binding: read_optional_hash(
                descriptor,
                public_inputs,
                ZkPublicInputName::SessionBinding,
            )?,
            envelope_binding: read_optional_hash(
                descriptor,
                public_inputs,
                ZkPublicInputName::EnvelopeBinding,
            )?,
            credential_binding: read_optional_hash(
                descriptor,
                public_inputs,
                ZkPublicInputName::CredentialBinding,
            )?,
            issuer_key: read_optional_public_key(
                descriptor,
                public_inputs,
                ZkPublicInputName::IssuerPublicKeyX,
                ZkPublicInputName::IssuerPublicKeyY,
            )?,
            persona_key: read_optional_public_key(
                descriptor,
                public_inputs,
                ZkPublicInputName::PersonaPublicKeyX,
                ZkPublicInputName::PersonaPublicKeyY,
            )?,
            value_length: read_optional_u32(
                descriptor,
                public_inputs,
                ZkPublicInputName::ValueLength,
            )?,
            value: read_optional_value(descriptor, public_inputs, ZkPublicInputName::Value)?,
            claim_name_hash: read_optional_hash(
                descriptor,
                public_inputs,
                ZkPublicInputName::ClaimNameHash,
            )?,
        })
    }
}
