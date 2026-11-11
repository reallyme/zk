// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical, stage-specific public-input ABI for imported Noir circuits.

use crate::{
    capabilities::circuit_ref_capabilities,
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
};

/// Maximum public-input byte length accepted by the API boundary.
pub const MAX_PUBLIC_INPUT_BYTES: usize = 4 * 1024;

pub(crate) const HASH_BYTES: usize = 32;
pub(crate) const VALUE_BYTES: usize = 64;
const U32_BYTES: usize = 4;
const U64_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZkPublicKeyCoordinates {
    pub(crate) x: [u8; HASH_BYTES],
    pub(crate) y: [u8; HASH_BYTES],
}

/// Stable semantic name for one Noir public input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkPublicInputName {
    /// Issuer public-key x coordinate.
    IssuerPublicKeyX,
    /// Issuer public-key y coordinate.
    IssuerPublicKeyY,
    /// Public persona-key x coordinate.
    PersonaPublicKeyX,
    /// Public persona-key y coordinate.
    PersonaPublicKeyY,
    /// Presentation challenge derived from the OpenID4VP nonce.
    Challenge,
    /// Verifier/audience hash.
    AudienceHash,
    /// Transaction-data hash from the active OpenID4VP request.
    TransactionDataHash,
    /// Presentation expiry as an unsigned 64-bit Unix timestamp.
    ExpiryUnix,
    /// Presentation-scoped holder or persona session commitment.
    SessionBinding,
    /// Presentation-scoped issuer envelope commitment.
    EnvelopeBinding,
    /// Presentation-scoped credential/root commitment.
    CredentialBinding,
    /// Revealed claim value length.
    ValueLength,
    /// Revealed, zero-padded claim value.
    Value,
    /// Revealed claim-name hash.
    ClaimNameHash,
    /// Number of active claims in a bounded bundle.
    BundleCount,
    /// Canonical commitment to ordered claim names and values in the bundle.
    BundleHash,
}

mod input_type;
pub use input_type::ZkPublicInputType;

mod descriptor;
pub use descriptor::{ZkPublicInputDescriptor, ZkPublicInputField};

const SESSION_BINDING_ABI_V1_FIELDS: &[ZkPublicInputName] = &[
    ZkPublicInputName::Challenge,
    ZkPublicInputName::AudienceHash,
];

const SESSION_BINDING_ABI_V1_TRANSACTION_FIELDS: &[ZkPublicInputName] = &[
    ZkPublicInputName::Challenge,
    ZkPublicInputName::AudienceHash,
    ZkPublicInputName::TransactionDataHash,
];

/// Versioned active-session public-input binding ABI.
///
/// Current production circuits expose challenge, audience, and the canonical
/// transaction-data binding value. Requests without transaction data bind the
/// reserved absence sentinel instead of omitting the circuit field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkSessionBindingPublicInputAbi {
    /// Legacy circuit ABI: OpenID4VP nonce/challenge and verifier audience.
    V1ChallengeAudience,
    /// Transaction-bound ABI: challenge, audience, and transaction-data hash.
    V1ChallengeAudienceTransaction,
}

impl ZkSessionBindingPublicInputAbi {
    /// Returns the active ABI for an exact circuit version.
    pub fn for_circuit(circuit_ref: ZkCircuitRef) -> Result<Self, ZkError> {
        circuit_ref_capabilities(circuit_ref)?;
        Ok(Self::V1ChallengeAudienceTransaction)
    }

    /// Ordered active-session binding fields in compact public-input order.
    #[must_use]
    pub const fn fields(self) -> &'static [ZkPublicInputName] {
        match self {
            Self::V1ChallengeAudience => SESSION_BINDING_ABI_V1_FIELDS,
            Self::V1ChallengeAudienceTransaction => SESSION_BINDING_ABI_V1_TRANSACTION_FIELDS,
        }
    }

    /// Whether the ABI contains transaction data as a circuit public input.
    #[must_use]
    pub const fn supports_transaction_data_hash(self) -> bool {
        match self {
            Self::V1ChallengeAudience => false,
            Self::V1ChallengeAudienceTransaction => true,
        }
    }
}

/// Circuit public inputs in the canonical compact provider encoding.
///
/// The owner is deliberately non-cloneable so copies cannot outlive its
/// zeroizing drop path:
///
/// ```compile_fail
/// use reallyme_zk_api::proofs::ZkPublicInputs;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ZkPublicInputs>();
/// ```
#[derive(PartialEq, Eq)]
pub struct ZkPublicInputs {
    bytes: Vec<u8>,
}

impl ZkPublicInputs {
    /// Validates a platform-reported length before an adapter reads or copies
    /// the corresponding buffer.
    pub const fn validate_length(length: usize) -> Result<(), ZkError> {
        if length == 0 {
            return Err(ZkError::new(ZkErrorReason::EmptyInput));
        }
        if length > MAX_PUBLIC_INPUT_BYTES {
            return Err(ZkError::new(ZkErrorReason::PublicInputsTooLarge));
        }
        Ok(())
    }

    /// Applies coarse transport bounds before the exact circuit is known.
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, ZkError> {
        Self::validate_length(bytes.len())?;
        Ok(Self { bytes })
    }

    /// Checks a borrowed platform buffer before allocating its owned copy.
    pub fn try_copy_from_slice(bytes: &[u8]) -> Result<Self, ZkError> {
        Self::validate_length(bytes.len())?;

        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        owned.extend_from_slice(bytes);
        Ok(Self { bytes: owned })
    }

    /// Borrows the compact encoded public inputs.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consumes this wrapper and returns the compact encoded public inputs.
    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl Drop for ZkPublicInputs {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

impl core::fmt::Debug for ZkPublicInputs {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkPublicInputs")
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

mod decoded;
pub use decoded::ZkDecodedPublicInputs;

mod session_binding;
use session_binding::{
    read_hash, read_optional_hash, read_optional_public_key, read_optional_u32,
    read_optional_value, read_u64,
};
pub use session_binding::{ZkSessionBinding, ABSENT_TRANSACTION_DATA_HASH};

#[cfg(test)]
mod tests;
