// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generic proof metadata shared by provider and format adapters.

use crate::{
    circuits::{ZkCircuitId, ZkCircuitRef},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use zeroize::Zeroize;

/// Maximum public-input name length accepted by the proof API boundary.
pub const MAX_PUBLIC_INPUT_NAME_BYTES: usize = 128;

/// Maximum named public-input value length accepted by the proof API boundary.
pub const MAX_NAMED_PUBLIC_INPUT_VALUE_BYTES: usize = 1024 * 1024;

/// Stable proof metadata used by provider and proof-format boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkProofMetadata {
    /// Circuit that produced the proof.
    circuit_id: ZkCircuitId,
    /// Exact imported circuit source used to produce the proof, when known.
    circuit_ref: ZkCircuitRef,
    /// Hash of the verification key used by the verifier.
    verification_key_sha256: [u8; 32],
    /// Exact suite used to create and verify the proof.
    proof_suite: ZkProofSuite,
}

impl ZkProofMetadata {
    /// Constructs proof metadata from validated domain values.
    #[must_use]
    pub const fn new(
        circuit_ref: ZkCircuitRef,
        verification_key_sha256: [u8; 32],
        proof_suite: ZkProofSuite,
    ) -> Self {
        Self {
            circuit_id: circuit_ref.circuit_id(),
            circuit_ref,
            verification_key_sha256,
            proof_suite,
        }
    }

    /// Circuit that produced the proof.
    #[must_use]
    pub const fn circuit_id(&self) -> ZkCircuitId {
        self.circuit_id
    }

    /// Exact imported circuit source used to produce the proof, when known.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Revision of the exact source circuit.
    #[must_use]
    pub const fn circuit_revision(&self) -> u32 {
        self.circuit_ref.revision
    }

    /// Hash of the verification key used by the verifier.
    #[must_use]
    pub const fn verification_key_sha256(&self) -> [u8; 32] {
        self.verification_key_sha256
    }

    /// Exact suite used to create and verify the proof.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }
}

/// Bounded named public input for formats that need semantic labels.
#[derive(PartialEq, Eq)]
pub struct NamedPublicInput {
    name: String,
    value: Vec<u8>,
}

impl NamedPublicInput {
    /// Validates and stores a named public input.
    pub fn try_from_parts(name: String, value: Vec<u8>) -> Result<Self, ZkError> {
        if name.is_empty() || name.len() > MAX_PUBLIC_INPUT_NAME_BYTES {
            return Err(ZkError::new(ZkErrorReason::InvalidPublicInputName));
        }

        if value.is_empty() {
            return Err(ZkError::new(ZkErrorReason::EmptyInput));
        }

        if value.len() > MAX_NAMED_PUBLIC_INPUT_VALUE_BYTES {
            return Err(ZkError::new(ZkErrorReason::PublicInputsTooLarge));
        }

        Ok(Self { name, value })
    }

    /// Returns the public-input name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the public-input value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Consumes the wrapper and returns the owned parts.
    #[must_use]
    pub fn into_parts(mut self) -> (String, Vec<u8>) {
        (
            core::mem::take(&mut self.name),
            core::mem::take(&mut self.value),
        )
    }
}

impl core::fmt::Debug for NamedPublicInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NamedPublicInput")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for NamedPublicInput {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

#[cfg(test)]
mod tests;
