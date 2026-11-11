// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    capabilities::{circuit_ref_capabilities, ZkSemanticGuarantee},
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
};
use subtle::ConstantTimeEq;

use super::{
    ZkDecodedPublicInputs, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs,
    ZkPublicKeyCoordinates, ZkSessionBindingPublicInputAbi, HASH_BYTES, U32_BYTES, U64_BYTES,
    VALUE_BYTES,
};

/// Domain-separated public-input value used when a verifier request omits
/// transaction data.
///
/// The value is `SHA-256("ReallyMe ZK absent transaction data v1")`. It keeps
/// absence explicit inside the circuit ABI while preserving an optional
/// transaction hash at the protocol boundary. Callers that supply this exact
/// value as real transaction data are rejected so `None` and `Some(_)` cannot
/// be replayed across each other.
pub const ABSENT_TRANSACTION_DATA_HASH: [u8; HASH_BYTES] = [
    91, 78, 241, 88, 7, 232, 126, 177, 177, 131, 109, 112, 2, 4, 88, 59, 120, 149, 185, 19, 196,
    86, 121, 196, 170, 197, 102, 14, 81, 110, 143, 196,
];

/// Hashes that bind a proof to the active presentation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkSessionBinding {
    /// Hash of the OpenID4VP nonce/challenge.
    pub nonce_hash: [u8; HASH_BYTES],
    /// Hash of the verifier identity or audience value.
    pub audience_hash: [u8; HASH_BYTES],
    /// Hash of transaction data when supplied by the verifier request.
    pub transaction_data_hash: Option<[u8; HASH_BYTES]>,
}

impl ZkSessionBinding {
    /// Returns the 32-byte value that must appear in circuit public inputs.
    #[must_use]
    pub const fn transaction_data_public_input(self) -> [u8; HASH_BYTES] {
        match self.transaction_data_hash {
            Some(value) => value,
            None => ABSENT_TRANSACTION_DATA_HASH,
        }
    }

    /// Validates that an exact circuit version supports every requested binding.
    pub fn validate_for_circuit(self, circuit_ref: ZkCircuitRef) -> Result<(), ZkError> {
        if bool::from(self.nonce_hash.ct_eq(&[0_u8; HASH_BYTES]))
            || bool::from(self.audience_hash.ct_eq(&[0_u8; HASH_BYTES]))
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        let capabilities = circuit_ref_capabilities(circuit_ref)?;
        let binding_abi = ZkSessionBindingPublicInputAbi::for_circuit(circuit_ref)?;
        let transaction_data_supported = binding_abi.supports_transaction_data_hash()
            && capabilities
                .semantic_guarantees
                .contains(&ZkSemanticGuarantee::TransactionDataBound);
        match (self.transaction_data_hash, transaction_data_supported) {
            (Some(transaction_data_hash), true)
                if bool::from(transaction_data_hash.ct_eq(&[0_u8; HASH_BYTES])) =>
            {
                return Err(ZkError::new(ZkErrorReason::BindingMismatch));
            }
            (Some(transaction_data_hash), true)
                if bool::from(transaction_data_hash.ct_eq(&ABSENT_TRANSACTION_DATA_HASH)) =>
            {
                return Err(ZkError::new(ZkErrorReason::BindingMismatch));
            }
            (Some(_), true) => {}
            (Some(_), false) => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
            (None, true) => {}
            (None, false) => {}
        }
        Ok(())
    }

    /// Decodes and validates public session fields for the exact circuit ABI.
    pub fn decode_and_validate(
        self,
        circuit_ref: ZkCircuitRef,
        public_inputs: &ZkPublicInputs,
    ) -> Result<ZkDecodedPublicInputs, ZkError> {
        self.validate_for_circuit(circuit_ref)?;
        let decoded = ZkDecodedPublicInputs::try_decode(circuit_ref, public_inputs)?;
        if !bool::from(decoded.challenge().ct_eq(&self.nonce_hash))
            || !bool::from(decoded.audience_hash().ct_eq(&self.audience_hash))
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        match (
            transaction_data_supported(circuit_ref)?,
            decoded.transaction_data_hash(),
        ) {
            (true, Some(actual))
                if bool::from(self.transaction_data_public_input().ct_eq(&actual)) => {}
            (true, Some(_)) | (true, None) => {
                return Err(ZkError::new(ZkErrorReason::BindingMismatch));
            }
            (false, Some(_)) => return Err(ZkError::new(ZkErrorReason::BindingMismatch)),
            (false, None) => {}
        }
        Ok(decoded)
    }
}

fn transaction_data_supported(circuit_ref: ZkCircuitRef) -> Result<bool, ZkError> {
    let capabilities = circuit_ref_capabilities(circuit_ref)?;
    let binding_abi = ZkSessionBindingPublicInputAbi::for_circuit(circuit_ref)?;
    Ok(binding_abi.supports_transaction_data_hash()
        && capabilities
            .semantic_guarantees
            .contains(&ZkSemanticGuarantee::TransactionDataBound))
}

pub(super) fn read_optional_public_key(
    descriptor: ZkPublicInputDescriptor,
    public_inputs: &ZkPublicInputs,
    x_name: ZkPublicInputName,
    y_name: ZkPublicInputName,
) -> Result<Option<ZkPublicKeyCoordinates>, ZkError> {
    match (
        descriptor.field_range(x_name),
        descriptor.field_range(y_name),
    ) {
        (Ok(_), Ok(_)) => Ok(Some(ZkPublicKeyCoordinates {
            x: read_hash(descriptor, public_inputs, x_name)?,
            y: read_hash(descriptor, public_inputs, y_name)?,
        })),
        (Err(x), Err(y))
            if x.reason() == ZkErrorReason::InvalidPublicInputName
                && y.reason() == ZkErrorReason::InvalidPublicInputName =>
        {
            Ok(None)
        }
        _ => Err(ZkError::new(ZkErrorReason::InvalidProofEncoding)),
    }
}

pub(super) fn read_optional_u32(
    descriptor: ZkPublicInputDescriptor,
    public_inputs: &ZkPublicInputs,
    name: ZkPublicInputName,
) -> Result<Option<u32>, ZkError> {
    let range = match descriptor.field_range(name) {
        Ok(range) => range,
        Err(error) if error.reason() == ZkErrorReason::InvalidPublicInputName => return Ok(None),
        Err(error) => return Err(error),
    };
    let bytes: [u8; U32_BYTES] = public_inputs
        .as_bytes()
        .get(range)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    Ok(Some(u32::from_be_bytes(bytes)))
}

pub(super) fn read_optional_value(
    descriptor: ZkPublicInputDescriptor,
    public_inputs: &ZkPublicInputs,
    name: ZkPublicInputName,
) -> Result<Option<[u8; VALUE_BYTES]>, ZkError> {
    let range = match descriptor.field_range(name) {
        Ok(range) => range,
        Err(error) if error.reason() == ZkErrorReason::InvalidPublicInputName => return Ok(None),
        Err(error) => return Err(error),
    };
    public_inputs
        .as_bytes()
        .get(range)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .try_into()
        .map(Some)
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

pub(super) fn read_hash(
    descriptor: ZkPublicInputDescriptor,
    public_inputs: &ZkPublicInputs,
    name: ZkPublicInputName,
) -> Result<[u8; HASH_BYTES], ZkError> {
    let range = descriptor.field_range(name)?;
    public_inputs
        .as_bytes()
        .get(range)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

pub(super) fn read_optional_hash(
    descriptor: ZkPublicInputDescriptor,
    public_inputs: &ZkPublicInputs,
    name: ZkPublicInputName,
) -> Result<Option<[u8; HASH_BYTES]>, ZkError> {
    match descriptor.field_range(name) {
        Ok(_) => read_hash(descriptor, public_inputs, name).map(Some),
        Err(error) if error.reason() == ZkErrorReason::InvalidPublicInputName => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn read_u64(
    descriptor: ZkPublicInputDescriptor,
    public_inputs: &ZkPublicInputs,
    name: ZkPublicInputName,
) -> Result<u64, ZkError> {
    let range = descriptor.field_range(name)?;
    let bytes: [u8; U64_BYTES] = public_inputs
        .as_bytes()
        .get(range)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    Ok(u64::from_be_bytes(bytes))
}
