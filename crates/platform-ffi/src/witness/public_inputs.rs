// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs, ZkSessionBinding,
        ABSENT_TRANSACTION_DATA_HASH,
    },
};
use reallyme_zk_noir_witness_core::{
    circuits::{
        credential_envelope_v1::CredentialEnvelopeV1PublicInputs,
        credential_root_v1::CredentialRootV1PublicInputs,
        credential_subject_claim_v1_claim::CredentialSubjectClaimV1ClaimPublicInputs,
        private_persona_claim_v1_claim::PrivatePersonaClaimV1ClaimPublicInputs,
    },
    ClaimDisclosure, IssuerBoundContext, SessionBindingHash, SessionContext, FIELD_ELEMENT_BYTES,
    MAX_CLAIM_VALUE_BYTES,
};
use zeroize::Zeroizing;

pub(super) fn private_session_public_inputs(
    circuit_ref: ZkCircuitRef,
    context: &SessionContext,
) -> Result<ZkPublicInputs, ZkError> {
    let mut writer = PublicInputWriter::new(circuit_ref)?;
    writer.write32(
        ZkPublicInputName::Challenge,
        context.challenge_nonce_hash.as_bytes(),
    )?;
    writer.write32(
        ZkPublicInputName::AudienceHash,
        context.audience_hash.as_bytes(),
    )?;
    writer.write32(
        ZkPublicInputName::TransactionDataHash,
        context.transaction_data_hash.as_bytes(),
    )?;
    writer.write_u64(ZkPublicInputName::ExpiryUnix, context.expiry_unix.value())?;
    writer.write32(
        ZkPublicInputName::SessionBinding,
        context.session_binding_hash.as_bytes(),
    )?;
    writer.finish()
}

pub(super) fn private_persona_session_public_inputs(
    circuit_ref: ZkCircuitRef,
    context: &SessionContext,
) -> Result<ZkPublicInputs, ZkError> {
    private_session_public_inputs(circuit_ref, context)
}

pub(super) fn credential_envelope_public_inputs(
    circuit_ref: ZkCircuitRef,
    inputs: &CredentialEnvelopeV1PublicInputs,
) -> Result<ZkPublicInputs, ZkError> {
    let mut writer = issuer_writer(circuit_ref, &inputs.issuer_context)?;
    writer.write32(
        ZkPublicInputName::EnvelopeBinding,
        inputs.envelope_binding_hash.as_bytes(),
    )?;
    writer.finish()
}

pub(super) fn credential_root_public_inputs(
    circuit_ref: ZkCircuitRef,
    inputs: &CredentialRootV1PublicInputs,
) -> Result<ZkPublicInputs, ZkError> {
    let mut writer = issuer_writer(circuit_ref, &inputs.issuer_context)?;
    writer.write32(
        ZkPublicInputName::EnvelopeBinding,
        inputs.envelope_binding_hash.as_bytes(),
    )?;
    writer.write32(
        ZkPublicInputName::CredentialBinding,
        inputs.credential_binding_hash.as_bytes(),
    )?;
    writer.finish()
}

pub(super) fn credential_subject_claim_public_inputs<T>(
    circuit_ref: ZkCircuitRef,
    inputs: &T,
) -> Result<ZkPublicInputs, ZkError>
where
    T: CredentialSubjectClaimPublicInputView,
{
    let mut writer = issuer_writer(circuit_ref, inputs.issuer_context())?;
    writer.write32(
        ZkPublicInputName::SessionBinding,
        inputs.session_binding_hash().as_bytes(),
    )?;
    write_disclosure(&mut writer, inputs.disclosure())?;
    writer.finish()
}

pub(super) trait CredentialSubjectClaimPublicInputView {
    fn issuer_context(&self) -> &IssuerBoundContext;
    fn session_binding_hash(&self) -> &SessionBindingHash;
    fn disclosure(&self) -> &ClaimDisclosure;
}

impl CredentialSubjectClaimPublicInputView for CredentialSubjectClaimV1ClaimPublicInputs {
    fn issuer_context(&self) -> &IssuerBoundContext {
        &self.issuer_context
    }
    fn session_binding_hash(&self) -> &SessionBindingHash {
        &self.session_binding_hash
    }
    fn disclosure(&self) -> &ClaimDisclosure {
        &self.disclosure
    }
}

impl CredentialSubjectClaimPublicInputView for PrivatePersonaClaimV1ClaimPublicInputs {
    fn issuer_context(&self) -> &IssuerBoundContext {
        &self.issuer_context
    }
    fn session_binding_hash(&self) -> &SessionBindingHash {
        &self.session_binding_hash
    }
    fn disclosure(&self) -> &ClaimDisclosure {
        &self.disclosure
    }
}

pub(super) fn session_binding_from_public_inputs(
    circuit_ref: ZkCircuitRef,
    public_inputs: &ZkPublicInputs,
) -> Result<ZkSessionBinding, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let nonce_hash = read32(descriptor, public_inputs, ZkPublicInputName::Challenge)?;
    let audience_hash = read32(descriptor, public_inputs, ZkPublicInputName::AudienceHash)?;
    let transaction_data_hash = read32(
        descriptor,
        public_inputs,
        ZkPublicInputName::TransactionDataHash,
    )?;
    Ok(ZkSessionBinding {
        nonce_hash,
        audience_hash,
        transaction_data_hash: if transaction_data_hash == ABSENT_TRANSACTION_DATA_HASH {
            None
        } else {
            Some(transaction_data_hash)
        },
    })
}

fn issuer_writer(
    circuit_ref: ZkCircuitRef,
    context: &IssuerBoundContext,
) -> Result<PublicInputWriter, ZkError> {
    let mut writer = PublicInputWriter::new(circuit_ref)?;
    writer.write32(
        ZkPublicInputName::IssuerPublicKeyX,
        context.issuer_public_key.x.as_bytes(),
    )?;
    writer.write32(
        ZkPublicInputName::IssuerPublicKeyY,
        context.issuer_public_key.y.as_bytes(),
    )?;
    writer.write32(
        ZkPublicInputName::Challenge,
        context.challenge_nonce_hash.as_bytes(),
    )?;
    writer.write32(
        ZkPublicInputName::AudienceHash,
        context.audience_hash.as_bytes(),
    )?;
    writer.write32(
        ZkPublicInputName::TransactionDataHash,
        context.transaction_data_hash.as_bytes(),
    )?;
    writer.write_u64(ZkPublicInputName::ExpiryUnix, context.expiry_unix.value())?;
    Ok(writer)
}

fn write_disclosure(
    writer: &mut PublicInputWriter,
    disclosure: &ClaimDisclosure,
) -> Result<(), ZkError> {
    writer.write32(
        ZkPublicInputName::CredentialBinding,
        disclosure.credential_binding_hash.as_bytes(),
    )?;
    writer.write_u32(
        ZkPublicInputName::ValueLength,
        disclosure.claim_value.length().value(),
    )?;
    writer.write64(ZkPublicInputName::Value, disclosure.claim_value.as_bytes())?;
    writer.write32(
        ZkPublicInputName::ClaimNameHash,
        disclosure.claim_name_hash.as_bytes(),
    )
}

struct PublicInputWriter {
    descriptor: ZkPublicInputDescriptor,
    bytes: Zeroizing<Vec<u8>>,
}

impl PublicInputWriter {
    fn new(circuit_ref: ZkCircuitRef) -> Result<Self, ZkError> {
        let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
        let len = descriptor.encoded_len()?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(len)
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        bytes.resize(len, 0);
        Ok(Self { descriptor, bytes })
    }

    fn write32(
        &mut self,
        name: ZkPublicInputName,
        value: &[u8; FIELD_ELEMENT_BYTES],
    ) -> Result<(), ZkError> {
        self.write(name, value)
    }

    fn write64(
        &mut self,
        name: ZkPublicInputName,
        value: &[u8; MAX_CLAIM_VALUE_BYTES],
    ) -> Result<(), ZkError> {
        self.write(name, value)
    }

    fn write_u32(&mut self, name: ZkPublicInputName, value: u32) -> Result<(), ZkError> {
        self.write(name, &value.to_be_bytes())
    }

    fn write_u64(&mut self, name: ZkPublicInputName, value: u64) -> Result<(), ZkError> {
        self.write(name, &value.to_be_bytes())
    }

    fn write(&mut self, name: ZkPublicInputName, value: &[u8]) -> Result<(), ZkError> {
        let range = self.descriptor.field_range(name)?;
        let slot = self
            .bytes
            .get_mut(range)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        if slot.len() != value.len() {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        slot.copy_from_slice(value);
        Ok(())
    }

    fn finish(mut self) -> Result<ZkPublicInputs, ZkError> {
        ZkPublicInputs::try_from_bytes(core::mem::take(&mut *self.bytes))
    }
}

fn read32(
    descriptor: ZkPublicInputDescriptor,
    public_inputs: &ZkPublicInputs,
    name: ZkPublicInputName,
) -> Result<[u8; FIELD_ELEMENT_BYTES], ZkError> {
    public_inputs
        .as_bytes()
        .get(descriptor.field_range(name)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))
}
