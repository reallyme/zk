// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict codec for common-credential-root raw public-input streams.
//!
//! Common-credential-root verification consumes raw Barretenberg field streams whose ABI is
//! intentionally separate from the compact production-bundle public-input ABI.

use buffa::{DecodeOptions, EnumValue, Message, MessageField};
use reallyme_zk_api::{
    common_root::{
        ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot,
        ZkCommonCredentialRootRawPublicInputs,
        COMMON_CREDENTIAL_ROOT_V1_MAX_RAW_PUBLIC_INPUT_BYTES,
    },
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, Zeroizing};

use crate::artifact::circuit_ref_to_proto;
use crate::domain::circuit_ref_from_proto_message;

mod presentation;
#[cfg(any(feature = "native", feature = "wasm"))]
mod selected_record_builder;
mod witness;

pub(crate) use presentation::{
    common_credential_root_join_policy_from_proto, common_credential_root_presentation_from_proto,
    common_credential_root_raw_proof_package_from_proto,
    zeroize_common_credential_root_join_policy_proto,
};

pub use presentation::{
    common_credential_root_persona_mode_to_proto_public,
    common_credential_root_presentation_to_proto,
    common_credential_root_raw_proof_package_to_proto, ZkCommonCredentialRootClaimExpectationOwner,
    ZkCommonCredentialRootJoinPolicyOwner, ZkCommonCredentialRootPresentation,
    ZkCommonCredentialRootRawProofPackage,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use selected_record_builder::{
    build_common_credential_root_selected_record_presentation_operation,
    encode_common_credential_root_selected_record_presentation_request,
    ZkCommonCredentialRootPresenterAuthorization, ZkCommonCredentialRootSelectedCredentialRecord,
    ZkCommonCredentialRootSelectedIssuerStatus,
    ZkCommonCredentialRootSelectedRecordPresentationInput,
    ZkCommonCredentialRootSelectedRecordPresentationOperationOwner,
};
pub use witness::{
    common_credential_root_witness_plan, common_credential_root_witness_plan_for_circuit,
    ZkCommonCredentialRootWitnessPlan,
};

const COMMON_CREDENTIAL_ROOT_RAW_INPUT_RECURSION_LIMIT: u32 = 8;
const COMMON_CREDENTIAL_ROOT_RAW_INPUT_UNKNOWN_FIELD_LIMIT: usize = 0;
const COMMON_CREDENTIAL_ROOT_RAW_INPUT_OVERHEAD_BYTES: usize = 16 * 1024;
const MAX_COMMON_CREDENTIAL_ROOT_RAW_INPUT_MESSAGE_BYTES: usize =
    COMMON_CREDENTIAL_ROOT_V1_MAX_RAW_PUBLIC_INPUT_BYTES
        + COMMON_CREDENTIAL_ROOT_RAW_INPUT_OVERHEAD_BYTES;

/// Decoded common-credential-root raw public-input package.
pub struct ZkCommonCredentialRootRawPublicInputPackage {
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slot: ZkCommonCredentialRootProofSlot,
    public_inputs: ZkCommonCredentialRootRawPublicInputs,
}

impl ZkCommonCredentialRootRawPublicInputPackage {
    /// Persona mode selected by the complete common-credential-root persona_mode.
    #[must_use]
    pub const fn persona_mode(&self) -> ZkCommonCredentialRootPersonaMode {
        self.persona_mode
    }

    /// Ordered proof slot that produced these raw public inputs.
    #[must_use]
    pub const fn slot(&self) -> ZkCommonCredentialRootProofSlot {
        self.slot
    }

    /// Exact raw public inputs after circuit/slot validation.
    #[must_use]
    pub const fn public_inputs(&self) -> &ZkCommonCredentialRootRawPublicInputs {
        &self.public_inputs
    }

    /// Consumes the package and returns the zeroizing input owner.
    #[must_use]
    pub fn into_public_inputs(self) -> ZkCommonCredentialRootRawPublicInputs {
        self.public_inputs
    }
}

impl core::fmt::Debug for ZkCommonCredentialRootRawPublicInputPackage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkCommonCredentialRootRawPublicInputPackage")
            .field("persona_mode", &self.persona_mode)
            .field("slot", &self.slot)
            .field("public_inputs", &self.public_inputs)
            .finish()
    }
}

/// Encodes one validated common-credential-root raw public-input stream.
pub fn encode_common_credential_root_raw_public_inputs(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slot: ZkCommonCredentialRootProofSlot,
    public_inputs: &ZkCommonCredentialRootRawPublicInputs,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let expected_ref =
        persona_mode.source_ref(public_inputs.circuit_ref().credential_hash_algorithm, slot);
    if expected_ref != public_inputs.circuit_ref() {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let mut message = pb::ZkCommonCredentialRootRawPublicInputs {
        persona_mode: EnumValue::from(common_credential_root_persona_mode_to_proto(persona_mode)),
        slot: EnumValue::from(common_credential_root_slot_to_proto(slot)),
        circuit_ref: MessageField::some(circuit_ref_to_proto(public_inputs.circuit_ref())),
        raw_fields: public_inputs.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let encoded = encode_canonical_raw_public_inputs(&message);
    message.raw_fields.zeroize();
    encoded
}

/// Decodes one canonical common-credential-root raw public-input protobuf message.
pub fn decode_common_credential_root_raw_public_inputs(
    bytes: &[u8],
) -> Result<ZkCommonCredentialRootRawPublicInputPackage, ZkError> {
    if bytes.len() > MAX_COMMON_CREDENTIAL_ROOT_RAW_INPUT_MESSAGE_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let decoded = DecodeOptions::new()
        .with_recursion_limit(COMMON_CREDENTIAL_ROOT_RAW_INPUT_RECURSION_LIMIT)
        .with_unknown_field_limit(COMMON_CREDENTIAL_ROOT_RAW_INPUT_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(MAX_COMMON_CREDENTIAL_ROOT_RAW_INPUT_MESSAGE_BYTES)
        .with_max_message_size(MAX_COMMON_CREDENTIAL_ROOT_RAW_INPUT_MESSAGE_BYTES)
        .decode_from_slice::<pb::ZkCommonCredentialRootRawPublicInputs>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let owner = RawPublicInputsProtoOwner::new(decoded);
    let canonical = encode_canonical_raw_public_inputs(owner.message())?;
    if canonical.as_slice() != bytes {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    common_credential_root_raw_public_inputs_from_owner(owner)
}

/// Converts a generated protobuf message into the strict common-credential-root package.
pub(crate) fn common_credential_root_raw_public_inputs_from_proto(
    input: pb::ZkCommonCredentialRootRawPublicInputs,
) -> Result<ZkCommonCredentialRootRawPublicInputPackage, ZkError> {
    common_credential_root_raw_public_inputs_from_owner(RawPublicInputsProtoOwner::new(input))
}

/// Converts strict raw public inputs to generated protobuf without encoding.
pub fn common_credential_root_raw_public_inputs_to_proto(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slot: ZkCommonCredentialRootProofSlot,
    public_inputs: &ZkCommonCredentialRootRawPublicInputs,
) -> Result<pb::ZkCommonCredentialRootRawPublicInputs, ZkError> {
    let expected_ref =
        persona_mode.source_ref(public_inputs.circuit_ref().credential_hash_algorithm, slot);
    if expected_ref != public_inputs.circuit_ref() {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    Ok(pb::ZkCommonCredentialRootRawPublicInputs {
        persona_mode: EnumValue::from(common_credential_root_persona_mode_to_proto(persona_mode)),
        slot: EnumValue::from(common_credential_root_slot_to_proto(slot)),
        circuit_ref: MessageField::some(circuit_ref_to_proto(public_inputs.circuit_ref())),
        raw_fields: public_inputs.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn common_credential_root_raw_public_inputs_from_owner(
    mut owner: RawPublicInputsProtoOwner,
) -> Result<ZkCommonCredentialRootRawPublicInputPackage, ZkError> {
    let persona_mode = common_credential_root_persona_mode_from_proto(owner.persona_mode())?;
    let slot = common_credential_root_slot_from_proto(owner.slot())?;
    let circuit_ref = circuit_ref_from_proto_message(owner.take_circuit_ref())?;
    let expected_ref = persona_mode.source_ref(circuit_ref.credential_hash_algorithm, slot);
    if expected_ref != circuit_ref {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let public_inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
        circuit_ref,
        owner.take_raw_fields(),
    )?;
    Ok(ZkCommonCredentialRootRawPublicInputPackage {
        persona_mode,
        slot,
        public_inputs,
    })
}

struct RawPublicInputsProtoOwner {
    message: pb::ZkCommonCredentialRootRawPublicInputs,
}

impl RawPublicInputsProtoOwner {
    fn new(message: pb::ZkCommonCredentialRootRawPublicInputs) -> Self {
        Self { message }
    }

    fn message(&self) -> &pb::ZkCommonCredentialRootRawPublicInputs {
        &self.message
    }

    fn persona_mode(&self) -> EnumValue<pb::ZkCommonCredentialRootPersonaMode> {
        self.message.persona_mode
    }

    fn slot(&self) -> EnumValue<pb::ZkCommonCredentialRootProofSlot> {
        self.message.slot
    }

    fn take_circuit_ref(
        &mut self,
    ) -> MessageField<pb::ZkCircuitRef, buffa::Inline<pb::ZkCircuitRef>> {
        core::mem::take(&mut self.message.circuit_ref)
    }

    fn take_raw_fields(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.message.raw_fields)
    }
}

impl Drop for RawPublicInputsProtoOwner {
    fn drop(&mut self) {
        self.message.raw_fields.zeroize();
    }
}

fn encode_canonical_raw_public_inputs(
    input: &pb::ZkCommonCredentialRootRawPublicInputs,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let maximum = u32::try_from(MAX_COMMON_CREDENTIAL_ROOT_RAW_INPUT_MESSAGE_BYTES)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let encoded_len = input
        .try_encoded_len()
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    if encoded_len > maximum {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let encoded_len =
        usize::try_from(encoded_len).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    input
        .try_encode_bounded(maximum, &mut *encoded)
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    Ok(encoded)
}

pub(crate) fn common_credential_root_persona_mode_from_proto(
    persona_mode: EnumValue<pb::ZkCommonCredentialRootPersonaMode>,
) -> Result<ZkCommonCredentialRootPersonaMode, ZkError> {
    match persona_mode.as_known() {
        Some(
            pb::ZkCommonCredentialRootPersonaMode::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1,
        ) => Ok(ZkCommonCredentialRootPersonaMode::PrivatePersona),
        Some(
            pb::ZkCommonCredentialRootPersonaMode::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PUBLIC_PERSONA_V1,
        ) => Ok(ZkCommonCredentialRootPersonaMode::PublicPersona),
        Some(pb::ZkCommonCredentialRootPersonaMode::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_UNSPECIFIED)
        | None => Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle)),
    }
}

pub(crate) fn common_credential_root_persona_mode_to_proto(
    persona_mode: ZkCommonCredentialRootPersonaMode,
) -> pb::ZkCommonCredentialRootPersonaMode {
    match persona_mode {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => {
            pb::ZkCommonCredentialRootPersonaMode::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1
        }
        ZkCommonCredentialRootPersonaMode::PublicPersona => {
            pb::ZkCommonCredentialRootPersonaMode::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PUBLIC_PERSONA_V1
        }
    }
}

pub(crate) fn common_credential_root_slot_from_proto(
    slot: EnumValue<pb::ZkCommonCredentialRootProofSlot>,
) -> Result<ZkCommonCredentialRootProofSlot, ZkError> {
    match slot.as_known() {
        Some(pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_ATTESTATION) => {
            Ok(ZkCommonCredentialRootProofSlot::RootAttestation)
        }
        Some(pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_STATUS) => {
            Ok(ZkCommonCredentialRootProofSlot::RootStatus)
        }
        Some(pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_0) => {
            Ok(ZkCommonCredentialRootProofSlot::Lineage0)
        }
        Some(pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_1) => {
            Ok(ZkCommonCredentialRootProofSlot::Lineage1)
        }
        Some(pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_0) => {
            Ok(ZkCommonCredentialRootProofSlot::SelectedClaim0)
        }
        Some(pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_1) => {
            Ok(ZkCommonCredentialRootProofSlot::SelectedClaim1)
        }
        Some(pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION) => {
            Ok(ZkCommonCredentialRootProofSlot::Session)
        }
        Some(pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0) => {
            Ok(ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0)
        }
        Some(pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_1) => {
            Ok(ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1)
        }
        Some(pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))
        }
    }
}

pub(crate) fn common_credential_root_slot_to_proto(
    slot: ZkCommonCredentialRootProofSlot,
) -> pb::ZkCommonCredentialRootProofSlot {
    match slot {
        ZkCommonCredentialRootProofSlot::RootAttestation => {
            pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_ATTESTATION
        }
        ZkCommonCredentialRootProofSlot::RootStatus => {
            pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_STATUS
        }
        ZkCommonCredentialRootProofSlot::Lineage0 => {
            pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_0
        }
        ZkCommonCredentialRootProofSlot::Lineage1 => {
            pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_1
        }
        ZkCommonCredentialRootProofSlot::SelectedClaim0 => {
            pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_0
        }
        ZkCommonCredentialRootProofSlot::SelectedClaim1 => {
            pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_1
        }
        ZkCommonCredentialRootProofSlot::Session => {
            pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION
        }
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 => {
            pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0
        }
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => {
            pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_1
        }
        _ => pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_UNSPECIFIED,
    }
}
