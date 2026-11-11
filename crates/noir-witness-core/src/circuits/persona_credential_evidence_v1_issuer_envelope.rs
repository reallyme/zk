// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed witness boundary for the first prepared credential-evidence stage.
//!
//! The issuer's signed envelope and hidden subject are held by `SecretInputs`.
//! The public token join is checked against the exact compiled circuit ABI.

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::abi_encoding::{
    byte_array_type, input_value_for_byte_array, input_value_for_u64, unsigned_integer_type,
};
use crate::circuits::support::{abi_parameter, empty_input_map};
use crate::domain::{CompiledProgramArtifactJson, SecretInputs, SerializedWitnessStack};
use crate::execution::generate_witness;
use crate::{WitnessError, WitnessErrorReason};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PersonaCredentialEvidenceV1IssuerEnvelopePublicInputs {
    pub issuer_x: [u8; 32],
    pub issuer_y: [u8; 32],
    pub holder_x: [u8; 32],
    pub holder_y: [u8; 32],
    pub token_nonce: [u8; 32],
    pub prepared_from: u64,
    pub prepared_until: u64,
    pub credential_binding: [u8; 32],
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PersonaCredentialEvidenceV1IssuerEnvelopePrivateInputs {
    pub envelope_hash: [u8; 32],
    pub claims_root: [u8; 32],
    pub subject_x: [u8; 32],
    pub subject_y: [u8; 32],
    pub issuer_envelope_signature: [u8; 64],
    pub issuer_subject_binding_signature: [u8; 64],
}

pub struct PersonaCredentialEvidenceV1IssuerEnvelopeInputs {
    pub public_inputs: PersonaCredentialEvidenceV1IssuerEnvelopePublicInputs,
    pub private_inputs: SecretInputs<PersonaCredentialEvidenceV1IssuerEnvelopePrivateInputs>,
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &PersonaCredentialEvidenceV1IssuerEnvelopeInputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    validate_inputs(inputs)?;
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn validate_inputs(
    inputs: &PersonaCredentialEvidenceV1IssuerEnvelopeInputs,
) -> Result<(), WitnessError> {
    let public = &inputs.public_inputs;
    let private = inputs.private_inputs.expose();
    let zero_key = |x: &[u8; 32], y: &[u8; 32]| {
        x.iter().all(|byte| *byte == 0) && y.iter().all(|byte| *byte == 0)
    };
    if zero_key(&public.issuer_x, &public.issuer_y)
        || zero_key(&public.holder_x, &public.holder_y)
        || zero_key(&private.subject_x, &private.subject_y)
        || public.token_nonce.iter().all(|byte| *byte == 0)
        || public.prepared_from >= public.prepared_until
        || private.envelope_hash.iter().all(|byte| *byte == 0)
        || private.claims_root.iter().all(|byte| *byte == 0)
    {
        return Err(WitnessError::new(
            WitnessErrorReason::PreparedClaimInputOutOfRange,
        ));
    }
    Ok(())
}

fn expected_abi_parameters() -> [AbiParameter; 14] {
    [
        abi_parameter("pk_issuer_x", byte_array_type(32), AbiVisibility::Public),
        abi_parameter("pk_issuer_y", byte_array_type(32), AbiVisibility::Public),
        abi_parameter("holder_x", byte_array_type(32), AbiVisibility::Public),
        abi_parameter("holder_y", byte_array_type(32), AbiVisibility::Public),
        abi_parameter("token_nonce", byte_array_type(32), AbiVisibility::Public),
        abi_parameter(
            "prepared_from",
            unsigned_integer_type(64),
            AbiVisibility::Public,
        ),
        abi_parameter(
            "prepared_until",
            unsigned_integer_type(64),
            AbiVisibility::Public,
        ),
        abi_parameter(
            "credential_binding",
            byte_array_type(32),
            AbiVisibility::Public,
        ),
        abi_parameter("envelope_hash", byte_array_type(32), AbiVisibility::Private),
        abi_parameter("claims_root", byte_array_type(32), AbiVisibility::Private),
        abi_parameter("pk_subject_x", byte_array_type(32), AbiVisibility::Private),
        abi_parameter("pk_subject_y", byte_array_type(32), AbiVisibility::Private),
        abi_parameter(
            "issuer_envelope_sig",
            byte_array_type(64),
            AbiVisibility::Private,
        ),
        abi_parameter(
            "issuer_subject_bind_sig",
            byte_array_type(64),
            AbiVisibility::Private,
        ),
    ]
}

fn encode_inputs(inputs: &PersonaCredentialEvidenceV1IssuerEnvelopeInputs) -> InputMap {
    let public = &inputs.public_inputs;
    let private = inputs.private_inputs.expose();
    let mut map = empty_input_map();
    for (name, value) in [
        ("pk_issuer_x", &public.issuer_x),
        ("pk_issuer_y", &public.issuer_y),
        ("holder_x", &public.holder_x),
        ("holder_y", &public.holder_y),
        ("token_nonce", &public.token_nonce),
        ("credential_binding", &public.credential_binding),
        ("envelope_hash", &private.envelope_hash),
        ("claims_root", &private.claims_root),
        ("pk_subject_x", &private.subject_x),
        ("pk_subject_y", &private.subject_y),
    ] {
        map.insert(String::from(name), input_value_for_byte_array(value));
    }
    map.insert(
        String::from("prepared_from"),
        input_value_for_u64(public.prepared_from),
    );
    map.insert(
        String::from("prepared_until"),
        input_value_for_u64(public.prepared_until),
    );
    map.insert(
        String::from("issuer_envelope_sig"),
        input_value_for_byte_array(&private.issuer_envelope_signature),
    );
    map.insert(
        String::from("issuer_subject_bind_sig"),
        input_value_for_byte_array(&private.issuer_subject_binding_signature),
    );
    map
}

#[cfg(test)]
#[path = "persona_credential_evidence_v1_issuer_envelope/tests.rs"]
mod tests;
