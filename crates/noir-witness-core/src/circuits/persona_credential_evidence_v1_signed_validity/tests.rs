// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    generate_witness_from_artifact_json, validate_inputs,
    PersonaCredentialEvidenceV1SignedValidityInputs,
    PersonaCredentialEvidenceV1SignedValidityPrivateInputs,
    PersonaCredentialEvidenceV1SignedValidityPublicInputs,
};
use crate::{CompiledProgramArtifactJson, SecretInputs, WitnessError, WitnessErrorReason};
use acir::native_types::WitnessStack;
use acvm::FieldElement;
use std::{fs, path::Path};

fn fixture_error() -> WitnessError {
    WitnessError::new(WitnessErrorReason::AbiEncodingFailed)
}

fn array<const N: usize>(table: &toml::Value, name: &str) -> Result<[u8; N], WitnessError> {
    let values = table
        .get(name)
        .and_then(toml::Value::as_array)
        .ok_or_else(fixture_error)?;
    if values.len() != N {
        return Err(fixture_error());
    }
    let mut output = [0_u8; N];
    for (destination, value) in output.iter_mut().zip(values) {
        let integer = value.as_integer().ok_or_else(fixture_error)?;
        *destination = u8::try_from(integer).map_err(|_| fixture_error())?;
    }
    Ok(output)
}

fn unsigned(table: &toml::Value, name: &str) -> Result<u64, WitnessError> {
    let integer = table
        .get(name)
        .and_then(toml::Value::as_integer)
        .ok_or_else(fixture_error)?;
    u64::try_from(integer).map_err(|_| fixture_error())
}

fn fixture_inputs(
    path: &Path,
) -> Result<PersonaCredentialEvidenceV1SignedValidityInputs, WitnessError> {
    let source = fs::read_to_string(path).map_err(|_| fixture_error())?;
    let fixture: toml::Value = toml::from_str(&source).map_err(|_| fixture_error())?;
    let slot = fixture.get("slot").ok_or_else(fixture_error)?;
    let witness = fixture.get("witness").ok_or_else(fixture_error)?;
    Ok(PersonaCredentialEvidenceV1SignedValidityInputs {
        public_inputs: PersonaCredentialEvidenceV1SignedValidityPublicInputs {
            issuer_x: array(slot, "issuer_x")?,
            issuer_y: array(slot, "issuer_y")?,
            holder_x: array(slot, "holder_x")?,
            holder_y: array(slot, "holder_y")?,
            token_nonce: array(slot, "token_nonce")?,
            prepared_from: unsigned(slot, "prepared_from")?,
            prepared_until: unsigned(slot, "prepared_until")?,
            credential_binding: array(slot, "credential_binding")?,
            status_list_id: array(slot, "status_list_id")?,
            status_url_hash: array(slot, "status_url_hash")?,
            status_purpose: u8::try_from(unsigned(slot, "status_purpose")?)
                .map_err(|_| fixture_error())?,
        },
        private_inputs: SecretInputs::new(PersonaCredentialEvidenceV1SignedValidityPrivateInputs {
            envelope_hash: array(witness, "envelope_hash")?,
            claims_root: array(witness, "claims_root")?,
            subject_x: array(witness, "subject_x")?,
            subject_y: array(witness, "subject_y")?,
            issuer_validity_status_signature: array(witness, "issuer_validity_status_signature")?,
            valid_from: unsigned(witness, "valid_from")?,
            valid_until: unsigned(witness, "valid_until")?,
            status_index: unsigned(witness, "status_index")?,
        }),
    })
}

#[test]
fn rejects_interval_and_status_pointer_inputs() -> Result<(), WitnessError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture = root.join(
        "circuits/sha256/families/persona_credential_evidence_v1/signed_validity/Prover.toml",
    );
    let mut bad_interval = fixture_inputs(&fixture)?;
    bad_interval.public_inputs.prepared_from = bad_interval
        .private_inputs
        .expose()
        .valid_from
        .checked_sub(1)
        .ok_or_else(fixture_error)?;
    let mut bad_purpose = fixture_inputs(&fixture)?;
    bad_purpose.public_inputs.status_purpose = 3;
    for input in [bad_interval, bad_purpose] {
        assert_eq!(
            validate_inputs(&input).err().map(|error| error.reason),
            Some(WitnessErrorReason::PreparedStatusInputOutOfRange)
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires the pinned Nargo compiled persona-credential-evidence fixtures"]
fn compiled_signed_validity_witness_matches_noir_in_both_lanes() -> Result<(), WitnessError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for lane in ["sha256", "poseidon2"] {
        let circuit = repository
            .join("circuits")
            .join(lane)
            .join("families/persona_credential_evidence_v1/signed_validity");
        let name = format!("credential_persona_credential_evidence_v1_signed_validity_{lane}");
        let artifact_bytes = fs::read(circuit.join("target").join(format!("{name}.json")))
            .map_err(|_| WitnessError::new(WitnessErrorReason::ArtifactEmpty))?;
        let retained_bytes = fs::read(circuit.join("target").join(format!("{name}.gz")))
            .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?;
        let inputs = fixture_inputs(&circuit.join("PrivateJoined.toml"))?;
        let artifact = CompiledProgramArtifactJson::try_from_bytes(&artifact_bytes)?;
        let produced = generate_witness_from_artifact_json(artifact, &inputs)?;
        let expected = WitnessStack::<FieldElement>::deserialize(&retained_bytes)
            .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?;
        let actual = WitnessStack::<FieldElement>::deserialize(produced.as_bytes())
            .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?;
        if actual != expected {
            return Err(WitnessError::new(WitnessErrorReason::ArtifactAbiMismatch));
        }
    }
    Ok(())
}
