// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    generate_witness_from_artifact_json, validate_inputs,
    PersonaCredentialEvidenceV1CurrentStateInputs,
    PersonaCredentialEvidenceV1CurrentStatePrivateInputs,
    PersonaCredentialEvidenceV1CurrentStatePublicInputs,
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
) -> Result<PersonaCredentialEvidenceV1CurrentStateInputs, WitnessError> {
    let source = fs::read_to_string(path).map_err(|_| fixture_error())?;
    let fixture: toml::Value = toml::from_str(&source).map_err(|_| fixture_error())?;
    let slot = fixture.get("slot").ok_or_else(fixture_error)?;
    let witness = fixture.get("witness").ok_or_else(fixture_error)?;
    let rows = witness
        .get("path")
        .and_then(toml::Value::as_array)
        .ok_or_else(fixture_error)?;
    if rows.len() != 12 {
        return Err(fixture_error());
    }
    let mut status_path = [[0_u8; 32]; 12];
    for (destination, row) in status_path.iter_mut().zip(rows) {
        let row_values = row.as_array().ok_or_else(fixture_error)?;
        if row_values.len() != 32 {
            return Err(fixture_error());
        }
        for (byte, value) in destination.iter_mut().zip(row_values) {
            let integer = value.as_integer().ok_or_else(fixture_error)?;
            *byte = u8::try_from(integer).map_err(|_| fixture_error())?;
        }
    }
    Ok(PersonaCredentialEvidenceV1CurrentStateInputs {
        public_inputs: PersonaCredentialEvidenceV1CurrentStatePublicInputs {
            issuer_x: array(slot, "issuer_x")?,
            issuer_y: array(slot, "issuer_y")?,
            holder_x: array(slot, "holder_x")?,
            holder_y: array(slot, "holder_y")?,
            token_nonce: array(slot, "token_nonce")?,
            prepared_from: unsigned(slot, "prepared_from")?,
            prepared_until: unsigned(slot, "prepared_until")?,
            credential_binding: array(slot, "credential_binding")?,
            status_root: array(slot, "status_root")?,
            status_length: unsigned(slot, "status_length")?,
            status_list_id: array(slot, "status_list_id")?,
            status_url_hash: array(slot, "status_url_hash")?,
            status_purpose: u8::try_from(unsigned(slot, "status_purpose")?)
                .map_err(|_| fixture_error())?,
        },
        private_inputs: SecretInputs::new(PersonaCredentialEvidenceV1CurrentStatePrivateInputs {
            envelope_hash: array(witness, "envelope_hash")?,
            claims_root: array(witness, "claims_root")?,
            subject_x: array(witness, "subject_x")?,
            subject_y: array(witness, "subject_y")?,
            issuer_validity_status_signature: array(witness, "issuer_validity_status_signature")?,
            valid_from: unsigned(witness, "valid_from")?,
            valid_until: unsigned(witness, "valid_until")?,
            status_index: unsigned(witness, "status_index")?,
            status_chunk: array(witness, "status_chunk")?,
            path_length: u32::try_from(unsigned(witness, "path_len")?)
                .map_err(|_| fixture_error())?,
            path: status_path,
        }),
    })
}

fn valid_inputs() -> PersonaCredentialEvidenceV1CurrentStateInputs {
    inputs_with_status_opening(3, 0)
}

fn inputs_with_status_opening(
    status_index: u64,
    path_length: u32,
) -> PersonaCredentialEvidenceV1CurrentStateInputs {
    PersonaCredentialEvidenceV1CurrentStateInputs {
        public_inputs: PersonaCredentialEvidenceV1CurrentStatePublicInputs {
            issuer_x: [1; 32],
            issuer_y: [2; 32],
            holder_x: [3; 32],
            holder_y: [4; 32],
            token_nonce: [5; 32],
            prepared_from: 100,
            prepared_until: 200,
            credential_binding: [6; 32],
            status_root: [7; 32],
            status_length: 8,
            status_list_id: [8; 32],
            status_url_hash: [9; 32],
            status_purpose: 1,
        },
        private_inputs: SecretInputs::new(PersonaCredentialEvidenceV1CurrentStatePrivateInputs {
            envelope_hash: [10; 32],
            claims_root: [11; 32],
            subject_x: [13; 32],
            subject_y: [14; 32],
            issuer_validity_status_signature: [12; 64],
            valid_from: 90,
            valid_until: 210,
            status_index,
            status_chunk: [0; 32],
            path_length,
            path: [[0; 32]; 12],
        }),
    }
}

#[test]
fn valid_prepared_interval_and_status_bounds_reach_artifact_admission() -> Result<(), WitnessError>
{
    let inputs = valid_inputs();
    validate_inputs(&inputs)?;
    let artifact = CompiledProgramArtifactJson::try_from_bytes(b"{}")?;
    let error = generate_witness_from_artifact_json(artifact, &inputs)
        .err()
        .map(|failure| failure.reason);
    assert_eq!(error, Some(WitnessErrorReason::ArtifactJsonInvalid));
    Ok(())
}

#[test]
fn prepared_status_rejects_bad_windows_and_status_openings() -> Result<(), WitnessError> {
    let mut empty_token = valid_inputs();
    empty_token.public_inputs.token_nonce = [0; 32];
    let mut outside_validity = valid_inputs();
    outside_validity.public_inputs.prepared_until = 211;
    let wrong_status_index = inputs_with_status_opening(8, 0);
    let excess_path = inputs_with_status_opening(3, 13);
    let mut wrong_purpose = valid_inputs();
    wrong_purpose.public_inputs.status_purpose = 3;
    for inputs in [
        empty_token,
        outside_validity,
        wrong_status_index,
        excess_path,
        wrong_purpose,
    ] {
        assert_eq!(
            validate_inputs(&inputs).err().map(|error| error.reason),
            Some(WitnessErrorReason::PreparedStatusInputOutOfRange),
        );
    }
    Ok(())
}

// Nargo compilation is an explicit prerequisite for this retained-witness
// parity check. The linked prepared-proof script runs it after compiling both
// hash lanes; ordinary workspace tests do not depend on ignored build output.
#[test]
#[ignore = "requires the pinned Nargo compiled persona-credential-evidence fixtures"]
fn compiled_prepared_status_witness_matches_noir_in_both_lanes() -> Result<(), WitnessError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for lane in ["sha256", "poseidon2"] {
        let circuit = repository
            .join("circuits")
            .join(lane)
            .join("families/persona_credential_evidence_v1/current_state");
        let name = format!("credential_persona_credential_evidence_v1_current_state_{lane}");
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
        // Never print either witness on a parity failure.
        if actual != expected {
            return Err(WitnessError::new(WitnessErrorReason::ArtifactAbiMismatch));
        }
    }
    Ok(())
}
