// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    generate_witness_from_artifact_json, validate_inputs, PersonaCredentialEvidenceClaimMode,
    PersonaCredentialEvidencePrivatePersonaAuthorization, PersonaCredentialEvidenceV1ClaimInputs,
    PersonaCredentialEvidenceV1ClaimPrivateInputs, PersonaCredentialEvidenceV1ClaimPublicInputs,
};
use crate::{CompiledProgramArtifactJson, SecretInputs, WitnessError, WitnessErrorReason};
use acir::native_types::WitnessStack;
use acvm::FieldElement;
use std::{fs, path::Path};

fn invalid_fixture() -> WitnessError {
    WitnessError::new(WitnessErrorReason::AbiEncodingFailed)
}

fn array<const N: usize>(table: &toml::Value, name: &str) -> Result<[u8; N], WitnessError> {
    let values = table
        .get(name)
        .and_then(toml::Value::as_array)
        .ok_or_else(invalid_fixture)?;
    if values.len() != N {
        return Err(invalid_fixture());
    }
    let mut output = [0_u8; N];
    for (destination, value) in output.iter_mut().zip(values) {
        let integer = value.as_integer().ok_or_else(invalid_fixture)?;
        *destination = u8::try_from(integer).map_err(|_| invalid_fixture())?;
    }
    Ok(output)
}

fn unsigned(table: &toml::Value, name: &str) -> Result<u64, WitnessError> {
    let integer = table
        .get(name)
        .and_then(toml::Value::as_integer)
        .ok_or_else(invalid_fixture)?;
    u64::try_from(integer).map_err(|_| invalid_fixture())
}

fn fixture_inputs(
    path: &Path,
    mode: PersonaCredentialEvidenceClaimMode,
) -> Result<PersonaCredentialEvidenceV1ClaimInputs, WitnessError> {
    fixture_inputs_with_path_length(path, mode, None)
}

fn fixture_inputs_with_path_length(
    path: &Path,
    mode: PersonaCredentialEvidenceClaimMode,
    path_length_override: Option<u32>,
) -> Result<PersonaCredentialEvidenceV1ClaimInputs, WitnessError> {
    let source = fs::read_to_string(path).map_err(|_| invalid_fixture())?;
    let fixture: toml::Value = toml::from_str(&source).map_err(|_| invalid_fixture())?;
    let rows = fixture
        .get("path")
        .and_then(toml::Value::as_array)
        .ok_or_else(invalid_fixture)?;
    if rows.len() != 6 {
        return Err(invalid_fixture());
    }
    let mut claim_path = [[0_u8; 32]; 6];
    for (destination, row) in claim_path.iter_mut().zip(rows) {
        let row_values = row.as_array().ok_or_else(invalid_fixture)?;
        if row_values.len() != 32 {
            return Err(invalid_fixture());
        }
        for (byte, value) in destination.iter_mut().zip(row_values) {
            let integer = value.as_integer().ok_or_else(invalid_fixture)?;
            *byte = u8::try_from(integer).map_err(|_| invalid_fixture())?;
        }
    }
    let private_persona = if mode == PersonaCredentialEvidenceClaimMode::PrivateOneTime {
        Some(PersonaCredentialEvidencePrivatePersonaAuthorization {
            persona_x: array(&fixture, "pk_persona_x")?,
            persona_y: array(&fixture, "pk_persona_y")?,
            persona_token_authorization_signature: array(&fixture, "persona_token_auth_sig")?,
        })
    } else {
        None
    };
    Ok(PersonaCredentialEvidenceV1ClaimInputs {
        mode,
        public_inputs: PersonaCredentialEvidenceV1ClaimPublicInputs {
            issuer_x: array(&fixture, "pk_issuer_x")?,
            issuer_y: array(&fixture, "pk_issuer_y")?,
            holder_x: array(&fixture, "holder_x")?,
            holder_y: array(&fixture, "holder_y")?,
            token_nonce: array(&fixture, "token_nonce")?,
            prepared_from: unsigned(&fixture, "prepared_from")?,
            prepared_until: unsigned(&fixture, "prepared_until")?,
            credential_binding: array(&fixture, "credential_binding")?,
            value_length: u32::try_from(unsigned(&fixture, "val_len")?)
                .map_err(|_| invalid_fixture())?,
            value: array(&fixture, "val_pub")?,
            claim_name_hash: array(&fixture, "name_hash")?,
        },
        private_inputs: SecretInputs::new(PersonaCredentialEvidenceV1ClaimPrivateInputs {
            envelope_hash: array(&fixture, "envelope_hash")?,
            claims_root: array(&fixture, "merkle_root")?,
            issuer_subject_binding_signature: array(&fixture, "issuer_subject_bind_sig")?,
            subject_x: array(&fixture, "pk_subject_x")?,
            subject_y: array(&fixture, "pk_subject_y")?,
            subject_persona_link_signature: array(&fixture, "subject_link_sig")?,
            private_persona,
            claim_salt: array(&fixture, "salt")?,
            claim_index: u32::try_from(unsigned(&fixture, "index")?)
                .map_err(|_| invalid_fixture())?,
            path_length: match path_length_override {
                Some(path_length) => path_length,
                None => {
                    u32::try_from(unsigned(&fixture, "path_len")?).map_err(|_| invalid_fixture())?
                }
            },
            path: claim_path,
        }),
    })
}

#[test]
fn prepared_claim_rejects_incorrect_mode_and_value_bounds() -> Result<(), WitnessError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let circuit =
        repository.join("circuits/sha256/families/persona_credential_evidence_v1/public_claim");
    let mut inputs = fixture_inputs(
        &circuit.join("Prover.toml"),
        PersonaCredentialEvidenceClaimMode::Public,
    )?;
    validate_inputs(&inputs)?;
    let artifact = CompiledProgramArtifactJson::try_from_bytes(b"{}")?;
    assert_eq!(
        generate_witness_from_artifact_json(artifact, &inputs)
            .err()
            .map(|error| error.reason),
        Some(WitnessErrorReason::ArtifactJsonInvalid),
    );
    inputs.mode = PersonaCredentialEvidenceClaimMode::PrivateOneTime;
    assert_eq!(
        validate_inputs(&inputs).err().map(|error| error.reason),
        Some(WitnessErrorReason::PreparedClaimInputOutOfRange),
    );
    inputs.mode = PersonaCredentialEvidenceClaimMode::Public;
    inputs.public_inputs.value[63] = 1;
    assert_eq!(
        validate_inputs(&inputs).err().map(|error| error.reason),
        Some(WitnessErrorReason::PreparedClaimInputOutOfRange),
    );
    inputs.public_inputs.value[63] = 0;
    inputs.public_inputs.token_nonce = [0; 32];
    assert_eq!(
        validate_inputs(&inputs).err().map(|error| error.reason),
        Some(WitnessErrorReason::PreparedClaimInputOutOfRange),
    );
    let private_circuit =
        repository.join("circuits/sha256/families/persona_credential_evidence_v1/private_claim");
    let mut private_inputs = fixture_inputs(
        &private_circuit.join("Prover.toml"),
        PersonaCredentialEvidenceClaimMode::PrivateOneTime,
    )?;
    validate_inputs(&private_inputs)?;
    private_inputs.mode = PersonaCredentialEvidenceClaimMode::Public;
    assert_eq!(
        validate_inputs(&private_inputs)
            .err()
            .map(|error| error.reason),
        Some(WitnessErrorReason::PreparedClaimInputOutOfRange),
    );
    Ok(())
}

#[test]
fn prepared_claim_requires_the_fixed_claim_tree_depth() -> Result<(), WitnessError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (name, mode) in [
        ("public_claim", PersonaCredentialEvidenceClaimMode::Public),
        (
            "private_claim",
            PersonaCredentialEvidenceClaimMode::PrivateOneTime,
        ),
    ] {
        let circuit = repository
            .join("circuits/sha256/families/persona_credential_evidence_v1")
            .join(name);
        let fixture = circuit.join("Prover.toml");
        let inputs = fixture_inputs(&fixture, mode)?;
        assert_eq!(inputs.private_inputs.expose().path_length, 6);
        validate_inputs(&inputs)?;
        for rejected in [0_u32, 1, 5, 7] {
            let inputs = fixture_inputs_with_path_length(&fixture, mode, Some(rejected))?;
            assert_eq!(
                validate_inputs(&inputs).err().map(|error| error.reason),
                Some(WitnessErrorReason::PreparedClaimInputOutOfRange),
            );
            // The rejection happens before the artifact is even parsed.
            let artifact = CompiledProgramArtifactJson::try_from_bytes(b"{}")?;
            assert_eq!(
                generate_witness_from_artifact_json(artifact, &inputs)
                    .err()
                    .map(|error| error.reason),
                Some(WitnessErrorReason::PreparedClaimInputOutOfRange),
            );
        }
        let inputs = fixture_inputs_with_path_length(&fixture, mode, Some(6))?;
        validate_inputs(&inputs)?;
    }
    Ok(())
}

// The linked prepared-proof script runs this only after compiling and
// executing all four claim packages with the pinned Noir toolchain.
#[test]
#[ignore = "requires compiled pinned Noir persona credential evidence claim fixtures"]
fn compiled_prepared_claim_witness_matches_noir_in_both_lanes() -> Result<(), WitnessError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for lane in ["sha256", "poseidon2"] {
        for (name, mode) in [
            ("public_claim", PersonaCredentialEvidenceClaimMode::Public),
            (
                "private_claim",
                PersonaCredentialEvidenceClaimMode::PrivateOneTime,
            ),
        ] {
            let circuit = repository
                .join("circuits")
                .join(lane)
                .join("families/persona_credential_evidence_v1")
                .join(name);
            let program_name = format!("credential_persona_credential_evidence_v1_{name}_{lane}");
            let artifact_bytes =
                fs::read(circuit.join("target").join(format!("{program_name}.json")))
                    .map_err(|_| WitnessError::new(WitnessErrorReason::ArtifactEmpty))?;
            let retained_bytes = fs::read(
                circuit.join("target").join(format!("{program_name}.gz")),
            )
            .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?;
            let inputs = fixture_inputs(&circuit.join("Prover.toml"), mode)?;
            let artifact = CompiledProgramArtifactJson::try_from_bytes(&artifact_bytes)?;
            let produced = generate_witness_from_artifact_json(artifact, &inputs)?;
            let expected = WitnessStack::<FieldElement>::deserialize(&retained_bytes)
                .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?;
            let actual = WitnessStack::<FieldElement>::deserialize(produced.as_bytes())
                .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?;
            // A parity failure must never log the witness or private opening.
            if actual != expected {
                return Err(WitnessError::new(WitnessErrorReason::ArtifactAbiMismatch));
            }
        }
    }
    Ok(())
}
