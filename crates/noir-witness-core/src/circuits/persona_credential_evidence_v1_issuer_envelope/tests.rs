// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    generate_witness_from_artifact_json, validate_inputs,
    PersonaCredentialEvidenceV1IssuerEnvelopeInputs,
    PersonaCredentialEvidenceV1IssuerEnvelopePrivateInputs,
    PersonaCredentialEvidenceV1IssuerEnvelopePublicInputs,
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

fn fixture_inputs(
    path: &Path,
) -> Result<PersonaCredentialEvidenceV1IssuerEnvelopeInputs, WitnessError> {
    let source = fs::read_to_string(path).map_err(|_| fixture_error())?;
    let fixture: toml::Value = toml::from_str(&source).map_err(|_| fixture_error())?;
    let unsigned = |name: &str| -> Result<u64, WitnessError> {
        let integer = fixture
            .get(name)
            .and_then(toml::Value::as_integer)
            .ok_or_else(fixture_error)?;
        u64::try_from(integer).map_err(|_| fixture_error())
    };
    Ok(PersonaCredentialEvidenceV1IssuerEnvelopeInputs {
        public_inputs: PersonaCredentialEvidenceV1IssuerEnvelopePublicInputs {
            issuer_x: array(&fixture, "pk_issuer_x")?,
            issuer_y: array(&fixture, "pk_issuer_y")?,
            holder_x: array(&fixture, "holder_x")?,
            holder_y: array(&fixture, "holder_y")?,
            token_nonce: array(&fixture, "token_nonce")?,
            prepared_from: unsigned("prepared_from")?,
            prepared_until: unsigned("prepared_until")?,
            credential_binding: array(&fixture, "credential_binding")?,
        },
        private_inputs: SecretInputs::new(PersonaCredentialEvidenceV1IssuerEnvelopePrivateInputs {
            envelope_hash: array(&fixture, "envelope_hash")?,
            claims_root: array(&fixture, "claims_root")?,
            subject_x: array(&fixture, "pk_subject_x")?,
            subject_y: array(&fixture, "pk_subject_y")?,
            issuer_envelope_signature: array(&fixture, "issuer_envelope_sig")?,
            issuer_subject_binding_signature: array(&fixture, "issuer_subject_bind_sig")?,
        }),
    })
}

#[test]
fn rejects_empty_join_and_invalid_prepared_window() -> Result<(), WitnessError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture = root.join(
        "circuits/sha256/families/persona_credential_evidence_v1/issuer_envelope/Prover.toml",
    );
    let mut empty_nonce = fixture_inputs(&fixture)?;
    empty_nonce.public_inputs.token_nonce = [0; 32];
    let mut reversed_window = fixture_inputs(&fixture)?;
    reversed_window.public_inputs.prepared_until = reversed_window.public_inputs.prepared_from;
    for inputs in [empty_nonce, reversed_window] {
        assert_eq!(
            validate_inputs(&inputs).err().map(|error| error.reason),
            Some(WitnessErrorReason::PreparedClaimInputOutOfRange)
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires the pinned Nargo compiled persona-credential-evidence fixtures"]
fn compiled_issuer_envelope_witness_matches_noir_in_both_lanes() -> Result<(), WitnessError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for lane in ["sha256", "poseidon2"] {
        let circuit = repository
            .join("circuits")
            .join(lane)
            .join("families/persona_credential_evidence_v1/issuer_envelope");
        let name = format!("credential_persona_credential_evidence_v1_issuer_envelope_{lane}");
        let artifact_bytes = fs::read(circuit.join("target").join(format!("{name}.json")))
            .map_err(|_| WitnessError::new(WitnessErrorReason::ArtifactEmpty))?;
        let retained_bytes = fs::read(circuit.join("target").join(format!("{name}.gz")))
            .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?;
        // The linked runner executes PrivateJoined last for each lane, so its
        // retained stack is the exact comparator for this test.
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
