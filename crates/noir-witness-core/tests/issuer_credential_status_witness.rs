// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Execute the production typed ABI against both compiled status circuits.

use std::path::Path;

use reallyme_zk_noir_witness_core::{
    circuits::common_credential_root_v1_issuer_credential_status::{
        generate_witness_from_artifact_json, CommonCredentialRootV1IssuerCredentialStatusInputs,
        CommonCredentialRootV1IssuerCredentialStatusPrivate,
        CommonCredentialRootV1IssuerCredentialStatusPublic,
    },
    CompiledProgramArtifactJson, SecretInputs,
};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
enum FixtureError {
    #[error("compiled circuit fixture is unavailable")]
    File,
    #[error("fixture has an invalid shape")]
    Shape,
    #[error("typed Noir witness rejected the fixture")]
    Witness,
}

#[derive(Deserialize)]
struct Fixture {
    challenge: Vec<u8>,
    audience_hash: Vec<u8>,
    transaction_data_hash: Vec<u8>,
    slot: PublicSlot,
    witness: PrivateWitness,
}

#[derive(Deserialize)]
struct PublicSlot {
    issuer_x: Vec<u8>,
    issuer_y: Vec<u8>,
    presentation_expiry: u64,
    credential_binding: Vec<u8>,
    status_root: Vec<u8>,
    status_length: u64,
    status_list_id: Vec<u8>,
    status_url_hash: Vec<u8>,
    status_purpose: u8,
    verifier_now: u64,
}

#[derive(Deserialize)]
struct PrivateWitness {
    envelope_hash: Vec<u8>,
    claims_root: Vec<u8>,
    issuer_validity_status_signature: Vec<u8>,
    valid_from: u64,
    valid_until: u64,
    status_index: u64,
    status_chunk: Vec<u8>,
    path_len: u32,
    path: Vec<Vec<u8>>,
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], FixtureError> {
    value.try_into().map_err(|_| FixtureError::Shape)
}

fn inputs(
    fixture: Fixture,
) -> Result<CommonCredentialRootV1IssuerCredentialStatusInputs, FixtureError> {
    let slot = fixture.slot;
    let witness = fixture.witness;
    let path = witness
        .path
        .into_iter()
        .map(fixed::<32>)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| FixtureError::Shape)?;
    Ok(CommonCredentialRootV1IssuerCredentialStatusInputs {
        public_inputs: CommonCredentialRootV1IssuerCredentialStatusPublic {
            challenge: fixed(fixture.challenge)?,
            audience_hash: fixed(fixture.audience_hash)?,
            transaction_data_hash: fixed(fixture.transaction_data_hash)?,
            issuer_x: fixed(slot.issuer_x)?,
            issuer_y: fixed(slot.issuer_y)?,
            presentation_expiry: slot.presentation_expiry,
            credential_binding: fixed(slot.credential_binding)?,
            status_root: fixed(slot.status_root)?,
            status_length: slot.status_length,
            status_list_id: fixed(slot.status_list_id)?,
            status_url_hash: fixed(slot.status_url_hash)?,
            status_purpose: slot.status_purpose,
            verifier_now: slot.verifier_now,
        },
        private_inputs: SecretInputs::new(CommonCredentialRootV1IssuerCredentialStatusPrivate {
            envelope_hash: fixed(witness.envelope_hash)?,
            claims_root: fixed(witness.claims_root)?,
            issuer_validity_status_signature: fixed(witness.issuer_validity_status_signature)?,
            valid_from: witness.valid_from,
            valid_until: witness.valid_until,
            status_index: witness.status_index,
            status_chunk: fixed(witness.status_chunk)?,
            path_length: witness.path_len,
            path,
        }),
    })
}

#[test]
#[ignore = "requires nargo compile of both pinned issuer-status circuits"]
fn typed_witness_executes_both_hash_lanes() -> Result<(), FixtureError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../circuits");
    for (lane, artifact_name) in [
        (
            "sha256",
            "credential_common_credential_root_v1_issuer_credential_status_sha256",
        ),
        (
            "poseidon2",
            "credential_common_credential_root_v1_issuer_credential_status_poseidon2",
        ),
    ] {
        let folder = root
            .join(lane)
            .join("families/common_credential_root_v1/issuer_credential_status");
        let source =
            std::fs::read_to_string(folder.join("Prover.toml")).map_err(|_| FixtureError::File)?;
        let fixture: Fixture = toml::from_str(&source).map_err(|_| FixtureError::Shape)?;
        let expired_at = fixture.witness.valid_until;
        let mut input = inputs(fixture)?;
        let artifact = std::fs::read(folder.join("target").join(format!("{artifact_name}.json")))
            .map_err(|_| FixtureError::File)?;
        let artifact = CompiledProgramArtifactJson::try_from_bytes(&artifact)
            .map_err(|_| FixtureError::Shape)?;
        let witness = generate_witness_from_artifact_json(artifact, &input)
            .map_err(|_| FixtureError::Witness)?;
        assert!(!witness.as_bytes().is_empty());
        input.public_inputs.verifier_now = expired_at;
        assert!(generate_witness_from_artifact_json(artifact, &input).is_err());
    }
    Ok(())
}
