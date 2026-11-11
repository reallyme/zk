// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use buffa::Message;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use sha2::{Digest as _, Sha256};

use super::fields::ProverFields;
use super::proto_json::stage_proto_json;
use super::{
    FixtureCredentialHashAlgorithm, FixtureError, PROFILE_CREDENTIAL_SUBJECT_CLAIM,
    PROFILE_PRIVATE_PERSONA, STAGE_CLAIM, STAGE_CREDENTIAL_ENVELOPE, STAGE_CREDENTIAL_ROOT,
    STAGE_SESSION,
};

pub(super) struct DemoVector {
    file_stem: &'static str,
    flat_json: Vec<u8>,
    protobuf: Vec<u8>,
}

pub(super) fn build_vectors(root: &Path) -> Result<Vec<DemoVector>, FixtureError> {
    let mut vectors = Vec::new();
    for credential_hash_algorithm in FixtureCredentialHashAlgorithm::ALL {
        for profile in [PROFILE_CREDENTIAL_SUBJECT_CLAIM, PROFILE_PRIVATE_PERSONA] {
            for stage in [
                STAGE_SESSION,
                STAGE_CREDENTIAL_ENVELOPE,
                STAGE_CREDENTIAL_ROOT,
                STAGE_CLAIM,
            ] {
                vectors.push(build_vector(
                    root,
                    credential_hash_algorithm,
                    profile,
                    stage,
                )?);
            }
        }
    }
    Ok(vectors)
}

pub(super) fn write_vectors(root: &Path, vectors: &[DemoVector]) -> Result<(), FixtureError> {
    let vector_root = vector_root(root);
    fs::create_dir_all(&vector_root).map_err(|_| FixtureError::Io)?;
    let mut manifest = String::from("sha256  bytes  file\n");
    for vector in vectors {
        let json_path = vector_root.join(format_file_name(vector.file_stem, "json")?);
        let pb_path = vector_root.join(format_file_name(vector.file_stem, "pb")?);
        fs::write(&json_path, &vector.flat_json).map_err(|_| FixtureError::Io)?;
        fs::write(&pb_path, &vector.protobuf).map_err(|_| FixtureError::Io)?;
        append_manifest_line(&mut manifest, vector.file_stem, &vector.protobuf)?;
    }
    fs::write(vector_root.join("SHA256SUMS"), manifest).map_err(|_| FixtureError::Io)?;
    stage_swift_resources(root, vectors)
}

pub(super) fn check_vectors(root: &Path, vectors: &[DemoVector]) -> Result<(), FixtureError> {
    let vector_root = vector_root(root);
    check_expected_files(&vector_root, &expected_vector_file_names(vectors)?)?;
    let mut manifest = String::from("sha256  bytes  file\n");
    for vector in vectors {
        let json_path = vector_root.join(format_file_name(vector.file_stem, "json")?);
        let pb_path = vector_root.join(format_file_name(vector.file_stem, "pb")?);
        let existing_json = fs::read(json_path).map_err(|_| FixtureError::Io)?;
        let existing_pb = fs::read(pb_path).map_err(|_| FixtureError::Io)?;
        if existing_json != vector.flat_json || existing_pb != vector.protobuf {
            return Err(FixtureError::FixtureMismatch);
        }
        append_manifest_line(&mut manifest, vector.file_stem, &vector.protobuf)?;
    }
    let existing_manifest =
        fs::read(vector_root.join("SHA256SUMS")).map_err(|_| FixtureError::Io)?;
    if existing_manifest != manifest.as_bytes() {
        return Err(FixtureError::FixtureMismatch);
    }
    check_swift_resources(root, vectors)
}

fn build_vector(
    root: &Path,
    credential_hash_algorithm: FixtureCredentialHashAlgorithm,
    profile: &'static str,
    stage: &'static str,
) -> Result<DemoVector, FixtureError> {
    let fields = ProverFields::read(root, credential_hash_algorithm, profile, stage)?;
    let flat_json = fields.flat_json()?;
    let proto_json = stage_proto_json(profile, stage, &fields)?;
    let message: pb::ZkStageWitnessInput =
        serde_json::from_value(proto_json).map_err(|_| FixtureError::Decode)?;
    let mut protobuf = message.encode_to_vec();
    if protobuf.is_empty() {
        return Err(FixtureError::Encode);
    }
    let file_stem = file_stem(credential_hash_algorithm, profile, stage)?;
    protobuf.shrink_to_fit();
    Ok(DemoVector {
        file_stem,
        flat_json,
        protobuf,
    })
}

fn stage_swift_resources(root: &Path, vectors: &[DemoVector]) -> Result<(), FixtureError> {
    let resource_root =
        root.join("packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo/Resources/flow_inputs");
    fs::create_dir_all(&resource_root).map_err(|_| FixtureError::Io)?;
    for vector in vectors {
        let target = resource_root.join(format_file_name(vector.file_stem, "pb")?);
        fs::write(target, &vector.protobuf).map_err(|_| FixtureError::Io)?;
    }
    fs::write(resource_root.join("SHA256SUMS"), swift_manifest(vectors)?)
        .map_err(|_| FixtureError::Io)
}

fn check_swift_resources(root: &Path, vectors: &[DemoVector]) -> Result<(), FixtureError> {
    let resource_root =
        root.join("packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo/Resources/flow_inputs");
    check_expected_files(&resource_root, &expected_swift_file_names(vectors)?)?;
    for vector in vectors {
        let target = resource_root.join(format_file_name(vector.file_stem, "pb")?);
        let existing = fs::read(target).map_err(|_| FixtureError::Io)?;
        if existing != vector.protobuf {
            return Err(FixtureError::FixtureMismatch);
        }
    }
    let existing_manifest =
        fs::read(resource_root.join("SHA256SUMS")).map_err(|_| FixtureError::Io)?;
    if existing_manifest != swift_manifest(vectors)?.as_bytes() {
        return Err(FixtureError::FixtureMismatch);
    }
    Ok(())
}

fn check_expected_files(path: &Path, expected: &[String]) -> Result<(), FixtureError> {
    let entries = fs::read_dir(path).map_err(|_| FixtureError::Io)?;
    let expected_names: BTreeMap<&str, ()> =
        expected.iter().map(|name| (name.as_str(), ())).collect();
    for entry in entries {
        let entry = entry.map_err(|_| FixtureError::Io)?;
        let file_type = entry.file_type().map_err(|_| FixtureError::Io)?;
        if !file_type.is_file() {
            return Err(FixtureError::FixtureMismatch);
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            return Err(FixtureError::FixtureMismatch);
        };
        if !expected_names.contains_key(name) {
            return Err(FixtureError::FixtureMismatch);
        }
    }
    Ok(())
}

fn expected_vector_file_names(vectors: &[DemoVector]) -> Result<Vec<String>, FixtureError> {
    let mut names = Vec::with_capacity(
        vectors
            .len()
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or(FixtureError::Encode)?,
    );
    for vector in vectors {
        names.push(format_file_name(vector.file_stem, "json")?);
        names.push(format_file_name(vector.file_stem, "pb")?);
    }
    names.push(String::from("SHA256SUMS"));
    Ok(names)
}

fn expected_swift_file_names(vectors: &[DemoVector]) -> Result<Vec<String>, FixtureError> {
    let mut names = Vec::with_capacity(vectors.len().checked_add(1).ok_or(FixtureError::Encode)?);
    for vector in vectors {
        names.push(format_file_name(vector.file_stem, "pb")?);
    }
    names.push(String::from("SHA256SUMS"));
    Ok(names)
}

fn append_manifest_line(
    manifest: &mut String,
    file_stem: &str,
    protobuf: &[u8],
) -> Result<(), FixtureError> {
    let digest = hex_sha256(protobuf);
    let length = protobuf.len();
    manifest.push_str(&digest);
    manifest.push_str("  ");
    manifest.push_str(&length.to_string());
    manifest.push_str("  ");
    manifest.push_str(&format_file_name(file_stem, "pb")?);
    manifest.push('\n');
    Ok(())
}

fn swift_manifest(vectors: &[DemoVector]) -> Result<String, FixtureError> {
    let mut manifest = String::from("sha256  bytes  file\n");
    for vector in vectors {
        append_manifest_line(&mut manifest, vector.file_stem, &vector.protobuf)?;
    }
    Ok(manifest)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0f);
        out.push(char::from(HEX[high]));
        out.push(char::from(HEX[low]));
    }
    out
}

fn vector_root(root: &Path) -> PathBuf {
    root.join("vectors/demo-flow-inputs/v1")
}

fn file_stem(
    credential_hash_algorithm: FixtureCredentialHashAlgorithm,
    profile: &'static str,
    stage: &'static str,
) -> Result<&'static str, FixtureError> {
    match (credential_hash_algorithm, profile, stage) {
        (
            FixtureCredentialHashAlgorithm::Sha256,
            PROFILE_CREDENTIAL_SUBJECT_CLAIM,
            STAGE_SESSION,
        ) => Ok("sha256_flow_credential_subject_claim_v1_session_inputs"),
        (
            FixtureCredentialHashAlgorithm::Sha256,
            PROFILE_CREDENTIAL_SUBJECT_CLAIM,
            STAGE_CREDENTIAL_ENVELOPE,
        ) => Ok("sha256_flow_credential_subject_claim_v1_credential_envelope_inputs"),
        (
            FixtureCredentialHashAlgorithm::Sha256,
            PROFILE_CREDENTIAL_SUBJECT_CLAIM,
            STAGE_CREDENTIAL_ROOT,
        ) => Ok("sha256_flow_credential_subject_claim_v1_credential_root_inputs"),
        (FixtureCredentialHashAlgorithm::Sha256, PROFILE_CREDENTIAL_SUBJECT_CLAIM, STAGE_CLAIM) => {
            Ok("sha256_flow_credential_subject_claim_v1_claim_inputs")
        }
        (FixtureCredentialHashAlgorithm::Sha256, PROFILE_PRIVATE_PERSONA, STAGE_SESSION) => {
            Ok("sha256_flow_private_persona_claim_v1_session_inputs")
        }
        (
            FixtureCredentialHashAlgorithm::Sha256,
            PROFILE_PRIVATE_PERSONA,
            STAGE_CREDENTIAL_ENVELOPE,
        ) => Ok("sha256_flow_private_persona_claim_v1_credential_envelope_inputs"),
        (
            FixtureCredentialHashAlgorithm::Sha256,
            PROFILE_PRIVATE_PERSONA,
            STAGE_CREDENTIAL_ROOT,
        ) => Ok("sha256_flow_private_persona_claim_v1_credential_root_inputs"),
        (FixtureCredentialHashAlgorithm::Sha256, PROFILE_PRIVATE_PERSONA, STAGE_CLAIM) => {
            Ok("sha256_flow_private_persona_claim_v1_claim_inputs")
        }
        (
            FixtureCredentialHashAlgorithm::Poseidon2,
            PROFILE_CREDENTIAL_SUBJECT_CLAIM,
            STAGE_SESSION,
        ) => Ok("poseidon2_flow_credential_subject_claim_v1_session_inputs"),
        (
            FixtureCredentialHashAlgorithm::Poseidon2,
            PROFILE_CREDENTIAL_SUBJECT_CLAIM,
            STAGE_CREDENTIAL_ENVELOPE,
        ) => Ok("poseidon2_flow_credential_subject_claim_v1_credential_envelope_inputs"),
        (
            FixtureCredentialHashAlgorithm::Poseidon2,
            PROFILE_CREDENTIAL_SUBJECT_CLAIM,
            STAGE_CREDENTIAL_ROOT,
        ) => Ok("poseidon2_flow_credential_subject_claim_v1_credential_root_inputs"),
        (
            FixtureCredentialHashAlgorithm::Poseidon2,
            PROFILE_CREDENTIAL_SUBJECT_CLAIM,
            STAGE_CLAIM,
        ) => Ok("poseidon2_flow_credential_subject_claim_v1_claim_inputs"),
        (FixtureCredentialHashAlgorithm::Poseidon2, PROFILE_PRIVATE_PERSONA, STAGE_SESSION) => {
            Ok("poseidon2_flow_private_persona_claim_v1_session_inputs")
        }
        (
            FixtureCredentialHashAlgorithm::Poseidon2,
            PROFILE_PRIVATE_PERSONA,
            STAGE_CREDENTIAL_ENVELOPE,
        ) => Ok("poseidon2_flow_private_persona_claim_v1_credential_envelope_inputs"),
        (
            FixtureCredentialHashAlgorithm::Poseidon2,
            PROFILE_PRIVATE_PERSONA,
            STAGE_CREDENTIAL_ROOT,
        ) => Ok("poseidon2_flow_private_persona_claim_v1_credential_root_inputs"),
        (FixtureCredentialHashAlgorithm::Poseidon2, PROFILE_PRIVATE_PERSONA, STAGE_CLAIM) => {
            Ok("poseidon2_flow_private_persona_claim_v1_claim_inputs")
        }
        _ => Err(FixtureError::MissingField),
    }
}

fn format_file_name(file_stem: &str, extension: &str) -> Result<String, FixtureError> {
    let capacity = file_stem
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(extension.len()))
        .ok_or(FixtureError::Encode)?;
    let mut name = String::with_capacity(capacity);
    name.push_str(file_stem);
    name.push('.');
    name.push_str(extension);
    Ok(name)
}
