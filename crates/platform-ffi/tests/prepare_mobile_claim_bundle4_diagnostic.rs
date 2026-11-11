// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prepares opt-in mobile assets for the `claim_bundle_4` peak-memory lane.
//!
//! The generated request is canonical protobuf transport, and the exact-source
//! tree contains only the reviewed largest `claim_bundle_4` source closure plus
//! the verification artifacts required by the diagnostic resolver.

#![cfg(feature = "diagnostic-exact-source")]

use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::ZkError,
    proofs::{ZkDecodedPublicInputs, ZkProofSuite, ZkPublicInputs, ZkSessionBinding, ZkWitness},
};
use reallyme_zk_backend_bb::BarretenbergPublicInputCodec;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_release_process::{
    normalize_modern_compiled_program_artifact, MAX_COMPILED_PROGRAM_ARTIFACT_BYTES,
};

const OUTPUT_ROOT_ENV: &str = "REALLYME_ZK_CLAIM_BUNDLE4_DIAGNOSTIC_ASSET_ROOT";
const LEGACY_ANDROID_OUTPUT_ROOT_ENV: &str =
    "REALLYME_ZK_ANDROID_CLAIM_BUNDLE4_DIAGNOSTIC_ASSET_ROOT";
const CIRCUITS_ROOT_ENV: &str = "REALLYME_ZK_ALL_CIRCUITS_V1_ROOT";
const DIAGNOSTIC_ASSET_ROOT: &str = "diagnostic_claim_bundle4";
const EXACT_SOURCE_ROOT: &str = "exact_source";
const REQUEST_FILE: &str = "prove_request.pb";
const METADATA_FILE: &str = "metadata.tsv";
const PUBLIC_INPUTS_FILE: &str = "public_inputs.compact";
const SOURCE_LOCK_FILE: &str = "modern-circuit-source-lock.tsv";
const TARGET_RUN: &str = "modern-run-01";

#[test]
#[ignore = "writes mobile diagnostic assets for the opt-in claim_bundle_4 device lane"]
fn prepare_mobile_claim_bundle4_diagnostic_assets() -> Result<(), FixtureError> {
    let repo_root = repo_root()?;
    let circuits_root = env::var_os(CIRCUITS_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join("circuits"));
    let output_root = required_path(OUTPUT_ROOT_ENV)?;
    let circuit_ref = largest_reviewed_claim_bundle4_ref();

    let asset_root = output_root.join(DIAGNOSTIC_ASSET_ROOT);
    if asset_root.exists() {
        fs::remove_dir_all(&asset_root)?;
    }
    fs::create_dir_all(&asset_root)?;

    stage_exact_source(
        &circuits_root,
        &asset_root.join(EXACT_SOURCE_ROOT),
        circuit_ref,
    )?;
    let compact_public_inputs = public_inputs(&circuits_root, circuit_ref)?;
    let binding = binding_for(circuit_ref, &compact_public_inputs)?;
    let witness = witness(&circuits_root, circuit_ref)?;
    let request = prove_request(circuit_ref, witness, compact_public_inputs, binding)?;
    let request_bytes = encode_request(&request)?;
    fs::write(asset_root.join(REQUEST_FILE), request_bytes.as_slice())?;
    fs::write(
        asset_root.join(PUBLIC_INPUTS_FILE),
        public_inputs(&circuits_root, circuit_ref)?.as_bytes(),
    )?;
    write_metadata(
        asset_root.join(METADATA_FILE).as_path(),
        circuit_ref,
        request_bytes.len(),
    )?;

    Ok(())
}

fn repo_root() -> Result<PathBuf, FixtureError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or(FixtureError::InvalidPath)
}

fn required_path(name: &str) -> Result<PathBuf, FixtureError> {
    env::var_os(name)
        .or_else(|| env::var_os(LEGACY_ANDROID_OUTPUT_ROOT_ENV))
        .map(PathBuf::from)
        .ok_or(FixtureError::MissingEnvironment)
}

fn largest_reviewed_claim_bundle4_ref() -> ZkCircuitRef {
    ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCircuitFamily::PrivatePersonaClaimV1,
        ZkCircuitStage::ClaimBundle4,
    )
}

fn stage_exact_source(
    circuits_root: &Path,
    exact_root: &Path,
    circuit_ref: ZkCircuitRef,
) -> Result<(), FixtureError> {
    fs::create_dir_all(exact_root)?;
    copy_file(
        circuits_root.join(SOURCE_LOCK_FILE).as_path(),
        exact_root.join(SOURCE_LOCK_FILE).as_path(),
    )?;
    copy_source_tree(
        circuits_root,
        circuit_source_dir(circuit_ref).as_path(),
        exact_root,
    )?;
    let vendor_dir = circuits_root.join("vendor");
    if vendor_dir.is_dir() {
        copy_source_tree(circuits_root, Path::new("vendor"), exact_root)?;
    }

    let source_target = circuits_root
        .join(circuit_source_dir(circuit_ref))
        .join("target");
    let target = exact_root
        .join(circuit_source_dir(circuit_ref))
        .join("target");
    fs::create_dir_all(target.join(TARGET_RUN))?;
    let package = package_json(&source_target)?;
    // Diagnostic identities must survive a different checkout path or host.
    // Use the release normalizer before hashing or shipping compiler metadata.
    let maximum = u64::try_from(MAX_COMPILED_PROGRAM_ARTIFACT_BYTES)
        .map_err(|_| FixtureError::MessageTooLarge)?;
    let read_limit = maximum
        .checked_add(1)
        .ok_or(FixtureError::MessageTooLarge)?;
    let mut program = Vec::new();
    fs::File::open(&package)?
        .take(read_limit)
        .read_to_end(&mut program)?;
    if program.len() > MAX_COMPILED_PROGRAM_ARTIFACT_BYTES {
        return Err(FixtureError::MessageTooLarge);
    }
    let normalized = normalize_modern_compiled_program_artifact(&program)
        .map_err(|_| FixtureError::MalformedProgram)?;
    fs::write(target.join(file_name(package.as_path())?), normalized)?;
    copy_file(
        source_target.join(TARGET_RUN).join("vk").as_path(),
        target.join(TARGET_RUN).join("vk").as_path(),
    )?;
    Ok(())
}

fn copy_source_tree(
    root: &Path,
    relative_dir: &Path,
    target_root: &Path,
) -> Result<(), FixtureError> {
    let source_dir = root.join(relative_dir);
    for entry in fs::read_dir(source_dir.as_path())? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| FixtureError::InvalidPath)?;
        if file_type.is_dir() {
            if !contains_component(relative, "target") {
                copy_source_tree(root, relative, target_root)?;
            }
            continue;
        }
        if !file_type.is_file() || contains_component(relative, "target") || !is_noir_source(&path)
        {
            continue;
        }
        copy_file(path.as_path(), target_root.join(relative).as_path())?;
    }
    Ok(())
}

fn is_noir_source(path: &Path) -> bool {
    path.file_name().and_then(|value| value.to_str()) == Some("Nargo.toml")
        || path.extension().and_then(|value| value.to_str()) == Some("nr")
}

fn contains_component(path: &Path, component: &str) -> bool {
    path.components()
        .any(|value| value.as_os_str().to_string_lossy() == component)
}

fn copy_file(source: &Path, target: &Path) -> Result<(), FixtureError> {
    let parent = target.parent().ok_or(FixtureError::InvalidPath)?;
    fs::create_dir_all(parent)?;
    fs::copy(source, target)?;
    Ok(())
}

fn package_json(target_dir: &Path) -> Result<PathBuf, FixtureError> {
    let mut found = None;
    for entry in fs::read_dir(target_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        if found.is_some() {
            return Err(FixtureError::AmbiguousArtifact);
        }
        found = Some(path);
    }
    found.ok_or(FixtureError::MissingArtifact)
}

fn file_name(path: &Path) -> Result<&std::ffi::OsStr, FixtureError> {
    path.file_name().ok_or(FixtureError::InvalidPath)
}

fn public_inputs(
    circuits_root: &Path,
    circuit_ref: ZkCircuitRef,
) -> Result<ZkPublicInputs, FixtureError> {
    let serialized = fs::read(
        circuits_root
            .join(circuit_source_dir(circuit_ref))
            .join("target")
            .join(TARGET_RUN)
            .join("public_inputs"),
    )?;
    Ok(BarretenbergPublicInputCodec::decode(
        circuit_ref,
        serialized.as_slice(),
    )?)
}

fn binding_for(
    circuit_ref: ZkCircuitRef,
    public_inputs: &ZkPublicInputs,
) -> Result<ZkSessionBinding, FixtureError> {
    let decoded = ZkDecodedPublicInputs::try_decode(circuit_ref, public_inputs)?;
    Ok(ZkSessionBinding {
        nonce_hash: decoded.challenge(),
        audience_hash: decoded.audience_hash(),
        transaction_data_hash: decoded.transaction_data_hash(),
    })
}

fn witness(circuits_root: &Path, circuit_ref: ZkCircuitRef) -> Result<ZkWitness, FixtureError> {
    let package = package_json(
        circuits_root
            .join(circuit_source_dir(circuit_ref))
            .join("target")
            .as_path(),
    )?;
    let mut witness_path = package;
    witness_path.set_extension("gz");
    let bytes = fs::read(witness_path)?;
    Ok(ZkWitness::try_from_noir_witness_stack_v1(
        circuit_ref,
        bytes,
    )?)
}

fn prove_request(
    circuit_ref: ZkCircuitRef,
    witness: ZkWitness,
    public_inputs: ZkPublicInputs,
    binding: ZkSessionBinding,
) -> Result<pb::ZkProviderOperationRequest, FixtureError> {
    Ok(pb::ZkProviderOperationRequest {
        operation: Some(pb::zk_provider_operation_request::Operation::ProveStage(
            Box::new(pb::ZkStageProveOperation {
                circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
                witness: MessageField::some(pb::ZkWitness {
                    encoded: witness.expose_bytes().to_vec(),
                    circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
                    encoding: EnumValue::from(
                        pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1,
                    ),
                    __buffa_unknown_fields: Default::default(),
                }),
                public_inputs: MessageField::some(pb::ZkPublicInputs {
                    encoded: public_inputs.as_bytes().to_vec(),
                    __buffa_unknown_fields: Default::default(),
                }),
                session_binding: MessageField::some(session_binding_to_proto(binding)),
                proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
                witness_handle: MessageField::none(),
                __buffa_unknown_fields: Default::default(),
            }),
        )),
        __buffa_unknown_fields: Default::default(),
    })
}

fn encode_request(
    request: &pb::ZkProviderOperationRequest,
) -> Result<zeroize::Zeroizing<Vec<u8>>, FixtureError> {
    let encoded_len = request
        .try_encoded_len()
        .map_err(|_| FixtureError::MessageTooLarge)?;
    let mut encoded = zeroize::Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(usize::try_from(encoded_len).map_err(|_| FixtureError::MessageTooLarge)?)
        .map_err(|_| FixtureError::MessageTooLarge)?;
    request
        .try_encode_bounded(encoded_len, &mut *encoded)
        .map_err(|_| FixtureError::MessageTooLarge)?;
    Ok(encoded)
}

fn write_metadata(
    path: &Path,
    circuit_ref: ZkCircuitRef,
    request_bytes: usize,
) -> Result<(), FixtureError> {
    fs::write(
        path,
        format!(
            "key\tvalue\ncircuit\t{}\nrequest_bytes\t{}\n",
            circuit_name(circuit_ref),
            request_bytes
        ),
    )?;
    Ok(())
}

fn circuit_ref_to_proto(circuit_ref: ZkCircuitRef) -> pb::ZkCircuitRef {
    pb::ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm_to_proto(
            circuit_ref.credential_hash_algorithm,
        )),
        family: EnumValue::from(family_to_proto(circuit_ref.family)),
        stage: EnumValue::from(stage_to_proto(circuit_ref.stage)),
        circuit_revision: ZkCircuitRef::CURRENT_REVISION,
        __buffa_unknown_fields: Default::default(),
    }
}

fn credential_hash_algorithm_to_proto(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> pb::ZkCredentialHashAlgorithm {
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => {
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256
        }
        ZkCredentialHashAlgorithm::Poseidon2 => {
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2
        }
        _ => pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_UNSPECIFIED,
    }
}

fn family_to_proto(family: ZkCircuitFamily) -> pb::ZkCircuitFamily {
    match family {
        ZkCircuitFamily::CredentialSubjectClaimV1 => {
            pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1
        }
        ZkCircuitFamily::PrivatePersonaClaimV1 => {
            pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1
        }
        _ => pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_UNSPECIFIED,
    }
}

fn stage_to_proto(stage: ZkCircuitStage) -> pb::ZkCircuitStage {
    match stage {
        ZkCircuitStage::Session => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION,
        ZkCircuitStage::CredentialEnvelope => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE
        }
        ZkCircuitStage::CredentialRoot => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ROOT,
        ZkCircuitStage::Claim => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM,
        ZkCircuitStage::ClaimBundle4 => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM_BUNDLE_4,
        _ => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_UNSPECIFIED,
    }
}

fn proof_suite_to_proto(proof_suite: ZkProofSuite) -> pb::ZkProofSuite {
    match proof_suite {
        ZkProofSuite::BarretenbergUltraHonkPoseidon2ZkNoIpa => {
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_ZK_NO_IPA
        }
        ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa => {
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA
        }
        ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa => {
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_UNMASKED_NO_IPA
        }
        ZkProofSuite::BarretenbergUltraHonkKeccakUnmaskedNoIpa => {
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_UNMASKED_NO_IPA
        }
        _ => pb::ZkProofSuite::ZK_PROOF_SUITE_UNSPECIFIED,
    }
}

fn session_binding_to_proto(binding: ZkSessionBinding) -> pb::ZkSessionBinding {
    pb::ZkSessionBinding {
        nonce_hash: binding.nonce_hash.to_vec(),
        audience_hash: binding.audience_hash.to_vec(),
        transaction_data_hash: binding
            .transaction_data_hash
            .map_or_else(Vec::new, |value| value.to_vec()),
        __buffa_unknown_fields: Default::default(),
    }
}

fn circuit_source_dir(circuit_ref: ZkCircuitRef) -> PathBuf {
    PathBuf::from(circuit_ref.credential_hash_algorithm.source_dir())
        .join("families")
        .join(circuit_ref.family.source_dir())
        .join(circuit_ref.stage.source_dir())
}

fn circuit_name(circuit_ref: ZkCircuitRef) -> String {
    circuit_source_dir(circuit_ref)
        .to_string_lossy()
        .replace('\\', "/")
}

#[derive(Debug)]
enum FixtureError {
    AmbiguousArtifact,
    InvalidPath,
    MalformedProgram,
    MessageTooLarge,
    MissingArtifact,
    MissingEnvironment,
    Io,
    Zk,
}

impl From<io::Error> for FixtureError {
    fn from(_value: io::Error) -> Self {
        Self::Io
    }
}

impl From<ZkError> for FixtureError {
    fn from(_value: ZkError) -> Self {
        Self::Zk
    }
}
