// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Packages cryptographically generated candidate proofs for mobile verifier examples.
//! These fixed requests exercise verification only; live presentations must be
//! regenerated for the verifier's active session and authenticated trust policy.

use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::decode_operation_request;
use thiserror::Error;

#[path = "generate_common_credential_root_mobile_fixtures/helpers.rs"]
mod helpers;

use helpers::{
    claim, field_byte, field_bytes32, field_u64, hex_bytes, hex_digest_bytes, key, read_nonempty,
    session_manifest_identity,
};

const REQUEST_TIME_UNIX: u64 = 1_900_000_000;
const STATUS_VALIDATION_MAX_AGE_SECONDS: u64 = 120;
const CHALLENGE: &str = "079218fa88fc77937eabd22a503fcbc388214e8a57b15d7094d139c3735f085f";
const AUDIENCE: &str = "4014008db00389b6cd1b90155ab0a04f3d7de8499d78711ad16c590ab60c6733";
const TRANSACTION: &str = "540f76b8e8e352e49fe0e4e3aa0ae642c56266ccc3043feaba7c6bbed282acc2";
const ASSURANCE_POLICY: &str = "ad1927afb41bd21ab87899732707f7c8aa5a75d97f4a43457cbc5f846095321d";
const STATUS_ROOT: &str = "b2079dd0ae99debe99a236712b550503afcd60eab87c7cdec364dc6152e02feb";
const SIGNER_X: &str = "8e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3";
const SIGNER_Y: &str = "73eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4";
const UNIVERSITY_X: &str = "3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1";
const UNIVERSITY_Y: &str = "9099209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740";
const EMPLOYER_X: &str = "47776904c0f1cc3a9c0984b66f75301a5fa68678f0d64af8ba1abce34738a73e";
const EMPLOYER_Y: &str = "aa005ee6b5b957286231856577648e8381b2804428d5733f32f787ff71f1fcdc";
const UNIVERSITY_CLAIM: &str = "052daff789976063a34b2ff97e457d57474e6c86f6a0ab6b92dc574c23c5216b";
const EMPLOYER_CLAIM: &str = "971a3625e73d57a42c2ec6713264895ded73ce552ebb7617689a0daad97b9002";
const RETAINED_ARTIFACT_ROOT_ENV: &str = "REALLYME_ZK_RETAINED_ARTIFACT_ROOT";
const DEFAULT_RETAINED_ARTIFACT_RELATIVE_ROOT: &str =
    "release-artifacts/modern-v1-bb-6.0.0/mobile-demo-artifacts-persona-credential-evidence-v1-candidate";
const COMMON_CREDENTIAL_ROOT_IDENTITY_MANIFEST: &str =
    "vectors/common-credential-root-artifact-identities-v1.tsv";
const MAX_IDENTITY_MANIFEST_BYTES: u64 = 4 * 1024;
const EXPECTED_COMMON_CREDENTIAL_ROOT_IDENTITIES: usize = 14;
const RAW_FIELD_BYTES: usize = 32;
const ISSUER_STATUS_FIELD_COUNT: usize = 292;
type CommonCredentialRootIdentities = BTreeMap<String, [u8; 32]>;

#[derive(Debug, Error)]
enum FixtureError {
    #[error("fixture path or argument is invalid")]
    InvalidPath,
    #[error("fixture file is missing or cannot be read")]
    Io,
    #[error("fixture digest or proof shape does not match the reviewed candidate")]
    InvalidFixture,
    #[error("fixture protobuf request is not canonical or is rejected by the strict codec")]
    InvalidRequest,
}

impl FixtureError {
    const fn audit_message(&self) -> &'static [u8] {
        match self {
            Self::InvalidPath => b"error: fixture path or argument is invalid\n",
            Self::Io => b"error: fixture file is missing or cannot be read\n",
            Self::InvalidFixture => b"error: fixture material is invalid\n",
            Self::InvalidRequest => b"error: fixture request is invalid\n",
        }
    }
}

#[derive(Clone, Copy)]
struct CircuitProof {
    slot: pb::ZkCommonCredentialRootProofSlot,
    family: pb::ZkCircuitFamily,
    stage: pb::ZkCircuitStage,
    path: &'static str,
    identity: [u8; 32],
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = io::stderr().write_all(error.audit_message());
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), FixtureError> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let output = arguments.next().ok_or(FixtureError::InvalidPath)?;
    if arguments.next().is_some() {
        return Err(FixtureError::InvalidPath);
    }
    let output = PathBuf::from(output);
    fs::create_dir_all(&output).map_err(|_| FixtureError::Io)?;
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or(FixtureError::InvalidPath)?
        .to_path_buf();
    for lane in ["sha256", "poseidon2"] {
        for mode in ["private", "public"] {
            let request = make_request(&repository, lane, mode)?;
            let encoded = request.encode_to_vec();
            decode_operation_request(&encoded).map_err(|_| FixtureError::InvalidRequest)?;
            fs::write(
                output.join(format!("common-credential-root-{lane}-{mode}.pb")),
                encoded,
            )
            .map_err(|_| FixtureError::Io)?;
        }
    }
    Ok(())
}

fn read_common_credential_root_identity_manifest(
    repository: &Path,
) -> Result<CommonCredentialRootIdentities, FixtureError> {
    let path = repository.join(COMMON_CREDENTIAL_ROOT_IDENTITY_MANIFEST);
    let metadata = fs::symlink_metadata(&path).map_err(|_| FixtureError::Io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_IDENTITY_MANIFEST_BYTES
    {
        return Err(FixtureError::InvalidFixture);
    }
    let contents = fs::read_to_string(path).map_err(|_| FixtureError::Io)?;
    let mut lines = contents.lines();
    if lines.next() != Some("circuit\tartifact_identity_sha256") {
        return Err(FixtureError::InvalidFixture);
    }
    let mut identities = BTreeMap::new();
    for line in lines {
        let (circuit, digest) = line.split_once('\t').ok_or(FixtureError::InvalidFixture)?;
        let mut components = circuit.split('/');
        let lane = components.next().ok_or(FixtureError::InvalidFixture)?;
        let family = components.next().ok_or(FixtureError::InvalidFixture)?;
        let profile = components.next().ok_or(FixtureError::InvalidFixture)?;
        let stage = components.next().ok_or(FixtureError::InvalidFixture)?;
        if components.next().is_some()
            || !matches!(lane, "sha256" | "poseidon2")
            || family != "families"
            || profile != "common_credential_root_v1"
            || !matches!(
                stage,
                "root_attestation"
                    | "root_status"
                    | "lineage"
                    | "issuer_credential_status"
                    | "private_persona_claim"
                    | "public_persona_claim"
                    | "public_session"
            )
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || identities
                .insert(circuit.to_owned(), hex_digest_bytes(digest)?)
                .is_some()
        {
            return Err(FixtureError::InvalidFixture);
        }
    }
    if identities.len() != EXPECTED_COMMON_CREDENTIAL_ROOT_IDENTITIES {
        return Err(FixtureError::InvalidFixture);
    }
    Ok(identities)
}

fn make_request(
    repository: &Path,
    lane: &str,
    mode: &str,
) -> Result<pb::ZkProviderOperationRequest, FixtureError> {
    let hash = match lane {
        "sha256" => pb::ZkCredentialHashAlgorithm::Sha256,
        "poseidon2" => pb::ZkCredentialHashAlgorithm::Poseidon2,
        _ => return Err(FixtureError::InvalidPath),
    };
    let (profile, session_family, claim_stage) = match mode {
        "private" => (
            pb::ZkCommonCredentialRootPersonaMode::PrivatePersonaV1,
            pb::ZkCircuitFamily::PrivatePersonaClaimV1,
            pb::ZkCircuitStage::PrivatePersonaClaim,
        ),
        "public" => (
            pb::ZkCommonCredentialRootPersonaMode::PublicPersonaV1,
            pb::ZkCircuitFamily::CommonCredentialRootV1,
            pb::ZkCircuitStage::PublicPersonaClaim,
        ),
        _ => return Err(FixtureError::InvalidPath),
    };
    let source_root = repository.join("circuits").join(lane).join("families");
    let root = source_root.join("common_credential_root_v1");
    let common_identities = read_common_credential_root_identity_manifest(repository)?;
    let common_identity = |stage: &str| -> Result<[u8; 32], FixtureError> {
        let key = format!("{lane}/families/common_credential_root_v1/{stage}");
        common_identities
            .get(&key)
            .copied()
            .ok_or(FixtureError::InvalidFixture)
    };
    let session_identity = if mode == "public" {
        common_identity("public_session")?
    } else {
        session_manifest_identity(repository, lane, mode)?
    };
    let specs = [
        CircuitProof {
            slot: pb::ZkCommonCredentialRootProofSlot::RootAttestation,
            family: pb::ZkCircuitFamily::CommonCredentialRootV1,
            stage: pb::ZkCircuitStage::RootAttestation,
            path: "root_attestation/target/attestation-proof",
            identity: common_identity("root_attestation")?,
        },
        CircuitProof {
            slot: pb::ZkCommonCredentialRootProofSlot::RootStatus,
            family: pb::ZkCircuitFamily::CommonCredentialRootV1,
            stage: pb::ZkCircuitStage::RootStatus,
            path: "root_status/target/status-proof",
            identity: common_identity("root_status")?,
        },
        CircuitProof {
            slot: pb::ZkCommonCredentialRootProofSlot::Lineage0,
            family: pb::ZkCircuitFamily::CommonCredentialRootV1,
            stage: pb::ZkCircuitStage::Lineage,
            path: "lineage/target/lineage-proof",
            identity: common_identity("lineage")?,
        },
        CircuitProof {
            slot: pb::ZkCommonCredentialRootProofSlot::Lineage1,
            family: pb::ZkCircuitFamily::CommonCredentialRootV1,
            stage: pb::ZkCircuitStage::Lineage,
            path: "lineage/target/lineage-proof-employer",
            identity: common_identity("lineage")?,
        },
        CircuitProof {
            slot: pb::ZkCommonCredentialRootProofSlot::SelectedClaim0,
            family: pb::ZkCircuitFamily::CommonCredentialRootV1,
            stage: claim_stage,
            path: "claim/target/proof",
            identity: common_identity(if mode == "private" {
                "private_persona_claim"
            } else {
                "public_persona_claim"
            })?,
        },
        CircuitProof {
            slot: pb::ZkCommonCredentialRootProofSlot::SelectedClaim1,
            family: pb::ZkCircuitFamily::CommonCredentialRootV1,
            stage: claim_stage,
            path: "claim/target/proof-employer",
            identity: common_identity(if mode == "private" {
                "private_persona_claim"
            } else {
                "public_persona_claim"
            })?,
        },
        CircuitProof {
            slot: pb::ZkCommonCredentialRootProofSlot::Session,
            family: session_family,
            stage: if mode == "public" {
                pb::ZkCircuitStage::PublicSession
            } else {
                pb::ZkCircuitStage::Session
            },
            path: "session/target/common-credential-root-session-proof",
            identity: session_identity,
        },
        CircuitProof {
            slot: pb::ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0,
            family: pb::ZkCircuitFamily::CommonCredentialRootV1,
            stage: pb::ZkCircuitStage::IssuerCredentialStatus,
            path: "issuer_credential_status/target/issuer-status-proof",
            identity: common_identity("issuer_credential_status")?,
        },
        CircuitProof {
            slot: pb::ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1,
            family: pb::ZkCircuitFamily::CommonCredentialRootV1,
            stage: pb::ZkCircuitStage::IssuerCredentialStatus,
            path: "issuer_credential_status/target/issuer-status-proof-employer",
            identity: common_identity("issuer_credential_status")?,
        },
    ];
    let mut proofs = Vec::with_capacity(specs.len());
    for spec in specs {
        let proof_directory = match spec.slot {
            pb::ZkCommonCredentialRootProofSlot::Session if mode == "public" => {
                root.join("public_session").join(
                    spec.path
                        .strip_prefix("session/")
                        .ok_or(FixtureError::InvalidPath)?,
                )
            }
            pb::ZkCommonCredentialRootProofSlot::Session => source_root
                .join(format!("{mode}_persona_claim_v1"))
                .join(spec.path),
            pb::ZkCommonCredentialRootProofSlot::SelectedClaim0
            | pb::ZkCommonCredentialRootProofSlot::SelectedClaim1 => {
                root.join(format!("{mode}_persona_claim")).join(
                    spec.path
                        .strip_prefix("claim/")
                        .ok_or(FixtureError::InvalidPath)?,
                )
            }
            _ => root.join(spec.path),
        };
        let proof_bytes = read_nonempty(&proof_directory.join("proof"))?;
        let public_inputs = read_nonempty(&proof_directory.join("public_inputs"))?;
        let circuit_ref = pb::ZkCircuitRef {
            credential_hash_algorithm: EnumValue::from(hash),
            family: EnumValue::from(spec.family),
            stage: EnumValue::from(spec.stage),
            circuit_revision: 1,
            ..Default::default()
        };
        let mut raw_inputs = pb::ZkCommonCredentialRootRawPublicInputs::default();
        raw_inputs.persona_mode = EnumValue::from(profile);
        raw_inputs.slot = EnumValue::from(spec.slot);
        raw_inputs.circuit_ref = MessageField::some(circuit_ref.clone());
        raw_inputs.raw_fields = public_inputs;
        let mut package = pb::ZkCommonCredentialRootRawProofPackage::default();
        package.persona_mode = EnumValue::from(profile);
        package.slot = EnumValue::from(spec.slot);
        package.circuit_ref = MessageField::some(circuit_ref);
        package.proof = proof_bytes;
        package.public_inputs = MessageField::some(raw_inputs);
        package.artifact_identity = Some(
            if spec.slot == pb::ZkCommonCredentialRootProofSlot::Session && mode == "private" {
                pb::ZkArtifactManifestDigest {
                    value: spec.identity.to_vec(),
                    __buffa_unknown_fields: Default::default(),
                }
                .into()
            } else {
                pb::ZkArtifactSetIdentity {
                    value: spec.identity.to_vec(),
                    __buffa_unknown_fields: Default::default(),
                }
                .into()
            },
        );
        package.proof_suite = EnumValue::from(pb::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa);
        proofs.push(package);
    }
    let mut binding = pb::ZkSessionBinding::default();
    binding.nonce_hash = hex_bytes(CHALLENGE)?;
    binding.audience_hash = hex_bytes(AUDIENCE)?;
    binding.transaction_data_hash = hex_bytes(TRANSACTION)?;
    let presentation = pb::ZkCommonCredentialRootPresentation {
        persona_mode: EnumValue::from(profile),
        credential_hash_algorithm: EnumValue::from(hash),
        proof_suite: EnumValue::from(pb::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa),
        session_binding: MessageField::some(binding),
        proofs,
        ..Default::default()
    };
    let mut policy = pb::ZkCommonCredentialRootJoinPolicy::default();
    policy.challenge = hex_bytes(CHALLENGE)?;
    policy.audience_hash = hex_bytes(AUDIENCE)?;
    policy.transaction_data_hash = hex_bytes(TRANSACTION)?;
    policy.request_time_unix = REQUEST_TIME_UNIX;
    // The verifier's authenticated status snapshot is checked separately from
    // the presentation request time. The fixture uses the same instant for both.
    policy.status_validation_time_unix = REQUEST_TIME_UNIX;
    policy.status_validation_max_age_seconds = STATUS_VALIDATION_MAX_AGE_SECONDS;
    policy.attestation_signer = MessageField::some(key(SIGNER_X, SIGNER_Y)?);
    policy.assurance_policy_id = hex_bytes(ASSURANCE_POLICY)?;
    policy.status_root = hex_bytes(STATUS_ROOT)?;
    policy.claims = vec![
        claim(
            UNIVERSITY_X,
            UNIVERSITY_Y,
            UNIVERSITY_CLAIM,
            b"verified:university",
        )?,
        claim(EMPLOYER_X, EMPLOYER_Y, EMPLOYER_CLAIM, b"verified:employer")?,
    ];
    for (index, status_slot) in [7_usize, 8_usize].into_iter().enumerate() {
        let raw = &presentation
            .proofs
            .get(status_slot)
            .ok_or(FixtureError::InvalidFixture)?
            .public_inputs
            .raw_fields;
        let lineage_slot = 2_usize
            .checked_add(index)
            .ok_or(FixtureError::InvalidFixture)?;
        let lineage = &presentation
            .proofs
            .get(lineage_slot)
            .ok_or(FixtureError::InvalidFixture)?
            .public_inputs
            .raw_fields;
        if raw.len() != ISSUER_STATUS_FIELD_COUNT * RAW_FIELD_BYTES
            || field_bytes32(raw, 161)? != field_bytes32(lineage, 193)?
            || field_u64(raw, 160)? != field_u64(lineage, 192)?
            || field_u64(raw, 291)? != REQUEST_TIME_UNIX
        {
            return Err(FixtureError::InvalidFixture);
        }
        let mut expected = pb::ZkCommonCredentialRootIssuerStatusExpectation::default();
        expected.root = field_bytes32(raw, 193)?.to_vec();
        expected.length = field_u64(raw, 225)?;
        expected.list_id = field_bytes32(raw, 226)?.to_vec();
        expected.url_hash = field_bytes32(raw, 258)?.to_vec();
        expected.purpose = EnumValue::from(match field_byte(raw, 290)? {
            1 => pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_REVOCATION,
            2 => pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_SUSPENSION,
            _ => return Err(FixtureError::InvalidFixture),
        });
        if expected.length == 0 {
            return Err(FixtureError::InvalidFixture);
        }
        policy.issuer_status.push(expected);
    }
    Ok(pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::VerifyCommonCredentialRoot(Box::new(
                pb::ZkCommonCredentialRootVerifyOperation {
                    presentation: MessageField::some(presentation),
                    join_policy: MessageField::some(policy),
                    expected_proof_suite: EnumValue::from(
                        pb::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
                    ),
                    ..Default::default()
                },
            )),
        ),
        ..Default::default()
    })
}
