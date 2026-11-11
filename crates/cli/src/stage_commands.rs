// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{ffi::OsStr, io::Write, path::Path};

use crate::{
    io::{read_bounded_public, read_bounded_secret_utf8, write_new_secret},
    stage_args::{
        parse_stage_args, parse_validate_artifact_args, parse_witness_args, StageCommandKind,
    },
    CliError, CliErrorReason, CliExit,
};
#[cfg(feature = "native")]
use crate::{
    io::{read_bounded_secret, write_new_public},
    stage_args::StageArgs,
};
#[cfg(feature = "native")]
use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    proofs::{ZkProof, ZkProofSuite},
};
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    proofs::ZkWitness,
};
use reallyme_zk_artifacts::{
    ArtifactBytes, ArtifactKind, VerifiedArtifactBytes, MAX_ACIR_BYTECODE_BYTES,
    MAX_VERIFICATION_KEY_BYTES,
};
use reallyme_zk_backend_bb::BbStageArtifacts;
#[cfg(feature = "native")]
use reallyme_zk_backend_bb::{
    BarretenbergProverCrs, BarretenbergVerifierCrs, BbStageProveRequest,
    BbStageVerificationArtifacts, BbStageVerifyRequest, LinkedBarretenbergBackend,
    NativeBarretenbergBackend,
};
use reallyme_zk_noir_witness_core::{
    generate_witness_from_artifact_json_and_toml, CompiledProgramArtifactJson,
    MAX_COMPILED_PROGRAM_ARTIFACT_JSON_BYTES,
};
use reallyme_zk_proto_codec::artifact::{decode_artifact_manifest, MAX_ZK_ARTIFACT_MANIFEST_BYTES};
#[cfg(feature = "native")]
use reallyme_zk_proto_codec::proof::{decode_exact_proof, encode_exact_proof};

const MAX_PROVER_TOML_BYTES: usize = 1024 * 1024;
#[cfg(feature = "native")]
const MAX_WITNESS_FILE_BYTES: usize = reallyme_zk_api::proofs::MAX_WITNESS_BYTES;
#[cfg(feature = "native")]
const MAX_PROOF_PACKAGE_BYTES: usize = 512 * 1024;
#[cfg(feature = "native")]
const MAX_FULL_PROVER_CRS_G1_BYTES: usize = 67_108_928;
#[cfg(feature = "native")]
const MAX_VERIFIER_CRS_G1_BYTES: usize = 64;
#[cfg(feature = "native")]
const MAX_CRS_G2_BYTES: usize = 128;

pub(crate) fn run_witness<I, S>(args: I, stdout: &mut dyn Write) -> Result<CliExit, CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = parse_witness_args(args)?;
    let artifact_bytes = read_bounded_public(
        &args.artifact_json,
        MAX_COMPILED_PROGRAM_ARTIFACT_JSON_BYTES,
    )?;
    let artifact = CompiledProgramArtifactJson::try_from_bytes(&artifact_bytes)
        .map_err(|_| CliError::new(CliErrorReason::WitnessFailed))?;
    let prover_toml = read_bounded_secret_utf8(&args.prover_toml, MAX_PROVER_TOML_BYTES)?;
    let witness = generate_witness_from_artifact_json_and_toml(artifact, prover_toml.as_str())
        .map_err(|_| CliError::new(CliErrorReason::WitnessFailed))?;
    let encoded = witness.into_zeroizing_bytes();
    let checked = ZkWitness::try_from_noir_witness_stack_v1_zeroizing(args.circuit_ref, encoded)
        .map_err(map_artifact_error)?;
    write_new_secret(&args.out, checked.expose_bytes())?;
    stdout.write_all(b"witness: ok\n")?;
    Ok(CliExit::Success)
}

pub(crate) fn run_validate_artifacts<I, S>(
    args: I,
    stdout: &mut dyn Write,
) -> Result<CliExit, CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = parse_validate_artifact_args(args)?;
    let _artifacts = read_stage_artifacts(&args.manifest, &args.bytecode, &args.verification_key)?;
    stdout.write_all(b"artifacts: ok\n")?;
    Ok(CliExit::Success)
}

#[cfg(feature = "native")]
pub(crate) fn run_prove_stage<I, S>(args: I, stdout: &mut dyn Write) -> Result<CliExit, CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = parse_stage_args(args, StageCommandKind::Prove)?;
    let bytecode = args
        .bytecode
        .as_ref()
        .ok_or(CliError::new(CliErrorReason::InvalidInput))?;
    let witness = args
        .witness
        .as_ref()
        .ok_or(CliError::new(CliErrorReason::InvalidInput))?;
    let out = args
        .out
        .as_ref()
        .ok_or(CliError::new(CliErrorReason::InvalidInput))?;
    let circuit_ref = args
        .bundle_kind
        .source_ref(args.credential_hash_algorithm, args.stage);
    let artifacts = read_stage_artifacts(&args.manifest, bytecode, &args.verification_key)?;
    validate_stage_manifest(&args, circuit_ref, artifacts.manifest())?;
    let witness_bytes = read_bounded_secret(witness, MAX_WITNESS_FILE_BYTES)?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1_zeroizing(circuit_ref, witness_bytes)
        .map_err(map_artifact_error)?;
    let backend = NativeBarretenbergBackend::try_new().map_err(map_backend_error)?;
    let crs_g1 = read_bounded_public(&args.crs_g1, MAX_FULL_PROVER_CRS_G1_BYTES)?;
    let crs_g2 = read_bounded_public(&args.crs_g2, MAX_CRS_G2_BYTES)?;
    let crs = BarretenbergProverCrs::try_from_pinned_slices(&crs_g1, &crs_g2)
        .map_err(map_artifact_error)?;
    backend
        .initialize_prover_crs(crs)
        .map_err(map_backend_error)?;
    let response = backend
        .prove_stage(BbStageProveRequest {
            bundle_kind: args.bundle_kind,
            stage: args.stage,
            circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            witness: &witness,
            session_binding: args.binding,
        })
        .map_err(map_backend_error)?;
    let (proof_bytes, public_inputs) = response.into_parts();
    let proof = ZkProof::try_from_exact_bounded_parts(
        args.bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        artifacts.manifest().manifest_sha256(),
        proof_bytes,
        public_inputs,
    )
    .map_err(map_artifact_error)?;
    let encoded = encode_exact_proof(&proof).map_err(map_artifact_error)?;
    write_new_public(out, encoded.as_slice())?;
    stdout.write_all(b"prove-stage: ok\n")?;
    Ok(CliExit::Success)
}

#[cfg(not(feature = "native"))]
pub(crate) fn run_prove_stage<I, S>(args: I, _stdout: &mut dyn Write) -> Result<CliExit, CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    let _validated = parse_stage_args(args, StageCommandKind::Prove)?;
    Err(CliError::new(CliErrorReason::BackendUnavailable))
}

#[cfg(feature = "native")]
pub(crate) fn run_verify_stage<I, S>(args: I, stdout: &mut dyn Write) -> Result<CliExit, CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = parse_stage_args(args, StageCommandKind::Verify)?;
    let proof_path = args
        .proof
        .as_ref()
        .ok_or(CliError::new(CliErrorReason::InvalidInput))?;
    let circuit_ref = args
        .bundle_kind
        .source_ref(args.credential_hash_algorithm, args.stage);
    let artifacts = read_stage_verification_artifacts(&args.manifest, &args.verification_key)?;
    validate_stage_manifest(&args, circuit_ref, artifacts.manifest())?;
    let proof_bytes = read_bounded_public(proof_path, MAX_PROOF_PACKAGE_BYTES)?;
    let proof = decode_exact_proof(&proof_bytes).map_err(map_verification_error)?;
    if proof.circuit_ref() != circuit_ref {
        return Err(CliError::new(CliErrorReason::VerificationFailed));
    }
    let backend = NativeBarretenbergBackend::try_new().map_err(map_backend_error)?;
    let crs_g1 = read_bounded_public(&args.crs_g1, MAX_VERIFIER_CRS_G1_BYTES)?;
    let crs_g2 = read_bounded_public(&args.crs_g2, MAX_CRS_G2_BYTES)?;
    let crs = BarretenbergVerifierCrs::try_from_pinned_slices(&crs_g1, &crs_g2)
        .map_err(map_artifact_error)?;
    backend
        .initialize_verifier_crs(crs)
        .map_err(map_backend_error)?;
    backend
        .verify_stage(BbStageVerifyRequest {
            bundle_kind: args.bundle_kind,
            stage: args.stage,
            circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            proof: &proof,
            expected_binding: args.binding,
        })
        .map_err(map_verification_error)?;
    stdout.write_all(b"verify-stage: diagnostic-stage-proof-ok; not-presentation-admission\n")?;
    Ok(CliExit::Success)
}

#[cfg(not(feature = "native"))]
pub(crate) fn run_verify_stage<I, S>(args: I, _stdout: &mut dyn Write) -> Result<CliExit, CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    let _validated = parse_stage_args(args, StageCommandKind::Verify)?;
    Err(CliError::new(CliErrorReason::BackendUnavailable))
}

fn read_stage_artifacts(
    manifest: &Path,
    bytecode: &Path,
    verification_key: &Path,
) -> Result<BbStageArtifacts, CliError> {
    let manifest = read_manifest(manifest)?;
    let bytecode = read_verified_artifact(bytecode, ArtifactKind::AcirBytecode)?;
    let verification_key = read_verified_artifact(verification_key, ArtifactKind::VerificationKey)?;
    BbStageArtifacts::try_new(manifest, bytecode, verification_key).map_err(map_artifact_error)
}

#[cfg(feature = "native")]
fn read_stage_verification_artifacts(
    manifest: &Path,
    verification_key: &Path,
) -> Result<BbStageVerificationArtifacts, CliError> {
    let manifest = read_manifest(manifest)?;
    let verification_key = read_verified_artifact(verification_key, ArtifactKind::VerificationKey)?;
    BbStageVerificationArtifacts::try_new(manifest, verification_key).map_err(map_artifact_error)
}

fn read_manifest(
    path: &Path,
) -> Result<reallyme_zk_artifacts::ProductionArtifactManifest, CliError> {
    let bytes = read_bounded_public(path, MAX_ZK_ARTIFACT_MANIFEST_BYTES)?;
    decode_artifact_manifest(&bytes).map_err(map_artifact_error)
}

fn read_verified_artifact(
    path: &Path,
    kind: ArtifactKind,
) -> Result<VerifiedArtifactBytes, CliError> {
    let max_bytes = match kind {
        ArtifactKind::AcirBytecode => MAX_ACIR_BYTECODE_BYTES,
        ArtifactKind::VerificationKey => MAX_VERIFICATION_KEY_BYTES,
    };
    let bytes = read_bounded_public(path, max_bytes)?;
    let artifact = ArtifactBytes::try_from_bytes(kind, bytes).map_err(map_artifact_error)?;
    let digest = reallyme_zk_artifacts::Digest32::sha256(artifact.as_bytes());
    VerifiedArtifactBytes::try_from_bounded(artifact, digest).map_err(map_artifact_error)
}

#[cfg(feature = "native")]
fn validate_stage_manifest(
    args: &StageArgs,
    circuit_ref: ZkCircuitRef,
    manifest: &reallyme_zk_artifacts::ProductionArtifactManifest,
) -> Result<(), CliError> {
    if manifest.bundle_kind() != args.bundle_kind
        || manifest.stage() != args.stage
        || manifest.circuit_ref() != circuit_ref
        || manifest.proof_suite() != ZkProofSuite::PRODUCTION
    {
        return Err(CliError::new(CliErrorReason::ArtifactValidationFailed));
    }
    Ok(())
}

fn map_artifact_error(error: ZkError) -> CliError {
    match error.reason() {
        ZkErrorReason::MessageTooLarge
        | ZkErrorReason::ArtifactTooLarge
        | ZkErrorReason::WitnessTooLarge => CliError::new(CliErrorReason::InputTooLarge),
        _ => CliError::new(CliErrorReason::ArtifactValidationFailed),
    }
}

#[cfg(feature = "native")]
fn map_backend_error(error: ZkError) -> CliError {
    match error.reason() {
        ZkErrorReason::ArtifactMismatch
        | ZkErrorReason::UnsupportedProofSuite
        | ZkErrorReason::StageMismatch => CliError::new(CliErrorReason::ArtifactValidationFailed),
        _ => CliError::new(CliErrorReason::BackendFailed),
    }
}

#[cfg(feature = "native")]
fn map_verification_error(error: ZkError) -> CliError {
    match error.reason() {
        ZkErrorReason::ArtifactMismatch
        | ZkErrorReason::UnsupportedProofSuite
        | ZkErrorReason::StageMismatch => CliError::new(CliErrorReason::ArtifactValidationFailed),
        _ => CliError::new(CliErrorReason::VerificationFailed),
    }
}
