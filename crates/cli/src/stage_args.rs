// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{ffi::OsStr, path::PathBuf};

use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkSessionBinding,
};

use crate::{CliError, CliErrorReason};

const HEX_DIGEST_CHARS: usize = 64;

pub(crate) struct WitnessArgs {
    pub(crate) circuit_ref: ZkCircuitRef,
    pub(crate) artifact_json: PathBuf,
    pub(crate) prover_toml: PathBuf,
    pub(crate) out: PathBuf,
}

// The non-native lane still parses the complete command before returning its
// typed unsupported result, but only the linked lane consumes these fields.
#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) struct StageArgs {
    pub(crate) bundle_kind: ZkClaimProofBundleKind,
    pub(crate) stage: ZkClaimProofBundleStage,
    pub(crate) credential_hash_algorithm: ZkCredentialHashAlgorithm,
    pub(crate) manifest: PathBuf,
    pub(crate) bytecode: Option<PathBuf>,
    pub(crate) verification_key: PathBuf,
    pub(crate) witness: Option<PathBuf>,
    pub(crate) proof: Option<PathBuf>,
    pub(crate) crs_g1: PathBuf,
    pub(crate) crs_g2: PathBuf,
    pub(crate) binding: ZkSessionBinding,
    pub(crate) out: Option<PathBuf>,
}

pub(crate) struct ValidateArtifactArgs {
    pub(crate) manifest: PathBuf,
    pub(crate) bytecode: PathBuf,
    pub(crate) verification_key: PathBuf,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageCommandKind {
    Prove,
    Verify,
}

pub(crate) fn parse_witness_args<I, S>(args: I) -> Result<WitnessArgs, CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut parsed = ParsedWitnessArgs::default();
    for (flag, value) in pairs(args)? {
        match flag {
            "--circuit" => parsed.circuit_ref = Some(parse_circuit_ref(&value)?),
            "--artifact-json" => parsed.artifact_json = Some(PathBuf::from(value)),
            "--prover-toml" => parsed.prover_toml = Some(PathBuf::from(value)),
            "--out" => parsed.out = Some(PathBuf::from(value)),
            _ => return Err(CliError::new(CliErrorReason::UnexpectedArgument)),
        }
    }
    Ok(WitnessArgs {
        circuit_ref: parsed
            .circuit_ref
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        artifact_json: parsed
            .artifact_json
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        prover_toml: parsed
            .prover_toml
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        out: parsed
            .out
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
    })
}

pub(crate) fn parse_validate_artifact_args<I, S>(args: I) -> Result<ValidateArtifactArgs, CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut manifest = None;
    let mut bytecode = None;
    let mut verification_key = None;
    for (flag, value) in pairs(args)? {
        match flag {
            "--manifest" => manifest = Some(PathBuf::from(value)),
            "--bytecode" => bytecode = Some(PathBuf::from(value)),
            "--verification-key" => verification_key = Some(PathBuf::from(value)),
            _ => return Err(CliError::new(CliErrorReason::UnexpectedArgument)),
        }
    }
    Ok(ValidateArtifactArgs {
        manifest: manifest.ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        bytecode: bytecode.ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        verification_key: verification_key.ok_or(CliError::new(CliErrorReason::InvalidInput))?,
    })
}

pub(crate) fn parse_stage_args<I, S>(args: I, kind: StageCommandKind) -> Result<StageArgs, CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut parsed = ParsedStageArgs::default();
    for (flag, value) in pairs(args)? {
        match flag {
            "--bundle-kind" => parsed.bundle_kind = Some(parse_bundle_kind(&value)?),
            "--stage" => parsed.stage = Some(parse_stage(&value)?),
            "--hash-strategy" => {
                parsed.credential_hash_algorithm = Some(parse_credential_hash_algorithm(&value)?)
            }
            "--manifest" => parsed.manifest = Some(PathBuf::from(value)),
            "--bytecode" => parsed.bytecode = Some(PathBuf::from(value)),
            "--verification-key" => parsed.verification_key = Some(PathBuf::from(value)),
            "--witness" => parsed.witness = Some(PathBuf::from(value)),
            "--proof" => parsed.proof = Some(PathBuf::from(value)),
            "--crs-g1" => parsed.crs_g1 = Some(PathBuf::from(value)),
            "--crs-g2" => parsed.crs_g2 = Some(PathBuf::from(value)),
            "--nonce-hash" => parsed.nonce_hash = Some(parse_digest_hex(&value)?),
            "--audience-hash" => parsed.audience_hash = Some(parse_digest_hex(&value)?),
            "--transaction-data-hash" => {
                parsed.transaction_data_hash = Some(parse_digest_hex(&value)?);
            }
            "--out" => parsed.out = Some(PathBuf::from(value)),
            _ => return Err(CliError::new(CliErrorReason::UnexpectedArgument)),
        }
    }
    validate_required_stage_args(kind, &parsed)?;
    Ok(StageArgs {
        bundle_kind: parsed
            .bundle_kind
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        stage: parsed
            .stage
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        credential_hash_algorithm: parsed
            .credential_hash_algorithm
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        manifest: parsed
            .manifest
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        bytecode: parsed.bytecode,
        verification_key: parsed
            .verification_key
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        witness: parsed.witness,
        proof: parsed.proof,
        crs_g1: parsed
            .crs_g1
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        crs_g2: parsed
            .crs_g2
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
        binding: ZkSessionBinding {
            nonce_hash: parsed
                .nonce_hash
                .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
            audience_hash: parsed
                .audience_hash
                .ok_or(CliError::new(CliErrorReason::InvalidInput))?,
            transaction_data_hash: parsed.transaction_data_hash,
        },
        out: parsed.out,
    })
}

fn validate_required_stage_args(
    kind: StageCommandKind,
    parsed: &ParsedStageArgs,
) -> Result<(), CliError> {
    if kind == StageCommandKind::Prove
        && (parsed.bytecode.is_none() || parsed.witness.is_none() || parsed.out.is_none())
    {
        return Err(CliError::new(CliErrorReason::InvalidInput));
    }
    if kind == StageCommandKind::Prove && parsed.proof.is_some() {
        return Err(CliError::new(CliErrorReason::UnexpectedArgument));
    }
    if kind == StageCommandKind::Verify && parsed.proof.is_none() {
        return Err(CliError::new(CliErrorReason::InvalidInput));
    }
    if kind == StageCommandKind::Verify
        && (parsed.bytecode.is_some() || parsed.witness.is_some() || parsed.out.is_some())
    {
        return Err(CliError::new(CliErrorReason::UnexpectedArgument));
    }
    Ok(())
}

#[derive(Default)]
struct ParsedWitnessArgs {
    circuit_ref: Option<ZkCircuitRef>,
    artifact_json: Option<PathBuf>,
    prover_toml: Option<PathBuf>,
    out: Option<PathBuf>,
}

#[derive(Default)]
struct ParsedStageArgs {
    bundle_kind: Option<ZkClaimProofBundleKind>,
    stage: Option<ZkClaimProofBundleStage>,
    credential_hash_algorithm: Option<ZkCredentialHashAlgorithm>,
    manifest: Option<PathBuf>,
    bytecode: Option<PathBuf>,
    verification_key: Option<PathBuf>,
    witness: Option<PathBuf>,
    proof: Option<PathBuf>,
    crs_g1: Option<PathBuf>,
    crs_g2: Option<PathBuf>,
    nonce_hash: Option<[u8; 32]>,
    audience_hash: Option<[u8; 32]>,
    transaction_data_hash: Option<[u8; 32]>,
    out: Option<PathBuf>,
}

fn pairs<I, S>(mut args: I) -> Result<Vec<(&'static str, std::ffi::OsString)>, CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut pairs = Vec::new();
    while let Some(flag) = args.next() {
        let flag = match flag.as_ref().to_str() {
            Some(flag) => flag,
            None => return Err(CliError::new(CliErrorReason::UnexpectedArgument)),
        };
        let Some(value) = args.next() else {
            return Err(CliError::new(CliErrorReason::UnexpectedArgument));
        };
        let stable_flag = known_flag(flag)?;
        if pairs.iter().any(|(existing, _)| *existing == stable_flag) {
            return Err(CliError::new(CliErrorReason::UnexpectedArgument));
        }
        pairs
            .try_reserve_exact(1)
            .map_err(|_| CliError::new(CliErrorReason::InputTooLarge))?;
        pairs.push((stable_flag, value.as_ref().to_os_string()));
    }
    Ok(pairs)
}

fn known_flag(flag: &str) -> Result<&'static str, CliError> {
    match flag {
        "--circuit" => Ok("--circuit"),
        "--artifact-json" => Ok("--artifact-json"),
        "--prover-toml" => Ok("--prover-toml"),
        "--out" => Ok("--out"),
        "--bundle-kind" => Ok("--bundle-kind"),
        "--stage" => Ok("--stage"),
        "--hash-strategy" => Ok("--hash-strategy"),
        "--manifest" => Ok("--manifest"),
        "--bytecode" => Ok("--bytecode"),
        "--verification-key" => Ok("--verification-key"),
        "--witness" => Ok("--witness"),
        "--proof" => Ok("--proof"),
        "--crs-g1" => Ok("--crs-g1"),
        "--crs-g2" => Ok("--crs-g2"),
        "--nonce-hash" => Ok("--nonce-hash"),
        "--audience-hash" => Ok("--audience-hash"),
        "--transaction-data-hash" => Ok("--transaction-data-hash"),
        _ => Err(CliError::new(CliErrorReason::UnexpectedArgument)),
    }
}

fn parse_circuit_ref(value: &OsStr) -> Result<ZkCircuitRef, CliError> {
    let value = value
        .to_str()
        .ok_or(CliError::new(CliErrorReason::InvalidInput))?;
    ZkCircuitRef::try_from_stable_name(value).map_err(map_artifact_error)
}

fn parse_bundle_kind(value: &OsStr) -> Result<ZkClaimProofBundleKind, CliError> {
    match value.to_str() {
        Some("credential_subject_claim_v1") => Ok(ZkClaimProofBundleKind::CredentialSubjectClaimV1),
        Some("private_persona_claim_v1") => Ok(ZkClaimProofBundleKind::PrivatePersonaClaimV1),
        _ => Err(CliError::new(CliErrorReason::InvalidInput)),
    }
}

fn parse_stage(value: &OsStr) -> Result<ZkClaimProofBundleStage, CliError> {
    match value.to_str() {
        Some("session") => Ok(ZkClaimProofBundleStage::Session),
        Some("credential_envelope") => Ok(ZkClaimProofBundleStage::CredentialEnvelope),
        Some("credential_root") => Ok(ZkClaimProofBundleStage::CredentialRoot),
        Some("claim") => Ok(ZkClaimProofBundleStage::Claim),
        _ => Err(CliError::new(CliErrorReason::InvalidInput)),
    }
}

fn parse_credential_hash_algorithm(value: &OsStr) -> Result<ZkCredentialHashAlgorithm, CliError> {
    match value.to_str() {
        Some("sha256") => Ok(ZkCredentialHashAlgorithm::Sha256),
        Some("poseidon2") => Ok(ZkCredentialHashAlgorithm::Poseidon2),
        _ => Err(CliError::new(CliErrorReason::InvalidInput)),
    }
}

fn parse_digest_hex(value: &OsStr) -> Result<[u8; 32], CliError> {
    let value = value
        .to_str()
        .ok_or(CliError::new(CliErrorReason::InvalidInput))?;
    if value.len() != HEX_DIGEST_CHARS {
        return Err(CliError::new(CliErrorReason::InvalidInput));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        let byte = high
            .checked_mul(16)
            .and_then(|prefix| prefix.checked_add(low))
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?;
        let target = output
            .get_mut(index)
            .ok_or(CliError::new(CliErrorReason::InvalidInput))?;
        *target = byte;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, CliError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CliError::new(CliErrorReason::InvalidInput)),
    }
}

fn map_artifact_error(error: ZkError) -> CliError {
    match error.reason() {
        ZkErrorReason::MessageTooLarge
        | ZkErrorReason::ArtifactTooLarge
        | ZkErrorReason::WitnessTooLarge => CliError::new(CliErrorReason::InputTooLarge),
        _ => CliError::new(CliErrorReason::ArtifactValidationFailed),
    }
}
