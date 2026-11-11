// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(dead_code)]

use std::{
    env, fs, io,
    io::{Read, Write},
    mem::MaybeUninit,
    path::{Path, PathBuf},
};

use reallyme_zk_api::{
    artifacts::ZkArtifactSetIdentity,
    circuits::{ZkCircuitFamily, ZkCircuitRef},
    common_root::ZkCommonCredentialRootRawPublicInputs,
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkDecodedPublicInputs, ZkProof, ZkProofSuite, ZkPublicInputs, ZkSessionBinding, ZkWitness,
    },
};
use reallyme_zk_artifacts::{ArtifactKind, Digest32, VerifiedArtifactBytes};
use reallyme_zk_backend_bb::{BarretenbergPublicInputCodec, BbExactCircuitArtifacts};
use reallyme_zk_noir_witness_core::{
    generate_witness_from_artifact_json_and_toml, CompiledProgramArtifactJson, WitnessError,
};
use thiserror::Error;

#[path = "modern_all30_negatives.rs"]
mod negatives;

#[allow(unused_imports)]
pub use negatives::negative_outcomes;

pub const ROOT_ENV: &str = "REALLYME_ZK_ALL_CIRCUITS_V1_ROOT";
pub const G1_PATH_ENV: &str = "REALLYME_BN254_G1_PATH";
pub const G2_PATH_ENV: &str = "REALLYME_BN254_G2_PATH";
pub const VERIFY_SUMMARY_ENV: &str = "REALLYME_LINKED_ALL30_VERIFY_SUMMARY";
pub const PROVE_SUMMARY_ENV: &str = "REALLYME_LINKED_ALL30_PROVE_SUMMARY";

const VERIFIER_G1_PREFIX_BYTES: usize = 64;
const VERIFIER_G2_BYTES: usize = 128;
const FULL_PROVER_CRS_G1_PREFIX_BYTES: usize = 67_108_928;

#[derive(Debug, Error)]
pub enum MatrixError {
    #[error("required environment is missing")]
    MissingEnvironment,
    #[error("fixture layout is incomplete")]
    MissingField,
    #[error("fixture layout is ambiguous")]
    AmbiguousField,
    #[error("fixture length is invalid")]
    UnexpectedLength,
    #[error("linked backend returned an unexpected error reason")]
    UnexpectedErrorReason {
        expected: ZkErrorReason,
        actual: Option<ZkErrorReason>,
    },
    #[error("source lock does not match current circuit sources")]
    SourceLockMismatch,
    #[error("fresh linked public inputs differ from the retained circuit fixture")]
    EvidenceMismatch,
    #[error("witness transport encoding is invalid")]
    InvalidWitnessTransport,
    #[error("i/o failure")]
    Io(#[from] io::Error),
    #[error("zk failure")]
    Zk(#[from] ZkError),
    #[error("witness failure")]
    Witness(#[from] WitnessError),
}

pub struct CircuitEvidence {
    pub circuit_ref: ZkCircuitRef,
    pub circuit_name: String,
    pub package_name: String,
    pub source_closure_sha256: Digest32,
    pub artifact_identity: ZkArtifactSetIdentity,
    pub artifacts: BbExactCircuitArtifacts,
    pub public_inputs: ZkPublicInputs,
    pub proof: ZkProof,
}

pub struct RawCircuitEvidence {
    pub circuit_ref: ZkCircuitRef,
    pub artifact_identity: ZkArtifactSetIdentity,
    pub artifacts: BbExactCircuitArtifacts,
    pub public_inputs: ZkCommonCredentialRootRawPublicInputs,
}

struct ArtifactEvidence {
    package_name: String,
    source_closure_sha256: Digest32,
    artifact_identity: ZkArtifactSetIdentity,
    artifacts: BbExactCircuitArtifacts,
    run_dir: PathBuf,
}

#[derive(Clone, Copy)]
pub enum EvidenceRun {
    RetainedRequestBound,
    CommonCredentialRootPublicSession,
}

impl EvidenceRun {
    const fn directory(self) -> &'static str {
        match self {
            Self::RetainedRequestBound => "modern-run-01",
            Self::CommonCredentialRootPublicSession => "common-credential-root-session-proof",
        }
    }
}

pub struct NegativeOutcomes {
    pub wrong_nonce: ZkErrorReason,
    pub wrong_audience: ZkErrorReason,
    pub wrong_transaction: ZkErrorReason,
    pub absent_transaction: ZkErrorReason,
    pub sentinel_transaction: ZkErrorReason,
    pub wrong_circuit: ZkErrorReason,
    pub wrong_artifact_identity: ZkErrorReason,
    pub wrong_verification_key: ZkErrorReason,
    pub tampered_proof_same_length: ZkErrorReason,
    pub tampered_proof_malformed_length: ZkErrorReason,
    pub tampered_public_inputs: ZkErrorReason,
}

pub struct MatrixSummaryRow {
    pub circuit_name: String,
    pub package_name: String,
    pub source_closure_sha256: Digest32,
    pub artifact_identity: ZkArtifactSetIdentity,
    pub artifact_identity_scope: &'static str,
    pub witness_bytes: usize,
    pub proof_bytes: usize,
    pub public_input_bytes: usize,
    pub verification_key_bytes: usize,
    pub witness_ms: u128,
    pub prove_ms: u128,
    pub verify_ms: u128,
    pub process_rss_kib: u64,
    pub negatives: NegativeOutcomes,
}

pub struct MatrixRowMeasurements {
    pub witness_bytes: usize,
    pub proof_bytes: usize,
    pub witness_ms: u128,
    pub prove_ms: u128,
    pub verify_ms: u128,
    pub process_rss_kib: u64,
}

impl MatrixSummaryRow {
    pub fn from_evidence(
        evidence: &CircuitEvidence,
        measurements: MatrixRowMeasurements,
        negatives: NegativeOutcomes,
    ) -> Self {
        Self {
            circuit_name: evidence.circuit_name.clone(),
            package_name: evidence.package_name.clone(),
            source_closure_sha256: evidence.source_closure_sha256,
            artifact_identity: evidence.artifact_identity,
            artifact_identity_scope: "source_lock_plus_current_artifact_hashes",
            witness_bytes: measurements.witness_bytes,
            proof_bytes: measurements.proof_bytes,
            public_input_bytes: evidence.public_inputs.as_bytes().len(),
            verification_key_bytes: evidence.artifacts.verification_key().as_bytes().len(),
            witness_ms: measurements.witness_ms,
            prove_ms: measurements.prove_ms,
            verify_ms: measurements.verify_ms,
            process_rss_kib: measurements.process_rss_kib,
            negatives,
        }
    }
}

pub fn required_path(name: &str) -> Result<PathBuf, MatrixError> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or(MatrixError::MissingEnvironment)
}

pub const RETAINED_REQUEST_BOUND_CIRCUIT_COUNT: usize = 20;

pub fn retained_request_bound_circuit_refs() -> impl Iterator<Item = &'static ZkCircuitRef> {
    ZkCircuitRef::ALL
        .iter()
        // This retained-proof matrix contains only the two request-bound
        // families. Common-credential-root and persona-credential-evidence proofs have separate
        // joined gates with different witness and status contracts.
        .filter(|circuit_ref| {
            matches!(
                circuit_ref.family,
                ZkCircuitFamily::CredentialSubjectClaimV1 | ZkCircuitFamily::PrivatePersonaClaimV1
            )
        })
}

pub fn read_verifier_g1_prefix(path: &Path) -> Result<[u8; VERIFIER_G1_PREFIX_BYTES], MatrixError> {
    let mut file = fs::File::open(path)?;
    let mut prefix = [0_u8; VERIFIER_G1_PREFIX_BYTES];
    file.read_exact(&mut prefix)?;
    Ok(prefix)
}

pub fn read_prover_g1_prefix(path: &Path) -> Result<Vec<u8>, MatrixError> {
    let file = fs::File::open(path)?;
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(FULL_PROVER_CRS_G1_PREFIX_BYTES)
        .map_err(|_| MatrixError::UnexpectedLength)?;
    let limit = u64::try_from(FULL_PROVER_CRS_G1_PREFIX_BYTES)
        .map_err(|_| MatrixError::UnexpectedLength)?;
    let mut take = file.take(limit);
    take.read_to_end(&mut prefix)?;
    if prefix.len() != FULL_PROVER_CRS_G1_PREFIX_BYTES {
        return Err(MatrixError::UnexpectedLength);
    }
    Ok(prefix)
}

pub fn read_g2(path: &Path) -> Result<[u8; VERIFIER_G2_BYTES], MatrixError> {
    let bytes = fs::read(path)?;
    bytes.try_into().map_err(|_| MatrixError::UnexpectedLength)
}

pub fn load_circuit_evidence(
    root: &Path,
    circuit_ref: ZkCircuitRef,
) -> Result<CircuitEvidence, MatrixError> {
    load_circuit_evidence_from_run(root, circuit_ref, EvidenceRun::RetainedRequestBound)
}

pub fn load_circuit_evidence_from_run(
    root: &Path,
    circuit_ref: ZkCircuitRef,
    run: EvidenceRun,
) -> Result<CircuitEvidence, MatrixError> {
    load_circuit_evidence_from_lock_and_run(
        root,
        root.join("modern-circuit-source-lock.tsv").as_path(),
        circuit_ref,
        run,
    )
}

pub fn load_circuit_evidence_from_lock(
    root: &Path,
    source_lock_path: &Path,
    circuit_ref: ZkCircuitRef,
) -> Result<CircuitEvidence, MatrixError> {
    load_circuit_evidence_from_lock_and_run(
        root,
        source_lock_path,
        circuit_ref,
        EvidenceRun::RetainedRequestBound,
    )
}

fn load_circuit_evidence_from_lock_and_run(
    root: &Path,
    source_lock_path: &Path,
    circuit_ref: ZkCircuitRef,
    run: EvidenceRun,
) -> Result<CircuitEvidence, MatrixError> {
    let artifact =
        load_artifact_evidence_from_lock_and_run(root, source_lock_path, circuit_ref, run)?;
    let serialized_public_inputs = fs::read(artifact.run_dir.join("public_inputs"))?;
    let public_inputs =
        BarretenbergPublicInputCodec::decode(circuit_ref, serialized_public_inputs.as_slice())?;
    let proof_bytes = fs::read(artifact.run_dir.join("proof"))?;
    let proof = ZkProof::try_from_exact_parts(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        artifact.artifact_identity,
        proof_bytes,
        ZkPublicInputs::try_copy_from_slice(public_inputs.as_bytes())?,
    )?;

    Ok(CircuitEvidence {
        circuit_ref,
        circuit_name: circuit_name(circuit_ref),
        package_name: artifact.package_name,
        source_closure_sha256: artifact.source_closure_sha256,
        artifact_identity: artifact.artifact_identity,
        artifacts: artifact.artifacts,
        public_inputs,
        proof,
    })
}

pub fn load_common_credential_root_public_session_evidence(
    root: &Path,
    circuit_ref: ZkCircuitRef,
) -> Result<RawCircuitEvidence, MatrixError> {
    let artifact = load_artifact_evidence_from_lock_and_run(
        root,
        root.join("modern-circuit-source-lock.tsv").as_path(),
        circuit_ref,
        EvidenceRun::CommonCredentialRootPublicSession,
    )?;
    let public_inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
        circuit_ref,
        fs::read(artifact.run_dir.join("public_inputs"))?,
    )?;
    Ok(RawCircuitEvidence {
        circuit_ref,
        artifact_identity: artifact.artifact_identity,
        artifacts: artifact.artifacts,
        public_inputs,
    })
}

fn load_artifact_evidence_from_lock_and_run(
    root: &Path,
    source_lock_path: &Path,
    circuit_ref: ZkCircuitRef,
    run: EvidenceRun,
) -> Result<ArtifactEvidence, MatrixError> {
    let circuit_dir = circuit_dir(root, circuit_ref);
    let target_dir = circuit_dir.join("target");
    let (package_name, source_closure_sha256) =
        source_closure_entry(source_lock_path, circuit_ref)?;
    let artifact_path = target_dir.join(format!("{package_name}.json"));
    let run_dir = target_dir.join(run.directory());
    let verification_key_path = run_dir.join("vk");
    let recomputed_source_closure_sha256 = recompute_source_closure_digest(root, circuit_ref)?;
    if recomputed_source_closure_sha256 != source_closure_sha256 {
        return Err(MatrixError::SourceLockMismatch);
    }
    let bytecode_bytes = fs::read(artifact_path)?;
    let verification_key_bytes = fs::read(verification_key_path)?;
    let bytecode_digest = Digest32::sha256(bytecode_bytes.as_slice());
    let verification_key_digest = Digest32::sha256(verification_key_bytes.as_slice());
    let artifact_identity = artifact_identity(
        circuit_ref,
        source_closure_sha256,
        bytecode_digest,
        verification_key_digest,
    );
    let bytecode = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::AcirBytecode,
        bytecode_bytes,
        bytecode_digest,
    )?;
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        verification_key_bytes,
        verification_key_digest,
    )?;
    let artifacts = BbExactCircuitArtifacts::try_new(
        circuit_ref,
        artifact_identity,
        bytecode,
        verification_key,
    )?;
    Ok(ArtifactEvidence {
        package_name,
        source_closure_sha256,
        artifact_identity,
        artifacts,
        run_dir,
    })
}

pub fn generate_witness(root: &Path, evidence: &CircuitEvidence) -> Result<ZkWitness, MatrixError> {
    generate_witness_for_artifacts(root, evidence.circuit_ref, &evidence.artifacts)
}

pub fn generate_witness_for_artifacts(
    root: &Path,
    circuit_ref: ZkCircuitRef,
    artifacts: &BbExactCircuitArtifacts,
) -> Result<ZkWitness, MatrixError> {
    generate_witness_for_artifacts_with_toml(
        circuit_ref,
        artifacts,
        circuit_dir(root, circuit_ref).join("Prover.toml").as_path(),
    )
}

pub fn generate_witness_for_artifacts_with_toml(
    circuit_ref: ZkCircuitRef,
    artifacts: &BbExactCircuitArtifacts,
    prover_toml_path: &Path,
) -> Result<ZkWitness, MatrixError> {
    let artifact_bytes = artifacts.bytecode().as_bytes();
    let artifact_json = CompiledProgramArtifactJson::try_from_bytes(artifact_bytes)?;
    let prover_toml = fs::read_to_string(prover_toml_path)?;
    let witness = generate_witness_from_artifact_json_and_toml(artifact_json, &prover_toml)?;
    let witness = witness.into_zeroizing_bytes();
    ensure_gzip_transport(witness.as_slice())?;
    Ok(ZkWitness::try_from_noir_witness_stack_v1_zeroizing(
        circuit_ref,
        witness,
    )?)
}

pub fn binding_for(
    public_inputs: &ZkPublicInputs,
    circuit_ref: ZkCircuitRef,
) -> Result<ZkSessionBinding, MatrixError> {
    let decoded = ZkDecodedPublicInputs::try_decode(circuit_ref, public_inputs)?;
    Ok(ZkSessionBinding {
        nonce_hash: decoded.challenge(),
        audience_hash: decoded.audience_hash(),
        transaction_data_hash: decoded.transaction_data_hash(),
    })
}

fn optional_u8_array_32(source: &str, name: &str) -> Result<Option<[u8; 32]>, MatrixError> {
    match parse_u8_array_32(source, name) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(MatrixError::MissingField) => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn binding_from_prover_toml(
    root: &Path,
    circuit_ref: ZkCircuitRef,
) -> Result<ZkSessionBinding, MatrixError> {
    binding_from_prover_toml_path(circuit_dir(root, circuit_ref).join("Prover.toml").as_path())
}

pub fn binding_from_prover_toml_path(path: &Path) -> Result<ZkSessionBinding, MatrixError> {
    let source = fs::read_to_string(path)?;
    Ok(ZkSessionBinding {
        nonce_hash: parse_u8_array_32(&source, "challenge")?,
        audience_hash: parse_u8_array_32(&source, "audience_hash")?,
        transaction_data_hash: optional_u8_array_32(&source, "transaction_data_hash")?,
    })
}

pub fn write_summary(path: &Path, rows: &[MatrixSummaryRow]) -> Result<(), MatrixError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    writeln!(
        file,
        "circuit\tpackage\tsource_closure_sha256\tartifact_identity_sha256\tartifact_identity_scope\twitness_bytes\tproof_bytes\tpublic_input_bytes\tvk_bytes\twitness_ms\tprove_ms\tverify_ms\tprocess_rss_kib\twrong_nonce\twrong_audience\twrong_transaction\tabsent_transaction\tsentinel_transaction\twrong_circuit\twrong_artifact_identity\twrong_verification_key\ttampered_proof_same_length\ttampered_proof_malformed_length\ttampered_public_inputs"
    )?;
    for row in rows {
        writeln!(
            file,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.circuit_name,
            row.package_name,
            hex32(row.source_closure_sha256.as_bytes()),
            hex32(row.artifact_identity.as_bytes()),
            row.artifact_identity_scope,
            row.witness_bytes,
            row.proof_bytes,
            row.public_input_bytes,
            row.verification_key_bytes,
            row.witness_ms,
            row.prove_ms,
            row.verify_ms,
            row.process_rss_kib,
            row.negatives.wrong_nonce.proto_name(),
            row.negatives.wrong_audience.proto_name(),
            row.negatives.wrong_transaction.proto_name(),
            row.negatives.absent_transaction.proto_name(),
            row.negatives.sentinel_transaction.proto_name(),
            row.negatives.wrong_circuit.proto_name(),
            row.negatives.wrong_artifact_identity.proto_name(),
            row.negatives.wrong_verification_key.proto_name(),
            row.negatives.tampered_proof_same_length.proto_name(),
            row.negatives.tampered_proof_malformed_length.proto_name(),
            row.negatives.tampered_public_inputs.proto_name(),
        )?;
    }
    Ok(())
}

#[allow(unsafe_code)]
pub fn process_rss_kib() -> Result<u64, MatrixError> {
    let mut usage = MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` points to valid writable storage for `getrusage` to
    // initialize, and the call does not retain the pointer.
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if status != 0 {
        return Err(MatrixError::Io(io::Error::last_os_error()));
    }
    // SAFETY: `getrusage` returned success, so the structure is initialized.
    let usage = unsafe { usage.assume_init() };
    let raw = u64::try_from(usage.ru_maxrss).map_err(|_| MatrixError::UnexpectedLength)?;
    #[cfg(target_os = "macos")]
    {
        raw.checked_div(1024).ok_or(MatrixError::UnexpectedLength)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(raw)
    }
}

fn ensure_gzip_transport(bytes: &[u8]) -> Result<(), MatrixError> {
    match bytes.get(..2) {
        Some([0x1f, 0x8b]) => Ok(()),
        _ => Err(MatrixError::InvalidWitnessTransport),
    }
}

fn parse_u8_array_32(source: &str, name: &str) -> Result<[u8; 32], MatrixError> {
    let prefix = format!("{name} = [");
    for line in source.lines() {
        let Some(rest) = line.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let body = rest
            .strip_suffix(']')
            .ok_or(MatrixError::UnexpectedLength)?;
        let mut bytes = [0_u8; 32];
        let mut count = 0_usize;
        for value in body.split(',') {
            let slot = bytes.get_mut(count).ok_or(MatrixError::UnexpectedLength)?;
            *slot = value
                .trim()
                .parse::<u8>()
                .map_err(|_| MatrixError::UnexpectedLength)?;
            count = count.checked_add(1).ok_or(MatrixError::UnexpectedLength)?;
        }
        if count != bytes.len() {
            return Err(MatrixError::UnexpectedLength);
        }
        return Ok(bytes);
    }
    Err(MatrixError::MissingField)
}

fn source_closure_entry(
    lock_path: &Path,
    circuit_ref: ZkCircuitRef,
) -> Result<(String, Digest32), MatrixError> {
    let lock = fs::read_to_string(lock_path)?;
    let expected_circuit = circuit_name(circuit_ref);
    for line in lock.lines().skip(1) {
        let mut fields = line.split('\t');
        if fields.next() == Some(expected_circuit.as_str()) {
            let package = fields.next().ok_or(MatrixError::MissingField)?;
            if package.is_empty()
                || !package
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err(MatrixError::UnexpectedLength);
            }
            let digest = fields.next().ok_or(MatrixError::MissingField)?;
            if fields.next().is_some() {
                return Err(MatrixError::AmbiguousField);
            }
            return Ok((package.to_owned(), parse_digest32(digest)?));
        }
    }
    Err(MatrixError::MissingField)
}

fn recompute_source_closure_digest(
    root: &Path,
    circuit_ref: ZkCircuitRef,
) -> Result<Digest32, MatrixError> {
    let mut source_paths = Vec::new();
    collect_source_files(root, circuit_name(circuit_ref).as_str(), &mut source_paths)?;
    if root.join("vendor").is_dir() {
        collect_source_files(root, "vendor", &mut source_paths)?;
    }
    source_paths.sort();

    let mut closure_lines = Vec::new();
    for source_path in source_paths {
        let source_bytes = fs::read(root.join(source_path.as_str()))?;
        let source_digest = Digest32::sha256(source_bytes.as_slice());
        closure_lines.extend_from_slice(source_path.as_bytes());
        closure_lines.extend_from_slice(b"\t");
        closure_lines.extend_from_slice(hex32(source_digest.as_bytes()).as_bytes());
        closure_lines.extend_from_slice(b"\n");
    }
    Ok(Digest32::sha256(closure_lines.as_slice()))
}

fn collect_source_files(
    root: &Path,
    relative_dir: &str,
    out: &mut Vec<String>,
) -> Result<(), MatrixError> {
    let dir = root.join(relative_dir);
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| MatrixError::UnexpectedLength)?
                .to_str()
                .ok_or(MatrixError::UnexpectedLength)?;
            if !relative.split('/').any(|component| component == "target") {
                collect_source_files(root, relative, out)?;
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            return Err(MatrixError::UnexpectedLength);
        };
        let include = file_name == "Nargo.toml"
            || path.extension().and_then(|value| value.to_str()) == Some("nr");
        if !include {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| MatrixError::UnexpectedLength)?
            .to_str()
            .ok_or(MatrixError::UnexpectedLength)?;
        if relative.split('/').any(|component| component == "target") {
            continue;
        }
        out.push(relative.to_owned());
    }
    Ok(())
}

// This digest binds a source closure, program, and verification key. It is
// an artifact-set identity; no canonical protobuf manifest is hashed here.
fn artifact_identity(
    circuit_ref: ZkCircuitRef,
    source_closure_sha256: Digest32,
    bytecode_sha256: Digest32,
    verification_key_sha256: Digest32,
) -> ZkArtifactSetIdentity {
    let mut material = Vec::new();
    material.extend_from_slice(b"reallyme-zk-linked-all30-v1\n");
    material.extend_from_slice(circuit_name(circuit_ref).as_bytes());
    material.extend_from_slice(b"\n");
    material.extend_from_slice(ZkProofSuite::PRODUCTION.as_str().as_bytes());
    material.extend_from_slice(b"\n");
    material.extend_from_slice(source_closure_sha256.as_bytes());
    material.extend_from_slice(bytecode_sha256.as_bytes());
    material.extend_from_slice(verification_key_sha256.as_bytes());
    ZkArtifactSetIdentity::from_bytes(*Digest32::sha256(material.as_slice()).as_bytes())
}

fn parse_digest32(value: &str) -> Result<Digest32, MatrixError> {
    if value.len() != 64 {
        return Err(MatrixError::UnexpectedLength);
    }
    let mut bytes = [0_u8; 32];
    let (chunks, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(MatrixError::UnexpectedLength);
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(Digest32::from_bytes(bytes))
}

fn hex_nibble(value: u8) -> Result<u8, MatrixError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(MatrixError::UnexpectedLength),
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn circuit_dir(root: &Path, circuit_ref: ZkCircuitRef) -> PathBuf {
    root.join(circuit_ref.credential_hash_algorithm.source_dir())
        .join("families")
        .join(circuit_ref.family.source_dir())
        .join(circuit_ref.stage.source_dir())
}

pub fn circuit_name(circuit_ref: ZkCircuitRef) -> String {
    [
        circuit_ref.credential_hash_algorithm.source_dir(),
        "families",
        circuit_ref.family.source_dir(),
        circuit_ref.stage.source_dir(),
    ]
    .join("/")
}
