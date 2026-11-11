// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact audit of one Barretenberg public-input output file.

use std::{
    ffi::OsString,
    fs::{self, File},
    io::{Read, Take},
    path::{Path, PathBuf},
};

use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
};
use reallyme_zk_backend_bb::BarretenbergPublicInputCodec;
use thiserror::Error;

const REQUIRED_ARGUMENT_COUNT: usize = 4;

fn main() -> Result<(), PublicInputAuditError> {
    let arguments = parse_arguments(std::env::args_os())?;
    audit_file(arguments.circuit_ref(), &arguments.input)
}

struct Arguments {
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    bundle_kind: ZkClaimProofBundleKind,
    stage: AuditStage,
    input: PathBuf,
}

impl Arguments {
    const fn circuit_ref(&self) -> ZkCircuitRef {
        match self.stage {
            AuditStage::Production(stage) => self
                .bundle_kind
                .source_ref(self.credential_hash_algorithm, stage),
            AuditStage::ClaimBundle4 => ZkCircuitRef::new(
                self.credential_hash_algorithm,
                self.bundle_kind.family(),
                ZkCircuitStage::ClaimBundle4,
            ),
        }
    }
}

/// Exact stage accepted by the release-output auditor.
///
/// The bundle circuit is deliberately not promoted into `ZkClaimProofBundleStage`:
/// accepting its compiler output for audit must not silently expand the stable
/// provider contract exposed to platform SDKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditStage {
    Production(ZkClaimProofBundleStage),
    ClaimBundle4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicInputAuditErrorReason {
    InvalidArguments,
    InvalidPath,
    Filesystem(std::io::ErrorKind),
    InvalidPublicInputs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("ReallyMe ZK public-input audit failed")]
struct PublicInputAuditError {
    reason: PublicInputAuditErrorReason,
}

impl PublicInputAuditError {
    const fn new(reason: PublicInputAuditErrorReason) -> Self {
        Self { reason }
    }
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, PublicInputAuditError> {
    let mut arguments = arguments.into_iter();
    let _executable = arguments.next();
    let mut values = Vec::new();
    values
        .try_reserve_exact(REQUIRED_ARGUMENT_COUNT)
        .map_err(|_| PublicInputAuditError::new(PublicInputAuditErrorReason::InvalidArguments))?;
    for _ in 0..REQUIRED_ARGUMENT_COUNT {
        values.push(arguments.next().ok_or(PublicInputAuditError::new(
            PublicInputAuditErrorReason::InvalidArguments,
        ))?);
    }
    if arguments.next().is_some() {
        return Err(PublicInputAuditError::new(
            PublicInputAuditErrorReason::InvalidArguments,
        ));
    }
    let mut values = values.into_iter();
    let credential_hash_algorithm = parse_hash(next_utf8(&mut values)?)?;
    let bundle_kind = parse_profile(next_utf8(&mut values)?)?;
    let stage = parse_stage(next_utf8(&mut values)?)?;
    let input = PathBuf::from(values.next().ok_or(PublicInputAuditError::new(
        PublicInputAuditErrorReason::InvalidArguments,
    ))?);
    Ok(Arguments {
        credential_hash_algorithm,
        bundle_kind,
        stage,
        input,
    })
}

fn next_utf8(
    values: &mut impl Iterator<Item = OsString>,
) -> Result<OsString, PublicInputAuditError> {
    let value = values.next().ok_or(PublicInputAuditError::new(
        PublicInputAuditErrorReason::InvalidArguments,
    ))?;
    if value.to_str().is_none() {
        return Err(PublicInputAuditError::new(
            PublicInputAuditErrorReason::InvalidArguments,
        ));
    }
    Ok(value)
}

fn parse_hash(value: OsString) -> Result<ZkCredentialHashAlgorithm, PublicInputAuditError> {
    match value.to_str() {
        Some("sha256") => Ok(ZkCredentialHashAlgorithm::Sha256),
        Some("poseidon2") => Ok(ZkCredentialHashAlgorithm::Poseidon2),
        Some(_) | None => Err(PublicInputAuditError::new(
            PublicInputAuditErrorReason::InvalidArguments,
        )),
    }
}

fn parse_profile(value: OsString) -> Result<ZkClaimProofBundleKind, PublicInputAuditError> {
    match value.to_str() {
        Some("credential_subject_claim_v1") => Ok(ZkClaimProofBundleKind::CredentialSubjectClaimV1),
        Some("private_persona_claim_v1") => Ok(ZkClaimProofBundleKind::PrivatePersonaClaimV1),
        Some(_) | None => Err(PublicInputAuditError::new(
            PublicInputAuditErrorReason::InvalidArguments,
        )),
    }
}

fn parse_stage(value: OsString) -> Result<AuditStage, PublicInputAuditError> {
    match value.to_str() {
        Some("session") => Ok(AuditStage::Production(ZkClaimProofBundleStage::Session)),
        Some("credential_envelope") => Ok(AuditStage::Production(
            ZkClaimProofBundleStage::CredentialEnvelope,
        )),
        Some("credential_root") => Ok(AuditStage::Production(
            ZkClaimProofBundleStage::CredentialRoot,
        )),
        Some("claim") => Ok(AuditStage::Production(ZkClaimProofBundleStage::Claim)),
        Some("claim_bundle_4") => Ok(AuditStage::ClaimBundle4),
        Some(_) | None => Err(PublicInputAuditError::new(
            PublicInputAuditErrorReason::InvalidArguments,
        )),
    }
}

fn audit_file(
    circuit_ref: reallyme_zk_api::circuits::ZkCircuitRef,
    path: &Path,
) -> Result<(), PublicInputAuditError> {
    if !path.is_absolute() {
        return Err(PublicInputAuditError::new(
            PublicInputAuditErrorReason::InvalidPath,
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(filesystem_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PublicInputAuditError::new(
            PublicInputAuditErrorReason::InvalidPath,
        ));
    }
    let expected_len = BarretenbergPublicInputCodec::serialized_len(circuit_ref)
        .map_err(|_| invalid_public_inputs())?;
    let expected_len_u64 = u64::try_from(expected_len).map_err(|_| invalid_public_inputs())?;
    if metadata.len() != expected_len_u64 {
        return Err(invalid_public_inputs());
    }

    let file = File::open(path).map_err(filesystem_error)?;
    let limit = expected_len_u64
        .checked_add(1)
        .ok_or_else(invalid_public_inputs)?;
    let mut bounded: Take<File> = file.take(limit);
    let mut serialized = Vec::new();
    serialized
        .try_reserve_exact(expected_len)
        .map_err(|_| invalid_public_inputs())?;
    bounded
        .read_to_end(&mut serialized)
        .map_err(filesystem_error)?;
    if serialized.len() != expected_len {
        return Err(invalid_public_inputs());
    }

    let compact = BarretenbergPublicInputCodec::decode(circuit_ref, &serialized)
        .map_err(|_| invalid_public_inputs())?;
    let round_trip = BarretenbergPublicInputCodec::encode(circuit_ref, &compact)
        .map_err(|_| invalid_public_inputs())?;
    if round_trip != serialized {
        return Err(invalid_public_inputs());
    }
    Ok(())
}

fn filesystem_error(error: std::io::Error) -> PublicInputAuditError {
    PublicInputAuditError::new(PublicInputAuditErrorReason::Filesystem(error.kind()))
}

const fn invalid_public_inputs() -> PublicInputAuditError {
    PublicInputAuditError::new(PublicInputAuditErrorReason::InvalidPublicInputs)
}

#[cfg(test)]
#[path = "check-public-inputs/tests.rs"]
mod tests;
