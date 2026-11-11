// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use reallyme_zk_api::{circuits::ZkCircuitStage, keys::ZkIssuerPublicKey};

use crate::error::HarnessError;

#[derive(PartialEq, Eq)]
struct SubjectKey {
    x: [u8; 32],
    y: [u8; 32],
}

pub(crate) struct CredentialFixture {
    session_toml: PathBuf,
    envelope_toml: PathBuf,
    root_toml: PathBuf,
    claim_toml: PathBuf,
    status_toml: PathBuf,
    pub(crate) issuer_key: ZkIssuerPublicKey,
    subject_key: SubjectKey,
    credential_binding: [u8; 32],
    session_link: [u8; 32],
    expiry_unix: u64,
}

pub(crate) struct FixtureIssuerStatus {
    pub(crate) list_id: [u8; 32],
    pub(crate) url_hash: [u8; 32],
    pub(crate) status_chunk: [u8; 32],
    pub(crate) length: u64,
    pub(crate) verification_time_unix: u64,
}

impl CredentialFixture {
    pub(crate) fn try_new(root: &Path, name: &str) -> Result<Self, HarnessError> {
        let session_toml = root.join("session").join("Prover.toml");
        let credential_root = root.join(name);
        let envelope_toml = credential_root
            .join("credential_envelope")
            .join("Prover.toml");
        let root_toml = credential_root.join("credential_root").join("Prover.toml");
        let claim_toml = credential_root.join("claim").join("Prover.toml");
        let status_toml = credential_root
            .join("issuer_credential_status")
            .join("Prover.toml");
        for path in [
            &session_toml,
            &envelope_toml,
            &root_toml,
            &claim_toml,
            &status_toml,
        ] {
            if !path.is_file() {
                return Err(HarnessError::MissingField);
            }
        }
        let claim_source = fs::read_to_string(&claim_toml)?;
        let issuer_key = ZkIssuerPublicKey {
            x: parse_u8_array_32(&claim_source, "pk_issuer_x")?,
            y: parse_u8_array_32(&claim_source, "pk_issuer_y")?,
        };
        let subject_key = SubjectKey {
            x: parse_u8_array_32(&claim_source, "pk_subject_x")?,
            y: parse_u8_array_32(&claim_source, "pk_subject_y")?,
        };
        let credential_binding = parse_u8_array_32(&claim_source, "credential_binding")?;
        let session_link = parse_u8_array_32(&claim_source, "session_binding")?;
        let session_source = fs::read_to_string(&session_toml)?;
        let expiry_unix = parse_u64_field(&session_source, "expiry_unix")?;
        Ok(Self {
            session_toml,
            envelope_toml,
            root_toml,
            claim_toml,
            status_toml,
            issuer_key,
            subject_key,
            credential_binding,
            session_link,
            expiry_unix,
        })
    }

    pub(crate) fn prover_toml_for(&self, stage: ZkCircuitStage) -> Result<PathBuf, HarnessError> {
        match stage {
            ZkCircuitStage::Session => Ok(self.session_toml.clone()),
            ZkCircuitStage::CredentialEnvelope => Ok(self.envelope_toml.clone()),
            ZkCircuitStage::CredentialRoot => Ok(self.root_toml.clone()),
            ZkCircuitStage::Claim => Ok(self.claim_toml.clone()),
            ZkCircuitStage::IssuerCredentialStatus => Ok(self.status_toml.clone()),
            ZkCircuitStage::ClaimBundle4 => Err(HarnessError::InvalidLength),
            _ => Err(HarnessError::InvalidLength),
        }
    }

    pub(crate) fn issuer_status(&self) -> Result<FixtureIssuerStatus, HarnessError> {
        let source = fs::read_to_string(&self.status_toml)?;
        Ok(FixtureIssuerStatus {
            list_id: parse_u8_array_32(&source, "status_list_id")?,
            url_hash: parse_u8_array_32(&source, "status_url_hash")?,
            status_chunk: parse_u8_array_32(&source, "status_chunk")?,
            length: parse_u64_field(&source, "status_length")?,
            verification_time_unix: parse_u64_field(&source, "verifier_now")?,
        })
    }
}

pub(crate) fn validate_fixture_relationships(
    first: &CredentialFixture,
    second: &CredentialFixture,
    wrong: &CredentialFixture,
) -> Result<(), HarnessError> {
    if first.subject_key == second.subject_key
        || first.issuer_key == second.issuer_key
        || first.credential_binding == second.credential_binding
        || first.session_link != second.session_link
        || first.subject_key != wrong.subject_key
        || first.issuer_key != wrong.issuer_key
        || first.credential_binding != wrong.credential_binding
        || first.session_link == wrong.session_link
    {
        return Err(HarnessError::InvalidLength);
    }
    Ok(())
}

pub(crate) fn trusted_issuers_from_fixtures<const N: usize>(
    fixtures: [&CredentialFixture; N],
) -> Result<Vec<ZkIssuerPublicKey>, HarnessError> {
    let mut issuers = Vec::new();
    issuers
        .try_reserve_exact(N)
        .map_err(|_| HarnessError::InvalidLength)?;
    for fixture in fixtures {
        if !issuers.contains(&fixture.issuer_key) {
            issuers.push(fixture.issuer_key);
        }
    }
    Ok(issuers)
}

pub(crate) fn verification_time_for_fixtures<const N: usize>(
    fixtures: [&CredentialFixture; N],
) -> Result<u64, HarnessError> {
    let earliest_expiry = fixtures
        .iter()
        .map(|fixture| fixture.expiry_unix)
        .min()
        .ok_or(HarnessError::MissingField)?;
    earliest_expiry
        .checked_sub(60)
        .ok_or(HarnessError::InvalidLength)
}

pub(crate) fn lower_hex(bytes: &[u8; 32]) -> Result<String, HarnessError> {
    let mut out = String::new();
    out.try_reserve_exact(64)
        .map_err(|_| HarnessError::InvalidLength)?;
    for byte in bytes {
        write!(out, "{byte:02x}").map_err(|_| HarnessError::InvalidLength)?;
    }
    Ok(out)
}

fn parse_u8_array_32(source: &str, name: &str) -> Result<[u8; 32], HarnessError> {
    let value = field_value(source, name)?;
    let body = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or(HarnessError::InvalidLength)?;
    let mut bytes = [0_u8; 32];
    let mut count = 0_usize;
    for value in body.split(',') {
        let slot = bytes.get_mut(count).ok_or(HarnessError::InvalidLength)?;
        let value = value.trim();
        if value.is_empty() {
            return Err(HarnessError::InvalidLength);
        }
        *slot = value
            .parse::<u8>()
            .map_err(|_| HarnessError::InvalidLength)?;
        count = count.checked_add(1).ok_or(HarnessError::InvalidLength)?;
    }
    if count != bytes.len() {
        return Err(HarnessError::InvalidLength);
    }
    Ok(bytes)
}

fn parse_u64_field(source: &str, name: &str) -> Result<u64, HarnessError> {
    field_value(source, name)?
        .parse::<u64>()
        .map_err(|_| HarnessError::InvalidLength)
}

fn field_value<'a>(source: &'a str, name: &str) -> Result<&'a str, HarnessError> {
    let mut found = None;
    for line in source.lines() {
        let candidate = line
            .split_once('#')
            .map_or(line, |(before_comment, _comment)| before_comment)
            .trim();
        if candidate.is_empty() {
            continue;
        }
        let Some((key, value)) = candidate.split_once('=') else {
            continue;
        };
        if key.trim() != name {
            continue;
        }
        if found.is_some() {
            return Err(HarnessError::AmbiguousField);
        }
        found = Some(value.trim());
    }
    found.ok_or(HarnessError::MissingField)
}
