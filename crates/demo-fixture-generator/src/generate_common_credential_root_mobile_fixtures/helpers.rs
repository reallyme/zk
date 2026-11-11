// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use buffa::MessageField;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use sha2::{Digest as _, Sha256};

use super::{
    FixtureError, DEFAULT_RETAINED_ARTIFACT_RELATIVE_ROOT, RAW_FIELD_BYTES,
    RETAINED_ARTIFACT_ROOT_ENV,
};

pub(super) fn field_byte(raw: &[u8], index: usize) -> Result<u8, FixtureError> {
    let offset = index
        .checked_mul(RAW_FIELD_BYTES)
        .ok_or(FixtureError::InvalidFixture)?;
    let end = offset
        .checked_add(RAW_FIELD_BYTES)
        .ok_or(FixtureError::InvalidFixture)?;
    let field = raw.get(offset..end).ok_or(FixtureError::InvalidFixture)?;
    if field[..RAW_FIELD_BYTES - 1].iter().any(|byte| *byte != 0) {
        return Err(FixtureError::InvalidFixture);
    }
    Ok(field[RAW_FIELD_BYTES - 1])
}

pub(super) fn field_bytes32(raw: &[u8], start: usize) -> Result<[u8; 32], FixtureError> {
    let mut bytes = [0_u8; 32];
    for (offset, byte) in bytes.iter_mut().enumerate() {
        let index = start
            .checked_add(offset)
            .ok_or(FixtureError::InvalidFixture)?;
        *byte = field_byte(raw, index)?;
    }
    Ok(bytes)
}

pub(super) fn field_u64(raw: &[u8], index: usize) -> Result<u64, FixtureError> {
    let offset = index
        .checked_mul(RAW_FIELD_BYTES)
        .ok_or(FixtureError::InvalidFixture)?;
    let end = offset
        .checked_add(RAW_FIELD_BYTES)
        .ok_or(FixtureError::InvalidFixture)?;
    let field = raw.get(offset..end).ok_or(FixtureError::InvalidFixture)?;
    if field[..RAW_FIELD_BYTES - 8].iter().any(|byte| *byte != 0) {
        return Err(FixtureError::InvalidFixture);
    }
    let last: [u8; 8] = field[RAW_FIELD_BYTES - 8..]
        .try_into()
        .map_err(|_| FixtureError::InvalidFixture)?;
    Ok(u64::from_be_bytes(last))
}

pub(super) fn session_manifest_identity(
    repository: &Path,
    lane: &str,
    mode: &str,
) -> Result<[u8; 32], FixtureError> {
    let directory = retained_artifact_root(repository)
        .join("v1")
        .join(lane)
        .join(format!("{mode}_persona_claim_v1/session"));
    let mut entries = fs::read_dir(directory).map_err(|_| FixtureError::Io)?;
    let entry = entries
        .next()
        .ok_or(FixtureError::InvalidFixture)?
        .map_err(|_| FixtureError::Io)?;
    if entries.next().is_some() {
        return Err(FixtureError::InvalidFixture);
    }
    let name = entry
        .file_name()
        .into_string()
        .map_err(|_| FixtureError::InvalidPath)?;
    let manifest = read_nonempty(&entry.path().join("manifest.pb"))?;
    if hex_digest(&manifest) != name {
        return Err(FixtureError::InvalidFixture);
    }
    hex_digest_bytes(&name)
}

pub(super) fn retained_artifact_root(repository: &Path) -> PathBuf {
    match env::var_os(RETAINED_ARTIFACT_ROOT_ENV) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => repository.join(DEFAULT_RETAINED_ARTIFACT_RELATIVE_ROOT),
    }
}

pub(super) fn key(x: &str, y: &str) -> Result<pb::ZkP256PublicKey, FixtureError> {
    Ok(pb::ZkP256PublicKey {
        x: hex_bytes(x)?,
        y: hex_bytes(y)?,
        ..Default::default()
    })
}

pub(super) fn claim(
    x: &str,
    y: &str,
    name: &str,
    value: &[u8],
) -> Result<pb::ZkCommonCredentialRootClaimExpectation, FixtureError> {
    let mut claim = pb::ZkCommonCredentialRootClaimExpectation::default();
    claim.issuer = MessageField::some(key(x, y)?);
    claim.claim_name_hash = hex_bytes(name)?;
    claim.claim_value = value.to_vec();
    claim.claim_value_length =
        u32::try_from(value.len()).map_err(|_| FixtureError::InvalidFixture)?;
    Ok(claim)
}

pub(super) fn hex_bytes(value: &str) -> Result<Vec<u8>, FixtureError> {
    if value.len() != 64 {
        return Err(FixtureError::InvalidFixture);
    }
    (0..32)
        .map(|index| {
            let offset = index * 2;
            u8::from_str_radix(
                value
                    .get(offset..offset + 2)
                    .ok_or(FixtureError::InvalidFixture)?,
                16,
            )
            .map_err(|_| FixtureError::InvalidFixture)
        })
        .collect()
}

pub(super) fn hex_digest_bytes(value: &str) -> Result<[u8; 32], FixtureError> {
    let bytes = hex_bytes(value)?;
    bytes.try_into().map_err(|_| FixtureError::InvalidFixture)
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn read_nonempty(path: &Path) -> Result<Vec<u8>, FixtureError> {
    let bytes = fs::read(path).map_err(|_| FixtureError::Io)?;
    if bytes.is_empty() {
        return Err(FixtureError::InvalidFixture);
    }
    Ok(bytes)
}
