// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs,
    path::{Path, PathBuf},
};

use toml::Value as TomlValue;

use crate::{constants::COMMON_CREDENTIAL_ROOT_FIXTURE_ROOT_ENV, error::HarnessError};

use super::super::COMMON_CREDENTIAL_ROOT_RELEASE_ROOT;

pub(super) fn read_toml(path: PathBuf) -> Result<TomlValue, HarnessError> {
    let text = fs::read_to_string(path)?;
    toml::from_str::<TomlValue>(&text).map_err(|_| HarnessError::InvalidLength)
}

pub(super) fn toml_bytes32(fixture: &TomlValue, key: &str) -> Result<[u8; 32], HarnessError> {
    let bytes = toml_bytes(fixture, key, 32)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| HarnessError::InvalidLength)
}

pub(super) fn toml_bytes(
    fixture: &TomlValue,
    key: &str,
    length: usize,
) -> Result<Vec<u8>, HarnessError> {
    let values = fixture
        .get(key)
        .and_then(TomlValue::as_array)
        .ok_or(HarnessError::MissingField)?;
    if values.len() != length {
        return Err(HarnessError::InvalidLength);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| HarnessError::InvalidLength)?;
    for value in values {
        let integer = value.as_integer().ok_or(HarnessError::InvalidLength)?;
        let byte = u8::try_from(integer).map_err(|_| HarnessError::InvalidLength)?;
        bytes.push(byte);
    }
    Ok(bytes)
}

pub(super) fn toml_u32(fixture: &TomlValue, key: &str) -> Result<u32, HarnessError> {
    let value = fixture
        .get(key)
        .and_then(TomlValue::as_integer)
        .ok_or(HarnessError::MissingField)?;
    u32::try_from(value).map_err(|_| HarnessError::InvalidLength)
}

pub(super) fn toml_u64(fixture: &TomlValue, key: &str) -> Result<u64, HarnessError> {
    let value = fixture
        .get(key)
        .and_then(TomlValue::as_integer)
        .ok_or(HarnessError::MissingField)?;
    u64::try_from(value).map_err(|_| HarnessError::InvalidLength)
}

pub(super) fn common_credential_root_fixture_root() -> Result<PathBuf, HarnessError> {
    std::env::var_os(COMMON_CREDENTIAL_ROOT_FIXTURE_ROOT_ENV)
        .map(PathBuf::from)
        .ok_or(HarnessError::MissingField)
}

pub(in crate::common_credential_root_direct_post) fn repo_root() -> Result<PathBuf, HarnessError> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or(HarnessError::InvalidLength)
}

pub(in crate::common_credential_root_direct_post) fn common_credential_root_release_root(
) -> Result<PathBuf, HarnessError> {
    let root = match std::env::var_os("REALLYME_ZK_COMMON_CREDENTIAL_ROOT_RELEASE_ROOT") {
        Some(path) => PathBuf::from(path),
        None => repo_root()?.join(COMMON_CREDENTIAL_ROOT_RELEASE_ROOT),
    };
    if !root.is_absolute() || !root.is_dir() || root.is_symlink() {
        return Err(HarnessError::InvalidLength);
    }
    Ok(root)
}

pub(super) fn hex_to_digest(value: &str) -> Result<[u8; 32], HarnessError> {
    if value.len() != 64 {
        return Err(HarnessError::InvalidLength);
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = decode_hex(chunk[0])?;
        let low = decode_hex(chunk[1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

const fn decode_hex(byte: u8) -> Result<u8, HarnessError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(HarnessError::InvalidLength),
    }
}
