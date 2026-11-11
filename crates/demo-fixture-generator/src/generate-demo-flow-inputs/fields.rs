// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fs, path::Path};

use serde_json::{json, Map, Value};

use super::{FixtureCredentialHashAlgorithm, FixtureError};

pub(super) struct ProverFields {
    values: toml::map::Map<String, toml::Value>,
}

impl ProverFields {
    pub(super) fn read(
        root: &Path,
        credential_hash_algorithm: FixtureCredentialHashAlgorithm,
        profile: &str,
        stage: &str,
    ) -> Result<Self, FixtureError> {
        let path = root
            .join("circuits")
            .join(credential_hash_algorithm.directory())
            .join("families")
            .join(profile)
            .join(stage)
            .join("Prover.toml");
        let source = fs::read_to_string(path).map_err(|_| FixtureError::Io)?;
        let parsed: toml::Value = toml::from_str(&source).map_err(|_| FixtureError::Toml)?;
        let values = parsed.as_table().ok_or(FixtureError::Toml)?.clone();
        Ok(Self { values })
    }

    pub(super) fn flat_json(&self) -> Result<Vec<u8>, FixtureError> {
        let mut object = Map::new();
        for (key, value) in &self.values {
            object.insert(key.clone(), toml_to_json(value)?);
        }
        let mut bytes =
            serde_json::to_vec_pretty(&Value::Object(object)).map_err(|_| FixtureError::Json)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub(super) fn bytes(
        &self,
        key: &'static str,
        expected_len: usize,
    ) -> Result<Vec<u8>, FixtureError> {
        let value = self.values.get(key).ok_or(FixtureError::MissingField)?;
        fixed_bytes(value, expected_len)
    }

    pub(super) fn uint32(&self, key: &'static str) -> Result<u32, FixtureError> {
        let value = self.uint64(key)?;
        u32::try_from(value).map_err(|_| FixtureError::Decode)
    }

    pub(super) fn uint64(&self, key: &'static str) -> Result<u64, FixtureError> {
        let value = self.values.get(key).ok_or(FixtureError::MissingField)?;
        let integer = value.as_integer().ok_or(FixtureError::Decode)?;
        u64::try_from(integer).map_err(|_| FixtureError::Decode)
    }

    pub(super) fn merkle_path(&self, key: &'static str) -> Result<Vec<Vec<u8>>, FixtureError> {
        let value = self.values.get(key).ok_or(FixtureError::MissingField)?;
        let rows = value.as_array().ok_or(FixtureError::Decode)?;
        if rows.len() != 6 {
            return Err(FixtureError::Decode);
        }
        let mut path = Vec::with_capacity(rows.len());
        for row in rows {
            path.push(fixed_bytes(row, 32)?);
        }
        Ok(path)
    }
}

fn toml_to_json(value: &toml::Value) -> Result<Value, FixtureError> {
    match value {
        toml::Value::Integer(integer) => Ok(json!(integer)),
        toml::Value::Array(values) => {
            let mut out = Vec::with_capacity(values.len());
            for item in values {
                out.push(toml_to_json(item)?);
            }
            Ok(Value::Array(out))
        }
        _ => Err(FixtureError::Toml),
    }
}

fn fixed_bytes(value: &toml::Value, expected_len: usize) -> Result<Vec<u8>, FixtureError> {
    let values = value.as_array().ok_or(FixtureError::Decode)?;
    if values.len() != expected_len {
        return Err(FixtureError::Decode);
    }
    let mut bytes = Vec::with_capacity(expected_len);
    for value in values {
        let integer = value.as_integer().ok_or(FixtureError::Decode)?;
        bytes.push(u8::try_from(integer).map_err(|_| FixtureError::Decode)?);
    }
    Ok(bytes)
}
