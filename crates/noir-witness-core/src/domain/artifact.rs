// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::Zeroizing;

use crate::{WitnessError, WitnessErrorReason};

/// Maximum admitted compiled-program JSON size.
///
/// Current production artifacts are below two MiB. The larger ceiling leaves
/// room for reviewed circuit growth while preventing an untrusted caller from
/// handing the JSON parser an effectively unbounded allocation workload.
pub const MAX_COMPILED_PROGRAM_ARTIFACT_JSON_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledProgramArtifactJson<'a> {
    bytes: &'a [u8],
}

impl<'a> CompiledProgramArtifactJson<'a> {
    pub fn try_from_bytes(bytes: &'a [u8]) -> Result<Self, WitnessError> {
        if bytes.is_empty() {
            return Err(WitnessError::new(WitnessErrorReason::ArtifactEmpty));
        }
        if bytes.len() > MAX_COMPILED_PROGRAM_ARTIFACT_JSON_BYTES {
            return Err(WitnessError::new(WitnessErrorReason::ArtifactTooLarge));
        }
        Ok(Self { bytes })
    }

    pub(crate) fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

pub struct SerializedWitnessStack(Zeroizing<Vec<u8>>);

impl SerializedWitnessStack {
    pub(crate) fn from_zeroizing_bytes(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub fn into_zeroizing_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SerializedWitnessStack {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SerializedWitnessStack")
            .field("len", &self.0.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests;
