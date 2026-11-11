// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    CompiledProgramArtifactJson, SerializedWitnessStack, MAX_COMPILED_PROGRAM_ARTIFACT_JSON_BYTES,
};
use crate::WitnessErrorReason;
use zeroize::Zeroizing;

#[test]
fn compiled_artifact_rejects_empty_input() {
    let error = CompiledProgramArtifactJson::try_from_bytes(&[])
        .err()
        .map(|error| error.reason);

    assert_eq!(error, Some(WitnessErrorReason::ArtifactEmpty));
}

#[test]
fn compiled_artifact_rejects_oversized_input() -> Result<(), crate::WitnessError> {
    let oversized_len = MAX_COMPILED_PROGRAM_ARTIFACT_JSON_BYTES
        .checked_add(1)
        .ok_or(crate::WitnessError::new(
            WitnessErrorReason::ArtifactTooLarge,
        ))?;
    let bytes = vec![0_u8; oversized_len];
    let error = CompiledProgramArtifactJson::try_from_bytes(bytes.as_slice())
        .err()
        .map(|error| error.reason);

    assert_eq!(error, Some(WitnessErrorReason::ArtifactTooLarge));
    Ok(())
}

#[test]
fn compiled_artifact_accepts_bounded_nonempty_input() -> Result<(), crate::WitnessError> {
    let artifact = CompiledProgramArtifactJson::try_from_bytes(b"{}")?;

    assert_eq!(artifact.as_bytes(), b"{}");
    Ok(())
}

#[test]
fn serialized_witness_debug_is_redacted() {
    let witness =
        SerializedWitnessStack::from_zeroizing_bytes(Zeroizing::new(vec![17_u8, 23_u8, 42_u8]));
    let debug = format!("{witness:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("17"));
    assert!(!debug.contains("23"));
    assert!(!debug.contains("42"));
}
