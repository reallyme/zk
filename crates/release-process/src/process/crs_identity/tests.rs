// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{ffi::OsString, path::PathBuf};

use super::{require_modern_crs_identity, G1_BYTES, G1_SHA256, G2_BYTES, G2_SHA256};
use crate::{ReleaseCommand, ReleaseProcessErrorReason, ReleaseTool, ReleaseToolOperation};

#[test]
fn pinned_constants_match_reviewed_lock() {
    let lock = include_str!("../../../../../circuits/toolchain-lock.json");
    let g1_bytes = format!("\"g1SourceBytes\": {G1_BYTES}");
    let g2_bytes = format!("\"g2Bytes\": {G2_BYTES}");
    let g1_sha256 = format!("\"g1SourceSha256\": \"{}\"", hex_lower(&G1_SHA256));
    let g2_sha256 = format!("\"g2Sha256\": \"{}\"", hex_lower(&G2_SHA256));

    assert!(lock.contains("\"bn254FullProver1048577Points\""));
    assert!(lock.contains(&g1_bytes));
    assert!(lock.contains(&g2_bytes));
    assert!(lock.contains(&g1_sha256));
    assert!(lock.contains(&g2_sha256));
}

#[test]
fn modern_command_rejects_missing_crs_before_execution() {
    let missing = std::env::temp_dir().join("reallyme-zk-missing-crs-identity");
    let command = ReleaseCommand {
        tool: ReleaseTool::Barretenberg,
        operation: ReleaseToolOperation::Prove,
        executable: PathBuf::from("/unused/bb"),
        current_directory: None,
        arguments: vec![
            OsString::from("prove"),
            OsString::from("-c"),
            missing.into_os_string(),
        ],
        capture_stdout: false,
    };
    assert_eq!(
        require_modern_crs_identity(&command)
            .err()
            .map(|error| error.reason()),
        Some(ReleaseProcessErrorReason::CrsIdentityMismatch)
    );
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}
