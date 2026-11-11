// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::Write as _;

use super::{preflight_json_budget, BoundedJsonWriter, ZkProtoJsonError};

#[test]
fn bounded_writer_rejects_growth_before_appending() -> Result<(), ZkProtoJsonError> {
    let mut writer = BoundedJsonWriter::with_exact_length(4)?;
    assert_eq!(writer.write(b"1234").ok(), Some(4));
    assert!(writer.write(b"5").is_err());
    assert_eq!(writer.bytes.as_slice(), b"1234");
    Ok(())
}

#[test]
fn exact_writer_capacity_never_relocates_sensitive_prefixes() -> Result<(), ZkProtoJsonError> {
    let mut writer = BoundedJsonWriter::with_exact_length(16)?;
    let allocation = writer.bytes.as_ptr();
    assert_eq!(writer.write(b"sensitive").ok(), Some(9));
    assert_eq!(writer.bytes.as_ptr(), allocation);
    assert_eq!(writer.write(b"-suffix").ok(), Some(7));
    assert_eq!(writer.bytes.as_ptr(), allocation);
    assert_eq!(writer.bytes.capacity(), 16);
    Ok(())
}

#[test]
fn preflight_rejects_repeated_container_amplification() {
    let mut json = String::from("[");
    for index in 0..=super::MAX_JSON_CONTAINER_ELEMENTS {
        if index != 0 {
            json.push(',');
        }
        json.push_str("{}");
    }
    json.push(']');

    assert_eq!(
        preflight_json_budget(json.as_bytes()),
        Err(ZkProtoJsonError::JsonTooLarge)
    );
}

#[test]
fn preflight_handles_escaped_delimiters_inside_strings() {
    assert_eq!(
        preflight_json_budget(br#"{"value":"[{},\"escaped\"]"}"#),
        Ok(())
    );
}
