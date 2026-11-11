// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{NamedPublicInput, MAX_PUBLIC_INPUT_NAME_BYTES};
use crate::errors::ZkErrorReason;

#[test]
fn named_public_input_rejects_empty_name() {
    let err = NamedPublicInput::try_from_parts(String::new(), vec![1])
        .err()
        .unwrap_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(err.reason(), ZkErrorReason::InvalidPublicInputName);
}

#[test]
fn named_public_input_rejects_long_name() {
    let err =
        NamedPublicInput::try_from_parts("a".repeat(MAX_PUBLIC_INPUT_NAME_BYTES + 1), vec![1])
            .err()
            .unwrap_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(err.reason(), ZkErrorReason::InvalidPublicInputName);
}

#[test]
fn named_public_input_debug_redacts_value_bytes() -> Result<(), crate::errors::ZkError> {
    let input = NamedPublicInput::try_from_parts("claim".to_owned(), vec![171, 205])?;
    let debug = format!("{input:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("171"));
    assert!(!debug.contains("205"));
    Ok(())
}
