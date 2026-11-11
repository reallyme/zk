// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    parse_bytes, poseidon2_bounded, poseidon2_bounded_with_len, FixtureHashError,
    MAX_BOUNDED_INPUT_BYTES,
};

#[test]
fn poseidon2_bounded_matches_reviewed_noir_vector() -> Result<(), FixtureHashError> {
    let hash = poseidon2_bounded(&[1, 2, 3])?;
    assert_eq!(
        hash,
        [
            35, 134, 74, 219, 22, 13, 221, 245, 144, 241, 211, 48, 54, 131, 235, 203, 145, 79, 130,
            142, 38, 53, 246, 232, 90, 50, 240, 161, 174, 205, 61, 216,
        ],
    );
    Ok(())
}

#[test]
fn parser_accepts_explicit_empty_preimage() -> Result<(), FixtureHashError> {
    let bytes = parse_bytes("[]")?;
    assert!(bytes.is_empty());
    let empty_hash = poseidon2_bounded(&bytes)?;
    let one_byte_hash = poseidon2_bounded(&[0])?;
    assert_ne!(empty_hash, one_byte_hash);
    Ok(())
}

#[test]
fn parser_rejects_inputs_larger_than_reviewed_circuit_bound() {
    let input = vec!["1"; MAX_BOUNDED_INPUT_BYTES + 1].join(",");
    assert!(matches!(
        parse_bytes(input.as_str()),
        Err(FixtureHashError::LineTooLarge)
    ));
}

#[test]
fn poseidon2_bounded_accepts_reviewed_maximum_length() -> Result<(), FixtureHashError> {
    let bytes = vec![7_u8; MAX_BOUNDED_INPUT_BYTES];
    let hash = poseidon2_bounded(&bytes)?;
    let repeated_hash = poseidon2_bounded(&bytes)?;

    assert_eq!(hash, repeated_hash);
    Ok(())
}

#[test]
fn poseidon2_bounded_rejects_declared_length_larger_than_buffer() {
    let error = poseidon2_bounded_with_len(&[1, 2, 3], 4)
        .err()
        .map(|error| error == FixtureHashError::InvalidLength);

    assert_eq!(error, Some(true));
}

#[test]
fn poseidon2_bounded_ignores_tail_after_declared_length() -> Result<(), FixtureHashError> {
    let prefix = [1_u8, 2, 3, 4];
    let mut left = [0_u8; 16];
    let mut right = [255_u8; 16];
    left[..prefix.len()].copy_from_slice(&prefix);
    right[..prefix.len()].copy_from_slice(&prefix);

    let left_hash = poseidon2_bounded_with_len(&left, prefix.len())?;
    let right_hash = poseidon2_bounded_with_len(&right, prefix.len())?;
    let extended_hash = poseidon2_bounded_with_len(&right, right.len())?;

    assert_eq!(left_hash, right_hash);
    assert_ne!(left_hash, extended_hash);
    Ok(())
}
