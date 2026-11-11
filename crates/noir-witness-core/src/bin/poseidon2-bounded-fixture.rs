// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Computes the byte-bounded Poseidon2 hash used by the imported Noir fixtures.
//!
//! This binary is a fixture regeneration oracle. Production off-circuit
//! Poseidon2 APIs belong in reallyme/crypto so application code does not grow a
//! second hashing implementation inside the ZK repository.

use std::io::{self, Read, Write};

use acir::{AcirField, FieldElement};
use bn254_blackbox_solver::poseidon2_permutation;
use thiserror::Error;

const RATE: usize = 3;
const STATE_WIDTH: usize = 4;
const HASH_BYTES: usize = 32;
const MAX_BOUNDED_INPUT_BYTES: usize = 515;
const MAX_FIXTURE_LINES: usize = 128;
const MAX_DECIMAL_BYTE_WIDTH: usize = 3;
const MAX_LINE_BYTES: usize =
    (MAX_BOUNDED_INPUT_BYTES * (MAX_DECIMAL_BYTE_WIDTH + 1)).saturating_sub(1);
const MAX_STDIN_BYTES: usize = (MAX_LINE_BYTES + 1) * MAX_FIXTURE_LINES;

fn main() -> Result<(), FixtureHashError> {
    let input = read_bounded_stdin()?;
    let mut stdout = io::stdout().lock();
    let mut line_count = 0_usize;
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        line_count = line_count
            .checked_add(1)
            .ok_or(FixtureHashError::TooManyLines)?;
        if line_count > MAX_FIXTURE_LINES {
            return Err(FixtureHashError::TooManyLines);
        }
        let bytes = parse_bytes(trimmed)?;
        let hash = poseidon2_bounded(&bytes)?;
        for (index, byte) in hash.iter().enumerate() {
            if index > 0 {
                stdout
                    .write_all(b",")
                    .map_err(|_| FixtureHashError::Write)?;
            }
            write!(stdout, "{byte}").map_err(|_| FixtureHashError::Write)?;
        }
        stdout
            .write_all(b"\n")
            .map_err(|_| FixtureHashError::Write)?;
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
enum FixtureHashError {
    #[error("fixture input is too large")]
    InputTooLarge,
    #[error("fixture input line is too large")]
    LineTooLarge,
    #[error("fixture input is not UTF-8")]
    InvalidUtf8,
    #[error("fixture input has too many lines")]
    TooManyLines,
    #[error("fixture byte value is invalid")]
    InvalidByte,
    #[error("fixture hash length is invalid")]
    InvalidHashLength,
    #[error("fixture length conversion failed")]
    InvalidLength,
    #[error("Poseidon2 permutation failed")]
    Poseidon2,
    #[error("fixture input could not be read")]
    Read,
    #[error("fixture output could not be written")]
    Write,
}

fn read_bounded_stdin() -> Result<String, FixtureHashError> {
    let mut stdin = io::stdin().take(stdin_limit()?);
    let mut input = Vec::new();
    input
        .try_reserve_exact(MAX_STDIN_BYTES)
        .map_err(|_| FixtureHashError::InputTooLarge)?;
    stdin
        .read_to_end(&mut input)
        .map_err(|_| FixtureHashError::Read)?;
    if input.len() > MAX_STDIN_BYTES {
        return Err(FixtureHashError::InputTooLarge);
    }
    String::from_utf8(input).map_err(|_| FixtureHashError::InvalidUtf8)
}

fn stdin_limit() -> Result<u64, FixtureHashError> {
    let limit = MAX_STDIN_BYTES
        .checked_add(1)
        .ok_or(FixtureHashError::InputTooLarge)?;
    u64::try_from(limit).map_err(|_| FixtureHashError::InvalidLength)
}

fn parse_bytes(input: &str) -> Result<Vec<u8>, FixtureHashError> {
    let trimmed = input.trim();
    if trimmed == "[]" {
        return Ok(Vec::new());
    }
    if trimmed.is_empty() {
        return Err(FixtureHashError::InvalidByte);
    }
    if trimmed.len() > MAX_LINE_BYTES {
        return Err(FixtureHashError::LineTooLarge);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(MAX_BOUNDED_INPUT_BYTES)
        .map_err(|_| FixtureHashError::InputTooLarge)?;
    for part in trimmed.split(',') {
        if out.len() == MAX_BOUNDED_INPUT_BYTES {
            return Err(FixtureHashError::LineTooLarge);
        }
        let value = part
            .trim()
            .parse::<u16>()
            .map_err(|_| FixtureHashError::InvalidByte)?;
        out.push(u8::try_from(value).map_err(|_| FixtureHashError::InvalidByte)?);
    }
    Ok(out)
}

fn poseidon2_bounded(bytes: &[u8]) -> Result<[u8; HASH_BYTES], FixtureHashError> {
    poseidon2_bounded_with_len(bytes, bytes.len())
}

fn poseidon2_bounded_with_len(
    bytes: &[u8],
    declared_len: usize,
) -> Result<[u8; HASH_BYTES], FixtureHashError> {
    if bytes.len() > MAX_BOUNDED_INPUT_BYTES {
        return Err(FixtureHashError::LineTooLarge);
    }
    if declared_len > bytes.len() {
        return Err(FixtureHashError::InvalidLength);
    }
    let length = u128::try_from(declared_len).map_err(|_| FixtureHashError::InvalidLength)?;
    let iv = FieldElement::from(length) * FieldElement::from(1_u128 << 64);
    let mut state = [FieldElement::zero(); STATE_WIDTH];
    state[RATE] = iv;
    let mut cache = [FieldElement::zero(); RATE];
    let mut cache_size = 0_usize;

    for byte in bytes.iter().take(declared_len) {
        if cache_size == RATE {
            perform_duplex(&mut state, &cache, cache_size)?;
            cache.fill(FieldElement::zero());
            cache[0] = FieldElement::from(*byte);
            cache_size = 1;
        } else {
            cache[cache_size] = FieldElement::from(*byte);
            cache_size += 1;
        }
    }
    perform_duplex(&mut state, &cache, cache_size)?;
    state[0]
        .to_be_bytes()
        .try_into()
        .map_err(|_| FixtureHashError::InvalidHashLength)
}

fn perform_duplex(
    state: &mut [FieldElement; STATE_WIDTH],
    cache: &[FieldElement],
    cache_size: usize,
) -> Result<(), FixtureHashError> {
    for index in 0..RATE {
        if index < cache_size {
            state[index] += cache[index];
        }
    }
    let next = poseidon2_permutation(state.as_slice()).map_err(|_| FixtureHashError::Poseidon2)?;
    let next: [FieldElement; STATE_WIDTH] = next
        .try_into()
        .map_err(|_| FixtureHashError::InvalidHashLength)?;
    *state = next;
    Ok(())
}

#[cfg(test)]
#[path = "poseidon2_bounded_fixture/tests.rs"]
mod tests;
