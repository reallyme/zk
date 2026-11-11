// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Retained SHA-256 bounded-hash vectors for declared-length tail handling.
//!
//! Noir source-contract tests assert the in-circuit implementation continues to
//! read only `msg[0..len)`. These vectors keep the host-side reviewed semantics
//! explicit for minimum, maximum, oversize, and tail-noninterference cases.

const HASH_BYTES: usize = 32;
const MAX_BOUNDED_INPUT_BYTES: usize = 515;
const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_LENGTH_BYTES: usize = 8;

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[test]
fn sha256_bounded_accepts_empty_and_distinguishes_one_byte() -> Result<(), TestError> {
    let empty = sha256_bounded_reference(&[], 0)?;
    let one_zero = sha256_bounded_reference(&[0], 1)?;

    assert_ne!(empty, one_zero);
    Ok(())
}

#[test]
fn sha256_bounded_accepts_reviewed_maximum_length() -> Result<(), TestError> {
    let bytes = vec![11_u8; MAX_BOUNDED_INPUT_BYTES];
    let hash = sha256_bounded_reference(&bytes, bytes.len())?;
    let repeated_hash = sha256_bounded_reference(&bytes, bytes.len())?;

    assert_eq!(hash, repeated_hash);
    Ok(())
}

#[test]
fn sha256_bounded_rejects_oversized_buffers() {
    let bytes = vec![0_u8; MAX_BOUNDED_INPUT_BYTES + 1];
    assert!(matches!(
        sha256_bounded_reference(&bytes, bytes.len()),
        Err(TestError::LineTooLarge)
    ));
}

#[test]
fn sha256_bounded_rejects_declared_length_larger_than_buffer() {
    assert!(matches!(
        sha256_bounded_reference(&[1, 2, 3], 4),
        Err(TestError::InvalidLength)
    ));
}

#[test]
fn sha256_bounded_ignores_tail_after_declared_length() -> Result<(), TestError> {
    let prefix = [1_u8, 2, 3, 4];
    let mut left = [0_u8; 16];
    let mut right = [255_u8; 16];
    left[..prefix.len()].copy_from_slice(&prefix);
    right[..prefix.len()].copy_from_slice(&prefix);

    let left_hash = sha256_bounded_reference(&left, prefix.len())?;
    let right_hash = sha256_bounded_reference(&right, prefix.len())?;
    let extended_hash = sha256_bounded_reference(&right, right.len())?;

    assert_eq!(left_hash, right_hash);
    assert_ne!(left_hash, extended_hash);
    Ok(())
}

fn sha256_bounded_reference(
    buffer: &[u8],
    declared_len: usize,
) -> Result<[u8; HASH_BYTES], TestError> {
    if buffer.len() > MAX_BOUNDED_INPUT_BYTES {
        return Err(TestError::LineTooLarge);
    }
    if declared_len > buffer.len() {
        return Err(TestError::InvalidLength);
    }

    sha256_digest(&buffer[..declared_len])
}

fn sha256_digest(message: &[u8]) -> Result<[u8; HASH_BYTES], TestError> {
    let bit_length = u64::try_from(message.len())
        .map_err(|_| TestError::InvalidLength)?
        .checked_mul(8)
        .ok_or(TestError::InvalidLength)?;
    let padded_capacity = message
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(SHA256_LENGTH_BYTES))
        .and_then(|value| value.checked_add(SHA256_BLOCK_BYTES - 1))
        .ok_or(TestError::InvalidLength)?;
    let mut padded = Vec::new();
    padded
        .try_reserve_exact(padded_capacity)
        .map_err(|_| TestError::InvalidLength)?;
    padded.extend_from_slice(message);
    padded.push(0x80);
    while padded
        .len()
        .checked_add(SHA256_LENGTH_BYTES)
        .ok_or(TestError::InvalidLength)?
        % SHA256_BLOCK_BYTES
        != 0
    {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = [
        0x6a09e667_u32,
        0xbb67ae85_u32,
        0x3c6ef372_u32,
        0xa54ff53a_u32,
        0x510e527f_u32,
        0x9b05688c_u32,
        0x1f83d9ab_u32,
        0x5be0cd19_u32,
    ];

    let (chunks, remainder) = padded.as_chunks::<SHA256_BLOCK_BYTES>();
    if !remainder.is_empty() {
        return Err(TestError::InvalidLength);
    }
    for chunk in chunks {
        compress_sha256_block(&mut state, chunk)?;
    }

    let mut out = [0_u8; HASH_BYTES];
    for (index, word) in state.iter().enumerate() {
        let start = index.checked_mul(4).ok_or(TestError::InvalidLength)?;
        let end = start.checked_add(4).ok_or(TestError::InvalidLength)?;
        out[start..end].copy_from_slice(&word.to_be_bytes());
    }
    Ok(out)
}

fn compress_sha256_block(state: &mut [u32; 8], block: &[u8]) -> Result<(), TestError> {
    if block.len() != SHA256_BLOCK_BYTES {
        return Err(TestError::InvalidLength);
    }

    let mut schedule = [0_u32; 64];
    let (words, remainder) = block.as_chunks::<4>();
    if !remainder.is_empty() {
        return Err(TestError::InvalidLength);
    }
    for (index, word_bytes) in words.iter().enumerate() {
        schedule[index] = u32::from_be_bytes(*word_bytes);
    }
    for index in 16..64 {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum TestError {
    InvalidLength,
    LineTooLarge,
}
