// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use poseidon2::poseidon2::Poseidon2;

// Bounded Poseidon2 over byte input:
// - maps msg[0..len) bytes to Field elements (0..255)
// - hashes with Poseidon2::hash(fields, len)
// - returns 32-byte big-endian output
pub fn poseidon2_bounded<let MAX_LEN: u32>(msg: [u8; MAX_LEN], len: u32) -> [u8; 32] {
    assert(len <= MAX_LEN);

    let mut fields: [Field; MAX_LEN] = [0; MAX_LEN];
    for i in 0..MAX_LEN {
        if i < len {
            fields[i] = msg[i] as Field;
        }
    }

    let h: Field = Poseidon2::hash(fields, len);
    let out: [u8; 32] = h.to_be_bytes();
    out
}
