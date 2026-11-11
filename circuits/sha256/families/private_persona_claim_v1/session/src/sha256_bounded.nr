// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::hash::sha256_compression;

// Bounded SHA-256: hashes msg[0..len) with standard padding.
// MAX_LEN: max bytes allowed at runtime; MAX_BLOCKS: ceil((MAX_LEN+9)/64)
pub fn sha256_bounded<let MAX_LEN: u32, let MAX_BLOCKS: u32>(
    msg: [u8; MAX_LEN],
    len: u32
) -> [u8; 32] {
    // Sanity: len <= MAX_LEN
    assert(len <= MAX_LEN);

    // Initial state
    let mut h: [u32; 8] = [
        0x6a09e667u32, 0xbb67ae85u32, 0x3c6ef372u32, 0xa54ff53au32,
        0x510e527fu32, 0x9b05688cu32, 0x1f83d9abu32, 0x5be0cd19u32,
    ];

    // Compute number of blocks B = ceil((len + 9) / 64)
    let len_plus_9: u32 = len + 9u32;
    let b_tmp: u32 = len_plus_9 + 63u32;
    let B: u32 = b_tmp / 64u32;

    // Ensure the runtime block count fits within the compile-time bound
    assert(B <= MAX_BLOCKS);

    // total bytes = B * 64
    let total_bytes: u32 = B * 64u32;

    // 64-bit bit length (big-endian) = len * 8
    let bitlen_lo: u32 = len * 8u32;
    let bitlen_hi: u32 = 0u32;

    // Process up to MAX_BLOCKS; only compress when b < B
    for b in 0..MAX_BLOCKS {
        let active: bool = b < B;

        // Build 16 big-endian u32 words for block b
        let mut blk: [u32; 16] = [0u32; 16];

        // pos 0..63 within the block
        for pos in 0..64 {
            // Only construct bytes for active blocks
            let mut by: u8 = 0u8;

            if active {
                let g: u32 = b * 64u32 + (pos as u32);

                if g < len {
                    by = msg[g];
                } else if g == len {
                    by = 0x80u8;
                } else {
                    // Last 8 bytes hold the 64-bit big-endian bit length
                    let last_region_start: u32 = total_bytes - 8u32;
                    if g >= last_region_start {
                        let off: u32 = g - last_region_start; // 0..7
                        // Map off to the correct bitlen byte
                        if off == 0u32      { by = ((bitlen_hi >> 24) & 0xff) as u8; }
                        else if off == 1u32 { by = ((bitlen_hi >> 16) & 0xff) as u8; }
                        else if off == 2u32 { by = ((bitlen_hi >>  8) & 0xff) as u8; }
                        else if off == 3u32 { by = ( bitlen_hi        & 0xff) as u8; }
                        else if off == 4u32 { by = ((bitlen_lo >> 24) & 0xff) as u8; }
                        else if off == 5u32 { by = ((bitlen_lo >> 16) & 0xff) as u8; }
                        else if off == 6u32 { by = ((bitlen_lo >>  8) & 0xff) as u8; }
                        else /* off == 7 */ { by = ( bitlen_lo        & 0xff) as u8; }
                    } // else by = 0
                }
            }

            // Pack into big-endian 32-bit words
            let wi: u32 = (pos as u32) / 4u32;           // 0..15
            let bi: u32 = (pos as u32) % 4u32;           // 0..3
            let sh: u32 = (3u32 - bi) * 8u32;            // 24,16,8,0
            blk[wi] = blk[wi] | ((by as u32) << sh);
        }

        // Compress active blocks
        if active {
            h = sha256_compression(blk, h);
        }
    }

    // Serialize state to 32 bytes (big-endian)
    let mut out: [u8; 32] = [0u8; 32];
    for j in 0..8 {
        let w = h[j];
        out[4*j + 0] = ((w >> 24) & 0xff) as u8;
        out[4*j + 1] = ((w >> 16) & 0xff) as u8;
        out[4*j + 2] = ((w >>  8) & 0xff) as u8;
        out[4*j + 3] = ( w         & 0xff) as u8;
    }
    out
}
