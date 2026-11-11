// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::sha256_bounded;

// SHA-256("ReallyMe/common-credential-root/v1/HKDF-Extract"). The public salt separates
// this use of the wallet root from every other derivation protocol.
global EXTRACT_SALT: [u8; 32] = [
    0x6b, 0xdb, 0x78, 0xe0, 0xe7, 0x35, 0x2c, 0x06, 0x0b, 0x77, 0x72, 0xc9, 0xc8, 0xe7, 0xbb, 0x9d,
    0x51, 0xd9, 0x99, 0xc3, 0xce, 0xd1, 0x01, 0x8e, 0xac, 0xda, 0xc8, 0x51, 0x8d, 0xdd, 0x2e, 0xf9,
];

fn hmac_sha256_32(message: [u8; 32], key: [u8; 32]) -> [u8; 32] {
    let mut inner: [u8; 96] = [0u8; 96];
    let mut outer: [u8; 96] = [0u8; 96];
    for i in 0..64 {
        let key_byte = if i < 32 { key[i] } else { 0u8 };
        inner[i] = key_byte ^ 0x36u8;
        outer[i] = key_byte ^ 0x5cu8;
    }
    for i in 0..32 {
        inner[64 + i] = message[i];
    }
    let inner_digest = sha256_bounded::sha256_bounded::<96, 2>(inner, 96u32);
    for i in 0..32 {
        outer[64 + i] = inner_digest[i];
    }
    sha256_bounded::sha256_bounded::<96, 2>(outer, 96u32)
}

fn hmac_sha256_33(message: [u8; 33], key: [u8; 32]) -> [u8; 32] {
    let mut inner: [u8; 97] = [0u8; 97];
    let mut outer: [u8; 96] = [0u8; 96];
    for i in 0..64 {
        let key_byte = if i < 32 { key[i] } else { 0u8 };
        inner[i] = key_byte ^ 0x36u8;
        outer[i] = key_byte ^ 0x5cu8;
    }
    for i in 0..33 {
        inner[64 + i] = message[i];
    }
    let inner_digest = sha256_bounded::sha256_bounded::<97, 2>(inner, 97u32);
    for i in 0..32 {
        outer[64 + i] = inner_digest[i];
    }
    sha256_bounded::sha256_bounded::<96, 2>(outer, 96u32)
}

pub fn extract(root: [u8; 32]) -> [u8; 32] {
    hmac_sha256_32(root, EXTRACT_SALT)
}

pub fn expand_lineage(prk: [u8; 32], context_hash: [u8; 32]) -> [u8; 32] {
    let mut info: [u8; 33] = [0u8; 33];
    for i in 0..32 {
        info[i] = context_hash[i];
    }
    // RFC 5869's first expansion block uses a one-byte counter of one.
    info[32] = 1u8;
    hmac_sha256_33(info, prk)
}

#[test]
fn extract_and_expand_match_reference_vector() {
    let mut root: [u8; 32] = [0u8; 32];
    let mut context_hash: [u8; 32] = [0u8; 32];
    for i in 0..32 {
        root[i] = i as u8;
        context_hash[i] = (31 - i) as u8;
    }
    let prk = extract(root);
    let tag = expand_lineage(prk, context_hash);
    assert(
        prk
            == [
                0xd6, 0x99, 0xbf, 0x1f, 0x7f, 0xfc, 0x90, 0x78, 0x8a, 0xf8, 0xa3, 0xd8, 0xc5, 0x4a,
                0xc5, 0xd8, 0xf0, 0xef, 0x10, 0x34, 0x59, 0x0e, 0xd5, 0xfc, 0xb2, 0xde, 0xba, 0x20,
                0xe1, 0x73, 0x4e, 0x88,
            ],
    );
    assert(
        tag
            == [
                0xd1, 0x3d, 0xa7, 0x79, 0xd7, 0x23, 0x7e, 0xcd, 0x81, 0xc7, 0x36, 0x95, 0xb7, 0x4e,
                0x26, 0x7b, 0xdd, 0x03, 0x81, 0x0b, 0xe3, 0x6b, 0xe7, 0x63, 0x1a, 0xc1, 0x76, 0x65,
                0x3e, 0x93, 0x1b, 0x9d,
            ],
    );
}
