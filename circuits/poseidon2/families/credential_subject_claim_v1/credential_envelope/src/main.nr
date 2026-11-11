// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod poseidon2_bounded;
use std::ecdsa_secp256r1;

global ENVB_TAG_LEN: u32 = 5; // "ENVB1"
global ENVB_LEN: u32     = ENVB_TAG_LEN + 32 + 32 + 32 + 32 + 32 + 32 + 8;

fn is_zero32(arr: [u8; 32]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..32 { acc = acc | arr[i]; }
    acc == 0u8
}

fn u64_to_be_bytes(x: u64) -> [u8; 8] {
    let mut out: [u8; 8] = [0u8; 8];
    out[0] = ((x >> 56) & 0xff) as u8;
    out[1] = ((x >> 48) & 0xff) as u8;
    out[2] = ((x >> 40) & 0xff) as u8;
    out[3] = ((x >> 32) & 0xff) as u8;
    out[4] = ((x >> 24) & 0xff) as u8;
    out[5] = ((x >> 16) & 0xff) as u8;
    out[6] = ((x >>  8) & 0xff) as u8;
    out[7] = ( x        & 0xff) as u8;
    out
}

pub fn main(
    pk_issuer_x: pub [u8; 32],
    pk_issuer_y: pub [u8; 32],
    challenge: pub [u8; 32],
    audience_hash: pub [u8; 32],
    transaction_data_hash: pub [u8; 32],
    expiry_unix: pub u64,
    envelope_binding: pub [u8; 32],

    envelope_hash: [u8; 32],
    issuer_sig: [u8; 64],
) {
    let issuer_pk_zero: bool = is_zero32(pk_issuer_x) & is_zero32(pk_issuer_y);
    assert(!issuer_pk_zero, "issuer pk zero");
    assert(!is_zero32(envelope_hash), "envelope hash zero");
    assert(!is_zero32(challenge), "challenge must be non-zero");
    assert(!is_zero32(audience_hash), "audience hash must be non-zero");
    assert(!is_zero32(transaction_data_hash), "transaction data hash must be non-zero");

    assert(
        ecdsa_secp256r1::verify_signature(pk_issuer_x, pk_issuer_y, issuer_sig, envelope_hash),
        "issuer signature invalid"
    );

    let expiry_bytes = u64_to_be_bytes(expiry_unix);
    let mut bind_pre: [u8; ENVB_LEN] = [0u8; ENVB_LEN];
    bind_pre[0] = 0x45; bind_pre[1] = 0x4E; bind_pre[2] = 0x56; bind_pre[3] = 0x42; bind_pre[4] = 0x31;
    let mut off: u32 = ENVB_TAG_LEN;
    for j in 0..32 { bind_pre[off + j] = pk_issuer_x[j]; }
    off = off + 32u32;
    for j in 0..32 { bind_pre[off + j] = pk_issuer_y[j]; }
    off = off + 32u32;
    for j in 0..32 { bind_pre[off + j] = envelope_hash[j]; }
    off = off + 32u32;
    for j in 0..32 { bind_pre[off + j] = challenge[j]; }
    off = off + 32u32;
    for j in 0..32 { bind_pre[off + j] = audience_hash[j]; }
    off = off + 32u32;
    for j in 0..32 { bind_pre[off + j] = transaction_data_hash[j]; }
    off = off + 32u32;
    for j in 0..8 { bind_pre[off + j] = expiry_bytes[j]; }
    let computed_binding = poseidon2_bounded::poseidon2_bounded::<ENVB_LEN>(bind_pre, ENVB_LEN);
    assert(computed_binding == envelope_binding, "envelope binding mismatch");
}
