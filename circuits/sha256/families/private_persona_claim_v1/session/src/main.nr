// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sha256_bounded;
use std::ecdsa_secp256r1;

global MSG_TAG_LEN: u32 = 5;  // "PERS2"
global MSG_LEN: u32     = MSG_TAG_LEN + 32 + 32 + 32 + 8;
global MSG_BLOCKS: u32   = ((MSG_LEN + 9 + 63) / 64);

global BIND_TAG_LEN: u32 = 6; // "PSESB2"
global BIND_LEN: u32     = BIND_TAG_LEN + 32 + 32 + 32 + 32 + 32 + 8;
global BIND_BLOCKS: u32  = ((BIND_LEN + 9 + 63) / 64);

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
    challenge: pub [u8; 32],
    audience_hash: pub [u8; 32],
    transaction_data_hash: pub [u8; 32],
    expiry_unix: pub u64,
    session_binding: pub [u8; 32],

    pk_persona_x: [u8; 32],
    pk_persona_y: [u8; 32],
    persona_sig: [u8; 64],
) {
    let persona_pk_zero: bool = is_zero32(pk_persona_x) & is_zero32(pk_persona_y);
    assert(!persona_pk_zero, "persona pk zero");
    assert(!is_zero32(challenge), "challenge must be non-zero");
    assert(!is_zero32(audience_hash), "audience hash must be non-zero");
    assert(!is_zero32(transaction_data_hash), "transaction data hash must be non-zero");

    let mut msg_pre: [u8; MSG_LEN] = [0u8; MSG_LEN];
    msg_pre[0] = 0x50; msg_pre[1] = 0x45; msg_pre[2] = 0x52; msg_pre[3] = 0x53; msg_pre[4] = 0x32;
    let mut moff: u32 = MSG_TAG_LEN;
    for j in 0..32 { msg_pre[moff + j] = challenge[j]; }
    moff = moff + 32u32;
    for j in 0..32 { msg_pre[moff + j] = audience_hash[j]; }
    moff = moff + 32u32;
    for j in 0..32 { msg_pre[moff + j] = transaction_data_hash[j]; }
    moff = moff + 32u32;
    let expiry_bytes = u64_to_be_bytes(expiry_unix);
    for j in 0..8 { msg_pre[moff + j] = expiry_bytes[j]; }
    let msg_hash = sha256_bounded::sha256_bounded::<MSG_LEN, MSG_BLOCKS>(msg_pre, MSG_LEN);

    assert(
        ecdsa_secp256r1::verify_signature(pk_persona_x, pk_persona_y, persona_sig, msg_hash),
        "persona session signature invalid"
    );

    let mut bind_pre: [u8; BIND_LEN] = [0u8; BIND_LEN];
    bind_pre[0] = 0x50; bind_pre[1] = 0x53; bind_pre[2] = 0x45; bind_pre[3] = 0x53; bind_pre[4] = 0x42; bind_pre[5] = 0x32;
    let mut boff: u32 = BIND_TAG_LEN;
    for j in 0..32 { bind_pre[boff + j] = pk_persona_x[j]; }
    boff = boff + 32u32;
    for j in 0..32 { bind_pre[boff + j] = pk_persona_y[j]; }
    boff = boff + 32u32;
    for j in 0..32 { bind_pre[boff + j] = challenge[j]; }
    boff = boff + 32u32;
    for j in 0..32 { bind_pre[boff + j] = audience_hash[j]; }
    boff = boff + 32u32;
    for j in 0..32 { bind_pre[boff + j] = transaction_data_hash[j]; }
    boff = boff + 32u32;
    for j in 0..8 { bind_pre[boff + j] = expiry_bytes[j]; }
    let computed_binding = sha256_bounded::sha256_bounded::<BIND_LEN, BIND_BLOCKS>(bind_pre, BIND_LEN);

    assert(computed_binding == session_binding, "session binding mismatch");
}
