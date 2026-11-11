// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sha256_bounded;
use std::ecdsa_secp256r1;

global BINDMRK_TAG_LEN: u32 = 8; // "BINDMRK1"
global BINDMRK_LEN: u32     = BINDMRK_TAG_LEN + 32 + 32;
global BINDMRK_BLOCKS: u32  = ((BINDMRK_LEN + 9 + 63) / 64);

global ENVB_TAG_LEN: u32 = 5; // "ENVB1"
global ENVB_LEN: u32     = ENVB_TAG_LEN + 32 + 32 + 32 + 32 + 32 + 32 + 8;
global ENVB_BLOCKS: u32  = ((ENVB_LEN + 9 + 63) / 64);

global CREDB_TAG_LEN: u32 = 6; // "CREDB1"
global CREDB_LEN: u32     = CREDB_TAG_LEN + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 8;
global CREDB_BLOCKS: u32  = ((CREDB_LEN + 9 + 63) / 64);

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
    credential_binding: pub [u8; 32],

    envelope_hash: [u8; 32],
    merkle_root: [u8; 32],
    issuer_root_bind_sig: [u8; 64],
) {
    let issuer_pk_zero: bool = is_zero32(pk_issuer_x) & is_zero32(pk_issuer_y);
    assert(!issuer_pk_zero, "issuer pk zero");
    assert(!is_zero32(envelope_hash), "envelope hash zero");
    assert(!is_zero32(merkle_root), "merkle root zero");
    assert(!is_zero32(challenge), "challenge must be non-zero");
    assert(!is_zero32(audience_hash), "audience hash must be non-zero");
    assert(!is_zero32(transaction_data_hash), "transaction data hash must be non-zero");

    let mut bind_root_pre: [u8; BINDMRK_LEN] = [0u8; BINDMRK_LEN];
    bind_root_pre[0] = 0x42; bind_root_pre[1] = 0x49; bind_root_pre[2] = 0x4E; bind_root_pre[3] = 0x44;
    bind_root_pre[4] = 0x4D; bind_root_pre[5] = 0x52; bind_root_pre[6] = 0x4B; bind_root_pre[7] = 0x31;
    let mut roff: u32 = BINDMRK_TAG_LEN;
    for j in 0..32 { bind_root_pre[roff + j] = envelope_hash[j]; }
    roff = roff + 32u32;
    for j in 0..32 { bind_root_pre[roff + j] = merkle_root[j]; }
    let root_bind_hash = sha256_bounded::sha256_bounded::<BINDMRK_LEN, BINDMRK_BLOCKS>(bind_root_pre, BINDMRK_LEN);

    assert(
        ecdsa_secp256r1::verify_signature(pk_issuer_x, pk_issuer_y, issuer_root_bind_sig, root_bind_hash),
        "issuer envelope-root binding signature invalid"
    );

    let expiry_bytes = u64_to_be_bytes(expiry_unix);

    let mut envb_pre: [u8; ENVB_LEN] = [0u8; ENVB_LEN];
    envb_pre[0] = 0x45; envb_pre[1] = 0x4E; envb_pre[2] = 0x56; envb_pre[3] = 0x42; envb_pre[4] = 0x31;
    let mut eoff: u32 = ENVB_TAG_LEN;
    for j in 0..32 { envb_pre[eoff + j] = pk_issuer_x[j]; }
    eoff = eoff + 32u32;
    for j in 0..32 { envb_pre[eoff + j] = pk_issuer_y[j]; }
    eoff = eoff + 32u32;
    for j in 0..32 { envb_pre[eoff + j] = envelope_hash[j]; }
    eoff = eoff + 32u32;
    for j in 0..32 { envb_pre[eoff + j] = challenge[j]; }
    eoff = eoff + 32u32;
    for j in 0..32 { envb_pre[eoff + j] = audience_hash[j]; }
    eoff = eoff + 32u32;
    for j in 0..32 { envb_pre[eoff + j] = transaction_data_hash[j]; }
    eoff = eoff + 32u32;
    for j in 0..8 { envb_pre[eoff + j] = expiry_bytes[j]; }
    let computed_envelope_binding = sha256_bounded::sha256_bounded::<ENVB_LEN, ENVB_BLOCKS>(envb_pre, ENVB_LEN);
    assert(computed_envelope_binding == envelope_binding, "envelope binding mismatch");

    let mut cred_pre: [u8; CREDB_LEN] = [0u8; CREDB_LEN];
    cred_pre[0] = 0x43; cred_pre[1] = 0x52; cred_pre[2] = 0x45; cred_pre[3] = 0x44; cred_pre[4] = 0x42; cred_pre[5] = 0x31;
    let mut coff: u32 = CREDB_TAG_LEN;
    for j in 0..32 { cred_pre[coff + j] = pk_issuer_x[j]; }
    coff = coff + 32u32;
    for j in 0..32 { cred_pre[coff + j] = pk_issuer_y[j]; }
    coff = coff + 32u32;
    for j in 0..32 { cred_pre[coff + j] = envelope_hash[j]; }
    coff = coff + 32u32;
    for j in 0..32 { cred_pre[coff + j] = merkle_root[j]; }
    coff = coff + 32u32;
    for j in 0..32 { cred_pre[coff + j] = challenge[j]; }
    coff = coff + 32u32;
    for j in 0..32 { cred_pre[coff + j] = audience_hash[j]; }
    coff = coff + 32u32;
    for j in 0..32 { cred_pre[coff + j] = transaction_data_hash[j]; }
    coff = coff + 32u32;
    for j in 0..8 { cred_pre[coff + j] = expiry_bytes[j]; }
    let computed_credential_binding = sha256_bounded::sha256_bounded::<CREDB_LEN, CREDB_BLOCKS>(cred_pre, CREDB_LEN);
    assert(computed_credential_binding == credential_binding, "credential binding mismatch");
}
