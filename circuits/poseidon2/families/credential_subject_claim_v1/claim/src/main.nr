// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod poseidon2_bounded;
use std::ecdsa_secp256r1;

global MAX_VAL_LEN: u32 = 64;
global SALT_LEN: u32    = 16;
global MAX_DEPTH: u32   = 6;
global MAX_LEAF_COUNT: u32 = 64;

global CLM_TAG_LEN: u32  = 4; // "CLM1"
global INNER_MAX: u32    = CLM_TAG_LEN + 4 + MAX_VAL_LEN + SALT_LEN;

global LEAF_TAG_LEN: u32 = 5; // "LEAF1"
global LEAF_LEN: u32     = LEAF_TAG_LEN + 32 + 32;

global NODE_TAG_LEN: u32 = 5; // "NODE1"
global NODE_LEN: u32     = NODE_TAG_LEN + 32 + 32;

global BINDSUB_TAG_LEN: u32 = 8; // "BINDSUB1"
global BINDSUB_LEN: u32     = BINDSUB_TAG_LEN + 32 + 32 + 32;

global SESS_BIND_TAG_LEN: u32 = 6; // "SESSB1"
global SESS_BIND_LEN: u32     = SESS_BIND_TAG_LEN + 32 + 32 + 32 + 32 + 32 + 8;

global CREDB_TAG_LEN: u32 = 6; // "CREDB1"
global CREDB_LEN: u32     = CREDB_TAG_LEN + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 8;

fn is_zero32(arr: [u8; 32]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..32 { acc = acc | arr[i]; }
    acc == 0u8
}

fn is_zero_salt(arr: [u8; SALT_LEN]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..SALT_LEN { acc = acc | arr[i]; }
    acc == 0u8
}

fn u32_to_be_bytes(x: u32) -> [u8; 4] {
    let mut out: [u8; 4] = [0u8; 4];
    out[0] = ((x >> 24) & 0xff) as u8;
    out[1] = ((x >> 16) & 0xff) as u8;
    out[2] = ((x >>  8) & 0xff) as u8;
    out[3] = ( x        & 0xff) as u8;
    out
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

fn bit_at(x: u32, k: u32) -> u8 {
    let shifted: u32 = x >> k;
    (shifted & 1u32) as u8
}

pub fn main(
    pk_issuer_x: pub [u8; 32],
    pk_issuer_y: pub [u8; 32],
    challenge: pub [u8; 32],
    audience_hash: pub [u8; 32],
    transaction_data_hash: pub [u8; 32],
    expiry_unix: pub u64,
    session_binding: pub [u8; 32],
    credential_binding: pub [u8; 32],
    val_len: pub u32,
    val_pub: pub [u8; MAX_VAL_LEN],
    name_hash: pub [u8; 32],

    envelope_hash: [u8; 32],
    merkle_root: [u8; 32],
    issuer_subject_bind_sig: [u8; 64],
    pk_subject_x: [u8; 32],
    pk_subject_y: [u8; 32],
    salt: [u8; SALT_LEN],
    index: u32,
    path_len: u32,
    path: [[u8; 32]; MAX_DEPTH],
) {
    let issuer_pk_zero: bool = is_zero32(pk_issuer_x) & is_zero32(pk_issuer_y);
    let subject_pk_zero: bool = is_zero32(pk_subject_x) & is_zero32(pk_subject_y);
    assert(!issuer_pk_zero, "issuer pk zero");
    assert(!subject_pk_zero, "subject pk zero");
    assert(!is_zero32(envelope_hash), "envelope hash zero");
    assert(!is_zero32(merkle_root), "merkle root zero");
    assert(!is_zero32(challenge), "challenge must be non-zero");
    assert(!is_zero32(audience_hash), "audience hash must be non-zero");
    assert(!is_zero32(transaction_data_hash), "transaction data hash must be non-zero");
    assert(val_len > 0u32, "empty value");
    assert(val_len <= MAX_VAL_LEN, "value too long");
    // The claim tree has one fixed depth. A shorter path would let a digest
    // that the issuer signed in a leaf position stand for a hidden subtree.
    assert(path_len == MAX_DEPTH, "claim tree path must have fixed depth");
    assert(index < MAX_LEAF_COUNT, "index exceeds path depth");
    assert(!is_zero_salt(salt), "salt must be non-zero");

    for j in 0..MAX_VAL_LEN {
        if j >= val_len {
            assert(val_pub[j] == 0u8, "value tail must be zero-padded");
        }
    }
    for lvl in 0..MAX_DEPTH {
        if lvl >= path_len {
            assert(bit_at(index, lvl) == 0u8, "unused index bits must be zero");
            for j in 0..32 { assert(path[lvl][j] == 0u8, "unused path entry must be zero"); }
        }
    }

    let mut bind_subject_pre: [u8; BINDSUB_LEN] = [0u8; BINDSUB_LEN];
    bind_subject_pre[0] = 0x42; bind_subject_pre[1] = 0x49; bind_subject_pre[2] = 0x4E; bind_subject_pre[3] = 0x44;
    bind_subject_pre[4] = 0x53; bind_subject_pre[5] = 0x55; bind_subject_pre[6] = 0x42; bind_subject_pre[7] = 0x31;
    let mut soff: u32 = BINDSUB_TAG_LEN;
    for j in 0..32 { bind_subject_pre[soff + j] = envelope_hash[j]; }
    soff = soff + 32u32;
    for j in 0..32 { bind_subject_pre[soff + j] = pk_subject_x[j]; }
    soff = soff + 32u32;
    for j in 0..32 { bind_subject_pre[soff + j] = pk_subject_y[j]; }
    let subject_bind_hash = poseidon2_bounded::poseidon2_bounded::<BINDSUB_LEN>(bind_subject_pre, BINDSUB_LEN);

    assert(
        ecdsa_secp256r1::verify_signature(pk_issuer_x, pk_issuer_y, issuer_subject_bind_sig, subject_bind_hash),
        "issuer envelope-subject binding signature invalid"
    );

    let expiry_bytes = u64_to_be_bytes(expiry_unix);

    let mut sess_pre: [u8; SESS_BIND_LEN] = [0u8; SESS_BIND_LEN];
    sess_pre[0] = 0x53; sess_pre[1] = 0x45; sess_pre[2] = 0x53; sess_pre[3] = 0x53; sess_pre[4] = 0x42; sess_pre[5] = 0x31;
    let mut seoff: u32 = SESS_BIND_TAG_LEN;
    for j in 0..32 { sess_pre[seoff + j] = pk_subject_x[j]; }
    seoff = seoff + 32u32;
    for j in 0..32 { sess_pre[seoff + j] = pk_subject_y[j]; }
    seoff = seoff + 32u32;
    for j in 0..32 { sess_pre[seoff + j] = challenge[j]; }
    seoff = seoff + 32u32;
    for j in 0..32 { sess_pre[seoff + j] = audience_hash[j]; }
    seoff = seoff + 32u32;
    for j in 0..32 { sess_pre[seoff + j] = transaction_data_hash[j]; }
    seoff = seoff + 32u32;
    for j in 0..8 { sess_pre[seoff + j] = expiry_bytes[j]; }
    let computed_session_binding = poseidon2_bounded::poseidon2_bounded::<SESS_BIND_LEN>(sess_pre, SESS_BIND_LEN);
    assert(computed_session_binding == session_binding, "session binding mismatch");

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
    let computed_credential_binding = poseidon2_bounded::poseidon2_bounded::<CREDB_LEN>(cred_pre, CREDB_LEN);
    assert(computed_credential_binding == credential_binding, "credential binding mismatch");

    let mut inner_pre: [u8; INNER_MAX] = [0u8; INNER_MAX];
    inner_pre[0] = 0x43; inner_pre[1] = 0x4C; inner_pre[2] = 0x4D; inner_pre[3] = 0x31;
    let len_bytes = u32_to_be_bytes(val_len);
    inner_pre[4] = len_bytes[0]; inner_pre[5] = len_bytes[1]; inner_pre[6] = len_bytes[2]; inner_pre[7] = len_bytes[3];
    let mut off: u32 = CLM_TAG_LEN + 4u32;
    for j in 0..MAX_VAL_LEN { if j < val_len { inner_pre[off + j] = val_pub[j]; } }
    off = off + val_len;
    for j in 0..SALT_LEN { inner_pre[off + j] = salt[j]; }
    let inner_len: u32 = CLM_TAG_LEN + 4u32 + val_len + SALT_LEN;
    let inner = poseidon2_bounded::poseidon2_bounded::<INNER_MAX>(inner_pre, inner_len);

    let mut leaf_pre: [u8; LEAF_LEN] = [0u8; LEAF_LEN];
    leaf_pre[0] = 0x4C; leaf_pre[1] = 0x45; leaf_pre[2] = 0x41; leaf_pre[3] = 0x46; leaf_pre[4] = 0x31;
    let mut loff: u32 = LEAF_TAG_LEN;
    for j in 0..32 { leaf_pre[loff + j] = name_hash[j]; }
    loff = loff + 32u32;
    for j in 0..32 { leaf_pre[loff + j] = inner[j]; }
    let leaf = poseidon2_bounded::poseidon2_bounded::<LEAF_LEN>(leaf_pre, LEAF_LEN);

    let mut cur: [u8; 32] = leaf;
    for lvl in 0..MAX_DEPTH {
        if lvl < path_len {
            let sib: [u8; 32] = path[lvl];
            let bit: u8 = bit_at(index, lvl);
            let mut node_pre: [u8; NODE_LEN] = [0u8; NODE_LEN];
            node_pre[0] = 0x4E; node_pre[1] = 0x4F; node_pre[2] = 0x44; node_pre[3] = 0x45; node_pre[4] = 0x31;
            let noff: u32 = NODE_TAG_LEN;
            if bit == 0u8 {
                for j in 0..32 { node_pre[noff + j] = cur[j]; }
                for j in 0..32 { node_pre[noff + 32 + j] = sib[j]; }
            } else {
                for j in 0..32 { node_pre[noff + j] = sib[j]; }
                for j in 0..32 { node_pre[noff + 32 + j] = cur[j]; }
            }
            cur = poseidon2_bounded::poseidon2_bounded::<NODE_LEN>(node_pre, NODE_LEN);
        }
    }
    assert(cur == merkle_root, "merkle root mismatch");
}
