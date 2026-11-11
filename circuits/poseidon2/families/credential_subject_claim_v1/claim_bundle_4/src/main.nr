// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod poseidon2_bounded;
use std::ecdsa_secp256r1;

global MAX_BUNDLE_CLAIMS: u32 = 4;
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

global BUNDLE_TAG_LEN: u32 = 7; // "BUNDLE1"
global BUNDLE_ITEM_MAX: u32 = 32 + 4 + MAX_VAL_LEN;
global BUNDLE_MAX: u32 = BUNDLE_TAG_LEN + 32 + 32 + 32 + 8 + 4 + (MAX_BUNDLE_CLAIMS * BUNDLE_ITEM_MAX);

fn is_zero32(arr: [u8; 32]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..32 { acc = acc | arr[i]; }
    acc == 0u8
}

fn is_zero_val(arr: [u8; MAX_VAL_LEN]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..MAX_VAL_LEN { acc = acc | arr[i]; }
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

fn lex_lt32(a: [u8; 32], b: [u8; 32]) -> bool {
    let mut decided: bool = false;
    let mut result: bool = false;
    for i in 0..32 {
        if !decided {
            if a[i] < b[i] {
                decided = true;
                result = true;
            }
            if a[i] > b[i] {
                decided = true;
                result = false;
            }
        }
    }
    result
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
    bundle_count: pub u32,
    bundle_hash: pub [u8; 32],

    envelope_hash: [u8; 32],
    merkle_root: [u8; 32],
    issuer_subject_bind_sig: [u8; 64],
    pk_subject_x: [u8; 32],
    pk_subject_y: [u8; 32],
    val_lens: [u32; MAX_BUNDLE_CLAIMS],
    val_pubs: [[u8; MAX_VAL_LEN]; MAX_BUNDLE_CLAIMS],
    name_hashes: [[u8; 32]; MAX_BUNDLE_CLAIMS],
    salts: [[u8; SALT_LEN]; MAX_BUNDLE_CLAIMS],
    indices: [u32; MAX_BUNDLE_CLAIMS],
    path_lens: [u32; MAX_BUNDLE_CLAIMS],
    paths: [[[u8; 32]; MAX_DEPTH]; MAX_BUNDLE_CLAIMS],
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
    assert(bundle_count > 0u32, "bundle must contain at least one claim");
    assert(bundle_count <= MAX_BUNDLE_CLAIMS, "bundle_count too large");

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

    let mut bundle_pre: [u8; BUNDLE_MAX] = [0u8; BUNDLE_MAX];
    bundle_pre[0] = 0x42; bundle_pre[1] = 0x55; bundle_pre[2] = 0x4E; bundle_pre[3] = 0x44;
    bundle_pre[4] = 0x4C; bundle_pre[5] = 0x45; bundle_pre[6] = 0x31;
    let mut boff: u32 = BUNDLE_TAG_LEN;
    for j in 0..32 { bundle_pre[boff + j] = challenge[j]; }
    boff = boff + 32u32;
    for j in 0..32 { bundle_pre[boff + j] = audience_hash[j]; }
    boff = boff + 32u32;
    for j in 0..32 { bundle_pre[boff + j] = transaction_data_hash[j]; }
    boff = boff + 32u32;
    for j in 0..8 { bundle_pre[boff + j] = expiry_bytes[j]; }
    boff = boff + 8u32;
    let count_bytes = u32_to_be_bytes(bundle_count);
    for j in 0..4 { bundle_pre[boff + j] = count_bytes[j]; }
    boff = boff + 4u32;

    for slot in 0..MAX_BUNDLE_CLAIMS {
        if slot < bundle_count {
            assert(val_lens[slot] > 0u32, "empty value in active bundle slot");
            assert(val_lens[slot] <= MAX_VAL_LEN, "value too long");
            assert(path_lens[slot] == MAX_DEPTH, "claim tree path must have fixed depth");
            assert(indices[slot] < MAX_LEAF_COUNT, "index exceeds path depth");
            assert(!is_zero32(name_hashes[slot]), "name_hash zero in active bundle slot");
            assert(!is_zero_salt(salts[slot]), "salt zero in active bundle slot");

            if slot > 0u32 {
                assert(lex_lt32(name_hashes[slot - 1u32], name_hashes[slot]), "bundle entries must be strictly sorted by name_hash");
            }

            for j in 0..MAX_VAL_LEN {
                if j >= val_lens[slot] {
                    assert(val_pubs[slot][j] == 0u8, "value tail must be zero-padded");
                }
            }
            for lvl in 0..MAX_DEPTH {
                if lvl >= path_lens[slot] {
                    assert(bit_at(indices[slot], lvl) == 0u8, "unused index bits must be zero");
                    for j in 0..32 { assert(paths[slot][lvl][j] == 0u8, "unused path entry must be zero"); }
                }
            }

            for j in 0..32 { bundle_pre[boff + j] = name_hashes[slot][j]; }
            boff = boff + 32u32;
            let item_len_bytes = u32_to_be_bytes(val_lens[slot]);
            for j in 0..4 { bundle_pre[boff + j] = item_len_bytes[j]; }
            boff = boff + 4u32;
            for j in 0..MAX_VAL_LEN {
                if j < val_lens[slot] {
                    bundle_pre[boff + j] = val_pubs[slot][j];
                }
            }
            boff = boff + val_lens[slot];
        } else {
            assert(val_lens[slot] == 0u32, "unused bundle slot must have zero val_len");
            assert(path_lens[slot] == 0u32, "unused bundle slot must have zero path_len");
            assert(indices[slot] == 0u32, "unused bundle slot must have zero index");
            assert(is_zero32(name_hashes[slot]), "unused bundle slot must have zero name_hash");
            assert(is_zero_val(val_pubs[slot]), "unused bundle slot must have zero value bytes");
            assert(is_zero_salt(salts[slot]), "unused bundle slot must have zero salt");
            for lvl in 0..MAX_DEPTH {
                for j in 0..32 { assert(paths[slot][lvl][j] == 0u8, "unused bundle slot path must be zero"); }
            }
        }
    }

    let computed_bundle_hash = poseidon2_bounded::poseidon2_bounded::<BUNDLE_MAX>(bundle_pre, boff);
    assert(computed_bundle_hash == bundle_hash, "bundle hash mismatch");

    for slot in 0..MAX_BUNDLE_CLAIMS {
        if slot < bundle_count {
            let mut inner_pre: [u8; INNER_MAX] = [0u8; INNER_MAX];
            inner_pre[0] = 0x43; inner_pre[1] = 0x4C; inner_pre[2] = 0x4D; inner_pre[3] = 0x31;
            let len_bytes = u32_to_be_bytes(val_lens[slot]);
            inner_pre[4] = len_bytes[0]; inner_pre[5] = len_bytes[1]; inner_pre[6] = len_bytes[2]; inner_pre[7] = len_bytes[3];
            let mut off: u32 = CLM_TAG_LEN + 4u32;
            for j in 0..MAX_VAL_LEN {
                if j < val_lens[slot] { inner_pre[off + j] = val_pubs[slot][j]; }
            }
            off = off + val_lens[slot];
            for j in 0..SALT_LEN { inner_pre[off + j] = salts[slot][j]; }
            let inner_len: u32 = CLM_TAG_LEN + 4u32 + val_lens[slot] + SALT_LEN;
            let inner = poseidon2_bounded::poseidon2_bounded::<INNER_MAX>(inner_pre, inner_len);

            let mut leaf_pre: [u8; LEAF_LEN] = [0u8; LEAF_LEN];
            leaf_pre[0] = 0x4C; leaf_pre[1] = 0x45; leaf_pre[2] = 0x41; leaf_pre[3] = 0x46; leaf_pre[4] = 0x31;
            let mut loff: u32 = LEAF_TAG_LEN;
            for j in 0..32 { leaf_pre[loff + j] = name_hashes[slot][j]; }
            loff = loff + 32u32;
            for j in 0..32 { leaf_pre[loff + j] = inner[j]; }
            let leaf = poseidon2_bounded::poseidon2_bounded::<LEAF_LEN>(leaf_pre, LEAF_LEN);

            let mut cur: [u8; 32] = leaf;
            for lvl in 0..MAX_DEPTH {
                if lvl < path_lens[slot] {
                    let sib: [u8; 32] = paths[slot][lvl];
                    let bit: u8 = bit_at(indices[slot], lvl);
                    let mut node_pre: [u8; NODE_LEN] = [0u8; NODE_LEN];
                    node_pre[0] = 0x4E; node_pre[1] = 0x4F; node_pre[2] = 0x44; node_pre[3] = 0x45; node_pre[4] = 0x31;
                    let noff: u32 = NODE_TAG_LEN;
                    if bit == 0u8 {
                        for j in 0..32 { node_pre[noff + j] = cur[j]; }
                        for j in 0..32 { node_pre[noff + 32u32 + j] = sib[j]; }
                    } else {
                        for j in 0..32 { node_pre[noff + j] = sib[j]; }
                        for j in 0..32 { node_pre[noff + 32u32 + j] = cur[j]; }
                    }
                    cur = poseidon2_bounded::poseidon2_bounded::<NODE_LEN>(node_pre, NODE_LEN);
                }
            }
            assert(cur == merkle_root, "merkle root mismatch");
        }
    }
}
