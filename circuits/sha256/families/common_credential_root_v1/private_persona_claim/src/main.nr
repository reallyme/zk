// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sha256_bounded;
use std::ecdsa_secp256r1;

global MAX_VAL_LEN: u32 = 64;
global SALT_LEN: u32 = 16;
global MAX_DEPTH: u32 = 6;
global MAX_LEAF_COUNT: u32 = 64;

// This protocol field carries the issuer-authenticated lineage value. A
// selected-claim proof must never publish it as an ordinary disclosed claim.
global LINEAGE_NAME_HASH: [u8; 32] = [
    0xa0, 0x0e, 0x5f, 0x5f, 0x55, 0xfa, 0x10, 0x52, 0x66, 0x8a, 0x6f, 0x10, 0x71, 0x98, 0xe8, 0x48,
    0x58, 0x90, 0x42, 0x51, 0x19, 0xb4, 0xca, 0x1a, 0xe1, 0xe8, 0x28, 0x7a, 0x77, 0x08, 0x46, 0xdd,
];

global CLM_TAG_LEN: u32 = 4; // "CLM1"
global INNER_MAX: u32 = CLM_TAG_LEN + 4 + MAX_VAL_LEN + SALT_LEN;
global INNER_BLOCKS: u32 = ((INNER_MAX + 9 + 63) / 64);

global LEAF_TAG_LEN: u32 = 5; // "LEAF1"
global LEAF_LEN: u32 = LEAF_TAG_LEN + 32 + 32;
global LEAF_BLOCKS: u32 = ((LEAF_LEN + 9 + 63) / 64);

global NODE_TAG_LEN: u32 = 5; // "NODE1"
global NODE_LEN: u32 = NODE_TAG_LEN + 32 + 32;
global NODE_BLOCKS: u32 = ((NODE_LEN + 9 + 63) / 64);

global BINDSUB_TAG_LEN: u32 = 8; // "BINDSUB1"
global BINDSUB_LEN: u32 = BINDSUB_TAG_LEN + 32 + 32 + 32;
global BINDSUB_BLOCKS: u32 = ((BINDSUB_LEN + 9 + 63) / 64);

global LINK_TAG_LEN: u32 = 5; // "LINK1"
global LINK_LEN: u32 = LINK_TAG_LEN + 33;
global LINK_BLOCKS: u32 = ((LINK_LEN + 9 + 63) / 64);

global SESS_BIND_TAG_LEN: u32 = 6; // "PSESB2"
global SESS_BIND_LEN: u32 = SESS_BIND_TAG_LEN + 32 + 32 + 32 + 32 + 32 + 8;
global SESS_BIND_BLOCKS: u32 = ((SESS_BIND_LEN + 9 + 63) / 64);

global CREDB_TAG_LEN: u32 = 6; // "CREDB1"
global CREDB_LEN: u32 = CREDB_TAG_LEN + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 8;
global CREDB_BLOCKS: u32 = ((CREDB_LEN + 9 + 63) / 64);

fn is_zero32(arr: [u8; 32]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..32 {
        acc = acc | arr[i];
    }
    acc == 0u8
}

fn is_zero_salt(arr: [u8; SALT_LEN]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..SALT_LEN {
        acc = acc | arr[i];
    }
    acc == 0u8
}

fn same32(a: [u8; 32], b: [u8; 32]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..32 {
        acc = acc | (a[i] ^ b[i]);
    }
    acc == 0u8
}

fn u32_to_be_bytes(x: u32) -> [u8; 4] {
    let mut out: [u8; 4] = [0u8; 4];
    out[0] = ((x >> 24) & 0xff) as u8;
    out[1] = ((x >> 16) & 0xff) as u8;
    out[2] = ((x >> 8) & 0xff) as u8;
    out[3] = (x & 0xff) as u8;
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
    out[6] = ((x >> 8) & 0xff) as u8;
    out[7] = (x & 0xff) as u8;
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
    subject_join: pub [u8; 32],
    val_len: pub u32,
    val_pub: pub [u8; MAX_VAL_LEN],
    name_hash: pub [u8; 32],
    envelope_hash: [u8; 32],
    merkle_root: [u8; 32],
    issuer_subject_bind_sig: [u8; 64],
    pk_subject_x: [u8; 32],
    pk_subject_y: [u8; 32],
    pk_persona_x: [u8; 32],
    pk_persona_y: [u8; 32],
    subject_link_sig: [u8; 64],
    join_salt: [u8; 32],
    salt: [u8; SALT_LEN],
    index: u32,
    path_len: u32,
    path: [[u8; 32]; MAX_DEPTH],
) {
    let issuer_pk_zero: bool = is_zero32(pk_issuer_x) & is_zero32(pk_issuer_y);
    let subject_pk_zero: bool = is_zero32(pk_subject_x) & is_zero32(pk_subject_y);
    let persona_pk_zero: bool = is_zero32(pk_persona_x) & is_zero32(pk_persona_y);
    let same_subject_persona_x: bool = same32(pk_subject_x, pk_persona_x);
    assert(!issuer_pk_zero, "issuer pk zero");
    assert(!subject_pk_zero, "subject pk zero");
    assert(!persona_pk_zero, "persona pk zero");
    assert(!same_subject_persona_x, "private persona x must differ from credential subject x");
    assert(!is_zero32(envelope_hash), "envelope hash zero");
    assert(!is_zero32(merkle_root), "merkle root zero");
    assert(!is_zero32(challenge), "challenge must be non-zero");
    assert(!is_zero32(audience_hash), "audience hash must be non-zero");
    assert(!is_zero32(transaction_data_hash), "transaction data hash must be non-zero");
    assert(val_len > 0u32, "empty value");
    assert(name_hash != LINEAGE_NAME_HASH, "lineage claim cannot be disclosed");
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
            for j in 0..32 {
                assert(path[lvl][j] == 0u8, "unused path entry must be zero");
            }
        }
    }

    let mut bind_subject_pre: [u8; BINDSUB_LEN] = [0u8; BINDSUB_LEN];
    bind_subject_pre[0] = 0x42;
    bind_subject_pre[1] = 0x49;
    bind_subject_pre[2] = 0x4E;
    bind_subject_pre[3] = 0x44;
    bind_subject_pre[4] = 0x53;
    bind_subject_pre[5] = 0x55;
    bind_subject_pre[6] = 0x42;
    bind_subject_pre[7] = 0x31;
    let mut soff: u32 = BINDSUB_TAG_LEN;
    for j in 0..32 {
        bind_subject_pre[soff + j] = envelope_hash[j];
    }
    soff = soff + 32u32;
    for j in 0..32 {
        bind_subject_pre[soff + j] = pk_subject_x[j];
    }
    soff = soff + 32u32;
    for j in 0..32 {
        bind_subject_pre[soff + j] = pk_subject_y[j];
    }
    let subject_bind_hash = sha256_bounded::sha256_bounded::<BINDSUB_LEN, BINDSUB_BLOCKS>(
        bind_subject_pre,
        BINDSUB_LEN,
    );

    assert(
        ecdsa_secp256r1::verify_signature(
            pk_issuer_x,
            pk_issuer_y,
            issuer_subject_bind_sig,
            subject_bind_hash,
        ),
        "issuer envelope-subject binding signature invalid",
    );

    let mut persona_comp: [u8; 33] = [0u8; 33];
    persona_comp[0] = if (pk_persona_y[31] & 1u8) == 1u8 {
        0x03u8
    } else {
        0x02u8
    };
    for j in 0..32 {
        persona_comp[1 + j] = pk_persona_x[j];
    }

    let mut link_pre: [u8; LINK_LEN] = [0u8; LINK_LEN];
    link_pre[0] = 0x4C;
    link_pre[1] = 0x49;
    link_pre[2] = 0x4E;
    link_pre[3] = 0x4B;
    link_pre[4] = 0x31;
    for j in 0..33 {
        link_pre[LINK_TAG_LEN + j] = persona_comp[j];
    }
    let link_hash = sha256_bounded::sha256_bounded::<LINK_LEN, LINK_BLOCKS>(link_pre, LINK_LEN);

    assert(
        ecdsa_secp256r1::verify_signature(pk_subject_x, pk_subject_y, subject_link_sig, link_hash),
        "subject-private-persona link signature invalid",
    );

    let expiry_bytes = u64_to_be_bytes(expiry_unix);

    let mut sess_pre: [u8; SESS_BIND_LEN] = [0u8; SESS_BIND_LEN];
    sess_pre[0] = 0x50;
    sess_pre[1] = 0x53;
    sess_pre[2] = 0x45;
    sess_pre[3] = 0x53;
    sess_pre[4] = 0x42;
    sess_pre[5] = 0x32;
    let mut seoff: u32 = SESS_BIND_TAG_LEN;
    for j in 0..32 {
        sess_pre[seoff + j] = pk_persona_x[j];
    }
    seoff = seoff + 32u32;
    for j in 0..32 {
        sess_pre[seoff + j] = pk_persona_y[j];
    }
    seoff = seoff + 32u32;
    for j in 0..32 {
        sess_pre[seoff + j] = challenge[j];
    }
    seoff = seoff + 32u32;
    for j in 0..32 {
        sess_pre[seoff + j] = audience_hash[j];
    }
    seoff = seoff + 32u32;
    for j in 0..32 {
        sess_pre[seoff + j] = transaction_data_hash[j];
    }
    seoff = seoff + 32u32;
    for j in 0..8 {
        sess_pre[seoff + j] = expiry_bytes[j];
    }
    let computed_session_binding =
        sha256_bounded::sha256_bounded::<SESS_BIND_LEN, SESS_BIND_BLOCKS>(sess_pre, SESS_BIND_LEN);
    assert(computed_session_binding == session_binding, "session binding mismatch");

    let mut cred_pre: [u8; CREDB_LEN] = [0u8; CREDB_LEN];
    cred_pre[0] = 0x43;
    cred_pre[1] = 0x52;
    cred_pre[2] = 0x45;
    cred_pre[3] = 0x44;
    cred_pre[4] = 0x42;
    cred_pre[5] = 0x31;
    let mut coff: u32 = CREDB_TAG_LEN;
    for j in 0..32 {
        cred_pre[coff + j] = pk_issuer_x[j];
    }
    coff = coff + 32u32;
    for j in 0..32 {
        cred_pre[coff + j] = pk_issuer_y[j];
    }
    coff = coff + 32u32;
    for j in 0..32 {
        cred_pre[coff + j] = envelope_hash[j];
    }
    coff = coff + 32u32;
    for j in 0..32 {
        cred_pre[coff + j] = merkle_root[j];
    }
    coff = coff + 32u32;
    for j in 0..32 {
        cred_pre[coff + j] = challenge[j];
    }
    coff = coff + 32u32;
    for j in 0..32 {
        cred_pre[coff + j] = audience_hash[j];
    }
    coff = coff + 32u32;
    for j in 0..32 {
        cred_pre[coff + j] = transaction_data_hash[j];
    }
    coff = coff + 32u32;
    for j in 0..8 {
        cred_pre[coff + j] = expiry_bytes[j];
    }
    let computed_credential_binding =
        sha256_bounded::sha256_bounded::<CREDB_LEN, CREDB_BLOCKS>(cred_pre, CREDB_LEN);
    assert(computed_credential_binding == credential_binding, "credential binding mismatch");

    let mut inner_pre: [u8; INNER_MAX] = [0u8; INNER_MAX];
    inner_pre[0] = 0x43;
    inner_pre[1] = 0x4C;
    inner_pre[2] = 0x4D;
    inner_pre[3] = 0x31;
    let len_bytes = u32_to_be_bytes(val_len);
    inner_pre[4] = len_bytes[0];
    inner_pre[5] = len_bytes[1];
    inner_pre[6] = len_bytes[2];
    inner_pre[7] = len_bytes[3];
    let mut off: u32 = CLM_TAG_LEN + 4u32;
    for j in 0..MAX_VAL_LEN {
        if j < val_len {
            inner_pre[off + j] = val_pub[j];
        }
    }
    off = off + val_len;
    for j in 0..SALT_LEN {
        inner_pre[off + j] = salt[j];
    }
    let inner_len: u32 = CLM_TAG_LEN + 4u32 + val_len + SALT_LEN;
    let inner = sha256_bounded::sha256_bounded::<INNER_MAX, INNER_BLOCKS>(inner_pre, inner_len);

    let mut leaf_pre: [u8; LEAF_LEN] = [0u8; LEAF_LEN];
    leaf_pre[0] = 0x4C;
    leaf_pre[1] = 0x45;
    leaf_pre[2] = 0x41;
    leaf_pre[3] = 0x46;
    leaf_pre[4] = 0x31;
    let mut loff: u32 = LEAF_TAG_LEN;
    for j in 0..32 {
        leaf_pre[loff + j] = name_hash[j];
    }
    loff = loff + 32u32;
    for j in 0..32 {
        leaf_pre[loff + j] = inner[j];
    }
    let leaf = sha256_bounded::sha256_bounded::<LEAF_LEN, LEAF_BLOCKS>(leaf_pre, LEAF_LEN);

    let mut cur: [u8; 32] = leaf;
    for lvl in 0..MAX_DEPTH {
        if lvl < path_len {
            let sib: [u8; 32] = path[lvl];
            let bit: u8 = bit_at(index, lvl);
            let mut node_pre: [u8; NODE_LEN] = [0u8; NODE_LEN];
            node_pre[0] = 0x4E;
            node_pre[1] = 0x4F;
            node_pre[2] = 0x44;
            node_pre[3] = 0x45;
            node_pre[4] = 0x31;
            let noff: u32 = NODE_TAG_LEN;
            if bit == 0u8 {
                for j in 0..32 {
                    node_pre[noff + j] = cur[j];
                }
                for j in 0..32 {
                    node_pre[noff + 32 + j] = sib[j];
                }
            } else {
                for j in 0..32 {
                    node_pre[noff + j] = sib[j];
                }
                for j in 0..32 {
                    node_pre[noff + 32 + j] = cur[j];
                }
            }
            cur = sha256_bounded::sha256_bounded::<NODE_LEN, NODE_BLOCKS>(node_pre, NODE_LEN);
        }
    }
    assert(cur == merkle_root, "merkle root mismatch");

    // This join is computed from the very subject whose issuer binding and
    // persona authorization were verified above. A lineage proof must publish
    // the same join for this selected-claim credential slot.
    assert(!is_zero32(join_salt), "join salt is zero");
    let mut join_pre: [u8; 200] = [0u8; 200];
    join_pre[0] = 0x52;
    join_pre[1] = 0x4d;
    join_pre[2] = 0x53;
    join_pre[3] = 0x4a;
    join_pre[4] = 0x4f;
    join_pre[5] = 0x49;
    join_pre[6] = 0x4e;
    join_pre[7] = 0x31; // "RMSJOIN1"
    for i in 0..32 {
        join_pre[8 + i] = pk_subject_x[i];
    }
    for i in 0..32 {
        join_pre[40 + i] = pk_subject_y[i];
    }
    for i in 0..32 {
        join_pre[72 + i] = join_salt[i];
    }
    for i in 0..32 {
        join_pre[104 + i] = challenge[i];
    }
    for i in 0..32 {
        join_pre[136 + i] = audience_hash[i];
    }
    for i in 0..32 {
        join_pre[168 + i] = transaction_data_hash[i];
    }
    let computed_join = sha256_bounded::sha256_bounded::<200, 4>(join_pre, 200u32);
    assert(computed_join == subject_join, "subject join mismatch");
}
