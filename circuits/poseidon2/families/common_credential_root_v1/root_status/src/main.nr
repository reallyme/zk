// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sha256_bounded;

global MAX_STATUS_DEPTH: u32 = 20;
global MAX_STATUS_LEAVES: u32 = 1048576;

fn is_zero32(bytes: [u8; 32]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..32 {
        acc = acc | bytes[i];
    }
    acc == 0u8
}

fn bit_at(index: u32, level: u32) -> u8 {
    ((index >> level) & 1u32) as u8
}

fn verify_active_status(
    attestation_id: [u8; 32],
    expected_status_root: [u8; 32],
    status_index: u32,
    status_path_len: u32,
    status_path: [[u8; 32]; MAX_STATUS_DEPTH],
) {
    assert(!is_zero32(expected_status_root), "status root is zero");
    assert(status_index < MAX_STATUS_LEAVES, "status index too large");
    assert(status_path_len <= MAX_STATUS_DEPTH, "status path too long");
    for level in 0..MAX_STATUS_DEPTH {
        if level >= status_path_len {
            assert(bit_at(status_index, level) == 0u8, "unused status index bit");
            for j in 0..32 {
                assert(status_path[level][j] == 0u8, "unused status path entry");
            }
        }
    }

    let mut leaf_pre: [u8; 38] = [0u8; 38];
    leaf_pre[0] = 0x52;
    leaf_pre[1] = 0x4d;
    leaf_pre[2] = 0x53;
    leaf_pre[3] = 0x54;
    leaf_pre[4] = 0x4c;
    leaf_pre[5] = 0x32; // "RMSTL2"
    for i in 0..32 {
        leaf_pre[6 + i] = attestation_id[i];
    }
    let mut current = sha256_bounded::sha256_bounded::<38, 1>(leaf_pre, 38u32);

    for level in 0..MAX_STATUS_DEPTH {
        if level < status_path_len {
            let sibling = status_path[level];
            let mut node_pre: [u8; 70] = [0u8; 70];
            node_pre[0] = 0x52;
            node_pre[1] = 0x4d;
            node_pre[2] = 0x53;
            node_pre[3] = 0x54;
            node_pre[4] = 0x4e;
            node_pre[5] = 0x31; // "RMSTN1"
            if bit_at(status_index, level) == 0u8 {
                for i in 0..32 {
                    node_pre[6 + i] = current[i];
                }
                for i in 0..32 {
                    node_pre[38 + i] = sibling[i];
                }
            } else {
                for i in 0..32 {
                    node_pre[6 + i] = sibling[i];
                }
                for i in 0..32 {
                    node_pre[38 + i] = current[i];
                }
            }
            current = sha256_bounded::sha256_bounded::<70, 2>(node_pre, 70u32);
        }
    }
    assert(current == expected_status_root, "root is absent from active status");
}

fn verify_attestation_join(
    attestation_id: [u8; 32],
    join_salt: [u8; 32],
    challenge: [u8; 32],
    audience_hash: [u8; 32],
    transaction_data_hash: [u8; 32],
    expected_join: [u8; 32],
) {
    let mut pre: [u8; 169] = [0u8; 169];
    pre[0] = 0x52;
    pre[1] = 0x4d;
    pre[2] = 0x41;
    pre[3] = 0x54;
    pre[4] = 0x4a;
    pre[5] = 0x4f;
    pre[6] = 0x49;
    pre[7] = 0x4e;
    pre[8] = 0x31; // "RMATJOIN1"
    for i in 0..32 {
        pre[9 + i] = attestation_id[i];
    }
    for i in 0..32 {
        pre[41 + i] = join_salt[i];
    }
    for i in 0..32 {
        pre[73 + i] = challenge[i];
    }
    for i in 0..32 {
        pre[105 + i] = audience_hash[i];
    }
    for i in 0..32 {
        pre[137 + i] = transaction_data_hash[i];
    }
    let join = sha256_bounded::sha256_bounded::<169, 3>(pre, 169u32);
    assert(join == expected_join, "attestation join mismatch");
}

fn verify_root_join(
    root: [u8; 32],
    join_salt: [u8; 32],
    challenge: [u8; 32],
    audience_hash: [u8; 32],
    transaction_data_hash: [u8; 32],
    expected_join: [u8; 32],
) {
    assert(!is_zero32(join_salt), "join salt is zero");
    let mut pre: [u8; 168] = [0u8; 168];
    pre[0] = 0x52;
    pre[1] = 0x4d;
    pre[2] = 0x52;
    pre[3] = 0x4a;
    pre[4] = 0x4f;
    pre[5] = 0x49;
    pre[6] = 0x4e;
    pre[7] = 0x31; // "RMRJOIN1"
    for i in 0..32 {
        pre[8 + i] = root[i];
    }
    for i in 0..32 {
        pre[40 + i] = join_salt[i];
    }
    for i in 0..32 {
        pre[72 + i] = challenge[i];
    }
    for i in 0..32 {
        pre[104 + i] = audience_hash[i];
    }
    for i in 0..32 {
        pre[136 + i] = transaction_data_hash[i];
    }
    let join = sha256_bounded::sha256_bounded::<168, 3>(pre, 168u32);
    assert(join == expected_join, "root join mismatch");
}

pub fn main(
    challenge: pub [u8; 32],
    audience_hash: pub [u8; 32],
    transaction_data_hash: pub [u8; 32],
    active_status_root: pub [u8; 32],
    root_join: pub [u8; 32],
    attestation_join: pub [u8; 32],
    root: [u8; 32],
    attestation_id: [u8; 32],
    join_salt: [u8; 32],
    status_index: u32,
    status_path_len: u32,
    status_path: [[u8; 32]; MAX_STATUS_DEPTH],
) {
    assert(!is_zero32(root), "root is zero");
    assert(!is_zero32(attestation_id), "attestation id is zero");
    assert(!is_zero32(challenge), "challenge is zero");
    assert(!is_zero32(audience_hash), "audience is zero");
    assert(!is_zero32(transaction_data_hash), "transaction hash is zero");
    verify_active_status(
        attestation_id,
        active_status_root,
        status_index,
        status_path_len,
        status_path,
    );
    verify_root_join(
        root,
        join_salt,
        challenge,
        audience_hash,
        transaction_data_hash,
        root_join,
    );
    verify_attestation_join(
        attestation_id,
        join_salt,
        challenge,
        audience_hash,
        transaction_data_hash,
        attestation_join,
    );
}
