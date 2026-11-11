// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use sha2::{Digest as _, Sha256};

use super::{
    BindingContext, PublicKeyBytes, CLAIM_TREE_DEPTH, EXPIRY_UNIX, HASH_BYTES, SALT_BYTES,
    SALT_OFFSETS, SIGNATURE_BYTES, VALUE_BYTES,
};
use crate::generate_private_persona_distinct_fixtures::FixtureError;

pub(super) fn persona_message_hash(binding_context: BindingContext) -> [u8; HASH_BYTES] {
    let expiry = EXPIRY_UNIX.to_be_bytes();
    domain_hash(
        b"PERS2",
        &[
            &binding_context.challenge,
            &binding_context.audience_hash,
            &binding_context.transaction_data_hash,
            &expiry,
        ],
    )
}

pub(super) fn session_binding(
    persona_key: &PublicKeyBytes,
    binding_context: BindingContext,
) -> [u8; HASH_BYTES] {
    let expiry = EXPIRY_UNIX.to_be_bytes();
    domain_hash(
        b"PSESB2",
        &[
            &persona_key.x,
            &persona_key.y,
            &binding_context.challenge,
            &binding_context.audience_hash,
            &binding_context.transaction_data_hash,
            &expiry,
        ],
    )
}

pub(super) fn direct_session_binding(
    subject_key: &PublicKeyBytes,
    binding_context: BindingContext,
) -> [u8; HASH_BYTES] {
    domain_hash(
        b"SESSB1",
        &[
            &subject_key.x,
            &subject_key.y,
            &binding_context.challenge,
            &binding_context.audience_hash,
            &binding_context.transaction_data_hash,
            &EXPIRY_UNIX.to_be_bytes(),
        ],
    )
}

pub(super) fn envelope_binding(
    issuer_key: &PublicKeyBytes,
    envelope_hash: &[u8; HASH_BYTES],
    binding_context: BindingContext,
) -> [u8; HASH_BYTES] {
    let expiry = EXPIRY_UNIX.to_be_bytes();
    domain_hash(
        b"ENVB1",
        &[
            &issuer_key.x,
            &issuer_key.y,
            envelope_hash,
            &binding_context.challenge,
            &binding_context.audience_hash,
            &binding_context.transaction_data_hash,
            &expiry,
        ],
    )
}

pub(super) fn credential_binding(
    issuer_key: &PublicKeyBytes,
    envelope_hash: &[u8; HASH_BYTES],
    merkle_root: &[u8; HASH_BYTES],
    binding_context: BindingContext,
) -> [u8; HASH_BYTES] {
    let expiry = EXPIRY_UNIX.to_be_bytes();
    domain_hash(
        b"CREDB1",
        &[
            &issuer_key.x,
            &issuer_key.y,
            envelope_hash,
            merkle_root,
            &binding_context.challenge,
            &binding_context.audience_hash,
            &binding_context.transaction_data_hash,
            &expiry,
        ],
    )
}

pub(super) fn merkle_root(
    name_hash: &[u8; HASH_BYTES],
    val_pub: &[u8; VALUE_BYTES],
    val_len: u32,
    salt: &[u8; SALT_BYTES],
    path: &[[u8; HASH_BYTES]; CLAIM_TREE_DEPTH],
    index: u32,
) -> Result<[u8; HASH_BYTES], FixtureError> {
    let value_len = usize::try_from(val_len).map_err(|_| FixtureError::Length)?;
    let len_bytes = val_len.to_be_bytes();
    let value = val_pub.get(..value_len).ok_or(FixtureError::Length)?;
    let inner = domain_hash(b"CLM1", &[&len_bytes, value, salt]);
    let mut current = domain_hash(b"LEAF1", &[name_hash, &inner]);
    // Every claim tree has the fixed depth, so the root folds all levels.
    for (path_index, sibling) in path.iter().enumerate() {
        let level = u32::try_from(path_index).map_err(|_| FixtureError::Length)?;
        if ((index >> level) & 1) == 0 {
            current = domain_hash(b"NODE1", &[&current, sibling]);
        } else {
            current = domain_hash(b"NODE1", &[sibling, &current]);
        }
    }
    Ok(current)
}

pub(super) fn domain_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; HASH_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0_u8; HASH_BYTES];
    out.copy_from_slice(&digest);
    out
}

pub(super) fn read_fixed_32(bytes: &[u8]) -> Result<[u8; HASH_BYTES], FixtureError> {
    bytes.try_into().map_err(|_| FixtureError::Length)
}

pub(super) fn read_fixed_64(bytes: &[u8]) -> Result<[u8; SIGNATURE_BYTES], FixtureError> {
    bytes.try_into().map_err(|_| FixtureError::Length)
}

pub(super) const fn scalar_bytes(value: u8) -> [u8; HASH_BYTES] {
    let mut out = [0_u8; HASH_BYTES];
    out[31] = value;
    out
}

pub(super) fn salt_for(index: u8) -> [u8; SALT_BYTES] {
    let mut out = [0_u8; SALT_BYTES];
    for (base, byte) in SALT_OFFSETS.iter().zip(out.iter_mut()) {
        *byte = base.wrapping_add(index).wrapping_add(1);
    }
    out
}

pub(super) fn material_label(index: u8) -> Result<&'static [u8], FixtureError> {
    match index {
        0 => Ok(b"credential-a"),
        1 => Ok(b"credential-b"),
        _ => Err(FixtureError::Length),
    }
}

pub(super) fn value_for(index: u8) -> Result<Vec<u8>, FixtureError> {
    let value = match index {
        0 => b"Springfield-A".as_slice(),
        1 => b"Springfield-B".as_slice(),
        _ => return Err(FixtureError::Length),
    };
    Ok(value.to_vec())
}

pub(super) fn merkle_path_for(
    index: u8,
) -> Result<[[u8; HASH_BYTES]; CLAIM_TREE_DEPTH], FixtureError> {
    let mut path = [[0_u8; HASH_BYTES]; CLAIM_TREE_DEPTH];
    for (level, sibling) in path.iter_mut().enumerate() {
        let level = u8::try_from(level).map_err(|_| FixtureError::Length)?;
        *sibling = domain_hash(b"SIBL1", &[&[index, level]]);
    }
    Ok(path)
}
