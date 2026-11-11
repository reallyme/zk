// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{BindingContext, PublicKeyBytes, EXPIRY_UNIX, HASH_BYTES};

pub(super) fn append_common_context(out: &mut String, binding_context: BindingContext) {
    append_array(out, "challenge", &binding_context.challenge);
    append_array(out, "audience_hash", &binding_context.audience_hash);
    append_array(
        out,
        "transaction_data_hash",
        &binding_context.transaction_data_hash,
    );
    out.push_str("expiry_unix = ");
    out.push_str(&EXPIRY_UNIX.to_string());
    out.push('\n');
}

pub(super) fn append_issuer_context(
    out: &mut String,
    issuer: &PublicKeyBytes,
    binding_context: BindingContext,
) {
    append_public_key(out, "issuer", issuer);
    append_common_context(out, binding_context);
}

pub(super) fn append_public_key(out: &mut String, prefix: &str, key: &PublicKeyBytes) {
    out.push_str("pk_");
    out.push_str(prefix);
    out.push_str("_x = ");
    append_array_value(out, &key.x);
    out.push('\n');
    out.push_str("pk_");
    out.push_str(prefix);
    out.push_str("_y = ");
    append_array_value(out, &key.y);
    out.push('\n');
}

pub(super) fn append_u32(out: &mut String, name: &str, value: u32) {
    out.push_str(name);
    out.push_str(" = ");
    out.push_str(&value.to_string());
    out.push('\n');
}

pub(super) fn append_u64(out: &mut String, name: &str, value: u64) {
    out.push_str(name);
    out.push_str(" = ");
    out.push_str(&value.to_string());
    out.push('\n');
}

pub(super) fn append_array<const N: usize>(out: &mut String, name: &str, value: &[u8; N]) {
    out.push_str(name);
    out.push_str(" = ");
    append_array_value(out, value);
    out.push('\n');
}

fn append_array_value(out: &mut String, value: &[u8]) {
    out.push('[');
    for (index, byte) in value.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&byte.to_string());
    }
    out.push(']');
}

pub(super) fn append_path<const N: usize>(
    out: &mut String,
    name: &str,
    path: &[[u8; HASH_BYTES]; N],
) {
    out.push_str(name);
    out.push_str(" = [");
    for (index, row) in path.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        append_array_value(out, row);
    }
    out.push_str("]\n");
}
