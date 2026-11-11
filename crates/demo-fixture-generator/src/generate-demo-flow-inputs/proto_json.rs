// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use zeroize::Zeroize;

use super::fields::ProverFields;
use super::{
    FixtureError, PROFILE_CREDENTIAL_SUBJECT_CLAIM, PROFILE_PRIVATE_PERSONA, STAGE_CLAIM,
    STAGE_CREDENTIAL_ENVELOPE, STAGE_CREDENTIAL_ROOT, STAGE_SESSION,
};

pub(super) fn stage_proto_json(
    profile: &str,
    stage: &str,
    fields: &ProverFields,
) -> Result<Value, FixtureError> {
    match (profile, stage) {
        (PROFILE_CREDENTIAL_SUBJECT_CLAIM, STAGE_SESSION) => Ok(json!({
            "credential_subject_claim_session": subject_session(fields, "subject_sig", "subject")?,
        })),
        (PROFILE_PRIVATE_PERSONA, STAGE_SESSION) => Ok(json!({
            "private_persona_session": persona_session(fields)?,
        })),
        (_, STAGE_CREDENTIAL_ENVELOPE) => Ok(json!({
            "credential_envelope": credential_envelope(fields)?,
        })),
        (_, STAGE_CREDENTIAL_ROOT) => Ok(json!({
            "credential_root": credential_root(fields)?,
        })),
        (PROFILE_CREDENTIAL_SUBJECT_CLAIM, STAGE_CLAIM) => Ok(json!({
            "credential_subject_claim": credential_subject_claim(fields)?,
        })),
        (PROFILE_PRIVATE_PERSONA, STAGE_CLAIM) => Ok(json!({
            "private_persona_claim": private_persona_claim(fields)?,
        })),
        _ => Err(FixtureError::MissingField),
    }
}

fn subject_session(
    fields: &ProverFields,
    signature_field: &'static str,
    public_key_prefix: &'static str,
) -> Result<Value, FixtureError> {
    Ok(json!({
        "session_context": session_context(fields)?,
        "authorization": {
            "subject_public_key": p256_public_key(fields, public_key_prefix)?,
            "subject_signature": bytes64(fields, signature_field)?,
        },
    }))
}

fn persona_session(fields: &ProverFields) -> Result<Value, FixtureError> {
    Ok(json!({
        "session_context": session_context(fields)?,
        "authorization": {
            "persona_public_key": p256_public_key(fields, "persona")?,
            "persona_signature": bytes64(fields, "persona_sig")?,
        },
    }))
}

fn credential_envelope(fields: &ProverFields) -> Result<Value, FixtureError> {
    Ok(json!({
        "issuer_context": issuer_context(fields)?,
        "envelope_binding": bytes32(fields, "envelope_binding")?,
        "proof": {
            "envelope_hash": bytes32(fields, "envelope_hash")?,
            "issuer_signature": bytes64(fields, "issuer_sig")?,
        },
    }))
}

fn credential_root(fields: &ProverFields) -> Result<Value, FixtureError> {
    Ok(json!({
        "issuer_context": issuer_context(fields)?,
        "envelope_binding": bytes32(fields, "envelope_binding")?,
        "credential_binding": bytes32(fields, "credential_binding")?,
        "proof": {
            "envelope_hash": bytes32(fields, "envelope_hash")?,
            "merkle_root": bytes32(fields, "merkle_root")?,
            "issuer_root_binding_signature": bytes64(fields, "issuer_root_bind_sig")?,
        },
    }))
}

fn credential_subject_claim(fields: &ProverFields) -> Result<Value, FixtureError> {
    Ok(json!({
        "issuer_context": issuer_context(fields)?,
        "session_binding": bytes32(fields, "session_binding")?,
        "disclosure": disclosure(fields)?,
        "proof": merkle_claim_proof(fields)?,
        "link": {
            "issuer_subject_binding_signature": bytes64(fields, "issuer_subject_bind_sig")?,
            "subject_public_key": p256_public_key(fields, "subject")?,
        },
    }))
}

fn private_persona_claim(fields: &ProverFields) -> Result<Value, FixtureError> {
    Ok(json!({
        "issuer_context": issuer_context(fields)?,
        "session_binding": bytes32(fields, "session_binding")?,
        "disclosure": disclosure(fields)?,
        "proof": merkle_claim_proof(fields)?,
        "link": {
            "issuer_subject_binding_signature": bytes64(fields, "issuer_subject_bind_sig")?,
            "subject_public_key": p256_public_key(fields, "subject")?,
            "persona_public_key": p256_public_key(fields, "persona")?,
            "subject_link_signature": bytes64(fields, "subject_link_sig")?,
        },
    }))
}

fn session_context(fields: &ProverFields) -> Result<Value, FixtureError> {
    Ok(json!({
        "challenge": bytes32(fields, "challenge")?,
        "audience_hash": bytes32(fields, "audience_hash")?,
        "transaction_data_hash": bytes32(fields, "transaction_data_hash")?,
        "expiry_unix": fields.uint64("expiry_unix")?,
        "session_binding": bytes32(fields, "session_binding")?,
    }))
}

fn issuer_context(fields: &ProverFields) -> Result<Value, FixtureError> {
    Ok(json!({
        "issuer_public_key": p256_public_key(fields, "issuer")?,
        "challenge": bytes32(fields, "challenge")?,
        "audience_hash": bytes32(fields, "audience_hash")?,
        "transaction_data_hash": bytes32(fields, "transaction_data_hash")?,
        "expiry_unix": fields.uint64("expiry_unix")?,
    }))
}

fn disclosure(fields: &ProverFields) -> Result<Value, FixtureError> {
    Ok(json!({
        "credential_binding": bytes32(fields, "credential_binding")?,
        "value_length": fields.uint32("val_len")?,
        "value": bytes64(fields, "val_pub")?,
        "claim_name_hash": bytes32(fields, "name_hash")?,
    }))
}

fn merkle_claim_proof(fields: &ProverFields) -> Result<Value, FixtureError> {
    let mut siblings = Vec::new();
    for sibling in fields.merkle_path("path")? {
        siblings.push(bytes_value(sibling));
    }
    Ok(json!({
        "envelope_hash": bytes32(fields, "envelope_hash")?,
        "merkle_root": bytes32(fields, "merkle_root")?,
        "claim_salt": bytes16(fields, "salt")?,
        "leaf_index": fields.uint32("index")?,
        "path": {
            "path_length": fields.uint32("path_len")?,
            "siblings": siblings,
        },
    }))
}

fn p256_public_key(fields: &ProverFields, prefix: &'static str) -> Result<Value, FixtureError> {
    let mut keys = BTreeMap::new();
    keys.insert("subject", ("pk_subject_x", "pk_subject_y"));
    keys.insert("persona", ("pk_persona_x", "pk_persona_y"));
    keys.insert("issuer", ("pk_issuer_x", "pk_issuer_y"));
    let (x, y) = keys.get(prefix).ok_or(FixtureError::MissingField)?;
    Ok(json!({
        "x": bytes32(fields, x)?,
        "y": bytes32(fields, y)?,
    }))
}

fn bytes16(fields: &ProverFields, key: &'static str) -> Result<Value, FixtureError> {
    Ok(bytes_value(fields.bytes(key, 16)?))
}

fn bytes32(fields: &ProverFields, key: &'static str) -> Result<Value, FixtureError> {
    Ok(bytes_value(fields.bytes(key, 32)?))
}

fn bytes64(fields: &ProverFields, key: &'static str) -> Result<Value, FixtureError> {
    Ok(bytes_value(fields.bytes(key, 64)?))
}

fn bytes_value(mut bytes: Vec<u8>) -> Value {
    let encoded = STANDARD.encode(&bytes);
    bytes.zeroize();
    json!({ "value": encoded })
}
