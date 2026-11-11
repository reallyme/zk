// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use sha2::{Digest as _, Sha256};

use crate::generate_private_persona_distinct_fixtures::FixtureError;

use super::{AUDIENCE_HASH, CHALLENGE, HASH_BYTES, TRANSACTION_DATA_HASH};

const ABSENT_TRANSACTION_DATA_HASH: [u8; HASH_BYTES] = [
    91, 78, 241, 88, 7, 232, 126, 177, 177, 131, 109, 112, 2, 4, 88, 59, 120, 149, 185, 19, 196,
    86, 121, 196, 170, 197, 102, 14, 81, 110, 143, 196,
];
const BINDING_CONTEXT_ENV: &str = "REALLYME_PRIVATE_PERSONA_BINDING_CONTEXT";
const BINDING_CONTEXT_OPENID4VP_DC_API: &str = "openid4vp-dc-api";
const BINDING_CONTEXT_OPENID4VP_DIRECT_POST: &str = "openid4vp-direct-post";
const OPENID4VP_DC_API_NONCE: &[u8] = b"linked-private-persona-openid4vp-nonce-v1";
const OPENID4VP_DC_API_AUDIENCE: &[u8] = b"origin:https://verifier.example";
const OPENID4VP_DIRECT_POST_AUDIENCE: &[u8] = b"decentralized_identifier:did:example:verifier";

#[derive(Clone, Copy)]
pub(in crate::generate_private_persona_distinct_fixtures) struct BindingContext {
    pub(in crate::generate_private_persona_distinct_fixtures::crypto) challenge: [u8; HASH_BYTES],
    pub(in crate::generate_private_persona_distinct_fixtures::crypto) audience_hash:
        [u8; HASH_BYTES],
    pub(in crate::generate_private_persona_distinct_fixtures::crypto) transaction_data_hash:
        [u8; HASH_BYTES],
}

impl BindingContext {
    pub(in crate::generate_private_persona_distinct_fixtures) fn from_environment(
    ) -> Result<Self, FixtureError> {
        match std::env::var(BINDING_CONTEXT_ENV) {
            Ok(value) if value == BINDING_CONTEXT_OPENID4VP_DC_API => Ok(Self::openid4vp_dc_api()),
            Ok(value) if value == BINDING_CONTEXT_OPENID4VP_DIRECT_POST => {
                Ok(Self::openid4vp_direct_post())
            }
            Ok(_value) => Err(FixtureError::Usage),
            Err(std::env::VarError::NotPresent) => Ok(Self::default_fixture()),
            Err(std::env::VarError::NotUnicode(_value)) => Err(FixtureError::Usage),
        }
    }

    const fn default_fixture() -> Self {
        Self {
            challenge: CHALLENGE,
            audience_hash: AUDIENCE_HASH,
            transaction_data_hash: TRANSACTION_DATA_HASH,
        }
    }

    fn openid4vp_dc_api() -> Self {
        Self {
            challenge: sha256(OPENID4VP_DC_API_NONCE),
            audience_hash: sha256(OPENID4VP_DC_API_AUDIENCE),
            transaction_data_hash: ABSENT_TRANSACTION_DATA_HASH,
        }
    }

    fn openid4vp_direct_post() -> Self {
        Self {
            challenge: sha256(OPENID4VP_DC_API_NONCE),
            audience_hash: sha256(OPENID4VP_DIRECT_POST_AUDIENCE),
            transaction_data_hash: ABSENT_TRANSACTION_DATA_HASH,
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; HASH_BYTES] {
    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; HASH_BYTES];
    out.copy_from_slice(&digest);
    out
}
