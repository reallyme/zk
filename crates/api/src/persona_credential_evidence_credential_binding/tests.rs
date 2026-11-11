// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashSet;

use super::{
    derive_persona_credential_evidence_binding, ZkPersonaCredentialEvidenceBindingInputs,
    ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceSubjectPublicKey,
};
use crate::{
    circuits::ZkCredentialHashAlgorithm,
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        ZkPersonaCredentialEvidenceValidityWindow, ZkPersonaCredentialEvidenceValidityWindowError,
    },
};

fn inputs(
    token_byte: u8,
    holder_byte: u8,
) -> Result<ZkPersonaCredentialEvidenceBindingInputs, ZkPersonaCredentialEvidenceValidityWindowError>
{
    Ok(ZkPersonaCredentialEvidenceBindingInputs {
        issuer_key: ZkIssuerPublicKey {
            x: [1; 32],
            y: [2; 32],
        },
        envelope_hash: [3; 32],
        claims_root: [4; 32],
        subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
            x: [8; 32],
            y: [9; 32],
        },
        holder_key: ZkPersonaCredentialEvidenceHolderPublicKey {
            x: [holder_byte; 32],
            y: [6; 32],
        },
        token_nonce: [token_byte; 32],
        proof_window: ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 200)?,
    })
}

#[test]
fn transcript_matches_both_noir_hash_lanes(
) -> Result<(), ZkPersonaCredentialEvidenceValidityWindowError> {
    let sha = derive_persona_credential_evidence_binding(
        ZkCredentialHashAlgorithm::Sha256,
        inputs(7, 5)?,
    );
    let poseidon = derive_persona_credential_evidence_binding(
        ZkCredentialHashAlgorithm::Poseidon2,
        inputs(7, 5)?,
    );
    assert_eq!(
        sha.ok(),
        Some([
            0xbb, 0x9c, 0x43, 0xc4, 0x2b, 0x5b, 0x26, 0x9c, 0x1e, 0xae, 0x3d, 0x1e, 0x7c, 0x0d,
            0xe5, 0xec, 0x62, 0xee, 0xf4, 0x44, 0x57, 0xb5, 0x3e, 0xb4, 0x2e, 0x9d, 0x1c, 0x32,
            0x41, 0x8c, 0xe9, 0xe0,
        ])
    );
    assert_eq!(
        poseidon.ok(),
        Some([
            0x0a, 0x21, 0x0e, 0x61, 0xe1, 0xd9, 0x1a, 0xdb, 0x52, 0x13, 0x99, 0x96, 0x4d, 0x97,
            0xb5, 0xf7, 0x5b, 0x87, 0xc8, 0x17, 0xe9, 0xa9, 0x1b, 0xb9, 0xde, 0xc5, 0x4c, 0x22,
            0x19, 0xd1, 0x69, 0x93,
        ])
    );
    Ok(())
}

#[test]
fn one_hundred_same_credential_tokens_have_distinct_public_joins(
) -> Result<(), crate::errors::ZkError> {
    let mut sha = HashSet::new();
    let mut poseidon = HashSet::new();
    let mut holder_keys = HashSet::new();
    let mut nonces = HashSet::new();
    for token in 1..=100_u8 {
        let mut secret_scalar = [0_u8; 32];
        secret_scalar[31] = token;
        let (compressed, _) = crypto_p256::generate_p256_keypair_from_secret_key(&secret_scalar)
            .map_err(|_| {
                crate::errors::ZkError::new(crate::errors::ZkErrorReason::BackendFailure)
            })?;
        let uncompressed = crypto_p256::decompress_p256(&compressed).map_err(|_| {
            crate::errors::ZkError::new(crate::errors::ZkErrorReason::BackendFailure)
        })?;
        assert_eq!(uncompressed.len(), 65);
        let mut holder_x = [0_u8; 32];
        let mut holder_y = [0_u8; 32];
        holder_x.copy_from_slice(&uncompressed[1..33]);
        holder_y.copy_from_slice(&uncompressed[33..65]);
        let nonce =
            crypto_sha2_256::digest(&[b"prepared-private-token".as_slice(), &[token]].concat())
                .into_bytes();
        let mut token_inputs = inputs(token, token).map_err(|_| {
            crate::errors::ZkError::new(crate::errors::ZkErrorReason::BackendFailure)
        })?;
        token_inputs.holder_key = ZkPersonaCredentialEvidenceHolderPublicKey {
            x: holder_x,
            y: holder_y,
        };
        token_inputs.token_nonce = nonce;
        assert!(holder_keys.insert(compressed));
        assert!(nonces.insert(nonce));
        let sha_binding = derive_persona_credential_evidence_binding(
            ZkCredentialHashAlgorithm::Sha256,
            ZkPersonaCredentialEvidenceBindingInputs {
                issuer_key: token_inputs.issuer_key,
                envelope_hash: token_inputs.envelope_hash,
                claims_root: token_inputs.claims_root,
                subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
                    x: [8; 32],
                    y: [9; 32],
                },
                holder_key: token_inputs.holder_key,
                token_nonce: token_inputs.token_nonce,
                proof_window: token_inputs.proof_window,
            },
        );
        let poseidon_binding = derive_persona_credential_evidence_binding(
            ZkCredentialHashAlgorithm::Poseidon2,
            token_inputs,
        );
        assert!(sha_binding.is_ok());
        assert!(poseidon_binding.is_ok());
        assert!(sha_binding.ok().is_some_and(|binding| sha.insert(binding)));
        assert!(poseidon_binding
            .ok()
            .is_some_and(|binding| poseidon.insert(binding)));
    }
    assert_eq!(sha.len(), 100);
    assert_eq!(poseidon.len(), 100);
    assert_eq!(holder_keys.len(), 100);
    assert_eq!(nonces.len(), 100);
    Ok(())
}

#[test]
fn issuer_subject_cannot_be_substituted_across_prepared_stages(
) -> Result<(), ZkPersonaCredentialEvidenceValidityWindowError> {
    for lane in ZkCredentialHashAlgorithm::ALL {
        let authenticated = derive_persona_credential_evidence_binding(*lane, inputs(7, 5)?);
        let mut substituted = inputs(7, 5)?;
        substituted.subject_key.x[0] ^= 1;
        let substituted = derive_persona_credential_evidence_binding(*lane, substituted);
        assert!(authenticated.is_ok());
        assert!(substituted.is_ok());
        assert_ne!(authenticated.ok(), substituted.ok());
    }
    Ok(())
}

#[test]
fn empty_nonce_and_holder_key_fail_closed(
) -> Result<(), ZkPersonaCredentialEvidenceValidityWindowError> {
    let mut zero_nonce = inputs(7, 5)?;
    zero_nonce.token_nonce = [0; 32];
    assert!(derive_persona_credential_evidence_binding(
        ZkCredentialHashAlgorithm::Sha256,
        zero_nonce
    )
    .is_err());
    let mut zero_holder = inputs(7, 5)?;
    zero_holder.holder_key.x = [0; 32];
    zero_holder.holder_key.y = [0; 32];
    assert!(derive_persona_credential_evidence_binding(
        ZkCredentialHashAlgorithm::Sha256,
        zero_holder
    )
    .is_err());
    let mut zero_subject = inputs(7, 5)?;
    zero_subject.subject_key.x = [0; 32];
    zero_subject.subject_key.y = [0; 32];
    assert!(derive_persona_credential_evidence_binding(
        ZkCredentialHashAlgorithm::Sha256,
        zero_subject
    )
    .is_err());
    Ok(())
}
