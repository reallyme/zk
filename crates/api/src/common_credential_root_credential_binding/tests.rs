// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    derive_common_credential_root_credential_binding, ZkCommonCredentialRootCredentialBindingInputs,
};
use crate::{
    circuits::ZkCredentialHashAlgorithm, common_root::ZkCommonCredentialRootRequestJoinContext,
    keys::ZkIssuerPublicKey,
};

#[test]
fn common_credential_root_credential_binding_is_hash_lane_aware(
) -> Result<(), crate::errors::ZkError> {
    let inputs = fixture_inputs(1_900_000_180);
    let sha = derive_common_credential_root_credential_binding(
        ZkCredentialHashAlgorithm::Sha256,
        inputs,
    )?;
    let poseidon2 = derive_common_credential_root_credential_binding(
        ZkCredentialHashAlgorithm::Poseidon2,
        fixture_inputs(1_900_000_180),
    )?;
    assert_ne!(sha, poseidon2);
    assert_eq!(
        sha,
        derive_common_credential_root_credential_binding(
            ZkCredentialHashAlgorithm::Sha256,
            fixture_inputs(1_900_000_180)
        )?
    );
    assert_eq!(
        poseidon2,
        derive_common_credential_root_credential_binding(
            ZkCredentialHashAlgorithm::Poseidon2,
            fixture_inputs(1_900_000_180)
        )?
    );
    Ok(())
}

#[test]
fn common_credential_root_credential_binding_binds_session_and_expiry(
) -> Result<(), crate::errors::ZkError> {
    let expected = derive_common_credential_root_credential_binding(
        ZkCredentialHashAlgorithm::Sha256,
        fixture_inputs(1_900_000_180),
    )?;
    let changed_expiry = derive_common_credential_root_credential_binding(
        ZkCredentialHashAlgorithm::Sha256,
        fixture_inputs(1_900_000_181),
    )?;
    let mut changed_request = fixture_inputs(1_900_000_180);
    changed_request.request.challenge = [0x91; 32];
    let changed_challenge = derive_common_credential_root_credential_binding(
        ZkCredentialHashAlgorithm::Sha256,
        changed_request,
    )?;
    assert_ne!(expected, changed_expiry);
    assert_ne!(expected, changed_challenge);
    Ok(())
}

fn fixture_inputs(expiry_unix: u64) -> ZkCommonCredentialRootCredentialBindingInputs {
    ZkCommonCredentialRootCredentialBindingInputs {
        issuer_key: ZkIssuerPublicKey {
            x: [0x11; 32],
            y: [0x12; 32],
        },
        envelope_hash: [0x31; 32],
        claims_root: [0x41; 32],
        request: ZkCommonCredentialRootRequestJoinContext {
            challenge: [0x51; 32],
            audience_hash: [0x61; 32],
            transaction_data_hash: [0x71; 32],
        },
        expiry_unix,
    }
}
