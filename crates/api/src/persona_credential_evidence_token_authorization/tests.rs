// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::persona_credential_evidence_private_token_authorization_digest;
use crate::persona_evidence::{
    ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceValidityWindow,
};

#[test]
fn token_authorization_binds_key_nonce_and_window() -> Result<(), crate::errors::ZkError> {
    let key = ZkPersonaCredentialEvidenceHolderPublicKey {
        x: [1; 32],
        y: [2; 32],
    };
    let window = ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 200)
        .map_err(|_| crate::errors::ZkError::new(crate::errors::ZkErrorReason::BindingMismatch))?;
    let expected = [
        0x73, 0x04, 0x28, 0xeb, 0xeb, 0x63, 0x65, 0xcc, 0x20, 0xd8, 0x8a, 0x4c, 0xc4, 0x31, 0x6d,
        0xca, 0xa8, 0x82, 0xbf, 0xa6, 0x97, 0xdf, 0x73, 0xa4, 0x85, 0x6a, 0xfd, 0x0b, 0x1d, 0x06,
        0x71, 0x8d,
    ];
    let digest =
        persona_credential_evidence_private_token_authorization_digest(key, [3; 32], window);
    assert_eq!(digest, expected);
    assert_ne!(
        digest,
        persona_credential_evidence_private_token_authorization_digest(key, [4; 32], window)
    );
    Ok(())
}
