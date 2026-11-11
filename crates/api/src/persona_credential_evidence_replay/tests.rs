// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ZkPersonaCredentialEvidenceReplayChallenge, ZkPersonaCredentialEvidenceReplayReason};

#[test]
fn challenge_rejects_empty_identity_and_nonce() {
    assert_eq!(
        ZkPersonaCredentialEvidenceReplayChallenge::try_new(&[0; 32], &[1; 32], 100)
            .err()
            .map(|error| error.reason()),
        Some(ZkPersonaCredentialEvidenceReplayReason::InvalidChallenge)
    );
    assert_eq!(
        ZkPersonaCredentialEvidenceReplayChallenge::try_new(&[1; 32], &[0; 32], 100)
            .err()
            .map(|error| error.reason()),
        Some(ZkPersonaCredentialEvidenceReplayReason::InvalidChallenge)
    );
    assert!(ZkPersonaCredentialEvidenceReplayChallenge::try_new(&[1; 32], &[2; 32], 100).is_ok());
}
