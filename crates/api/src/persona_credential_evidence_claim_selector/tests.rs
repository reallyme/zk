// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::persona_credential_evidence_claim_selector_digest;
use crate::{circuits::ZkCredentialHashAlgorithm, errors::ZkError};

#[test]
fn selector_binds_copy_lane_name_and_value() -> Result<(), ZkError> {
    let baseline = persona_credential_evidence_claim_selector_digest(
        "copy-1",
        ZkCredentialHashAlgorithm::Sha256,
        &[7; 32],
        b"over18",
    )?;
    assert_eq!(
        baseline,
        persona_credential_evidence_claim_selector_digest(
            "copy-1",
            ZkCredentialHashAlgorithm::Sha256,
            &[7; 32],
            b"over18"
        )?
    );
    assert_ne!(
        baseline,
        persona_credential_evidence_claim_selector_digest(
            "copy-2",
            ZkCredentialHashAlgorithm::Sha256,
            &[7; 32],
            b"over18"
        )?
    );
    assert_ne!(
        baseline,
        persona_credential_evidence_claim_selector_digest(
            "copy-1",
            ZkCredentialHashAlgorithm::Poseidon2,
            &[7; 32],
            b"over18"
        )?
    );
    assert_ne!(
        baseline,
        persona_credential_evidence_claim_selector_digest(
            "copy-1",
            ZkCredentialHashAlgorithm::Sha256,
            &[8; 32],
            b"over18"
        )?
    );
    assert_ne!(
        baseline,
        persona_credential_evidence_claim_selector_digest(
            "copy-1",
            ZkCredentialHashAlgorithm::Sha256,
            &[7; 32],
            b"over21"
        )?
    );
    assert!(persona_credential_evidence_claim_selector_digest(
        "",
        ZkCredentialHashAlgorithm::Sha256,
        &[7; 32],
        b"over18"
    )
    .is_err());
    assert!(persona_credential_evidence_claim_selector_digest(
        "copy-1",
        ZkCredentialHashAlgorithm::Sha256,
        &[7; 32],
        b""
    )
    .is_err());
    Ok(())
}
