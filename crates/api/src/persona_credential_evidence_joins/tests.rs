// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    check_persona_credential_evidence_v1_joins, ZkPersonaCredentialEvidenceJoinReason,
    ZkPersonaCredentialEvidenceStageJoin,
};
use crate::{
    circuits::ZkCredentialHashAlgorithm,
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceValidityWindow,
        ZkPersonaCredentialEvidenceValidityWindowError,
    },
    proofs::ZkProofSuite,
};

fn stage(
) -> Result<ZkPersonaCredentialEvidenceStageJoin, ZkPersonaCredentialEvidenceValidityWindowError> {
    Ok(ZkPersonaCredentialEvidenceStageJoin {
        credential_hash_algorithm: ZkCredentialHashAlgorithm::Sha256,
        proof_suite: ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        issuer_key: ZkIssuerPublicKey {
            x: [1; 32],
            y: [2; 32],
        },
        holder_key: ZkPersonaCredentialEvidenceHolderPublicKey {
            x: [3; 32],
            y: [4; 32],
        },
        token_nonce: [5; 32],
        proof_window: ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 200)?,
        credential_binding: [6; 32],
    })
}

#[test]
fn accepts_exact_verified_stage_join_at_current_time(
) -> Result<(), ZkPersonaCredentialEvidenceValidityWindowError> {
    let claim = stage()?;
    let status = stage()?;
    assert!(check_persona_credential_evidence_v1_joins(&claim, &status, 100).is_ok());
    assert!(check_persona_credential_evidence_v1_joins(&claim, &status, 199).is_ok());
    Ok(())
}

#[test]
fn rejects_each_mismatched_public_join(
) -> Result<(), ZkPersonaCredentialEvidenceValidityWindowError> {
    let claim = stage()?;
    for field in 0..10 {
        let mut status = stage()?;
        match field {
            0 => status.credential_hash_algorithm = ZkCredentialHashAlgorithm::Poseidon2,
            1 => status.proof_suite = ZkProofSuite::BarretenbergUltraHonkPoseidon2ZkNoIpa,
            2 => status.issuer_key.x[0] ^= 1,
            3 => status.issuer_key.y[0] ^= 1,
            4 => status.holder_key.x[0] ^= 1,
            5 => status.holder_key.y[0] ^= 1,
            6 => status.token_nonce[0] ^= 1,
            7 => status.credential_binding[0] ^= 1,
            8 => {
                status.proof_window = ZkPersonaCredentialEvidenceValidityWindow::try_new(101, 200)?
            }
            _ => {
                status.proof_window = ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 201)?
            }
        }
        assert_eq!(
            check_persona_credential_evidence_v1_joins(&claim, &status, 150)
                .err()
                .map(super::ZkPersonaCredentialEvidenceJoinError::reason),
            Some(ZkPersonaCredentialEvidenceJoinReason::Mismatch),
        );
    }
    Ok(())
}

#[test]
fn rejects_empty_token_and_exclusive_expiry(
) -> Result<(), ZkPersonaCredentialEvidenceValidityWindowError> {
    let claim = stage()?;
    let status = stage()?;
    for now in [99, 200, u64::MAX] {
        assert_eq!(
            check_persona_credential_evidence_v1_joins(&claim, &status, now)
                .err()
                .map(super::ZkPersonaCredentialEvidenceJoinError::reason),
            Some(ZkPersonaCredentialEvidenceJoinReason::NotCurrent),
        );
    }
    let mut empty = stage()?;
    empty.token_nonce = [0; 32];
    assert_eq!(
        check_persona_credential_evidence_v1_joins(&claim, &empty, 150)
            .err()
            .map(super::ZkPersonaCredentialEvidenceJoinError::reason),
        Some(ZkPersonaCredentialEvidenceJoinReason::InvalidInput),
    );
    let mut unmasked = stage()?;
    unmasked.proof_suite = ZkProofSuite::BarretenbergUltraHonkKeccakUnmaskedNoIpa;
    assert_eq!(
        check_persona_credential_evidence_v1_joins(&claim, &unmasked, 150)
            .err()
            .map(super::ZkPersonaCredentialEvidenceJoinError::reason),
        Some(ZkPersonaCredentialEvidenceJoinReason::UnsupportedSuite),
    );
    let mut empty = stage()?;
    empty.holder_key.x = [0; 32];
    empty.holder_key.y = [0; 32];
    assert_eq!(
        check_persona_credential_evidence_v1_joins(&claim, &empty, 150)
            .err()
            .map(super::ZkPersonaCredentialEvidenceJoinError::reason),
        Some(ZkPersonaCredentialEvidenceJoinReason::InvalidInput),
    );
    Ok(())
}
