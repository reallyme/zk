// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ZkProofSuite, ZkTranscriptHash};
use crate::errors::ZkErrorReason;

#[test]
fn production_suite_pins_every_backend_option() {
    let suite = ZkProofSuite::PRODUCTION;

    assert_eq!(suite.transcript_hash(), ZkTranscriptHash::Keccak);
    assert!(suite.zero_knowledge());
    assert!(!suite.ipa_accumulation());
    assert_eq!(suite.require_production(), Ok(()));
}

#[test]
fn every_supported_suite_has_explicit_transcript_and_masking() {
    let cases = [
        (
            ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
            ZkTranscriptHash::Keccak,
            true,
        ),
        (
            ZkProofSuite::BarretenbergUltraHonkPoseidon2ZkNoIpa,
            ZkTranscriptHash::Poseidon2,
            true,
        ),
        (
            ZkProofSuite::BarretenbergUltraHonkKeccakUnmaskedNoIpa,
            ZkTranscriptHash::Keccak,
            false,
        ),
        (
            ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa,
            ZkTranscriptHash::Poseidon2,
            false,
        ),
    ];

    assert_eq!(ZkProofSuite::ALL.len(), cases.len());
    for (suite, transcript, zero_knowledge) in cases {
        assert!(ZkProofSuite::ALL.contains(&suite));
        assert_eq!(
            ZkProofSuite::try_from_stable_name(suite.as_str()),
            Ok(suite)
        );
        assert_eq!(suite.transcript_hash(), transcript);
        assert_eq!(suite.zero_knowledge(), zero_knowledge);
        assert!(!suite.ipa_accumulation());
    }
}

#[test]
fn unmasked_suites_cannot_satisfy_zero_knowledge_policy() {
    for suite in [
        ZkProofSuite::BarretenbergUltraHonkKeccakUnmaskedNoIpa,
        ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa,
    ] {
        let error = suite
            .require_zero_knowledge()
            .err()
            .map(|error| error.reason());
        assert_eq!(error, Some(ZkErrorReason::UnsupportedProofSuite));
    }
}
