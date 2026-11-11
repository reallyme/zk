// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ReleaseProcessError, ReleaseProcessErrorReason};
use reallyme_zk_api::proofs::{ZkProofSuite, ZkTranscriptHash};

use super::ReleaseToolchainProfile;

pub(crate) fn require_profile_suite(
    profile: ReleaseToolchainProfile,
    proof_suite: ZkProofSuite,
) -> Result<(), ReleaseProcessError> {
    match profile {
        ReleaseToolchainProfile::LegacyProduction | ReleaseToolchainProfile::ModernCandidate => {
            match proof_suite {
                ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa
                | ZkProofSuite::BarretenbergUltraHonkKeccakUnmaskedNoIpa
                | ZkProofSuite::BarretenbergUltraHonkPoseidon2ZkNoIpa
                | ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa => Ok(()),
                _ => Err(ReleaseProcessError::new(
                    ReleaseProcessErrorReason::UnsupportedProofSuite,
                )),
            }
        }
    }
}

pub(crate) const fn verifier_target_name(proof_suite: ZkProofSuite) -> &'static str {
    match (
        proof_suite.transcript_hash(),
        proof_suite.zero_knowledge(),
        proof_suite.ipa_accumulation(),
    ) {
        (ZkTranscriptHash::Keccak, true, false) => "evm",
        (ZkTranscriptHash::Keccak, false, false) => "evm-no-zk",
        (ZkTranscriptHash::Poseidon2, true, false) => "noir-recursive",
        (ZkTranscriptHash::Poseidon2, false, false) => "noir-recursive-no-zk",
        (ZkTranscriptHash::Keccak | ZkTranscriptHash::Poseidon2, _, true) => "noir-rollup",
        (_, _, _) => "unsupported",
    }
}
