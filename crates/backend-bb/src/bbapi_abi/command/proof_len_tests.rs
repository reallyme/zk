// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::ZkErrorReason,
};

use super::{expected_production_proof_len, validate_expected_proof_len};

const FIELD_BYTES: usize = 32;

fn circuit(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    family: ZkCircuitFamily,
    stage: ZkCircuitStage,
) -> ZkCircuitRef {
    ZkCircuitRef::new(credential_hash_algorithm, family, stage)
}

#[test]
fn every_registered_circuit_has_one_pinned_production_proof_length() {
    for circuit_ref in ZkCircuitRef::ALL {
        let expected = expected_production_proof_len(*circuit_ref);
        assert!(
            expected.is_ok(),
            "registered circuit has no pinned proof length"
        );
        if let Ok(length) = expected {
            assert_eq!(length % FIELD_BYTES, 0);
            assert!(validate_expected_proof_len(*circuit_ref, length).is_ok());
            for wrong in [length - FIELD_BYTES, length + FIELD_BYTES, 0] {
                assert_eq!(
                    validate_expected_proof_len(*circuit_ref, wrong)
                        .err()
                        .map(|error| error.reason()),
                    Some(ZkErrorReason::InvalidProofEncoding)
                );
            }
        }
    }
}

#[test]
fn raw_lane_proof_lengths_match_the_measured_production_proofs() {
    use ZkCircuitFamily::{CommonCredentialRootV1, PersonaCredentialEvidenceV1};
    use ZkCredentialHashAlgorithm::{Poseidon2, Sha256};

    for (lane, family, stage, expected) in [
        (
            Sha256,
            CommonCredentialRootV1,
            ZkCircuitStage::PublicSession,
            9_152,
        ),
        (
            Poseidon2,
            CommonCredentialRootV1,
            ZkCircuitStage::PublicSession,
            8_768,
        ),
        (
            Sha256,
            CommonCredentialRootV1,
            ZkCircuitStage::RootAttestation,
            9_152,
        ),
        (
            Poseidon2,
            CommonCredentialRootV1,
            ZkCircuitStage::RootAttestation,
            9_152,
        ),
        (
            Sha256,
            CommonCredentialRootV1,
            ZkCircuitStage::RootStatus,
            9_536,
        ),
        (
            Poseidon2,
            CommonCredentialRootV1,
            ZkCircuitStage::Lineage,
            9_536,
        ),
        (
            Sha256,
            CommonCredentialRootV1,
            ZkCircuitStage::IssuerCredentialStatus,
            9_536,
        ),
        (
            Poseidon2,
            CommonCredentialRootV1,
            ZkCircuitStage::PrivatePersonaClaim,
            9_536,
        ),
        (
            Sha256,
            CommonCredentialRootV1,
            ZkCircuitStage::PublicPersonaClaim,
            9_536,
        ),
        (
            Sha256,
            PersonaCredentialEvidenceV1,
            ZkCircuitStage::EvidenceIssuerEnvelope,
            9_152,
        ),
        (
            Poseidon2,
            PersonaCredentialEvidenceV1,
            ZkCircuitStage::EvidenceClaimRoot,
            9_152,
        ),
        (
            Sha256,
            PersonaCredentialEvidenceV1,
            ZkCircuitStage::EvidenceSignedValidity,
            9_152,
        ),
        (
            Poseidon2,
            PersonaCredentialEvidenceV1,
            ZkCircuitStage::EvidencePublicClaim,
            9_536,
        ),
        (
            Sha256,
            PersonaCredentialEvidenceV1,
            ZkCircuitStage::EvidencePrivateClaim,
            9_536,
        ),
        (
            Poseidon2,
            PersonaCredentialEvidenceV1,
            ZkCircuitStage::EvidenceCurrentState,
            9_536,
        ),
    ] {
        assert_eq!(
            expected_production_proof_len(circuit(lane, family, stage)).ok(),
            Some(expected)
        );
    }
}
