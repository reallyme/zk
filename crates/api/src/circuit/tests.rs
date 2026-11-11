// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ParseZkCircuitIdError, ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage,
    ZkCredentialHashAlgorithm,
};
use crate::errors::ZkErrorReason;
use core::str::FromStr;

#[test]
fn canonical_ids_round_trip() -> Result<(), ParseZkCircuitIdError> {
    for circuit_id in ZkCircuitId::ALL {
        let parsed = ZkCircuitId::from_str(circuit_id.as_str())?;
        assert_eq!(*circuit_id, parsed);
    }
    Ok(())
}

#[test]
fn retired_aliases_are_rejected() {
    for alias in [
        "rm-base-v1",
        "rm-persona-v1",
        "rm-merkle-v1",
        "rm-merkle-persona-v1",
        "rm-zk-vc-base-v1",
        "rm-zk-vc-persona-v1",
        "rm-zk-vc-merkle-v1",
        "rm-zk-vc-merkle-persona-v1",
    ] {
        assert_eq!(ZkCircuitId::from_str(alias), Err(ParseZkCircuitIdError));
    }
}

#[test]
fn unknown_id_fails() {
    assert_eq!(
        ZkCircuitId::from_str("rm-zk-credential-subject-claim-v2"),
        Err(ParseZkCircuitIdError)
    );
}

#[test]
fn concrete_refs_cover_imported_circuit_tree() {
    const CREDENTIAL_FAMILY_REF_COUNT: usize = 20;
    const COMMON_CREDENTIAL_ROOT_REF_COUNT: usize = 14;
    const PERSONA_CREDENTIAL_EVIDENCE_REF_COUNT: usize = 12;
    assert_eq!(
        ZkCircuitRef::ALL.len(),
        CREDENTIAL_FAMILY_REF_COUNT
            + COMMON_CREDENTIAL_ROOT_REF_COUNT
            + PERSONA_CREDENTIAL_EVIDENCE_REF_COUNT
    );
    assert!(ZkCircuitRef::ALL.contains(&ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCircuitFamily::PrivatePersonaClaimV1,
        ZkCircuitStage::ClaimBundle4,
    )));
    assert!(ZkCircuitRef::ALL.contains(&ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::PublicPersonaClaim,
    )));
    assert!(ZkCircuitRef::ALL.contains(&ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCircuitFamily::PersonaCredentialEvidenceV1,
        ZkCircuitStage::EvidenceCurrentState,
    )));
}

#[test]
fn concrete_refs_preserve_policy_circuit_ids() {
    let credential_subject_claim = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Claim,
    );
    let public_persona = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::PublicSession,
    );

    assert_eq!(
        credential_subject_claim.circuit_id(),
        ZkCircuitId::CredentialSubjectClaimV1
    );
    assert_eq!(
        public_persona.circuit_id(),
        ZkCircuitId::CommonCredentialRootV1
    );
    assert_eq!(
        ZkCircuitRef::new(
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CommonCredentialRootV1,
            ZkCircuitStage::Lineage,
        )
        .circuit_id(),
        ZkCircuitId::CommonCredentialRootV1
    );
}

#[test]
fn concrete_refs_match_imported_noir_sources() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let circuits_dir = crate_dir.join("../../circuits");

    for circuit_ref in ZkCircuitRef::ALL {
        let nargo = circuits_dir
            .join(circuit_ref.credential_hash_algorithm.source_dir())
            .join("families")
            .join(circuit_ref.family.source_dir())
            .join(circuit_ref.stage.source_dir())
            .join("Nargo.toml");

        assert!(
            nargo.is_file(),
            "missing imported circuit source: {nargo:?}"
        );
    }
}

#[test]
fn stable_name_parser_rejects_unregistered_family_stage_pairs() {
    for stable_name in [
        "sha256:common_credential_root_v1:session:v1",
        "poseidon2:credential_subject_claim_v1:lineage:v1",
        "sha256:public_persona_claim_v1:root_attestation:v1",
        "sha256:persona_credential_evidence_v1:session:v1",
    ] {
        assert!(matches!(
            ZkCircuitRef::try_from_stable_name(stable_name),
            Err(error) if error.reason() == ZkErrorReason::UnsupportedCircuit
        ));
    }
}

#[test]
fn stable_name_parser_accepts_only_canonical_registry_entries() -> Result<(), crate::errors::ZkError>
{
    for circuit_ref in ZkCircuitRef::ALL {
        let stable_name = format!(
            "{}:{}:{}:v{}",
            circuit_ref.credential_hash_algorithm.as_str(),
            circuit_ref.family.as_str(),
            circuit_ref.stage.as_str(),
            circuit_ref.revision,
        );
        let parsed = ZkCircuitRef::try_from_stable_name(stable_name.as_ref())?;

        assert_eq!(parsed, *circuit_ref);
    }

    Ok(())
}
