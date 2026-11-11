// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    circuit_capabilities, circuit_ref_capabilities, family_capabilities, presentation_capabilities,
    PersonaBinding, SubjectBinding, ZkDisclosureMode, ZkSemanticGuarantee,
};
use crate::{
    circuits::{
        ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm,
    },
    errors::{ZkError, ZkErrorReason},
};

#[test]
fn credential_subject_claim_is_session_bound_without_an_unlinkability_claim() -> Result<(), ZkError>
{
    let capabilities = circuit_capabilities(ZkCircuitId::CredentialSubjectClaimV1)?;

    assert_eq!(capabilities.subject_binding, SubjectBinding::Required);
    assert_eq!(capabilities.persona_binding, PersonaBinding::Forbidden);
    assert!(capabilities.may_be_correlated);
    assert!(capabilities
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::SessionBound));
    assert!(capabilities
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::AudienceBound));
    assert!(capabilities
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::TransactionDataBound));
    assert_eq!(capabilities.disclosure_modes, &[ZkDisclosureMode::Reveal]);
    Ok(())
}

#[test]
fn persona_circuit_declares_private_persona_binding() -> Result<(), ZkError> {
    let capabilities = circuit_capabilities(ZkCircuitId::PrivatePersonaClaimV1)?;

    assert_eq!(capabilities.persona_binding, PersonaBinding::Required);
    assert!(capabilities.may_be_correlated);
    assert!(capabilities
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::PrivatePersonaBinding));
    Ok(())
}

#[test]
fn common_credential_root_family_does_not_invent_a_persona_mode() -> Result<(), ZkError> {
    for capabilities in [
        circuit_capabilities(ZkCircuitId::CommonCredentialRootV1)?,
        family_capabilities(ZkCircuitFamily::CommonCredentialRootV1),
    ] {
        assert_eq!(capabilities.persona_binding, PersonaBinding::Required);
        assert!(capabilities
            .semantic_guarantees
            .contains(&ZkSemanticGuarantee::CredentialAuthenticity));
        assert!(!capabilities
            .semantic_guarantees
            .contains(&ZkSemanticGuarantee::PrivatePersonaBinding));
        assert!(!capabilities
            .semantic_guarantees
            .contains(&ZkSemanticGuarantee::LinkablePersonaBinding));
    }

    for (stage, expected) in [
        (
            ZkCircuitStage::PrivatePersonaClaim,
            ZkSemanticGuarantee::PrivatePersonaBinding,
        ),
        (
            ZkCircuitStage::PublicPersonaClaim,
            ZkSemanticGuarantee::LinkablePersonaBinding,
        ),
    ] {
        let capabilities = circuit_ref_capabilities(ZkCircuitRef::new(
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CommonCredentialRootV1,
            stage,
        ))?;
        assert!(capabilities.semantic_guarantees.contains(&expected));
    }
    Ok(())
}

#[test]
fn private_persona_family_does_not_overclaim_unlinkability() {
    let capabilities = family_capabilities(ZkCircuitFamily::PrivatePersonaClaimV1);

    assert_eq!(capabilities.persona_binding, PersonaBinding::Required);
    assert!(capabilities.may_be_correlated);
    assert!(capabilities
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::PrivatePersonaBinding));
}

#[test]
fn common_credential_root_public_session_is_linkable_but_not_credential_authenticity(
) -> Result<(), ZkError> {
    let capabilities = circuit_ref_capabilities(ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::PublicSession,
    ))?;

    assert!(capabilities.may_be_correlated);
    assert!(capabilities.disclosure_modes.is_empty());
    assert!(capabilities
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::LinkablePersonaBinding));
    assert!(!capabilities
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::CredentialAuthenticity));
    Ok(())
}

#[test]
fn private_persona_session_does_not_claim_subject_or_credential_semantics() -> Result<(), ZkError> {
    let capabilities = circuit_ref_capabilities(ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::PrivatePersonaClaimV1,
        ZkCircuitStage::Session,
    ))?;

    assert_eq!(capabilities.subject_binding, SubjectBinding::Forbidden);
    assert_eq!(capabilities.persona_binding, PersonaBinding::Required);
    assert!(capabilities.disclosure_modes.is_empty());
    assert!(!capabilities
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::CredentialAuthenticity));
    assert!(!capabilities
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::ClaimIntegrity));
    assert!(!capabilities
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::PrivatePersonaBinding));
    Ok(())
}

#[test]
fn credential_stages_do_not_inherit_persona_or_claim_capabilities() -> Result<(), ZkError> {
    for family in [
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitFamily::PrivatePersonaClaimV1,
    ] {
        for stage in [
            ZkCircuitStage::CredentialEnvelope,
            ZkCircuitStage::CredentialRoot,
        ] {
            let capabilities = circuit_ref_capabilities(ZkCircuitRef::new(
                ZkCredentialHashAlgorithm::Sha256,
                family,
                stage,
            ))?;

            assert_eq!(capabilities.subject_binding, SubjectBinding::Forbidden);
            assert_eq!(capabilities.persona_binding, PersonaBinding::Forbidden);
            assert!(capabilities.may_be_correlated);
            assert!(capabilities.disclosure_modes.is_empty());
            let authenticates = capabilities
                .semantic_guarantees
                .contains(&ZkSemanticGuarantee::CredentialAuthenticity);
            assert_eq!(authenticates, stage == ZkCircuitStage::CredentialRoot);
        }
    }
    Ok(())
}

#[test]
fn every_imported_ref_is_reveal_only_or_non_disclosing() -> Result<(), ZkError> {
    for circuit_ref in ZkCircuitRef::ALL {
        let capabilities = circuit_ref_capabilities(*circuit_ref)?;
        match circuit_ref.stage {
            ZkCircuitStage::Claim
            | ZkCircuitStage::ClaimBundle4
            | ZkCircuitStage::PrivatePersonaClaim
            | ZkCircuitStage::PublicPersonaClaim
            | ZkCircuitStage::EvidencePublicClaim
            | ZkCircuitStage::EvidencePrivateClaim => {
                assert_eq!(capabilities.disclosure_modes, &[ZkDisclosureMode::Reveal]);
            }
            ZkCircuitStage::Session
            | ZkCircuitStage::PublicSession
            | ZkCircuitStage::CredentialEnvelope
            | ZkCircuitStage::CredentialRoot
            | ZkCircuitStage::RootAttestation
            | ZkCircuitStage::RootStatus
            | ZkCircuitStage::Lineage
            | ZkCircuitStage::IssuerCredentialStatus
            | ZkCircuitStage::EvidenceIssuerEnvelope
            | ZkCircuitStage::EvidenceClaimRoot
            | ZkCircuitStage::EvidenceSignedValidity
            | ZkCircuitStage::EvidenceCurrentState => {
                assert!(capabilities.disclosure_modes.is_empty());
            }
        }
        assert_eq!(
            capabilities
                .semantic_guarantees
                .contains(&ZkSemanticGuarantee::TransactionDataBound),
            circuit_ref.family != ZkCircuitFamily::PersonaCredentialEvidenceV1
        );
    }
    Ok(())
}

#[test]
fn presentation_capabilities_remain_distinct_from_stage_capabilities() -> Result<(), ZkError> {
    let bundle = presentation_capabilities(ZkCircuitFamily::PrivatePersonaClaimV1);
    let session = circuit_ref_capabilities(ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::PrivatePersonaClaimV1,
        ZkCircuitStage::Session,
    ))?;

    assert!(bundle
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::CredentialAuthenticity));
    assert!(bundle
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::PrivatePersonaBinding));
    assert!(!session
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::CredentialAuthenticity));
    assert!(!session
        .semantic_guarantees
        .contains(&ZkSemanticGuarantee::PrivatePersonaBinding));
    Ok(())
}

#[test]
fn unsupported_circuit_ref_version_fails_closed() {
    let mut circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Claim,
    );
    circuit_ref.revision = ZkCircuitRef::CURRENT_REVISION.saturating_add(1);

    let error = circuit_ref_capabilities(circuit_ref)
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedCircuit);
}

#[test]
fn every_registered_circuit_reports_only_implemented_predicates() -> Result<(), ZkError> {
    for family in ZkCircuitFamily::ALL {
        let capabilities = presentation_capabilities(*family);
        assert!(capabilities.predicate_types.is_empty());
        assert!(capabilities.may_be_correlated);
    }
    for circuit_ref in ZkCircuitRef::ALL {
        let capabilities = circuit_ref_capabilities(*circuit_ref)?;
        assert!(capabilities.predicate_types.is_empty());
    }
    Ok(())
}
