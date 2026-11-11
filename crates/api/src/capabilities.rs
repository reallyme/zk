// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    circuit::{ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage},
    errors::{ZkError, ZkErrorReason},
};

mod guarantees;

use guarantees::{
    CLAIM_PRIVATE_GUARANTEES, CLAIM_PRIVATE_PERSONA_GUARANTEES,
    COMMON_CREDENTIAL_ROOT_ATTESTATION_GUARANTEES, COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_GUARANTEES,
    COMMON_CREDENTIAL_ROOT_LINEAGE_GUARANTEES, COMMON_CREDENTIAL_ROOT_LINKABLE_GUARANTEES,
    COMMON_CREDENTIAL_ROOT_MODE_AGNOSTIC_GUARANTEES, COMMON_CREDENTIAL_ROOT_PRIVATE_GUARANTEES,
    CREDENTIAL_ENVELOPE_GUARANTEES, CREDENTIAL_ROOT_GUARANTEES,
    CREDENTIAL_SUBJECT_CLAIM_GUARANTEES, EVIDENCE_MODE_AGNOSTIC_GUARANTEES,
    EVIDENCE_PRIVATE_CLAIM_GUARANTEES, EVIDENCE_PUBLIC_CLAIM_GUARANTEES,
    EVIDENCE_SIGNED_EDGE_GUARANTEES, NO_DISCLOSURE_MODES, PRIVATE_PERSONA_GUARANTEES,
    REVEAL_DISCLOSURE_MODE, SESSION_LINKABLE_PERSONA_GUARANTEES, SESSION_PRIVATE_GUARANTEES,
};

mod types;

pub use types::{
    PersonaBinding, SubjectBinding, ZkCircuitCapabilities, ZkDisclosureMode, ZkPredicateType,
    ZkSemanticGuarantee,
};

/// Returns the registered semantic capabilities for a circuit.
pub const fn circuit_capabilities(id: ZkCircuitId) -> Result<ZkCircuitCapabilities, ZkError> {
    let capabilities = match id {
        ZkCircuitId::CredentialSubjectClaimV1 => ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Forbidden,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: CREDENTIAL_SUBJECT_CLAIM_GUARANTEES,
        },
        ZkCircuitId::PrivatePersonaClaimV1 => ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Required,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: PRIVATE_PERSONA_GUARANTEES,
        },
        ZkCircuitId::CommonCredentialRootV1 => ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Required,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: COMMON_CREDENTIAL_ROOT_MODE_AGNOSTIC_GUARANTEES,
        },
        ZkCircuitId::PersonaCredentialEvidenceV1 => ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Required,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: EVIDENCE_MODE_AGNOSTIC_GUARANTEES,
        },
    };
    Ok(capabilities)
}

/// Returns semantic capabilities for an imported VC family.
#[must_use]
pub const fn family_capabilities(family: ZkCircuitFamily) -> ZkCircuitCapabilities {
    presentation_capabilities(family)
}

/// Returns the guarantees established by a complete production-stage bundle.
///
/// Bundle capabilities must not be attached to an individual artifact. Each
/// stage manifest uses [`circuit_ref_capabilities`] so it can claim only the
/// statement enforced by that exact Noir program.
#[must_use]
pub const fn presentation_capabilities(family: ZkCircuitFamily) -> ZkCircuitCapabilities {
    match family {
        ZkCircuitFamily::CredentialSubjectClaimV1 => ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Forbidden,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: CREDENTIAL_SUBJECT_CLAIM_GUARANTEES,
        },
        ZkCircuitFamily::PrivatePersonaClaimV1 => ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Required,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: PRIVATE_PERSONA_GUARANTEES,
        },
        ZkCircuitFamily::CommonCredentialRootV1 => ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Required,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: COMMON_CREDENTIAL_ROOT_MODE_AGNOSTIC_GUARANTEES,
        },
        ZkCircuitFamily::PersonaCredentialEvidenceV1 => ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Required,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: EVIDENCE_MODE_AGNOSTIC_GUARANTEES,
        },
    }
}

/// Returns semantic capabilities for one exact imported source circuit.
///
/// Unsupported versions fail closed instead of inheriting v1 semantics. The
/// returned disclosure modes and guarantees describe only this stage; complete
/// presentation semantics are available through [`presentation_capabilities`].
pub fn circuit_ref_capabilities(
    circuit_ref: ZkCircuitRef,
) -> Result<ZkCircuitCapabilities, ZkError> {
    if circuit_ref.revision != ZkCircuitRef::CURRENT_REVISION {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }

    let capabilities = match circuit_ref.stage {
        ZkCircuitStage::Session => session_capabilities(circuit_ref.family)?,
        ZkCircuitStage::CredentialEnvelope => {
            require_single_credential_family(circuit_ref.family)?;
            credential_envelope_capabilities()
        }
        ZkCircuitStage::CredentialRoot => {
            require_single_credential_family(circuit_ref.family)?;
            credential_root_capabilities()
        }
        ZkCircuitStage::Claim | ZkCircuitStage::ClaimBundle4 => {
            claim_stage_capabilities(circuit_ref.family)?
        }
        ZkCircuitStage::RootAttestation => {
            common_credential_root_attestation_capabilities(circuit_ref.family)?
        }
        ZkCircuitStage::RootStatus => {
            common_credential_root_status_capabilities(circuit_ref.family)?
        }
        ZkCircuitStage::Lineage => common_credential_root_lineage_capabilities(circuit_ref.family)?,
        ZkCircuitStage::IssuerCredentialStatus => {
            common_credential_root_issuer_status_capabilities(circuit_ref.family)?
        }
        ZkCircuitStage::PrivatePersonaClaim => {
            common_credential_root_claim_capabilities(circuit_ref.family, false)?
        }
        ZkCircuitStage::PublicPersonaClaim => {
            common_credential_root_claim_capabilities(circuit_ref.family, true)?
        }
        ZkCircuitStage::PublicSession => {
            require_common_credential_root_family(circuit_ref.family)?;
            ZkCircuitCapabilities {
                subject_binding: SubjectBinding::Forbidden,
                persona_binding: PersonaBinding::Required,
                may_be_correlated: true,
                disclosure_modes: NO_DISCLOSURE_MODES,
                predicate_types: &[],
                semantic_guarantees: SESSION_LINKABLE_PERSONA_GUARANTEES,
            }
        }
        ZkCircuitStage::EvidenceIssuerEnvelope => {
            evidence_credential_fact_capabilities(circuit_ref.family, true)?
        }
        ZkCircuitStage::EvidenceClaimRoot | ZkCircuitStage::EvidenceSignedValidity => {
            evidence_credential_fact_capabilities(circuit_ref.family, false)?
        }
        ZkCircuitStage::EvidencePublicClaim => {
            evidence_claim_capabilities(circuit_ref.family, true)?
        }
        ZkCircuitStage::EvidencePrivateClaim => {
            evidence_claim_capabilities(circuit_ref.family, false)?
        }
        ZkCircuitStage::EvidenceCurrentState => {
            evidence_current_state_capabilities(circuit_ref.family)?
        }
    };

    Ok(capabilities)
}

fn require_single_credential_family(family: ZkCircuitFamily) -> Result<(), ZkError> {
    match family {
        ZkCircuitFamily::CredentialSubjectClaimV1 | ZkCircuitFamily::PrivatePersonaClaimV1 => {
            Ok(())
        }
        ZkCircuitFamily::CommonCredentialRootV1 | ZkCircuitFamily::PersonaCredentialEvidenceV1 => {
            Err(ZkError::new(ZkErrorReason::UnsupportedCircuit))
        }
    }
}

fn require_common_credential_root_family(family: ZkCircuitFamily) -> Result<(), ZkError> {
    match family {
        ZkCircuitFamily::CommonCredentialRootV1 => Ok(()),
        ZkCircuitFamily::CredentialSubjectClaimV1
        | ZkCircuitFamily::PrivatePersonaClaimV1
        | ZkCircuitFamily::PersonaCredentialEvidenceV1 => {
            Err(ZkError::new(ZkErrorReason::UnsupportedCircuit))
        }
    }
}

fn session_capabilities(family: ZkCircuitFamily) -> Result<ZkCircuitCapabilities, ZkError> {
    match family {
        ZkCircuitFamily::CredentialSubjectClaimV1 => Ok(ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Forbidden,
            may_be_correlated: true,
            disclosure_modes: NO_DISCLOSURE_MODES,
            predicate_types: &[],
            semantic_guarantees: SESSION_PRIVATE_GUARANTEES,
        }),
        ZkCircuitFamily::PrivatePersonaClaimV1 => Ok(ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Forbidden,
            persona_binding: PersonaBinding::Required,
            may_be_correlated: true,
            disclosure_modes: NO_DISCLOSURE_MODES,
            predicate_types: &[],
            semantic_guarantees: SESSION_PRIVATE_GUARANTEES,
        }),
        ZkCircuitFamily::CommonCredentialRootV1 | ZkCircuitFamily::PersonaCredentialEvidenceV1 => {
            Err(ZkError::new(ZkErrorReason::UnsupportedCircuit))
        }
    }
}

fn credential_envelope_capabilities() -> ZkCircuitCapabilities {
    ZkCircuitCapabilities {
        subject_binding: SubjectBinding::Forbidden,
        persona_binding: PersonaBinding::Forbidden,
        may_be_correlated: true,
        disclosure_modes: NO_DISCLOSURE_MODES,
        predicate_types: &[],
        semantic_guarantees: CREDENTIAL_ENVELOPE_GUARANTEES,
    }
}

fn credential_root_capabilities() -> ZkCircuitCapabilities {
    ZkCircuitCapabilities {
        subject_binding: SubjectBinding::Forbidden,
        persona_binding: PersonaBinding::Forbidden,
        may_be_correlated: true,
        disclosure_modes: NO_DISCLOSURE_MODES,
        predicate_types: &[],
        semantic_guarantees: CREDENTIAL_ROOT_GUARANTEES,
    }
}

fn claim_stage_capabilities(family: ZkCircuitFamily) -> Result<ZkCircuitCapabilities, ZkError> {
    match family {
        ZkCircuitFamily::CredentialSubjectClaimV1 => Ok(ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Forbidden,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: CLAIM_PRIVATE_GUARANTEES,
        }),
        ZkCircuitFamily::PrivatePersonaClaimV1 => Ok(ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Required,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: CLAIM_PRIVATE_PERSONA_GUARANTEES,
        }),
        ZkCircuitFamily::CommonCredentialRootV1 | ZkCircuitFamily::PersonaCredentialEvidenceV1 => {
            Err(ZkError::new(ZkErrorReason::UnsupportedCircuit))
        }
    }
}

fn evidence_claim_capabilities(
    family: ZkCircuitFamily,
    public_persona: bool,
) -> Result<ZkCircuitCapabilities, ZkError> {
    if family != ZkCircuitFamily::PersonaCredentialEvidenceV1 {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }
    Ok(ZkCircuitCapabilities {
        subject_binding: SubjectBinding::Required,
        persona_binding: PersonaBinding::Required,
        may_be_correlated: true,
        disclosure_modes: REVEAL_DISCLOSURE_MODE,
        predicate_types: &[],
        semantic_guarantees: if public_persona {
            EVIDENCE_PUBLIC_CLAIM_GUARANTEES
        } else {
            EVIDENCE_PRIVATE_CLAIM_GUARANTEES
        },
    })
}

fn evidence_credential_fact_capabilities(
    family: ZkCircuitFamily,
    authenticates_subject: bool,
) -> Result<ZkCircuitCapabilities, ZkError> {
    if family != ZkCircuitFamily::PersonaCredentialEvidenceV1 {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }
    Ok(ZkCircuitCapabilities {
        subject_binding: if authenticates_subject {
            SubjectBinding::Required
        } else {
            SubjectBinding::Forbidden
        },
        persona_binding: PersonaBinding::Forbidden,
        may_be_correlated: true,
        disclosure_modes: NO_DISCLOSURE_MODES,
        predicate_types: &[],
        semantic_guarantees: EVIDENCE_SIGNED_EDGE_GUARANTEES,
    })
}

fn evidence_current_state_capabilities(
    family: ZkCircuitFamily,
) -> Result<ZkCircuitCapabilities, ZkError> {
    if family != ZkCircuitFamily::PersonaCredentialEvidenceV1 {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }
    Ok(ZkCircuitCapabilities {
        subject_binding: SubjectBinding::Forbidden,
        persona_binding: PersonaBinding::Forbidden,
        may_be_correlated: true,
        disclosure_modes: NO_DISCLOSURE_MODES,
        predicate_types: &[],
        semantic_guarantees: EVIDENCE_SIGNED_EDGE_GUARANTEES,
    })
}

fn common_credential_root_attestation_capabilities(
    family: ZkCircuitFamily,
) -> Result<ZkCircuitCapabilities, ZkError> {
    match require_common_credential_root_family(family) {
        Ok(()) => Ok(ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Forbidden,
            persona_binding: PersonaBinding::Forbidden,
            may_be_correlated: true,
            disclosure_modes: NO_DISCLOSURE_MODES,
            predicate_types: &[],
            semantic_guarantees: COMMON_CREDENTIAL_ROOT_ATTESTATION_GUARANTEES,
        }),
        Err(error) => Err(error),
    }
}

fn common_credential_root_status_capabilities(
    family: ZkCircuitFamily,
) -> Result<ZkCircuitCapabilities, ZkError> {
    match require_common_credential_root_family(family) {
        Ok(()) => Ok(ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Forbidden,
            persona_binding: PersonaBinding::Forbidden,
            may_be_correlated: true,
            disclosure_modes: NO_DISCLOSURE_MODES,
            predicate_types: &[],
            semantic_guarantees: SESSION_PRIVATE_GUARANTEES,
        }),
        Err(error) => Err(error),
    }
}

fn common_credential_root_lineage_capabilities(
    family: ZkCircuitFamily,
) -> Result<ZkCircuitCapabilities, ZkError> {
    match require_common_credential_root_family(family) {
        Ok(()) => Ok(ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Forbidden,
            may_be_correlated: true,
            disclosure_modes: NO_DISCLOSURE_MODES,
            predicate_types: &[],
            semantic_guarantees: COMMON_CREDENTIAL_ROOT_LINEAGE_GUARANTEES,
        }),
        Err(error) => Err(error),
    }
}

fn common_credential_root_issuer_status_capabilities(
    family: ZkCircuitFamily,
) -> Result<ZkCircuitCapabilities, ZkError> {
    require_common_credential_root_family(family)?;
    Ok(ZkCircuitCapabilities {
        subject_binding: SubjectBinding::Forbidden,
        persona_binding: PersonaBinding::Forbidden,
        may_be_correlated: true,
        disclosure_modes: NO_DISCLOSURE_MODES,
        predicate_types: &[],
        semantic_guarantees: COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_GUARANTEES,
    })
}

fn common_credential_root_claim_capabilities(
    family: ZkCircuitFamily,
    public_persona: bool,
) -> Result<ZkCircuitCapabilities, ZkError> {
    match require_common_credential_root_family(family) {
        Ok(()) => Ok(ZkCircuitCapabilities {
            subject_binding: SubjectBinding::Required,
            persona_binding: PersonaBinding::Required,
            may_be_correlated: true,
            disclosure_modes: REVEAL_DISCLOSURE_MODE,
            predicate_types: &[],
            semantic_guarantees: if public_persona {
                COMMON_CREDENTIAL_ROOT_LINKABLE_GUARANTEES
            } else {
                COMMON_CREDENTIAL_ROOT_PRIVATE_GUARANTEES
            },
        }),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;
