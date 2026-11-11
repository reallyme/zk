// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::EnumValue;
use reallyme_zk_api::capabilities::{
    PersonaBinding, SubjectBinding, ZkCircuitCapabilities, ZkDisclosureMode, ZkPredicateType,
    ZkSemanticGuarantee,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

pub(crate) fn capabilities_to_proto(
    capabilities: ZkCircuitCapabilities,
) -> pb::ZkCircuitCapabilities {
    pb::ZkCircuitCapabilities {
        subject_binding: EnumValue::from(subject_binding_to_proto(capabilities.subject_binding)),
        persona_binding: EnumValue::from(persona_binding_to_proto(capabilities.persona_binding)),
        may_be_correlated: capabilities.may_be_correlated,
        disclosure_modes: capabilities
            .disclosure_modes
            .iter()
            .copied()
            .map(disclosure_mode_to_proto)
            .map(EnumValue::from)
            .collect(),
        predicate_types: capabilities
            .predicate_types
            .iter()
            .copied()
            .map(predicate_type_to_proto)
            .map(EnumValue::from)
            .collect(),
        semantic_guarantees: capabilities
            .semantic_guarantees
            .iter()
            .copied()
            .map(semantic_guarantee_to_proto)
            .map(EnumValue::from)
            .collect(),
        __buffa_unknown_fields: Default::default(),
    }
}

const fn subject_binding_to_proto(subject_binding: SubjectBinding) -> pb::ZkSubjectBinding {
    match subject_binding {
        SubjectBinding::Required => pb::ZkSubjectBinding::ZK_SUBJECT_BINDING_REQUIRED,
        SubjectBinding::Forbidden => pb::ZkSubjectBinding::ZK_SUBJECT_BINDING_FORBIDDEN,
        SubjectBinding::Optional => pb::ZkSubjectBinding::ZK_SUBJECT_BINDING_OPTIONAL,
        _ => pb::ZkSubjectBinding::ZK_SUBJECT_BINDING_UNSPECIFIED,
    }
}

const fn persona_binding_to_proto(persona_binding: PersonaBinding) -> pb::ZkPersonaBinding {
    match persona_binding {
        PersonaBinding::Required => pb::ZkPersonaBinding::ZK_PERSONA_BINDING_REQUIRED,
        PersonaBinding::Forbidden => pb::ZkPersonaBinding::ZK_PERSONA_BINDING_FORBIDDEN,
        PersonaBinding::Optional => pb::ZkPersonaBinding::ZK_PERSONA_BINDING_OPTIONAL,
        _ => pb::ZkPersonaBinding::ZK_PERSONA_BINDING_UNSPECIFIED,
    }
}

const fn disclosure_mode_to_proto(disclosure_mode: ZkDisclosureMode) -> pb::ZkDisclosureMode {
    match disclosure_mode {
        ZkDisclosureMode::Hidden => pb::ZkDisclosureMode::ZK_DISCLOSURE_MODE_HIDDEN,
        ZkDisclosureMode::Reveal => pb::ZkDisclosureMode::ZK_DISCLOSURE_MODE_REVEAL,
        _ => pb::ZkDisclosureMode::ZK_DISCLOSURE_MODE_UNSPECIFIED,
    }
}

const fn semantic_guarantee_to_proto(guarantee: ZkSemanticGuarantee) -> pb::ZkSemanticGuarantee {
    match guarantee {
        ZkSemanticGuarantee::SessionBound => {
            pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_SESSION_BOUND
        }
        ZkSemanticGuarantee::AudienceBound => {
            pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_AUDIENCE_BOUND
        }
        ZkSemanticGuarantee::TransactionDataBound => {
            pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_TRANSACTION_DATA_BOUND
        }
        ZkSemanticGuarantee::CredentialAuthenticity => {
            pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_CREDENTIAL_AUTHENTICITY
        }
        ZkSemanticGuarantee::ClaimIntegrity => {
            pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_CLAIM_INTEGRITY
        }
        ZkSemanticGuarantee::LinkablePersonaBinding => {
            pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_LINKABLE_PERSONA_BINDING
        }
        ZkSemanticGuarantee::PrivatePersonaBinding => {
            pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_PRIVATE_PERSONA_BINDING
        }
        _ => pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_UNSPECIFIED,
    }
}

const fn predicate_type_to_proto(predicate: ZkPredicateType) -> pb::ZkPredicateType {
    match predicate {
        ZkPredicateType::GreaterThanOrEqual => {
            pb::ZkPredicateType::ZK_PREDICATE_TYPE_GREATER_THAN_OR_EQUAL
        }
        ZkPredicateType::LessThanOrEqual => {
            pb::ZkPredicateType::ZK_PREDICATE_TYPE_LESS_THAN_OR_EQUAL
        }
        ZkPredicateType::Range => pb::ZkPredicateType::ZK_PREDICATE_TYPE_RANGE,
        _ => pb::ZkPredicateType::ZK_PREDICATE_TYPE_UNSPECIFIED,
    }
}
