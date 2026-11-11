// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Disclosure, predicate and binding vocabulary shared by capability records.

/// Whether the circuit proves binding to the credential subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubjectBinding {
    /// The circuit requires subject binding.
    Required,
    /// The circuit must not include subject binding.
    Forbidden,
    /// The circuit can support either mode.
    Optional,
}

/// Whether the circuit proves binding to a wallet/persona key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PersonaBinding {
    /// The circuit requires persona binding.
    Required,
    /// The circuit must not include persona binding.
    Forbidden,
    /// The circuit can support either mode.
    Optional,
}

/// Whether a circuit hides or reveals the selected claim value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkDisclosureMode {
    /// Claim value remains hidden.
    Hidden,
    /// Claim value is revealed as a public statement.
    Reveal,
}

/// Predicate that a circuit can prove independently of claim disclosure.
///
/// These names define the protocol vocabulary. Current circuits advertise an
/// empty predicate set; declaring a variant never establishes support for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkPredicateType {
    /// Claim value is greater than or equal to a threshold.
    GreaterThanOrEqual,
    /// Claim value is less than or equal to a threshold.
    LessThanOrEqual,
    /// Claim value lies within a closed range.
    Range,
}

/// High-level semantic guarantee asserted by a circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkSemanticGuarantee {
    /// The proof is bound to the active verifier/session challenge.
    SessionBound,
    /// The proof is bound to the intended verifier identity.
    AudienceBound,
    /// The proof is bound to transaction data when supplied by the request.
    TransactionDataBound,
    /// The proof demonstrates issuer credential authenticity.
    CredentialAuthenticity,
    /// The proof demonstrates claim integrity under the credential commitment.
    ClaimIntegrity,
    /// The proof binds each credential subject's authorization to the same
    /// hidden presenting persona within a composed presentation. It does not
    /// establish that the credentials share an original subject.
    PrivatePersonaBinding,
    /// The proof intentionally supports a linkable persona binding.
    LinkablePersonaBinding,
}

/// Semantic capabilities for a registered circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkCircuitCapabilities {
    /// Subject-binding requirement.
    pub subject_binding: SubjectBinding,
    /// Persona-binding requirement.
    pub persona_binding: PersonaBinding,
    /// Whether callers must permit potential presentation correlation.
    pub may_be_correlated: bool,
    /// Supported claim disclosure modes.
    pub disclosure_modes: &'static [ZkDisclosureMode],
    /// Supported predicates, independently of whether their operands are disclosed.
    pub predicate_types: &'static [ZkPredicateType],
    /// Guarantees the proof-format layer and policy engine may rely on.
    pub semantic_guarantees: &'static [ZkSemanticGuarantee],
}
