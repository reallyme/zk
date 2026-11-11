// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ZkDisclosureMode, ZkSemanticGuarantee};

pub(super) const NO_DISCLOSURE_MODES: &[ZkDisclosureMode] = &[];
pub(super) const REVEAL_DISCLOSURE_MODE: &[ZkDisclosureMode] = &[ZkDisclosureMode::Reveal];

pub(super) const SESSION_PRIVATE_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
];

pub(super) const SESSION_LINKABLE_PERSONA_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::LinkablePersonaBinding,
];

pub(super) const CREDENTIAL_ENVELOPE_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
];

pub(super) const CREDENTIAL_ROOT_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::CredentialAuthenticity,
];

pub(super) const CLAIM_PRIVATE_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::ClaimIntegrity,
];

pub(super) const CLAIM_PRIVATE_PERSONA_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::ClaimIntegrity,
    ZkSemanticGuarantee::PrivatePersonaBinding,
];

pub(super) const CREDENTIAL_SUBJECT_CLAIM_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::CredentialAuthenticity,
    ZkSemanticGuarantee::ClaimIntegrity,
];

pub(super) const PRIVATE_PERSONA_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::CredentialAuthenticity,
    ZkSemanticGuarantee::ClaimIntegrity,
    ZkSemanticGuarantee::PrivatePersonaBinding,
];

pub(super) const COMMON_CREDENTIAL_ROOT_PRIVATE_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::CredentialAuthenticity,
    ZkSemanticGuarantee::ClaimIntegrity,
    ZkSemanticGuarantee::PrivatePersonaBinding,
];

// A family-level lookup has no persona mode. Advertise only guarantees shared
// by private and public common-credential-root presentations; the exact claim stage
// supplies the mode-specific persona guarantee.
pub(super) const COMMON_CREDENTIAL_ROOT_MODE_AGNOSTIC_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::CredentialAuthenticity,
    ZkSemanticGuarantee::ClaimIntegrity,
];

pub(super) const COMMON_CREDENTIAL_ROOT_LINKABLE_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::CredentialAuthenticity,
    ZkSemanticGuarantee::ClaimIntegrity,
    ZkSemanticGuarantee::LinkablePersonaBinding,
];

pub(super) const COMMON_CREDENTIAL_ROOT_ATTESTATION_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::CredentialAuthenticity,
];

pub(super) const COMMON_CREDENTIAL_ROOT_LINEAGE_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::CredentialAuthenticity,
    ZkSemanticGuarantee::ClaimIntegrity,
];

// The verifier must authenticate the signed issuer status snapshot and bind
// its public root and clock. A circuit's membership check alone cannot claim
// that a holder-supplied root is current.
pub(super) const COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::SessionBound,
    ZkSemanticGuarantee::AudienceBound,
    ZkSemanticGuarantee::TransactionDataBound,
    ZkSemanticGuarantee::CredentialAuthenticity,
];

// Prepared source proofs do not include a verifier request. The live holder
// signature is a separate acceptance condition and must never be inferred
// from these circuit guarantees.
pub(super) const EVIDENCE_MODE_AGNOSTIC_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::CredentialAuthenticity,
    ZkSemanticGuarantee::ClaimIntegrity,
];
pub(super) const EVIDENCE_PRIVATE_CLAIM_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::ClaimIntegrity,
    ZkSemanticGuarantee::PrivatePersonaBinding,
];
pub(super) const EVIDENCE_PUBLIC_CLAIM_GUARANTEES: &[ZkSemanticGuarantee] = &[
    ZkSemanticGuarantee::ClaimIntegrity,
    ZkSemanticGuarantee::LinkablePersonaBinding,
];
// A single issuer, root, or validity stage authenticates only one signed edge.
// Credential authenticity belongs to the verified composition of all stages.
pub(super) const EVIDENCE_SIGNED_EDGE_GUARANTEES: &[ZkSemanticGuarantee] = &[];
