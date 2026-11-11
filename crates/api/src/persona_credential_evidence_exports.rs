// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit persona credential evidence exports, keeping the crate root structural.

pub use crate::persona_credential_evidence::{
    ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceValidityWindow,
    ZkPersonaCredentialEvidenceValidityWindowError,
    ZkPersonaCredentialEvidenceValidityWindowReason,
};
pub use crate::persona_credential_evidence_claim_selector::persona_credential_evidence_claim_selector_digest;
pub use crate::persona_credential_evidence_credential_binding::{
    derive_persona_credential_evidence_binding, ZkPersonaCredentialEvidenceBindingInputs,
    ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceSubjectPublicKey,
};
pub use crate::persona_credential_evidence_joins::{
    check_persona_credential_evidence_v1_joins, ZkPersonaCredentialEvidenceJoinError,
    ZkPersonaCredentialEvidenceJoinReason, ZkPersonaCredentialEvidenceStageJoin,
};
pub use crate::persona_credential_evidence_public_inputs::{
    ZkPersonaCredentialEvidenceRawPublicInputs, ZkPersonaCredentialEvidenceSourceStage,
    PERSONA_CREDENTIAL_EVIDENCE_V1_MAX_RAW_PUBLIC_INPUT_BYTES,
};
pub use crate::persona_credential_evidence_replay::{
    ZkPersonaCredentialEvidenceReplayChallenge, ZkPersonaCredentialEvidenceReplayError,
    ZkPersonaCredentialEvidenceReplayReason, ZkPersonaCredentialEvidenceReplayStore,
};
pub use crate::persona_credential_evidence_token_authorization::persona_credential_evidence_private_token_authorization_digest;
pub use crate::persona_credential_evidence_verification::{
    verify_persona_credential_evidence_with, ZkPersonaCredentialEvidenceStageProof,
    ZkPersonaCredentialEvidenceStageVerifier, ZkPersonaCredentialEvidenceVerifyRequest,
    ZkVerifiedPersonaCredentialEvidence,
};
