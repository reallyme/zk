// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
};

/// Canonical source-circuit selection for one common-credential-root witness/prove slot.
///
/// This type deliberately stores `ZkCircuitRef` instead of deriving circuit
/// identity from protobuf transport fields later. The common-credential-root persona_mode
/// registry in `reallyme-zk-api` remains the only authority for exact source
/// circuit selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootWitnessPlan {
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slot: ZkCommonCredentialRootProofSlot,
    circuit_ref: ZkCircuitRef,
}

impl ZkCommonCredentialRootWitnessPlan {
    /// Complete common-credential-root persona_mode being proved.
    #[must_use]
    pub const fn persona_mode(self) -> ZkCommonCredentialRootPersonaMode {
        self.persona_mode
    }

    /// Ordered proof slot in the complete common-credential-root presentation.
    #[must_use]
    pub const fn slot(self) -> ZkCommonCredentialRootProofSlot {
        self.slot
    }

    /// Exact source circuit required for this persona_mode/slot pair.
    #[must_use]
    pub const fn circuit_ref(self) -> ZkCircuitRef {
        self.circuit_ref
    }
}

/// Builds the canonical source-circuit plan for a common-credential-root slot.
#[must_use]
pub fn common_credential_root_witness_plan(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    slot: ZkCommonCredentialRootProofSlot,
) -> ZkCommonCredentialRootWitnessPlan {
    ZkCommonCredentialRootWitnessPlan {
        persona_mode,
        slot,
        circuit_ref: persona_mode.source_ref(credential_hash_algorithm, slot),
    }
}

/// Validates an externally supplied source circuit against the canonical plan.
pub fn common_credential_root_witness_plan_for_circuit(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slot: ZkCommonCredentialRootProofSlot,
    circuit_ref: ZkCircuitRef,
) -> Result<ZkCommonCredentialRootWitnessPlan, ZkError> {
    let expected_ref = persona_mode.source_ref(circuit_ref.credential_hash_algorithm, slot);
    if circuit_ref != expected_ref {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    Ok(ZkCommonCredentialRootWitnessPlan {
        persona_mode,
        slot,
        circuit_ref,
    })
}
