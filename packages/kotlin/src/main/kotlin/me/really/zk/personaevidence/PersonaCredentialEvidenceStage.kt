// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.personaevidence

import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import reallyme.zk.v1.Manifest

/** A source circuit and returned slot must authenticate the same prepared fact. */
internal fun evidenceStageForCircuitStage(
    stage: Manifest.ZkCircuitStage,
): Manifest.ZkPersonaCredentialEvidenceProofSlot =
    when (stage) {
        Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_ISSUER_ENVELOPE ->
            Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE
        Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_CLAIM_ROOT ->
            Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT
        Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_SIGNED_VALIDITY ->
            Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY
        Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_PUBLIC_CLAIM,
        Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_PRIVATE_CLAIM,
        ->
            Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM
        Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_CURRENT_STATE ->
            Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE
        else -> throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
