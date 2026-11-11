// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import reallyme.zk.v1.Manifest

internal fun personaCredentialEvidenceStagesJoin(
    issuer: Manifest.ZkPersonaCredentialEvidenceStageProof,
    root: Manifest.ZkPersonaCredentialEvidenceStageProof,
    validity: Manifest.ZkPersonaCredentialEvidenceStageProof,
    claim: Manifest.ZkPersonaCredentialEvidenceStageProof,
    status: Manifest.ZkPersonaCredentialEvidenceStageProof,
): Boolean {
    val claimFields = claim.publicInputs.rawFields
    val statusFields = status.publicInputs.rawFields
    val stages = listOf(issuer, root, validity, claim, status)
    return issuer.proofSlot ==
        Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE &&
        root.proofSlot ==
        Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT &&
        validity.proofSlot ==
        Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY &&
        claim.proofSlot ==
        Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM &&
        status.proofSlot ==
        Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE &&
        claimFields.size() >= PREPARED_JOIN_BYTES &&
        stages.all {
            it.mode == claim.mode &&
                it.circuitRef.credentialHashAlgorithm == claim.circuitRef.credentialHashAlgorithm &&
                it.publicInputs.rawFields.size() >= PREPARED_JOIN_BYTES &&
                claimFields.substring(0, PREPARED_JOIN_BYTES) ==
                it.publicInputs.rawFields.substring(0, PREPARED_JOIN_BYTES)
        } &&
        validity.publicInputs.rawFields.size() >= PREPARED_SIGNED_VALIDITY_BYTES &&
        statusFields.size() >= PREPARED_STATUS_BYTES &&
        validity.publicInputs.rawFields.substring(PREPARED_JOIN_BYTES, PREPARED_SIGNED_VALIDITY_BYTES) ==
        statusFields.substring(PREPARED_STATUS_POINTER_START, PREPARED_STATUS_BYTES)
}

private const val PREPARED_JOIN_BYTES = 194 * 32
private const val PREPARED_SIGNED_VALIDITY_BYTES = 259 * 32
private const val PREPARED_STATUS_POINTER_START = 227 * 32
private const val PREPARED_STATUS_BYTES = 292 * 32
