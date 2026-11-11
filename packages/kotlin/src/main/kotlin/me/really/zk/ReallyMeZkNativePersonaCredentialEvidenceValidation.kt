// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import me.really.zk.personaevidence.ZkPersonaCredentialEvidenceStageProveRequest
import me.really.zk.personaevidence.evidenceStageForCircuitStage
import reallyme.zk.v1.Manifest

/** Check the exact stage and public-input envelope before crossing JNI. */
internal fun isEvidenceStageProofWellFormed(proof: Manifest.ZkPersonaCredentialEvidenceStageProof): Boolean {
    val completeEnvelope = proof.hasPublicInputs() && proof.hasArtifactSetIdentitySha256()
    val digestSized = proof.artifactSetIdentitySha256.value.size() == BYTES_32
    val nonemptyProof = !proof.proof.isEmpty && !proof.publicInputs.rawFields.isEmpty
    val matchingIdentity = proof.publicInputs.mode == proof.mode && proof.publicInputs.proofSlot == proof.proofSlot
    val matchingCircuit = proof.publicInputs.circuitRef == proof.circuitRef
    val productionSuite = proof.proofSuite == PROOF_SUITE
    val shape = completeEnvelope && digestSized && nonemptyProof
    val binding = matchingIdentity && matchingCircuit && productionSuite
    return shape && binding
}

internal fun isProducedEvidenceStageProofWellFormed(
    proof: Manifest.ZkPersonaCredentialEvidenceStageProof,
    request: ZkPersonaCredentialEvidenceStageProveRequest,
): Boolean {
    val matchingRequest = proof.mode == request.mode && proof.circuitRef == request.circuitRef
    val matchingStage = proof.proofSlot == evidenceStageForCircuitStage(request.circuitRef.stage)
    return isEvidenceStageProofWellFormed(proof) && matchingRequest && matchingStage
}

/** Native success still needs to describe the exact proof submitted by the caller. */
internal fun requirePersonaCredentialEvidenceStageVerification(
    result: Manifest.ZkProviderOperationResult,
    proof: Manifest.ZkPersonaCredentialEvidenceStageProof,
): Manifest.ZkPersonaCredentialEvidenceStageVerification {
    val isStageVerification =
        result.resultCase ==
            Manifest.ZkProviderOperationResult.ResultCase.PERSONA_CREDENTIAL_EVIDENCE_STAGE_VERIFICATION
    if (!isStageVerification) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    val verified = result.personaCredentialEvidenceStageVerification
    val matchesProof =
        verified.mode == proof.mode &&
            verified.proofSlot == proof.proofSlot &&
            verified.circuitRef == proof.circuitRef &&
            verified.proofSuite == proof.proofSuite
    if (!matchesProof) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    return verified
}
