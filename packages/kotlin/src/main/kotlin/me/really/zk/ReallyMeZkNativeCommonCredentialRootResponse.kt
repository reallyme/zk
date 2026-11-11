// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import me.really.zk.commonroot.COMMON_CREDENTIAL_ROOT_PROOF_SLOTS
import me.really.zk.commonroot.ZkCommonCredentialRootPresentationProof
import me.really.zk.commonroot.ZkCommonCredentialRootStageProof
import reallyme.zk.v1.Manifest

private typealias RootVerification = Manifest.ZkCommonCredentialRootVerification

internal fun rootVerification(response: Manifest.ZkProviderOperationResponse): RootVerification {
    val result = requireResult(response)
    if (result.resultCase != Manifest.ZkProviderOperationResult.ResultCase.COMMON_CREDENTIAL_ROOT_VERIFICATION) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    return result.commonCredentialRootVerification
}

internal fun requireCommonCredentialRootStageProof(
    response: Manifest.ZkProviderOperationResponse,
    operation: Manifest.ZkCommonCredentialRootStageProveOperation,
): ZkCommonCredentialRootStageProof {
    val result = requireResult(response)
    if (result.resultCase != Manifest.ZkProviderOperationResult.ResultCase.COMMON_CREDENTIAL_ROOT_STAGE_PROOF) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    val proof = result.commonCredentialRootStageProof
    val matchingMetadata =
        proof.personaMode == operation.personaMode &&
            proof.slot == operation.slot &&
            proof.circuitRef == operation.circuitRef &&
            proof.proofSuite == PROOF_SUITE
    val matchingPublicInputs =
        proof.hasPublicInputs() &&
            proof.publicInputs.personaMode == proof.personaMode &&
            proof.publicInputs.slot == proof.slot &&
            proof.publicInputs.circuitRef == proof.circuitRef
    val completeProof =
        !proof.proof.isEmpty &&
            commonCredentialRootArtifactIdentityIsValid(proof)
    if (!matchingMetadata || !matchingPublicInputs || !completeProof) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    return ZkCommonCredentialRootStageProof(proof)
}

internal fun requireCommonCredentialRootPresentation(
    response: Manifest.ZkProviderOperationResponse,
    operation: Manifest.ZkCommonCredentialRootPresentationProveOperation,
): ZkCommonCredentialRootPresentationProof {
    val result = requireResult(response)
    if (result.resultCase != Manifest.ZkProviderOperationResult.ResultCase.COMMON_CREDENTIAL_ROOT_PRESENTATION) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    val presentation = result.commonCredentialRootPresentation
    if (!presentationEnvelopeMatches(presentation, operation) ||
        !presentationProofsMatch(presentation)
    ) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    return ZkCommonCredentialRootPresentationProof(presentation)
}

private fun presentationEnvelopeMatches(
    presentation: Manifest.ZkCommonCredentialRootPresentation,
    operation: Manifest.ZkCommonCredentialRootPresentationProveOperation,
): Boolean =
    presentation.personaMode == operation.personaMode &&
        presentation.proofSuite == operation.proofSuite &&
        presentation.sessionBinding == operation.expectedBinding

private fun presentationProofsMatch(presentation: Manifest.ZkCommonCredentialRootPresentation): Boolean =
    presentation.proofsCount == COMMON_CREDENTIAL_ROOT_PROOF_SLOTS.size &&
        presentation.proofsList.map { it.slot } == COMMON_CREDENTIAL_ROOT_PROOF_SLOTS &&
        presentation.proofsList.all { proof -> rawProofPackageMatchesPresentation(proof, presentation) }

private fun rawProofPackageMatchesPresentation(
    proof: Manifest.ZkCommonCredentialRootRawProofPackage,
    presentation: Manifest.ZkCommonCredentialRootPresentation,
): Boolean =
    proof.personaMode == presentation.personaMode &&
        proof.proofSuite == presentation.proofSuite &&
        proof.circuitRef.credentialHashAlgorithm == presentation.credentialHashAlgorithm &&
        proof.hasPublicInputs() &&
        proof.publicInputs.personaMode == proof.personaMode &&
        proof.publicInputs.slot == proof.slot &&
        proof.publicInputs.circuitRef == proof.circuitRef &&
        !proof.proof.isEmpty &&
        commonCredentialRootArtifactIdentityIsValid(proof)

/** Preserve the identity construction until the native verifier resolves its trusted pin. */
internal fun commonCredentialRootArtifactIdentityIsValid(
    proof: Manifest.ZkCommonCredentialRootRawProofPackage,
): Boolean {
    val bytes =
        when (proof.artifactIdentityCase) {
            Manifest.ZkCommonCredentialRootRawProofPackage.ArtifactIdentityCase.ARTIFACT_MANIFEST_SHA256 ->
                proof.artifactManifestSha256.value
            Manifest.ZkCommonCredentialRootRawProofPackage.ArtifactIdentityCase.ARTIFACT_SET_IDENTITY_SHA256 ->
                proof.artifactSetIdentitySha256.value
            else -> return false
        }
    return bytes.size() == BYTES_32 && bytes.any { it != 0.toByte() }
}
