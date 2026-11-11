// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import com.google.protobuf.InvalidProtocolBufferException
import reallyme.zk.v1.Manifest

internal fun parseOperationResponse(output: ByteArray): Manifest.ZkProviderOperationResponse =
    try {
        Manifest.ZkProviderOperationResponse.parseFrom(output)
    } catch (ignored: InvalidProtocolBufferException) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }

internal fun validateResponseHash(
    response: Manifest.ZkProviderOperationResponse,
    requestSha256: ByteArray,
) {
    val responseSha256 = response.requestSha256
    if (responseSha256.size() != requestSha256.size) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    var difference = 0
    var index = 0
    while (index < requestSha256.size) {
        difference = difference or (responseSha256.byteAt(index).toInt() xor requestSha256[index].toInt())
        index += 1
    }
    if (difference != 0) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
}

internal fun requireStageWitness(response: Manifest.ZkProviderOperationResponse): Manifest.ZkStageWitness {
    val result = requireResult(response)
    if (result.resultCase != Manifest.ZkProviderOperationResult.ResultCase.STAGE_WITNESS) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
    }
    val witness = result.stageWitness
    if (!witness.hasWitnessHandle() || !witness.hasPublicInputs() || !witness.hasSessionBinding()) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
    }
    return witness
}

internal fun requireStageProof(response: Manifest.ZkProviderOperationResponse): Manifest.ZkProofPackage {
    val result = requireResult(response)
    if (result.resultCase != Manifest.ZkProviderOperationResult.ResultCase.STAGE_PROOF) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    return result.stageProof
}

internal fun requireClaimProofBundle(response: Manifest.ZkProviderOperationResponse): Manifest.ZkClaimProofBundle {
    val result = requireResult(response)
    if (result.resultCase != Manifest.ZkProviderOperationResult.ResultCase.CLAIM_PROOF_BUNDLE) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    return result.claimProofBundle
}

internal fun requireClaimProofBundleVerification(
    response: Manifest.ZkProviderOperationResponse,
): Manifest.ZkPresentationBoundClaimBundleVerification {
    val result = requireResult(response)
    if (result.resultCase != Manifest.ZkProviderOperationResult.ResultCase.CLAIM_PROOF_BUNDLE_VERIFICATION) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    return result.claimProofBundleVerification
}

internal fun isSuccessfulStageVerification(
    response: Manifest.ZkProviderOperationResponse,
    operation: Manifest.ZkStageVerifyOperation,
): Boolean =
    when (response.outcomeCase) {
        Manifest.ZkProviderOperationResponse.OutcomeCase.RESULT -> {
            if (response.result.resultCase != Manifest.ZkProviderOperationResult.ResultCase.STAGE_VERIFICATION) {
                throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
            }
            requireStageVerificationReport(response.result.stageVerification, operation)
            true
        }
        Manifest.ZkProviderOperationResponse.OutcomeCase.ERROR -> {
            val reason = providerFailureReason(response.error.reason)
            if (reason == ZkProviderFailureReason.PROOF_REJECTED ||
                reason == ZkProviderFailureReason.MALFORMED_PROOF
            ) {
                false
            } else {
                throw ReallyMeZkProviderException(reason)
            }
        }
        Manifest.ZkProviderOperationResponse.OutcomeCase.OUTCOME_NOT_SET ->
            throw ReallyMeZkProviderException(ZkProviderFailureReason.EMPTY_BUFFER)
    }

internal fun requireStageWitnessRelease(response: Manifest.ZkProviderOperationResponse) {
    val result = requireResult(response)
    if (result.resultCase != Manifest.ZkProviderOperationResult.ResultCase.STAGE_WITNESS_RELEASE) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
    }
}

internal fun requireResult(response: Manifest.ZkProviderOperationResponse): Manifest.ZkProviderOperationResult =
    when (response.outcomeCase) {
        Manifest.ZkProviderOperationResponse.OutcomeCase.RESULT -> response.result
        Manifest.ZkProviderOperationResponse.OutcomeCase.ERROR ->
            throw ReallyMeZkProviderException(providerFailureReason(response.error.reason))
        Manifest.ZkProviderOperationResponse.OutcomeCase.OUTCOME_NOT_SET ->
            throw ReallyMeZkProviderException(ZkProviderFailureReason.EMPTY_BUFFER)
    }
