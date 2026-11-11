// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import me.really.zk.claimbundle.ZkPresentationBoundClaimBundlePolicyBinding
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleProofShape
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleSensitiveClaim
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerification
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerifyRequest
import reallyme.zk.v1.Manifest

internal fun verifiedClaimProofBundle(
    verification: Manifest.ZkPresentationBoundClaimBundleVerification,
    request: ZkPresentationBoundClaimBundleVerifyRequest,
    claimProofBundle: Manifest.ZkClaimProofBundle,
): ZkPresentationBoundClaimBundleVerification {
    requireBundleSuites(verification, claimProofBundle)
    requireBundleShape(verification, claimProofBundle)
    requireBundlePolicy(verification, request, claimProofBundle)
    return verifiedClaimProofBundleFromStatement(verification, request)
}

internal fun claimProofBundleByteCount(claimProofBundle: Manifest.ZkClaimProofBundle): Int {
    var total = 0
    for (stage in claimProofBundle.stagesList) {
        val next =
            total.toLong() +
                stage.proof.proof
                    .size()
                    .toLong()
        if (next > Int.MAX_VALUE) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.ARITHMETIC_OVERFLOW)
        }
        total = next.toInt()
    }
    return total
}

private fun requireBundleSuites(
    verification: Manifest.ZkPresentationBoundClaimBundleVerification,
    claimProofBundle: Manifest.ZkClaimProofBundle,
) {
    if (verification.proofSuite != PROOF_SUITE || claimProofBundle.proofSuite != PROOF_SUITE) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
}

private fun requireBundleShape(
    verification: Manifest.ZkPresentationBoundClaimBundleVerification,
    claimProofBundle: Manifest.ZkClaimProofBundle,
) {
    if (claimProofBundle.formatVersion != CLAIM_PROOF_BUNDLE_FORMAT_VERSION ||
        verification.verifiedStageCount != NATIVE_PRODUCTION_STAGE_COUNT ||
        claimProofBundle.stagesCount != NATIVE_PRODUCTION_STAGE_COUNT
    ) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    if (claimProofBundle.bundleKind != verification.bundleKind) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
}

private fun requireBundlePolicy(
    verification: Manifest.ZkPresentationBoundClaimBundleVerification,
    request: ZkPresentationBoundClaimBundleVerifyRequest,
    claimProofBundle: Manifest.ZkClaimProofBundle,
) {
    val statement = verification.statement
    requireSessionBinding(claimProofBundle, request)
    requireTrustedIssuer(statement, request)
    requireFreshPresentation(statement, request)
    requireStatementShape(statement)
}

private fun requireSessionBinding(
    claimProofBundle: Manifest.ZkClaimProofBundle,
    request: ZkPresentationBoundClaimBundleVerifyRequest,
) {
    if (claimProofBundle.sessionBinding != request.expectedSessionBinding) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
    }
}

private fun requireTrustedIssuer(
    statement: Manifest.ZkPresentationBoundClaimStatement,
    request: ZkPresentationBoundClaimBundleVerifyRequest,
) {
    if (!statement.hasIssuer() || request.trustedIssuers.none { it == statement.issuer }) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
    }
}

internal fun requireFreshPresentation(
    statement: Manifest.ZkPresentationBoundClaimStatement,
    request: ZkPresentationBoundClaimBundleVerifyRequest,
) {
    if (statement.presentationExpiryUnix <= 0 ||
        statement.presentationExpiryUnix <= request.verificationTimeUnix
    ) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
    }
    val remainingLifetime = statement.presentationExpiryUnix - request.verificationTimeUnix
    if (remainingLifetime > MAX_PRESENTATION_LIFETIME_SECONDS) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
    }
}

private fun requireStatementShape(statement: Manifest.ZkPresentationBoundClaimStatement) {
    val malformedCommitmentShape =
        statement.claimNameHash.size() != BYTES_32 ||
            statement.credentialBinding.size() != BYTES_32 ||
            statement.sessionLinkCommitment.size() != BYTES_32
    val malformedClaimValueShape = statement.claimValueLength > statement.claimValue.size()
    if (malformedCommitmentShape || malformedClaimValueShape) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
}

private fun verifiedClaimProofBundleFromStatement(
    verification: Manifest.ZkPresentationBoundClaimBundleVerification,
    request: ZkPresentationBoundClaimBundleVerifyRequest,
): ZkPresentationBoundClaimBundleVerification {
    val statement = verification.statement
    return ZkPresentationBoundClaimBundleVerification(
        proofShape =
            ZkPresentationBoundClaimBundleProofShape(
                bundleKind = verification.bundleKind,
                verifiedStageCount = verification.verifiedStageCount,
            ),
        policyBinding =
            ZkPresentationBoundClaimBundlePolicyBinding(
                sessionBinding = request.expectedSessionBinding,
                issuer = statement.issuer,
                persona = if (statement.hasPersona()) statement.persona else null,
                presentationExpiryUnix = statement.presentationExpiryUnix,
            ),
        sensitiveClaim =
            ZkPresentationBoundClaimBundleSensitiveClaim(
                claimNameHash = ZkSensitiveBytes(statement.claimNameHash.toByteArray()),
                claimValue = ZkSensitiveBytes(statement.claimValue.toByteArray()),
                claimValueLength = statement.claimValueLength,
                credentialBinding = ZkSensitiveBytes(statement.credentialBinding.toByteArray()),
                sessionLinkCommitment = ZkSensitiveBytes(statement.sessionLinkCommitment.toByteArray()),
            ),
    )
}
