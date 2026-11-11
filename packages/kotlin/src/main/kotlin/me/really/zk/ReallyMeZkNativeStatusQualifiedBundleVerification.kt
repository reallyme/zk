// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundlePolicyBinding
import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundleProofShape
import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundleSensitiveClaim
import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundleVerification
import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundleVerifyRequest
import reallyme.zk.v1.Manifest

/**
 * Accepts only the five-proof result case. Every other result, including the
 * four-proof claim-bundle verification, is a malformed provider response.
 */
internal fun requireStatusQualifiedClaimProofBundleVerification(
    response: Manifest.ZkProviderOperationResponse,
): Manifest.ZkStatusQualifiedClaimProofBundleVerification {
    val result = requireResult(response)
    val isStatusQualifiedVerification =
        result.resultCase ==
            Manifest.ZkProviderOperationResult.ResultCase.STATUS_QUALIFIED_CLAIM_PROOF_BUNDLE_VERIFICATION
    if (!isStatusQualifiedVerification) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    return result.statusQualifiedClaimProofBundleVerification
}

/**
 * Checks the provider report against the bundle that was dispatched and the
 * verifier's request before any value is returned. A mismatch throws; no
 * partially trusted result is ever constructed.
 */
internal fun verifiedStatusQualifiedClaimProofBundle(
    verification: Manifest.ZkStatusQualifiedClaimProofBundleVerification,
    request: ZkStatusQualifiedClaimBundleVerifyRequest,
    statusQualifiedClaimProofBundle: Manifest.ZkStatusQualifiedClaimProofBundle,
): ZkStatusQualifiedClaimBundleVerification {
    requireStatusQualifiedBundleParts(statusQualifiedClaimProofBundle)
    requireStatusQualifiedSuites(verification, statusQualifiedClaimProofBundle)
    requireStatusQualifiedShape(verification, statusQualifiedClaimProofBundle.claimProofBundle)
    requireStatusQualifiedPolicy(verification, request, statusQualifiedClaimProofBundle.claimProofBundle)
    return statusQualifiedVerificationFromStatement(verification, request)
}

private fun requireStatusQualifiedBundleParts(
    statusQualifiedClaimProofBundle: Manifest.ZkStatusQualifiedClaimProofBundle,
) {
    if (!statusQualifiedClaimProofBundle.hasClaimProofBundle() ||
        !statusQualifiedClaimProofBundle.hasIssuerCredentialStatus()
    ) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
}

private fun requireStatusQualifiedSuites(
    verification: Manifest.ZkStatusQualifiedClaimProofBundleVerification,
    statusQualifiedClaimProofBundle: Manifest.ZkStatusQualifiedClaimProofBundle,
) {
    if (verification.proofSuite != PROOF_SUITE ||
        statusQualifiedClaimProofBundle.claimProofBundle.proofSuite != PROOF_SUITE ||
        statusQualifiedClaimProofBundle.issuerCredentialStatus.proofSuite != PROOF_SUITE
    ) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
}

private fun requireStatusQualifiedShape(
    verification: Manifest.ZkStatusQualifiedClaimProofBundleVerification,
    claimProofBundle: Manifest.ZkClaimProofBundle,
) {
    if (claimProofBundle.formatVersion != CLAIM_PROOF_BUNDLE_FORMAT_VERSION ||
        claimProofBundle.stagesCount != NATIVE_PRODUCTION_STAGE_COUNT ||
        verification.verifiedProofCount != STATUS_QUALIFIED_PROOF_COUNT
    ) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    if (claimProofBundle.bundleKind != verification.bundleKind) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
}

private fun requireStatusQualifiedPolicy(
    verification: Manifest.ZkStatusQualifiedClaimProofBundleVerification,
    request: ZkStatusQualifiedClaimBundleVerifyRequest,
    claimProofBundle: Manifest.ZkClaimProofBundle,
) {
    if (verification.statusPurpose != request.currentIssuerStatus.purpose || !verification.hasStatement()) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    val statement = verification.statement
    requireStatusQualifiedSessionAndIssuer(statement, request, claimProofBundle)
    requireFreshStatusQualifiedPresentation(statement.presentationExpiryUnix, request.verificationTimeUnix)
    requireStatusQualifiedStatementShape(statement)
}

private fun requireStatusQualifiedSessionAndIssuer(
    statement: Manifest.ZkStatusQualifiedClaimStatement,
    request: ZkStatusQualifiedClaimBundleVerifyRequest,
    claimProofBundle: Manifest.ZkClaimProofBundle,
) {
    if (claimProofBundle.sessionBinding != request.expectedSessionBinding) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
    }
    if (!statement.hasIssuer() ||
        statement.issuer != request.expectedIssuer ||
        request.trustedIssuers.none { it == statement.issuer }
    ) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
    }
}

private fun requireFreshStatusQualifiedPresentation(
    presentationExpiryUnix: Long,
    verificationTimeUnix: Long,
) {
    if (presentationExpiryUnix <= 0 || presentationExpiryUnix <= verificationTimeUnix) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
    }
    val remainingLifetime = presentationExpiryUnix - verificationTimeUnix
    if (remainingLifetime > MAX_PRESENTATION_LIFETIME_SECONDS) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
    }
}

private fun requireStatusQualifiedStatementShape(statement: Manifest.ZkStatusQualifiedClaimStatement) {
    val malformedCommitmentShape =
        statement.claimNameHash.size() != BYTES_32 ||
            statement.credentialBinding.size() != BYTES_32 ||
            statement.sessionLinkCommitment.size() != BYTES_32
    // The wire length is unsigned; a negative value here is a length above Int.MAX_VALUE.
    val malformedClaimValueShape =
        statement.claimValueLength < 0 || statement.claimValueLength > statement.claimValue.size()
    if (malformedCommitmentShape || malformedClaimValueShape) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
}

private fun statusQualifiedVerificationFromStatement(
    verification: Manifest.ZkStatusQualifiedClaimProofBundleVerification,
    request: ZkStatusQualifiedClaimBundleVerifyRequest,
): ZkStatusQualifiedClaimBundleVerification {
    val statement = verification.statement
    return ZkStatusQualifiedClaimBundleVerification(
        proofShape =
            ZkStatusQualifiedClaimBundleProofShape(
                bundleKind = verification.bundleKind,
                verifiedProofCount = verification.verifiedProofCount,
                statusPurpose = verification.statusPurpose,
            ),
        policyBinding =
            ZkStatusQualifiedClaimBundlePolicyBinding(
                sessionBinding = request.expectedSessionBinding,
                issuer = statement.issuer,
                persona = if (statement.hasPersona()) statement.persona else null,
                presentationExpiryUnix = statement.presentationExpiryUnix,
            ),
        sensitiveClaim =
            ZkStatusQualifiedClaimBundleSensitiveClaim(
                claimNameHash = ZkSensitiveBytes(statement.claimNameHash.toByteArray()),
                claimValue = ZkSensitiveBytes(statement.claimValue.toByteArray()),
                claimValueLength = statement.claimValueLength,
                credentialBinding = ZkSensitiveBytes(statement.credentialBinding.toByteArray()),
                sessionLinkCommitment = ZkSensitiveBytes(statement.sessionLinkCommitment.toByteArray()),
            ),
    )
}

internal const val STATUS_QUALIFIED_PROOF_COUNT: Int = 5
