// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.claimbundle

import com.google.protobuf.ByteString
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.ZkSensitiveBytes
import me.really.zk.validateSessionBinding
import reallyme.zk.v1.Manifest

public typealias ZkIssuerStatusPurpose = Manifest.ZkIssuerStatusPurpose

/** Verifier-owned inputs for five-proof, status-qualified claim verification.
 * The provider has no network access and no trust store. Before constructing
 * this request the verifier application must authenticate the issuer status
 * list: its signature, its issuer, its freshness, and its rollback floor.
 * The authenticated list must belong to [expectedIssuer], which is the
 * credential issuer even if a delegated signer authenticates its status list.
 * [currentIssuerStatus] must describe that authenticated list and must never be
 * taken from the holder's presentation.
 */
public class ZkStatusQualifiedClaimBundleVerifyRequest(
    public val expectedSessionBinding: Manifest.ZkSessionBinding,
    public val expectedIssuer: Manifest.ZkP256PublicKey,
    trustedIssuers: List<Manifest.ZkP256PublicKey>,
    public val verificationTimeUnix: Long,
    public val currentIssuerStatus: Manifest.ZkCommonCredentialRootIssuerStatusExpectation,
) {
    public val trustedIssuers: List<Manifest.ZkP256PublicKey> = trustedIssuers.toList()

    init {
        validateSessionBinding(expectedSessionBinding)
        if (this.trustedIssuers.isEmpty()) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
        }
        if (expectedIssuer !in this.trustedIssuers) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
        }
        if (verificationTimeUnix <= 0) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
        }
        validateCurrentIssuerStatus(currentIssuerStatus)
    }

    override fun toString(): String =
        "ZkStatusQualifiedClaimBundleVerifyRequest(expectedSessionBinding=<redacted>, " +
            "expectedIssuer=<redacted>, trustedIssuers=<redacted>, " +
            "verificationTimeUnix=$verificationTimeUnix, currentIssuerStatus=<redacted>)"
}

internal class ZkStatusQualifiedClaimBundleProofShape(
    val bundleKind: ZkClaimProofBundleKind,
    val verifiedProofCount: Int,
    val statusPurpose: ZkIssuerStatusPurpose,
)

internal class ZkStatusQualifiedClaimBundlePolicyBinding(
    val sessionBinding: Manifest.ZkSessionBinding,
    val issuer: Manifest.ZkP256PublicKey,
    val persona: Manifest.ZkP256PublicKey?,
    val presentationExpiryUnix: Long,
)

internal class ZkStatusQualifiedClaimBundleSensitiveClaim(
    val claimNameHash: ZkSensitiveBytes,
    val claimValue: ZkSensitiveBytes,
    val claimValueLength: Int,
    val credentialBinding: ZkSensitiveBytes,
    val sessionLinkCommitment: ZkSensitiveBytes,
)

/** Five verified proofs checked against the verifier's current issuer status list.
 * Establishes the four request-bound claim proofs, issuer trust, session
 * binding, presentation expiry, issuer-signed credential validity, and that
 * the credential is not flagged in the issuer status list the verifier
 * supplied for [statusPurpose]. This is the only claim-bundle result that may
 * be used for credential acceptance.
 *
 * It does not consume the session. The verifier must atomically accept the
 * active session exactly once before granting access. Only a provider can
 * construct this value, and no conversion exists from
 * [ZkPresentationBoundClaimBundleVerification].
 */
public class ZkStatusQualifiedClaimBundleVerification internal constructor(
    private val proofShape: ZkStatusQualifiedClaimBundleProofShape,
    private val policyBinding: ZkStatusQualifiedClaimBundlePolicyBinding,
    private val sensitiveClaim: ZkStatusQualifiedClaimBundleSensitiveClaim,
) : AutoCloseable {
    public val bundleKind: ZkClaimProofBundleKind
        get() = proofShape.bundleKind

    public val verifiedProofCount: Int
        get() = proofShape.verifiedProofCount

    public val statusPurpose: ZkIssuerStatusPurpose
        get() = proofShape.statusPurpose

    public val sessionBinding: Manifest.ZkSessionBinding
        get() = policyBinding.sessionBinding

    public val issuer: Manifest.ZkP256PublicKey
        get() = policyBinding.issuer

    public val persona: Manifest.ZkP256PublicKey?
        get() = policyBinding.persona

    public val claimNameHash: ZkSensitiveBytes
        get() = sensitiveClaim.claimNameHash

    public val claimValue: ZkSensitiveBytes
        get() = sensitiveClaim.claimValue

    public val claimValueLength: Int
        get() = sensitiveClaim.claimValueLength

    public val credentialBinding: ZkSensitiveBytes
        get() = sensitiveClaim.credentialBinding

    public val sessionLinkCommitment: ZkSensitiveBytes
        get() = sensitiveClaim.sessionLinkCommitment

    public val presentationExpiryUnix: Long
        get() = policyBinding.presentationExpiryUnix

    override fun close() {
        claimNameHash.close()
        claimValue.close()
        credentialBinding.close()
        sessionLinkCommitment.close()
    }

    override fun toString(): String =
        buildString {
            append("ZkStatusQualifiedClaimBundleVerification(bundleKind=")
            append(bundleKind)
            append(", verifiedProofCount=")
            append(verifiedProofCount)
            append(", statusPurpose=")
            append(statusPurpose)
            append(", sensitive=<redacted>)")
        }
}

public interface ReallyMeZkStatusQualifiedClaimBundleVerifier<StatusQualifiedClaimProofBundleHandle : Any> {
    /** Verify all five proofs, session binding, trusted issuer, presentation
     * expiry, issuer-signed credential validity, and current issuer status.
     * The result does not consume the session: the verifier must atomically
     * accept the active session exactly once before granting access.
     */
    public fun verifyStatusQualifiedClaimBundle(
        request: ZkStatusQualifiedClaimBundleVerifyRequest,
        statusQualifiedClaimProofBundle: StatusQualifiedClaimProofBundleHandle,
    ): ZkStatusQualifiedClaimBundleVerification
}

private fun validateCurrentIssuerStatus(status: Manifest.ZkCommonCredentialRootIssuerStatusExpectation) {
    val validDigests =
        isNonZeroStatusDigest(status.root) &&
            isNonZeroStatusDigest(status.listId) &&
            isNonZeroStatusDigest(status.urlHash)
    val validLength = status.length in MIN_ISSUER_STATUS_LIST_LENGTH..MAX_ISSUER_STATUS_LIST_LENGTH
    val validPurpose =
        status.purpose == ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_REVOCATION ||
            status.purpose == ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_SUSPENSION
    if (!validDigests || !validLength || !validPurpose) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
    }
}

private fun isNonZeroStatusDigest(digest: ByteString): Boolean {
    if (digest.size() != ISSUER_STATUS_DIGEST_BYTES) {
        return false
    }
    var accumulated = 0
    for (index in 0 until ISSUER_STATUS_DIGEST_BYTES) {
        accumulated = accumulated or digest.byteAt(index).toInt()
    }
    return accumulated != 0
}

private const val ISSUER_STATUS_DIGEST_BYTES = 32
private const val MIN_ISSUER_STATUS_LIST_LENGTH = 1L
private const val MAX_ISSUER_STATUS_LIST_LENGTH = 1_000_000L
