// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.claimbundle

import me.really.zk.MAX_PROOF_BYTES
import me.really.zk.PRODUCTION_STAGE_COUNT
import me.really.zk.ReallyMeZkProvider
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.ZkSensitiveBytes
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.validateByteCount
import me.really.zk.validateSessionBinding
import reallyme.zk.v1.Manifest

public data class ZkClaimProofBundleMetrics(
    public val stageCount: Int,
    public val proofByteCount: Int,
) {
    init {
        validateByteCount(proofByteCount, MAX_PROOF_BYTES * PRODUCTION_STAGE_COUNT)
    }
}

public data class ZkProviderClaimProofBundleResult<ClaimProofBundleHandle : Any>(
    public val handle: ClaimProofBundleHandle,
    public val metrics: ZkClaimProofBundleMetrics,
)

public class ZkClaimProofBundleProveRequest(
    public val bundleKind: ZkClaimProofBundleKind,
    public val credentialHashAlgorithm: ZkCredentialHashAlgorithm =
        ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
    public val sessionBinding: Manifest.ZkSessionBinding,
) {
    init {
        validateSessionBinding(sessionBinding)
    }

    override fun toString(): String =
        buildString {
            append("ZkClaimProofBundleProveRequest(")
            append("bundleKind=")
            append(bundleKind)
            append(", credentialHashAlgorithm=")
            append(credentialHashAlgorithm)
            append(", sessionBinding=<redacted>)")
        }
}

public class ZkPresentationBoundClaimBundleVerifyRequest(
    public val expectedSessionBinding: Manifest.ZkSessionBinding,
    public val trustedIssuers: List<Manifest.ZkP256PublicKey>,
    public val verificationTimeUnix: Long,
) {
    init {
        validateSessionBinding(expectedSessionBinding)
        if (trustedIssuers.isEmpty()) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
        }
        if (verificationTimeUnix <= 0) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
        }
    }

    override fun toString(): String =
        "ZkPresentationBoundClaimBundleVerifyRequest(expectedSessionBinding=<redacted>, trustedIssuers=<redacted>, " +
            "verificationTimeUnix=$verificationTimeUnix)"
}

public class ZkPresentationBoundClaimBundleProofShape(
    public val bundleKind: ZkClaimProofBundleKind,
    public val verifiedStageCount: Int,
)

public class ZkPresentationBoundClaimBundlePolicyBinding(
    public val sessionBinding: Manifest.ZkSessionBinding,
    public val issuer: Manifest.ZkP256PublicKey,
    public val persona: Manifest.ZkP256PublicKey?,
    public val presentationExpiryUnix: Long,
)

public class ZkPresentationBoundClaimBundleSensitiveClaim(
    public val claimNameHash: ZkSensitiveBytes,
    public val claimValue: ZkSensitiveBytes,
    public val claimValueLength: Int,
    public val credentialBinding: ZkSensitiveBytes,
    public val sessionLinkCommitment: ZkSensitiveBytes,
)

/** Four verified claim proofs bound to the active request.
 * Issuer-signed credential validity and current status are not established.
 * Public construction supports injected providers; this value carries no
 * credential-acceptance capability and does not consume a session.
 */
public class ZkPresentationBoundClaimBundleVerification(
    private val proofShape: ZkPresentationBoundClaimBundleProofShape,
    private val policyBinding: ZkPresentationBoundClaimBundlePolicyBinding,
    private val sensitiveClaim: ZkPresentationBoundClaimBundleSensitiveClaim,
) : AutoCloseable {
    public val bundleKind: ZkClaimProofBundleKind
        get() = proofShape.bundleKind

    public val verifiedStageCount: Int
        get() = proofShape.verifiedStageCount

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
            append("ZkPresentationBoundClaimBundleVerification(bundleKind=")
            append(bundleKind)
            append(", verifiedStageCount=")
            append(verifiedStageCount)
            append(", sensitive=<redacted>)")
        }
}

public interface ReallyMeZkPresentationBoundClaimBundleVerifier<ClaimProofBundleHandle : Any> {
    /** Verify presentation binding, trusted issuer, and presentation expiry only.
     * Credential acceptance additionally requires joined signed validity/current
     * status evidence and atomic single-use session enforcement by the verifier.
     */
    public fun verifyPresentationBoundClaimBundle(
        request: ZkPresentationBoundClaimBundleVerifyRequest,
        claimProofBundle: ClaimProofBundleHandle,
    ): ZkPresentationBoundClaimBundleVerification
}

public interface ReallyMeZkClaimProofBundleProvider<
    WitnessHandle : Any,
    ProofHandle : Any,
    ClaimProofBundleHandle : Any,
> :
    ReallyMeZkProvider<WitnessHandle, ProofHandle>,
    ReallyMeZkPresentationBoundClaimBundleVerifier<ClaimProofBundleHandle> {
    /**
     * Proves a complete production bundle from four retained stage witnesses.
     *
     * A successful return consumes every supplied witness handle. If proving
     * throws, callers perform best-effort release of the original handles and
     * keep the proof error as primary; provider implementations must therefore
     * make release single-use and stale-handle safe.
     */
    public fun proveClaimProofBundle(
        request: ZkClaimProofBundleProveRequest,
        witnesses: List<WitnessHandle>,
    ): ZkProviderClaimProofBundleResult<ClaimProofBundleHandle>
}
