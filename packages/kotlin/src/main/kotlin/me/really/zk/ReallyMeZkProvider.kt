// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ReallyMeZkClaimProofBundleProvider
import me.really.zk.claimbundle.ReallyMeZkPresentationBoundClaimBundleVerifier
import me.really.zk.claimbundle.ReallyMeZkStatusQualifiedClaimBundleVerifier
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleProveRequest
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerification
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerifyRequest
import me.really.zk.claimbundle.ZkProviderClaimProofBundleResult
import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundleVerification
import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundleVerifyRequest
import reallyme.zk.v1.Manifest

public enum class ZkProviderFailureReason {
    PROVIDER_UNAVAILABLE,
    PROVIDER_BUSY,
    UNSUPPORTED_SUITE,
    UNSUPPORTED_CIRCUIT,
    UNSUPPORTED_TRANSPORT,
    CRS_MISSING,
    CRS_HASH_MISMATCH,
    MALFORMED_WITNESS,
    MALFORMED_PROOF,
    PROOF_REJECTED,
    EMPTY_BUFFER,
    OVERSIZED_BUFFER,
    INVALID_TIMING,
    ARITHMETIC_OVERFLOW,
    OPERATION_CANCELLED,
    CLEANUP_FAILED,
    INTERNAL_FAILURE,
}

// Keep the Java/Kotlin Exception hierarchy while distinguishing this typed
// superclass call from generic errors constructed in executable code.
private typealias ZkProviderExceptionBase = Exception

public class ReallyMeZkProviderException(
    public val reason: ZkProviderFailureReason,
) : ZkProviderExceptionBase("ReallyMe ZK provider failed")

public class ZkStageRequest(
    public val bundleKind: ZkClaimProofBundleKind,
    public val credentialHashAlgorithm: ZkCredentialHashAlgorithm =
        ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
    public val stage: ZkClaimProofBundleStage,
    private val witnessInput: Manifest.ZkStageWitnessInput = Manifest.ZkStageWitnessInput.getDefaultInstance(),
) {
    internal val witnessInputForProvider: Manifest.ZkStageWitnessInput
        get() = witnessInput

    override fun toString(): String =
        "ZkStageRequest(" +
            "bundleKind=$bundleKind, " +
            "credentialHashAlgorithm=$credentialHashAlgorithm, " +
            "stage=$stage, " +
            "witnessInput=<redacted>" +
            ")"
}

public class ZkStageVerifyRequest(
    public val bundleKind: ZkClaimProofBundleKind,
    public val credentialHashAlgorithm: ZkCredentialHashAlgorithm =
        ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
    public val stage: ZkClaimProofBundleStage,
    public val expectedSessionBinding: Manifest.ZkSessionBinding,
) {
    init {
        validateSessionBinding(expectedSessionBinding)
    }

    override fun toString(): String =
        "ZkStageVerifyRequest(" +
            "bundleKind=$bundleKind, " +
            "credentialHashAlgorithm=$credentialHashAlgorithm, " +
            "stage=$stage, " +
            "expectedSessionBinding=<redacted>" +
            ")"
}

public data class ZkWitnessMetrics(
    public val byteCount: Int? = null,
) {
    init {
        byteCount?.let { validateByteCount(it, MAX_WITNESS_BYTES) }
    }
}

public data class ZkProofMetrics(
    public val verificationKeyByteCount: Int? = null,
    public val publicInputByteCount: Int,
    public val proofByteCount: Int,
) {
    init {
        verificationKeyByteCount?.let { validateByteCount(it, MAX_VERIFICATION_KEY_BYTES) }
        validateByteCount(publicInputByteCount, MAX_PUBLIC_INPUT_BYTES)
        validateByteCount(proofByteCount, MAX_PROOF_BYTES)
    }
}

public data class ZkProviderWitnessResult<WitnessHandle : Any>(
    public val handle: WitnessHandle,
    public val metrics: ZkWitnessMetrics,
)

public data class ZkProviderProofResult<ProofHandle : Any>(
    public val handle: ProofHandle,
    public val metrics: ZkProofMetrics,
)

/**
 * Owns the provided byte array and wipes that same storage on close.
 *
 * Callers that need to retain their original array must pass a copy. The
 * native provider passes fresh protobuf-owned arrays so no extra sensitive copy
 * is left for the GC to reclaim.
 */
public class ZkSensitiveBytes(
    bytes: ByteArray,
) : AutoCloseable {
    private var storage: ByteArray? = bytes

    public val size: Int
        @Synchronized get() = storage?.size ?: 0

    @Synchronized
    public fun <T> useBytes(block: (ByteArray) -> T): T {
        val retained =
            storage ?: throw ReallyMeZkProviderException(ZkProviderFailureReason.CLEANUP_FAILED)
        val copy = retained.copyOf()
        return try {
            block(copy)
        } finally {
            copy.fill(0)
        }
    }

    @Synchronized
    override fun close() {
        storage?.fill(0)
        storage = null
    }

    override fun toString(): String = "ZkSensitiveBytes(<redacted>)"
}

public interface ReallyMeZkProvider<WitnessHandle : Any, ProofHandle : Any> {
    public fun generateWitness(request: ZkStageRequest): ZkProviderWitnessResult<WitnessHandle>

    /**
     * Proves from a retained witness. A successful return consumes the witness
     * handle; callers must only call releaseWitness when this method fails
     * before ownership is transferred.
     */
    public fun prove(
        request: ZkStageRequest,
        witness: WitnessHandle,
    ): ZkProviderProofResult<ProofHandle>

    /**
     * Verifies one diagnostic stage proof against its typed public binding.
     *
     * This is intentionally stage-scoped. A successful return is useful for
     * SDK demos, fixture validation, and backend diagnostics, but it is not a
     * production presentation decision. Verifiers that accept a ReallyMe ZK
     * presentation must validate joined credential validity/current status and
     * issuer, audience, nonce, transaction-data, and expiry policy, then atomically
     * consume its session. A
     * standalone credential-envelope stage result must never grant claim
     * admission by itself.
     */
    public fun verifyDiagnosticStage(
        request: ZkStageVerifyRequest,
        proof: ProofHandle,
    ): Boolean

    public fun releaseWitness(witness: WitnessHandle)
}

public object UnsupportedReallyMeZkProvider :
    ReallyMeZkProvider<UnsupportedWitnessHandle, UnsupportedProofHandle> {
    override fun generateWitness(request: ZkStageRequest): UnsupportedWitnessResult = providerUnavailable()

    override fun prove(
        request: ZkStageRequest,
        witness: UnsupportedWitnessHandle,
    ): UnsupportedProofResult = providerUnavailable()

    override fun verifyDiagnosticStage(
        request: ZkStageVerifyRequest,
        proof: UnsupportedProofHandle,
    ): Boolean = providerUnavailable()

    override fun releaseWitness(witness: UnsupportedWitnessHandle): Unit = providerUnavailable()
}

public object UnsupportedReallyMeZkPresentationBoundClaimBundleVerifier :
    ReallyMeZkPresentationBoundClaimBundleVerifier<UnsupportedClaimProofBundleHandle> {
    override fun verifyPresentationBoundClaimBundle(
        request: ZkPresentationBoundClaimBundleVerifyRequest,
        claimProofBundle: UnsupportedClaimProofBundleHandle,
    ): ZkPresentationBoundClaimBundleVerification = providerUnavailable()
}

public object UnsupportedReallyMeZkStatusQualifiedClaimBundleVerifier :
    ReallyMeZkStatusQualifiedClaimBundleVerifier<UnsupportedStatusQualifiedClaimProofBundleHandle> {
    override fun verifyStatusQualifiedClaimBundle(
        request: ZkStatusQualifiedClaimBundleVerifyRequest,
        statusQualifiedClaimProofBundle: UnsupportedStatusQualifiedClaimProofBundleHandle,
    ): ZkStatusQualifiedClaimBundleVerification = providerUnavailable()
}

public object UnsupportedReallyMeZkClaimProofBundleProvider :
    ReallyMeZkClaimProofBundleProvider<
        UnsupportedWitnessHandle,
        UnsupportedProofHandle,
        UnsupportedClaimProofBundleHandle,
    >,
    ReallyMeZkStatusQualifiedClaimBundleVerifier<UnsupportedStatusQualifiedClaimProofBundleHandle> {
    override fun generateWitness(request: ZkStageRequest): UnsupportedWitnessResult = providerUnavailable()

    override fun prove(
        request: ZkStageRequest,
        witness: UnsupportedWitnessHandle,
    ): UnsupportedProofResult = providerUnavailable()

    override fun verifyDiagnosticStage(
        request: ZkStageVerifyRequest,
        proof: UnsupportedProofHandle,
    ): Boolean = providerUnavailable()

    override fun releaseWitness(witness: UnsupportedWitnessHandle): Unit = providerUnavailable()

    override fun proveClaimProofBundle(
        request: ZkClaimProofBundleProveRequest,
        witnesses: List<UnsupportedWitnessHandle>,
    ): UnsupportedClaimProofBundleResult = providerUnavailable()

    override fun verifyPresentationBoundClaimBundle(
        request: ZkPresentationBoundClaimBundleVerifyRequest,
        claimProofBundle: UnsupportedClaimProofBundleHandle,
    ): ZkPresentationBoundClaimBundleVerification = providerUnavailable()

    override fun verifyStatusQualifiedClaimBundle(
        request: ZkStatusQualifiedClaimBundleVerifyRequest,
        statusQualifiedClaimProofBundle: UnsupportedStatusQualifiedClaimProofBundleHandle,
    ): ZkStatusQualifiedClaimBundleVerification = providerUnavailable()
}

public object UnsupportedWitnessHandle

public object UnsupportedProofHandle

public object UnsupportedClaimProofBundleHandle

public object UnsupportedStatusQualifiedClaimProofBundleHandle

public typealias UnsupportedWitnessResult = ZkProviderWitnessResult<UnsupportedWitnessHandle>

public typealias UnsupportedProofResult = ZkProviderProofResult<UnsupportedProofHandle>

public typealias UnsupportedClaimProofBundleResult =
    ZkProviderClaimProofBundleResult<UnsupportedClaimProofBundleHandle>

internal fun validateByteCount(
    value: Int,
    maximum: Int,
) {
    if (value <= 0) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.EMPTY_BUFFER)
    }
    if (value > maximum) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.OVERSIZED_BUFFER)
    }
}

private fun providerUnavailable(): Nothing = throw providerUnavailableException

private val providerUnavailableException: ReallyMeZkProviderException
    get() = ReallyMeZkProviderException(ZkProviderFailureReason.PROVIDER_UNAVAILABLE)

// Keep this aligned with the Rust API boundary. Current exact-source
// claim_bundle_4 witnesses can exceed one MiB after Noir serialization.
private const val MAX_WITNESS_BYTES = 4 * 1_024 * 1_024
private const val MAX_VERIFICATION_KEY_BYTES = 16_777_216
private const val MAX_PUBLIC_INPUT_BYTES = 4 * 1_024
internal const val MAX_PROOF_BYTES = 256 * 1_024
internal const val PRODUCTION_STAGE_COUNT = 4
internal const val MAX_PRESENTATION_LIFETIME_SECONDS = 300L
