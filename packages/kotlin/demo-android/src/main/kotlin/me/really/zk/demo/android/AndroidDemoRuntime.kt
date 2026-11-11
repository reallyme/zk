// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.content.Context
import android.util.Log
import me.really.zk.ReallyMeZkNativeProvider
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerifyRequest
import me.really.zk.commonroot.ZkCommonCredentialRootPersonaMode
import me.really.zk.commonroot.ZkCommonCredentialRootVerifyRequest
import me.really.zk.demo.shared.ReallyMeZkDemoFixtureWitnessInputs
import me.really.zk.demo.shared.ReallyMeZkDemoVerifierPolicy
import me.really.zk.demo.shared.ReallyMeZkSampleRunner
import me.really.zk.demo.shared.ZkSampleResult
import reallyme.zk.v1.Manifest

// Each sample flow has a separate entry point so the UI never selects a circuit by string.
internal class AndroidDemoRuntime(
    context: Context,
) {
    private val assets = AndroidDemoAssetStore(context)
    private val personaCredentialEvidenceRuntime = AndroidDemoPersonaCredentialEvidenceRuntime(assets)

    fun runFlow(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm =
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        progress: (String) -> Unit,
    ): ZkSampleResult = runFlowWithVerifyRequest(bundleKind, credentialHashAlgorithm, progress, ::expectedVerifyRequest)

    fun preparePersonaSample(
        mode: ZkCommonCredentialRootPersonaMode,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    ): PersonaCredentialEvidenceSampleProofs =
        personaCredentialEvidenceRuntime.prepareSample(mode, credentialHashAlgorithm)

    fun verifyCachedPersonaCredentialEvidenceStages(proofs: PersonaCredentialEvidenceSampleProofs): Double =
        personaCredentialEvidenceRuntime.verifyCachedStages(proofs)

    fun verifyCommonCredentialRootSample(
        mode: ZkCommonCredentialRootPersonaMode,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    ): CommonCredentialRootSampleResult {
        val request = assets.commonCredentialRootVerifyRequest(mode, credentialHashAlgorithm)
        val handle = assets.createContext()
        var result: CommonCredentialRootSampleResult? = null
        var primaryFailure: ReallyMeZkProviderException? = null
        try {
            val provider = ReallyMeZkNativeProvider(handle)
            val started = System.nanoTime()
            val verified = provider.verifyCommonCredentialRoot(request)
            val elapsedMilliseconds = (System.nanoTime() - started).toDouble() / NANOS_PER_MILLISECOND
            result = CommonCredentialRootSampleResult(verified.verifiedProofCount, elapsedMilliseconds)
        } catch (error: ReallyMeZkProviderException) {
            primaryFailure = error
        } catch (ignored: RuntimeException) {
            primaryFailure = ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        val cleanupFailure = destroyAndroidDemoContext(handle)
        return resolveCommonCredentialRootOutcome(result, primaryFailure, cleanupFailure)
    }

    fun generateCommonCredentialRootSample(
        mode: ZkCommonCredentialRootPersonaMode,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
        progress: (Int) -> Unit,
    ): CommonCredentialRootSampleResult {
        val prepared = assets.commonCredentialRootVerifyRequest(mode, credentialHashAlgorithm)
        val handle = assets.createContext()
        var result: CommonCredentialRootSampleResult? = null
        var primaryFailure: ReallyMeZkProviderException? = null
        try {
            val provider = ReallyMeZkNativeProvider(handle)
            val proofSet = proveCommonCredentialRootStages(provider, prepared, mode, credentialHashAlgorithm, progress)
            val presentation = prepared.presentation.withProofs(proofSet.proofs)
            val request = ZkCommonCredentialRootVerifyRequest(mode, presentation, prepared.policy)
            val verifyStarted = System.nanoTime()
            val verified = provider.verifyCommonCredentialRoot(request)
            val verificationMilliseconds = (System.nanoTime() - verifyStarted).toDouble() / NANOS_PER_MILLISECOND
            result =
                CommonCredentialRootSampleResult(
                    verified.verifiedProofCount,
                    verificationMilliseconds,
                    proofSet.generationMilliseconds,
                )
        } catch (error: ReallyMeZkProviderException) {
            primaryFailure = error
        } catch (ignored: RuntimeException) {
            primaryFailure = ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        val cleanupFailure = destroyAndroidDemoContext(handle)
        return resolveCommonCredentialRootOutcome(result, primaryFailure, cleanupFailure)
    }

    fun generateCommonCredentialRootSampleAndRejectAlteredSession(
        mode: ZkCommonCredentialRootPersonaMode,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
        progress: (Int) -> Unit,
    ): CommonCredentialRootSessionNegativeResult {
        val prepared = assets.commonCredentialRootVerifyRequest(mode, credentialHashAlgorithm)
        val handle = assets.createContext()
        var result: CommonCredentialRootSessionNegativeResult? = null
        var primaryFailure: ReallyMeZkProviderException? = null
        try {
            val provider = ReallyMeZkNativeProvider(handle)
            val proofSet = proveCommonCredentialRootStages(provider, prepared, mode, credentialHashAlgorithm, progress)
            val presentation = prepared.presentation.withProofs(proofSet.proofs)
            val verification = verifyCommonCredentialRootPresentation(provider, mode, presentation, prepared.policy)
            result =
                rejectAlteredCommonCredentialRootSession(
                    CommonCredentialRootRejectionContext(
                        provider = provider,
                        mode = mode,
                        presentation = presentation,
                        policy = prepared.policy,
                        acceptedProofCount = verification.verifiedProofCount,
                        verificationMilliseconds = verification.elapsedMilliseconds,
                        generationMilliseconds = proofSet.generationMilliseconds,
                    ),
                )
        } catch (error: ReallyMeZkProviderException) {
            primaryFailure = error
        } catch (ignored: RuntimeException) {
            primaryFailure = ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        val cleanupFailure = destroyAndroidDemoContext(handle)
        return resolveCommonCredentialRootOutcome(result, primaryFailure, cleanupFailure)
    }

    fun runFlowWithAlteredExpectedBinding(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm =
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        mutation: AndroidDemoBindingMutation = AndroidDemoBindingMutation.NONCE,
    ): ZkSampleResult =
        runFlowWithVerifyRequest(bundleKind, credentialHashAlgorithm, {}) { flowBundleKind, circuitHash ->
            val request = expectedVerifyRequest(flowBundleKind, circuitHash)
            ZkPresentationBoundClaimBundleVerifyRequest(
                expectedSessionBinding = alteredBinding(request.expectedSessionBinding, mutation),
                trustedIssuers = request.trustedIssuers,
                verificationTimeUnix = request.verificationTimeUnix,
            )
        }

    private fun runFlowWithVerifyRequest(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
        progress: (String) -> Unit,
        bundleVerifyRequestProvider: (
            ZkClaimProofBundleKind,
            ZkCredentialHashAlgorithm,
        ) -> ZkPresentationBoundClaimBundleVerifyRequest,
    ): ZkSampleResult {
        val handle = assets.createContext()
        val outcome =
            runProviderFlow(handle, bundleKind, credentialHashAlgorithm, progress, bundleVerifyRequestProvider)
        val cleanupFailure = destroyAndroidDemoContext(handle)
        return resolveRunOutcome(outcome.result, outcome.primaryFailure, cleanupFailure)
    }

    private fun runProviderFlow(
        handle: Long,
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
        progress: (String) -> Unit,
        bundleVerifyRequestProvider: (
            ZkClaimProofBundleKind,
            ZkCredentialHashAlgorithm,
        ) -> ZkPresentationBoundClaimBundleVerifyRequest,
    ): AndroidDemoRunOutcome {
        var result: ZkSampleResult? = null
        var primaryFailure: ReallyMeZkProviderException? = null
        try {
            val provider = ReallyMeZkNativeProvider(handle)
            val runner =
                ReallyMeZkSampleRunner(
                    provider = provider,
                    bundleVerifyRequestProvider = bundleVerifyRequestProvider,
                    witnessInputProvider = { flowBundleKind, circuitHash, stage ->
                        val input = assets.fixtureWitnessInput(flowBundleKind, circuitHash, stage)
                        if (stage == ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION) {
                            ReallyMeZkDemoVerifierPolicy.validateReviewedFixtureSession(
                                ReallyMeZkDemoFixtureWitnessInputs.sessionBinding(input),
                            )
                        } else if (stage == ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE) {
                            ReallyMeZkDemoVerifierPolicy.validateReviewedFixtureIssuer(
                                ReallyMeZkDemoFixtureWitnessInputs.issuer(input),
                            )
                        }
                        input
                    },
                )
            result = runner.runFlow(bundleKind, credentialHashAlgorithm, progress)
        } catch (error: ReallyMeZkProviderException) {
            primaryFailure = error
        } catch (ignored: RuntimeException) {
            primaryFailure = ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        return AndroidDemoRunOutcome(result, primaryFailure)
    }

    private fun proveCommonCredentialRootStages(
        provider: ReallyMeZkNativeProvider,
        prepared: ZkCommonCredentialRootVerifyRequest,
        mode: ZkCommonCredentialRootPersonaMode,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
        progress: (Int) -> Unit,
    ): CommonCredentialRootProofSet {
        val proofs = ArrayList<Manifest.ZkCommonCredentialRootRawProofPackage>(COMMON_CREDENTIAL_ROOT_STAGE_COUNT)
        val started = System.nanoTime()
        for (slot in 0 until COMMON_CREDENTIAL_ROOT_STAGE_COUNT) {
            val stage = assets.commonCredentialRootStageRequest(mode, credentialHashAlgorithm, slot)
            val proof =
                try {
                    if (stage.operation.expectedBinding != prepared.presentation.sessionBinding) {
                        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
                    }
                    provider.proveCommonCredentialRootStage(stage).proofPackage
                } catch (error: ReallyMeZkProviderException) {
                    Log.e(
                        COMMON_CREDENTIAL_ROOT_PROVE_EVIDENCE_TAG,
                        "commonCredentialRootStageProveFailed mode=$mode hash=${credentialHashAlgorithm.name} " +
                            "slot=$slot reason=${error.reason}",
                    )
                    throw error
                } finally {
                    stage.close()
                }
            proofs.add(proof)
            progress(slot + 1)
        }
        val generationMilliseconds = (System.nanoTime() - started).toDouble() / NANOS_PER_MILLISECOND
        return CommonCredentialRootProofSet(proofs, generationMilliseconds)
    }

    private fun expectedVerifyRequest(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    ): ZkPresentationBoundClaimBundleVerifyRequest {
        val sessionInput =
            assets.fixtureWitnessInput(
                bundleKind,
                credentialHashAlgorithm,
                ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
            )
        ReallyMeZkDemoVerifierPolicy.validateReviewedFixtureSession(
            ReallyMeZkDemoFixtureWitnessInputs.sessionBinding(sessionInput),
        )
        return ReallyMeZkDemoVerifierPolicy.bundleVerifyRequest()
    }
}

private fun Manifest.ZkCommonCredentialRootPresentation.withProofs(
    proofs: List<Manifest.ZkCommonCredentialRootRawProofPackage>,
): Manifest.ZkCommonCredentialRootPresentation =
    toBuilder()
        .clearProofs()
        .addAllProofs(proofs)
        .build()

private fun verifyCommonCredentialRootPresentation(
    provider: ReallyMeZkNativeProvider,
    mode: ZkCommonCredentialRootPersonaMode,
    presentation: Manifest.ZkCommonCredentialRootPresentation,
    policy: Manifest.ZkCommonCredentialRootJoinPolicy,
): CommonCredentialRootVerificationTiming {
    val verifyStarted = System.nanoTime()
    val verified = provider.verifyCommonCredentialRoot(ZkCommonCredentialRootVerifyRequest(mode, presentation, policy))
    val verificationMilliseconds = (System.nanoTime() - verifyStarted).toDouble() / NANOS_PER_MILLISECOND
    return CommonCredentialRootVerificationTiming(verified.verifiedProofCount, verificationMilliseconds)
}

private fun rejectAlteredCommonCredentialRootSession(
    context: CommonCredentialRootRejectionContext,
): CommonCredentialRootSessionNegativeResult {
    val alteredBinding = alteredBinding(context.presentation.sessionBinding, AndroidDemoBindingMutation.NONCE)
    val alteredPresentation =
        context.presentation
            .toBuilder()
            .setSessionBinding(alteredBinding)
            .build()
    val alteredPolicy =
        context.policy
            .toBuilder()
            .setChallenge(alteredBinding.nonceHash)
            .build()
    val rejectionStarted = System.nanoTime()
    try {
        context.provider.verifyCommonCredentialRoot(
            ZkCommonCredentialRootVerifyRequest(context.mode, alteredPresentation, alteredPolicy),
        )
    } catch (error: ReallyMeZkProviderException) {
        return alteredSessionRejection(error, context, rejectionStarted)
    }
    throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
}

private fun alteredSessionRejection(
    error: ReallyMeZkProviderException,
    context: CommonCredentialRootRejectionContext,
    rejectionStarted: Long,
): CommonCredentialRootSessionNegativeResult {
    if (error.reason != ZkProviderFailureReason.PROOF_REJECTED) {
        throw error
    }
    val rejectionMilliseconds = (System.nanoTime() - rejectionStarted).toDouble() / NANOS_PER_MILLISECOND
    return CommonCredentialRootSessionNegativeResult(
        acceptedProofCount = context.acceptedProofCount,
        rejectedAlteredSession = true,
        rejectionReason = error.reason,
        verificationMilliseconds = context.verificationMilliseconds,
        rejectionMilliseconds = rejectionMilliseconds,
        generationMilliseconds = context.generationMilliseconds,
    )
}

internal data class CommonCredentialRootSampleResult(
    val verifiedProofCount: Int,
    val verificationMilliseconds: Double,
    val generationMilliseconds: Double = 0.0,
)

internal data class CommonCredentialRootSessionNegativeResult(
    val acceptedProofCount: Int,
    val rejectedAlteredSession: Boolean,
    val rejectionReason: ZkProviderFailureReason,
    val verificationMilliseconds: Double,
    val rejectionMilliseconds: Double,
    val generationMilliseconds: Double,
)

private data class CommonCredentialRootProofSet(
    val proofs: List<Manifest.ZkCommonCredentialRootRawProofPackage>,
    val generationMilliseconds: Double,
)

private data class CommonCredentialRootVerificationTiming(
    val verifiedProofCount: Int,
    val elapsedMilliseconds: Double,
)

private data class CommonCredentialRootRejectionContext(
    val provider: ReallyMeZkNativeProvider,
    val mode: ZkCommonCredentialRootPersonaMode,
    val presentation: Manifest.ZkCommonCredentialRootPresentation,
    val policy: Manifest.ZkCommonCredentialRootJoinPolicy,
    val acceptedProofCount: Int,
    val verificationMilliseconds: Double,
    val generationMilliseconds: Double,
)

private const val NANOS_PER_MILLISECOND = 1_000_000.0
private const val COMMON_CREDENTIAL_ROOT_STAGE_COUNT = 9

private data class AndroidDemoRunOutcome(
    val result: ZkSampleResult?,
    val primaryFailure: ReallyMeZkProviderException?,
)

internal fun resolveRunOutcome(
    result: ZkSampleResult?,
    primaryFailure: ReallyMeZkProviderException?,
    cleanupFailure: ReallyMeZkProviderException?,
): ZkSampleResult =
    when {
        cleanupFailure != null -> failDemoRun(cleanupFailure)
        primaryFailure != null -> failDemoRun(primaryFailure)
        result != null -> result
        else -> failDemoRun(ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE))
    }

internal fun <Result : Any> resolveCommonCredentialRootOutcome(
    result: Result?,
    primaryFailure: ReallyMeZkProviderException?,
    cleanupFailure: ReallyMeZkProviderException?,
): Result =
    when {
        primaryFailure != null -> {
            if (cleanupFailure != null) {
                primaryFailure.addSuppressed(cleanupFailure)
            }
            failDemoRun(primaryFailure)
        }
        cleanupFailure != null -> failDemoRun(cleanupFailure)
        result != null -> result
        else -> failDemoRun(ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE))
    }

private fun failDemoRun(error: ReallyMeZkProviderException): Nothing = throw error

private const val COMMON_CREDENTIAL_ROOT_PROVE_EVIDENCE_TAG = "ReallyMeZKCommonCredentialRoot"
