// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.shared

import me.really.zk.ReallyMeZk
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.ZkProviderProofResult
import me.really.zk.ZkProviderWitnessResult
import me.really.zk.ZkStageRequest
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ReallyMeZkClaimProofBundleProvider
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleProveRequest
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerification
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerifyRequest
import me.really.zk.claimbundle.ZkProviderClaimProofBundleResult
import me.really.zk.displayName
import me.really.zk.fixturePrefix
import me.really.zk.label
import reallyme.zk.v1.Manifest
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.system.measureNanoTime

public data class ZkSampleResult(
    public val bundleKind: ZkClaimProofBundleKind,
    public val verificationKeySize: Int,
    public val publicInputsSize: Int,
    public val proofSize: Int,
    public val witnessMilliseconds: Double,
    public val proveMilliseconds: Double,
    public val verifyMilliseconds: Double,
    public val fixtureBundleVerified: Boolean,
)

private typealias WitnessInputProvider =
    (ZkClaimProofBundleKind, ZkCredentialHashAlgorithm, ZkClaimProofBundleStage) -> Manifest.ZkStageWitnessInput

private typealias BundleVerifyRequestProvider =
    (ZkClaimProofBundleKind, ZkCredentialHashAlgorithm) -> ZkPresentationBoundClaimBundleVerifyRequest

private typealias TimedBundleProof<ClaimProofBundleHandle> =
    TimedValue<ZkProviderClaimProofBundleResult<ClaimProofBundleHandle>>

/**
 * Runs the sample app proof flow through the production proof bundle boundary.
 *
 * The demo still shows per-stage witness progress, but the success decision is
 * made by verifyPresentationBoundClaimBundle with independent verifier policy.
 * This fixture flow establishes presentation evidence, not credential acceptance
 * or single-use enforcement for live sessions.
 */
public class ReallyMeZkSampleRunner<WitnessHandle : Any, ProofHandle : Any, ClaimProofBundleHandle : Any>(
    private val provider: ReallyMeZkClaimProofBundleProvider<WitnessHandle, ProofHandle, ClaimProofBundleHandle>,
    private val bundleVerifyRequestProvider: BundleVerifyRequestProvider,
    private val witnessInputProvider: WitnessInputProvider =
        { _, _, _ ->
            Manifest.ZkStageWitnessInput.getDefaultInstance()
        },
) {
    private val singleFlight: AtomicBoolean = AtomicBoolean(false)

    public fun runFlow(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm =
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        progress: (String) -> Unit = {},
    ): ZkSampleResult {
        checkCancellation()
        validateBundleKind(bundleKind)
        if (!singleFlight.compareAndSet(false, true)) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        try {
            return runFlowImpl(bundleKind, credentialHashAlgorithm, progress)
        } finally {
            singleFlight.set(false)
        }
    }

    private fun runFlowImpl(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
        progress: (String) -> Unit,
    ): ZkSampleResult {
        val totalProgressSteps = checkedAdd(ReallyMeZk.stages.size, BUNDLE_OPERATION_COUNT)
        var state = SampleRunState.empty()
        val witnesses = mutableListOf<WitnessHandle>()
        emitProgress(
            progress,
            "UI_STATUS|Starting ${bundleKind.displayName} ${credentialHashAlgorithm.fixturePrefix} proof flow.",
        )

        val verifyRequest =
            withWitnessCleanup(provider, witnesses) {
                val request = bundleVerifyRequest(bundleKind, credentialHashAlgorithm)
                for (stage in ReallyMeZk.stages) {
                    state =
                        generateStageWitness(
                            StageRunInput(
                                bundleKind = bundleKind,
                                credentialHashAlgorithm = credentialHashAlgorithm,
                                stage = stage,
                                state = state,
                                totalProgressSteps = totalProgressSteps,
                                progress = progress,
                            ),
                            witnesses,
                        )
                }
                request
            }

        val bundle =
            withWitnessCleanup(provider, witnesses) {
                checkCancellation()
                proveClaimProofBundle(
                    BundleProveInput(
                        bundleKind = bundleKind,
                        credentialHashAlgorithm = credentialHashAlgorithm,
                        verifyRequest = verifyRequest,
                        witnesses = witnesses,
                        progress = progress,
                    ),
                )
            }
        state = recordBundleProofStep(state, totalProgressSteps, progress, bundle)
        checkCancellation()
        val verified = verifyPresentationBoundClaimBundle(verifyRequest, bundle.value.handle, progress)
        state =
            verified.value.use {
                recordClaimProofBundleVerificationStep(
                    ClaimProofBundleVerificationStepInput(
                        bundleKind = bundleKind,
                        request = verifyRequest,
                        state = state,
                        totalProgressSteps = totalProgressSteps,
                        progress = progress,
                        verified = verified,
                    ),
                )
            }

        return buildSampleResult(bundleKind, state.metrics)
    }

    private fun generateStageWitness(
        input: StageRunInput,
        witnesses: MutableList<WitnessHandle>,
    ): SampleRunState {
        checkCancellation()
        validateStage(input.stage)
        val request =
            ZkStageRequest(
                input.bundleKind,
                input.credentialHashAlgorithm,
                input.stage,
                witnessInputProvider(input.bundleKind, input.credentialHashAlgorithm, input.stage),
            )
        val context = StageRunContext(request, input.stage, input.totalProgressSteps, input.progress)
        val witness = generateWitness(context)
        witnesses.add(witness.value.handle)
        return recordWitnessStep(input.state, context, witness)
    }

    private fun bundleVerifyRequest(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    ): ZkPresentationBoundClaimBundleVerifyRequest =
        try {
            bundleVerifyRequestProvider(bundleKind, credentialHashAlgorithm)
        } catch (error: ReallyMeZkProviderException) {
            throw error
        } catch (ignored: RuntimeException) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }

    private fun generateWitness(context: StageRunContext): TimedValue<ZkProviderWitnessResult<WitnessHandle>> {
        emitProgress(context.progress, "UI_STATUS|Generating ${context.stage.label} witness.")
        val witness = measureProviderCall { provider.generateWitness(context.request) }
        emitProgress(
            context.progress,
            "UI_METRIC|${context.stage.label}|$METRIC_OPERATION_WITNESS|${witness.milliseconds}",
        )
        return witness
    }

    private fun recordWitnessStep(
        state: SampleRunState,
        context: StageRunContext,
        witness: TimedValue<ZkProviderWitnessResult<WitnessHandle>>,
    ): SampleRunState {
        val nextStep = checkedAdd(state.progressStep, 1)
        emitProgress(
            context.progress,
            "UI_PROGRESS|$nextStep|${context.totalProgressSteps}|Generated ${context.stage.label} witness.",
        )
        return state.copy(
            progressStep = nextStep,
            metrics = state.metrics.withWitness(witness.milliseconds),
        )
    }

    private fun proveClaimProofBundle(
        input: BundleProveInput<WitnessHandle>,
    ): TimedBundleProof<ClaimProofBundleHandle> {
        emitProgress(input.progress, "UI_STATUS|Proving proof bundle.")
        val proveRequest =
            ZkClaimProofBundleProveRequest(
                bundleKind = input.bundleKind,
                credentialHashAlgorithm = input.credentialHashAlgorithm,
                sessionBinding = input.verifyRequest.expectedSessionBinding,
            )
        val bundle =
            measureProviderCall {
                provider.proveClaimProofBundle(proveRequest, input.witnesses)
            }
        emitProgress(
            input.progress,
            "UI_METRIC|bundle|$METRIC_OPERATION_PROVE|${bundle.milliseconds}",
        )
        return bundle
    }

    private fun recordBundleProofStep(
        state: SampleRunState,
        totalProgressSteps: Int,
        progress: (String) -> Unit,
        bundle: TimedValue<ZkProviderClaimProofBundleResult<ClaimProofBundleHandle>>,
    ): SampleRunState {
        val nextStep = checkedAdd(state.progressStep, 1)
        emitProgress(
            progress,
            "UI_PROGRESS|$nextStep|$totalProgressSteps|Generated proof bundle.",
        )
        return state.copy(
            progressStep = nextStep,
            metrics = state.metrics.withBundleProof(bundle),
        )
    }

    private fun verifyPresentationBoundClaimBundle(
        request: ZkPresentationBoundClaimBundleVerifyRequest,
        claimProofBundle: ClaimProofBundleHandle,
        progress: (String) -> Unit,
    ): TimedValue<ZkPresentationBoundClaimBundleVerification> {
        emitProgress(progress, "UI_STATUS|Verifying proof bundle.")
        val verified = measureProviderCall { provider.verifyPresentationBoundClaimBundle(request, claimProofBundle) }
        emitProgress(
            progress,
            "UI_METRIC|bundle|$METRIC_OPERATION_VERIFY|${verified.milliseconds}",
        )
        return verified
    }

    private fun recordClaimProofBundleVerificationStep(input: ClaimProofBundleVerificationStepInput): SampleRunState {
        checkCancellation()
        if (input.verified.value.bundleKind != input.bundleKind ||
            input.verified.value.verifiedStageCount != ReallyMeZk.stages.size ||
            input.verified.value.sessionBinding != input.request.expectedSessionBinding
        ) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
        }
        val nextStep = checkedAdd(input.state.progressStep, 1)
        emitProgress(
            input.progress,
            "UI_PROGRESS|$nextStep|${input.totalProgressSteps}|Bundle verified.",
        )
        return input.state.copy(
            progressStep = nextStep,
            metrics = input.state.metrics.withVerify(input.verified.milliseconds),
        )
    }
}

private fun buildSampleResult(
    bundleKind: ZkClaimProofBundleKind,
    metrics: SampleMetrics,
): ZkSampleResult =
    ZkSampleResult(
        bundleKind = bundleKind,
        verificationKeySize = metrics.verificationKeySize,
        publicInputsSize = metrics.publicInputsSize,
        proofSize = metrics.proofSize,
        witnessMilliseconds = metrics.witnessMilliseconds,
        proveMilliseconds = metrics.proveMilliseconds,
        verifyMilliseconds = metrics.verifyMilliseconds,
        fixtureBundleVerified = true,
    )

private class StageRunContext(
    val request: ZkStageRequest,
    val stage: ZkClaimProofBundleStage,
    val totalProgressSteps: Int,
    val progress: (String) -> Unit,
)

private class StageRunInput(
    val bundleKind: ZkClaimProofBundleKind,
    val credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    val stage: ZkClaimProofBundleStage,
    val state: SampleRunState,
    val totalProgressSteps: Int,
    val progress: (String) -> Unit,
)

private class BundleProveInput<WitnessHandle : Any>(
    val bundleKind: ZkClaimProofBundleKind,
    val credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    val verifyRequest: ZkPresentationBoundClaimBundleVerifyRequest,
    val witnesses: List<WitnessHandle>,
    val progress: (String) -> Unit,
)

private class ClaimProofBundleVerificationStepInput(
    val bundleKind: ZkClaimProofBundleKind,
    val request: ZkPresentationBoundClaimBundleVerifyRequest,
    val state: SampleRunState,
    val totalProgressSteps: Int,
    val progress: (String) -> Unit,
    val verified: TimedValue<ZkPresentationBoundClaimBundleVerification>,
)

private data class SampleMetrics(
    val verificationKeySize: Int,
    val publicInputsSize: Int,
    val proofSize: Int,
    val witnessMilliseconds: Double,
    val proveMilliseconds: Double,
    val verifyMilliseconds: Double,
) {
    fun withWitness(ms: Double): SampleMetrics = copy(witnessMilliseconds = witnessMilliseconds + ms)

    fun <ClaimProofBundleHandle : Any> withBundleProof(
        bundle: TimedBundleProof<ClaimProofBundleHandle>,
    ): SampleMetrics =
        copy(
            proofSize = bundle.value.metrics.proofByteCount,
            proveMilliseconds = proveMilliseconds + bundle.milliseconds,
        )

    fun <ProofHandle : Any> withProof(proof: TimedValue<ZkProviderProofResult<ProofHandle>>): SampleMetrics =
        copy(
            publicInputsSize = checkedAdd(publicInputsSize, proof.value.metrics.publicInputByteCount),
            proofSize = checkedAdd(proofSize, proof.value.metrics.proofByteCount),
            proveMilliseconds = proveMilliseconds + proof.milliseconds,
        )

    fun withVerify(ms: Double): SampleMetrics = copy(verifyMilliseconds = verifyMilliseconds + ms)

    companion object {
        fun empty(): SampleMetrics =
            SampleMetrics(
                verificationKeySize = 0,
                publicInputsSize = 0,
                proofSize = 0,
                witnessMilliseconds = 0.0,
                proveMilliseconds = 0.0,
                verifyMilliseconds = 0.0,
            )
    }
}

private data class SampleRunState(
    val progressStep: Int,
    val metrics: SampleMetrics,
) {
    companion object {
        fun empty(): SampleRunState = SampleRunState(0, SampleMetrics.empty())
    }
}

private fun checkedAdd(
    left: Int,
    right: Int,
): Int {
    val value = left.toLong() + right.toLong()
    if (value > Int.MAX_VALUE) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.ARITHMETIC_OVERFLOW)
    }
    return value.toInt()
}

private data class TimedValue<Value : Any>(
    val value: Value,
    val milliseconds: Double,
)

private fun <Value : Any> measureProviderCall(operation: () -> Value): TimedValue<Value> {
    var output: Value? = null
    val elapsedNanos =
        measureNanoTime {
            output = operation()
        }
    val value =
        output ?: throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
    return TimedValue(value, elapsedNanos.toDouble() / NANOS_PER_MILLISECOND)
}

private inline fun <WitnessHandle : Any, Value> withWitnessCleanup(
    provider: ReallyMeZkClaimProofBundleProvider<WitnessHandle, *, *>,
    witnesses: List<WitnessHandle>,
    operation: () -> Value,
): Value {
    val result = runCatching { operation() }
    val failure = result.exceptionOrNull()
    if (failure != null) {
        releaseRetainedWitnesses(provider, witnesses, failure)
    }
    return result.getOrThrow()
}

private fun <WitnessHandle : Any> releaseRetainedWitnesses(
    provider: ReallyMeZkClaimProofBundleProvider<WitnessHandle, *, *>,
    witnesses: List<WitnessHandle>,
    primary: Throwable,
) {
    for (witness in witnesses) {
        val cleanup = runCatching { provider.releaseWitness(witness) }
        val cleanupFailure = cleanup.exceptionOrNull()
        if (cleanupFailure != null) {
            primary.addSuppressed(cleanupFailure)
        }
    }
}

private fun emitProgress(
    progress: (String) -> Unit,
    line: String,
) {
    if (runCatching { progress(line) }.isFailure) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
    }
}

private fun checkCancellation() {
    if (Thread.interrupted()) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.OPERATION_CANCELLED)
    }
}

private fun validateBundleKind(bundleKind: ZkClaimProofBundleKind) {
    when (bundleKind) {
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
        -> Unit

        else -> throw ReallyMeZkProviderException(ZkProviderFailureReason.UNSUPPORTED_CIRCUIT)
    }
}

private fun validateStage(stage: ZkClaimProofBundleStage) {
    when (stage) {
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE,
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT,
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM,
        -> Unit

        else -> throw ReallyMeZkProviderException(ZkProviderFailureReason.UNSUPPORTED_CIRCUIT)
    }
}

private const val BUNDLE_OPERATION_COUNT = 2
private const val METRIC_OPERATION_WITNESS = "witness"
private const val METRIC_OPERATION_PROVE = "prove"
private const val METRIC_OPERATION_VERIFY = "verify"
private const val NANOS_PER_MILLISECOND = 1_000_000.0
