// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.shared

import com.google.protobuf.ByteString
import me.really.zk.ReallyMeZk
import me.really.zk.ReallyMeZkNativeProvider
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProofMetrics
import me.really.zk.ZkProviderFailureReason
import me.really.zk.ZkProviderProofResult
import me.really.zk.ZkProviderWitnessResult
import me.really.zk.ZkSensitiveBytes
import me.really.zk.ZkStageRequest
import me.really.zk.ZkStageVerifyRequest
import me.really.zk.ZkWitnessMetrics
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ReallyMeZkClaimProofBundleProvider
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleMetrics
import me.really.zk.claimbundle.ZkClaimProofBundleProveRequest
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundlePolicyBinding
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleProofShape
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleSensitiveClaim
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerification
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerifyRequest
import me.really.zk.claimbundle.ZkProviderClaimProofBundleResult
import reallyme.zk.v1.Manifest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

private object WitnessHandle

private object ProofHandle

private object ClaimProofBundleHandle

private typealias TestSampleRunner = ReallyMeZkSampleRunner<WitnessHandle, ProofHandle, ClaimProofBundleHandle>

private typealias TestWitnessResult = ZkProviderWitnessResult<WitnessHandle>

class ReallyMeZkSampleRunnerTest {
    @Test
    fun runnerEmitsBundleProgressStepsForSuccessfulProvider() {
        val runner = sampleRunner(StaticProvider)
        val updates = mutableListOf<String>()

        val result =
            runner.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1) {
                updates.add(it)
            }

        assertTrue(result.fixtureBundleVerified)
        assertEquals(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1, result.bundleKind)
        assertEquals(6, updates.count { it.startsWith("UI_PROGRESS|") })
        assertTrue(
            updates.any {
                it == "UI_STATUS|Starting Private Persona sha256 proof flow."
            },
        )
        assertEquals(
            "UI_PROGRESS|6|6|Bundle verified.",
            updates.last { it.startsWith("UI_PROGRESS|") },
        )
    }

    @Test
    fun runnerPassesPoseidon2CredentialHashAlgorithmToEveryProviderOperation() {
        val provider = CredentialHashAlgorithmRecordingProvider()
        val runner = sampleRunner(provider)

        runner.runFlow(
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2,
        )

        assertEquals(5, provider.hashStrategies.size)
        assertTrue(
            provider.hashStrategies.all { credentialHashAlgorithm ->
                credentialHashAlgorithm == ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2
            },
        )
    }

    @Test
    fun unsupportedProviderFailsClosedBeforeProgressCompletion() {
        val runner = sampleRunner(UnsupportedBundleProvider)
        val updates = mutableListOf<String>()

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                runner.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1) {
                    updates.add(it)
                }
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, error.reason)
        assertTrue(updates.any { it == "UI_STATUS|Generating session witness." })
        assertEquals(0, updates.count { it.startsWith("UI_PROGRESS|") })
    }

    @Test
    fun generatedProtoUnspecifiedProfileFailsClosed() {
        val runner = sampleRunner(StaticProvider)

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                runner.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_UNSPECIFIED)
            }

        assertEquals(ZkProviderFailureReason.UNSUPPORTED_CIRCUIT, error.reason)
    }

    @Test
    fun providerMetricsRejectOversizedProofs() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkProofMetrics(
                    verificationKeyByteCount = 1,
                    publicInputByteCount = 1,
                    proofByteCount = 262_145,
                )
            }

        assertEquals(ZkProviderFailureReason.OVERSIZED_BUFFER, error.reason)
    }

    @Test
    fun generatedWitnessesAreReleasedWhenBundleProveFails() {
        val provider = ProveFailingProvider()
        val runner = sampleRunner(provider)

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                runner.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1)
            }

        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
        assertEquals(ReallyMeZk.stages.size, provider.releaseCount)
    }

    @Test
    fun generatedWitnessIsReleasedWhenProviderCrashesBeforeBundleDispatch() {
        val provider = CrashingProveProvider()
        val runner = sampleRunner(provider)

        assertFailsWith<ProviderCrash> {
            runner.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1)
        }

        assertEquals(1, provider.releaseCount)
    }

    @Test
    fun generatedWitnessIsReleasedWhenProgressThrows() {
        val provider = ReleasingStaticProvider()
        val runner = sampleRunner(provider)

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                runner.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1) { line ->
                    if (line == "UI_PROGRESS|1|6|Generated session witness.") {
                        throw ProgressFailure()
                    }
                }
            }

        assertEquals(ZkProviderFailureReason.INTERNAL_FAILURE, error.reason)
        assertEquals(1, provider.releaseCount)
    }

    @Test
    fun interruptionsBetweenOperationsMapToCancellation() {
        val checkpoints =
            listOf(
                CancellationCheckpoint(
                    progressLine = "UI_PROGRESS|1|6|Generated session witness.",
                    expectedReleaseCount = 1,
                ),
                CancellationCheckpoint(
                    progressLine = "UI_PROGRESS|5|6|Generated proof bundle.",
                    expectedReleaseCount = 0,
                ),
            )

        for (checkpoint in checkpoints) {
            val provider = ReleasingStaticProvider()
            val error = runInterruptedFlow(provider, checkpoint.progressLine)

            assertEquals(ZkProviderFailureReason.OPERATION_CANCELLED, error.reason)
            assertEquals(checkpoint.expectedReleaseCount, provider.releaseCount)
        }
    }

    @Test
    fun failedWitnessReleaseIsPreservedOnPrimaryFailure() {
        val provider = ReleaseFailingProvider()
        val runner = sampleRunner(provider)

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                runner.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1)
            }

        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
        assertEquals(1, error.suppressed.size)
        assertEquals(
            ZkProviderFailureReason.INTERNAL_FAILURE,
            (error.suppressed[0] as ReallyMeZkProviderException).reason,
        )
    }

    @Test
    fun uncheckedWitnessReleaseFailureDoesNotStopRemainingReleases() {
        val provider = UncheckedReleaseFailingProvider()
        val runner = sampleRunner(provider)

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                runner.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1)
            }

        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
        assertEquals(2, provider.releaseAttempts)
        assertEquals(1, error.suppressed.size)
        assertTrue(error.suppressed[0] is ReleaseCrash)
    }

    @Test
    fun nativeProviderUsesGeneratedProtoOperationLifecycle() {
        val bridge = RecordingBridge()
        val provider = ReallyMeZkNativeProvider(contextHandle = 7L, bridge = bridge)
        val input =
            Manifest.ZkStageWitnessInput
                .newBuilder()
                .setCredentialSubjectClaimSession(Manifest.ZkCredentialSubjectClaimSessionInput.getDefaultInstance())
                .build()
        val request =
            ZkStageRequest(
                bundleKind = ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                stage = ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                witnessInput = input,
            )

        val witness = provider.generateWitness(request)
        val proof = provider.prove(request, witness.handle)
        val expectedBinding = expectedSessionBinding()
        val verified =
            provider.verifyDiagnosticStage(
                ZkStageVerifyRequest(
                    bundleKind = request.bundleKind,
                    stage = request.stage,
                    expectedSessionBinding = expectedBinding,
                ),
                proof.handle,
            )
        provider.releaseWitness(witness.handle)

        assertTrue(verified)
        assertEquals(listOf(expectedBinding), bridge.verifyExpectedBindings)
        assertNull(witness.metrics.byteCount)
        assertNull(proof.metrics.verificationKeyByteCount)
        assertEquals(
            listOf(
                NativeOperationKind.WITNESS,
                NativeOperationKind.PROVE,
                NativeOperationKind.VERIFY,
                NativeOperationKind.RELEASE,
            ),
            bridge.operationCases,
        )
    }

    @Test
    fun nativeProviderSurfacesRejectedTransactionBindingFromBridge() {
        val bridge = RecordingBridge()
        val provider = ReallyMeZkNativeProvider(contextHandle = 7L, bridge = bridge)
        val input =
            Manifest.ZkStageWitnessInput
                .newBuilder()
                .setCredentialSubjectClaimSession(Manifest.ZkCredentialSubjectClaimSessionInput.getDefaultInstance())
                .build()
        val request =
            ZkStageRequest(
                bundleKind = ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                stage = ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                witnessInput = input,
            )
        val witness = provider.generateWitness(request)
        val proof = provider.prove(request, witness.handle)

        val verified =
            provider.verifyDiagnosticStage(
                ZkStageVerifyRequest(
                    bundleKind = request.bundleKind,
                    stage = request.stage,
                    expectedSessionBinding =
                        expectedSessionBinding(
                            ByteString.copyFrom(ByteArray(32) { 9 }),
                        ),
                ),
                proof.handle,
            )

        assertEquals(false, verified)
        provider.releaseWitness(witness.handle)
    }

    @Test
    fun demoFixtureProtobufsMapEveryProfileStageToGeneratedWitnessInput() {
        for (coordinate in demoFixtureCoordinates()) {
            val data = fixtureData(coordinate.bundleKind, coordinate.credentialHashAlgorithm, coordinate.stage)
            try {
                val input =
                    ReallyMeZkDemoFixtureWitnessInputs.witnessInput(
                        coordinate.bundleKind,
                        coordinate.stage,
                        data,
                    )

                assertEquals(expectedInputCase(coordinate.bundleKind, coordinate.stage), input.inputCase)
            } finally {
                data.fill(0)
            }
        }
    }

    @Test
    fun demoFixtureRejectsMalformedProtobufBytes() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ReallyMeZkDemoFixtureWitnessInputs.witnessInput(
                    ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                    ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                    byteArrayOf(0x08, 0x80.toByte()),
                )
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_WITNESS, error.reason)
    }

    @Test
    fun demoFixtureRejectsWrongProfileStageBinding() {
        val data =
            fixtureData(
                ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
                ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
                ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
            )
        try {
            val error =
                assertFailsWith<ReallyMeZkProviderException> {
                    ReallyMeZkDemoFixtureWitnessInputs.witnessInput(
                        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                        data,
                    )
                }

            assertEquals(ZkProviderFailureReason.MALFORMED_WITNESS, error.reason)
        } finally {
            data.fill(0)
        }
    }

    @Test
    fun demoFixtureRejectsOversizedProtobufBeforeParsing() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ReallyMeZkDemoFixtureWitnessInputs.witnessInput(
                    ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                    ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                    ByteArray(16_385),
                )
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_WITNESS, error.reason)
    }

    private fun expectedInputCase(
        bundleKind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
    ): Manifest.ZkStageWitnessInput.InputCase =
        when (stage) {
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION -> expectedSessionInputCase(bundleKind)
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE ->
                Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_ENVELOPE
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT ->
                Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_ROOT
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM -> expectedClaimInputCase(bundleKind)
            else -> Manifest.ZkStageWitnessInput.InputCase.INPUT_NOT_SET
        }

    private fun expectedSessionInputCase(bundleKind: ZkClaimProofBundleKind): Manifest.ZkStageWitnessInput.InputCase =
        when (bundleKind) {
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1 ->
                Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_SUBJECT_CLAIM_SESSION
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1 ->
                Manifest.ZkStageWitnessInput.InputCase.PRIVATE_PERSONA_SESSION
            else -> Manifest.ZkStageWitnessInput.InputCase.INPUT_NOT_SET
        }

    private fun expectedClaimInputCase(bundleKind: ZkClaimProofBundleKind): Manifest.ZkStageWitnessInput.InputCase =
        when (bundleKind) {
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1 ->
                Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_SUBJECT_CLAIM
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1 ->
                Manifest.ZkStageWitnessInput.InputCase.PRIVATE_PERSONA_CLAIM
            else -> Manifest.ZkStageWitnessInput.InputCase.INPUT_NOT_SET
        }

    private fun sampleRunner(provider: TestBundleProvider): TestSampleRunner =
        ReallyMeZkSampleRunner(
            provider = provider,
            bundleVerifyRequestProvider = { _, _ ->
                ZkPresentationBoundClaimBundleVerifyRequest(
                    expectedSessionBinding = expectedSessionBinding(),
                    trustedIssuers = listOf(trustedIssuer()),
                    verificationTimeUnix = 100L,
                )
            },
        )

    private fun expectedSessionBinding(transactionDataHash: ByteString = ByteString.EMPTY): Manifest.ZkSessionBinding =
        Manifest.ZkSessionBinding
            .newBuilder()
            .setNonceHash(ByteString.copyFrom(ByteArray(32) { 1 }))
            .setAudienceHash(ByteString.copyFrom(ByteArray(32) { 2 }))
            .setTransactionDataHash(transactionDataHash)
            .build()

    private object StaticProvider : TestBundleProvider {
        override fun generateWitness(request: ZkStageRequest): ZkProviderWitnessResult<WitnessHandle> =
            ZkProviderWitnessResult(WitnessHandle, ZkWitnessMetrics(byteCount = 8))

        override fun prove(
            request: ZkStageRequest,
            witness: WitnessHandle,
        ): ZkProviderProofResult<ProofHandle> =
            ZkProviderProofResult(
                ProofHandle,
                ZkProofMetrics(
                    verificationKeyByteCount = 8,
                    publicInputByteCount = 8,
                    proofByteCount = 8,
                ),
            )

        override fun verifyDiagnosticStage(
            request: ZkStageVerifyRequest,
            proof: ProofHandle,
        ): Boolean = true

        override fun releaseWitness(witness: WitnessHandle): Unit = Unit
    }

    private class CredentialHashAlgorithmRecordingProvider : TestBundleProvider {
        val hashStrategies: MutableList<ZkCredentialHashAlgorithm> = mutableListOf()

        override fun generateWitness(request: ZkStageRequest): ZkProviderWitnessResult<WitnessHandle> {
            hashStrategies.add(request.credentialHashAlgorithm)
            return ZkProviderWitnessResult(WitnessHandle, ZkWitnessMetrics(byteCount = 8))
        }

        override fun prove(
            request: ZkStageRequest,
            witness: WitnessHandle,
        ): ZkProviderProofResult<ProofHandle> {
            hashStrategies.add(request.credentialHashAlgorithm)
            return ZkProviderProofResult(
                ProofHandle,
                ZkProofMetrics(
                    verificationKeyByteCount = 8,
                    publicInputByteCount = 8,
                    proofByteCount = 8,
                ),
            )
        }

        override fun verifyDiagnosticStage(
            request: ZkStageVerifyRequest,
            proof: ProofHandle,
        ): Boolean {
            hashStrategies.add(request.credentialHashAlgorithm)
            return true
        }

        override fun proveClaimProofBundle(
            request: ZkClaimProofBundleProveRequest,
            witnesses: List<WitnessHandle>,
        ): ZkProviderClaimProofBundleResult<ClaimProofBundleHandle> {
            hashStrategies.add(request.credentialHashAlgorithm)
            return claimProofBundleResult()
        }

        override fun releaseWitness(witness: WitnessHandle): Unit = Unit
    }

    private interface TestBundleProvider :
        ReallyMeZkClaimProofBundleProvider<WitnessHandle, ProofHandle, ClaimProofBundleHandle> {
        override fun prove(
            request: ZkStageRequest,
            witness: WitnessHandle,
        ): ZkProviderProofResult<ProofHandle> =
            ZkProviderProofResult(
                ProofHandle,
                ZkProofMetrics(
                    verificationKeyByteCount = 8,
                    publicInputByteCount = 8,
                    proofByteCount = 8,
                ),
            )

        override fun verifyDiagnosticStage(
            request: ZkStageVerifyRequest,
            proof: ProofHandle,
        ): Boolean = true

        override fun releaseWitness(witness: WitnessHandle): Unit = Unit

        override fun proveClaimProofBundle(
            request: ZkClaimProofBundleProveRequest,
            witnesses: List<WitnessHandle>,
        ): ZkProviderClaimProofBundleResult<ClaimProofBundleHandle> = claimProofBundleResult()

        override fun verifyPresentationBoundClaimBundle(
            request: ZkPresentationBoundClaimBundleVerifyRequest,
            claimProofBundle: ClaimProofBundleHandle,
        ): ZkPresentationBoundClaimBundleVerification = verifiedClaimProofBundle(request.expectedSessionBinding)
    }

    private class ProgressFailure : RuntimeException()

    private class ProviderCrash : RuntimeException()

    private class ReleaseCrash : RuntimeException()

    private data class CancellationCheckpoint(
        val progressLine: String,
        val expectedReleaseCount: Int,
    )

    private fun runInterruptedFlow(
        provider: ReleasingStaticProvider,
        progressLine: String,
    ): ReallyMeZkProviderException {
        try {
            val runner = sampleRunner(provider)
            return assertFailsWith<ReallyMeZkProviderException> {
                runner.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1) { line ->
                    if (line == progressLine) {
                        Thread.currentThread().interrupt()
                    }
                }
            }
        } finally {
            Thread.interrupted()
        }
    }

    private class ReleasingStaticProvider : TestBundleProvider {
        var releaseCount: Int = 0
            private set

        override fun generateWitness(request: ZkStageRequest): ZkProviderWitnessResult<WitnessHandle> =
            ZkProviderWitnessResult(WitnessHandle, ZkWitnessMetrics(byteCount = 8))

        override fun prove(
            request: ZkStageRequest,
            witness: WitnessHandle,
        ): ZkProviderProofResult<ProofHandle> =
            ZkProviderProofResult(
                ProofHandle,
                ZkProofMetrics(
                    verificationKeyByteCount = 8,
                    publicInputByteCount = 8,
                    proofByteCount = 8,
                ),
            )

        override fun verifyDiagnosticStage(
            request: ZkStageVerifyRequest,
            proof: ProofHandle,
        ): Boolean = true

        override fun releaseWitness(witness: WitnessHandle) {
            releaseCount += 1
        }
    }

    private class ProveFailingProvider : TestBundleProvider {
        var releaseCount: Int = 0
            private set

        override fun generateWitness(request: ZkStageRequest): ZkProviderWitnessResult<WitnessHandle> =
            ZkProviderWitnessResult(WitnessHandle, ZkWitnessMetrics(byteCount = 8))

        override fun prove(
            request: ZkStageRequest,
            witness: WitnessHandle,
        ): ZkProviderProofResult<ProofHandle> = rejectedProof()

        override fun proveClaimProofBundle(
            request: ZkClaimProofBundleProveRequest,
            witnesses: List<WitnessHandle>,
        ): ZkProviderClaimProofBundleResult<ClaimProofBundleHandle> = rejectedBundleProof()

        override fun verifyDiagnosticStage(
            request: ZkStageVerifyRequest,
            proof: ProofHandle,
        ): Boolean = false

        override fun releaseWitness(witness: WitnessHandle) {
            releaseCount += 1
        }
    }

    private class CrashingProveProvider : TestBundleProvider {
        var releaseCount: Int = 0
            private set
        private var generated = false

        override fun generateWitness(request: ZkStageRequest): ZkProviderWitnessResult<WitnessHandle> {
            if (generated) {
                throw ProviderCrash()
            }
            generated = true
            return ZkProviderWitnessResult(WitnessHandle, ZkWitnessMetrics(byteCount = 8))
        }

        override fun prove(
            request: ZkStageRequest,
            witness: WitnessHandle,
        ): ZkProviderProofResult<ProofHandle> = throw ProviderCrash()

        override fun verifyDiagnosticStage(
            request: ZkStageVerifyRequest,
            proof: ProofHandle,
        ): Boolean = false

        override fun releaseWitness(witness: WitnessHandle) {
            releaseCount += 1
        }
    }

    private class ReleaseFailingProvider : TestBundleProvider {
        private var generated = false

        override fun generateWitness(request: ZkStageRequest): ZkProviderWitnessResult<WitnessHandle> {
            if (generated) {
                throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
            }
            generated = true
            return ZkProviderWitnessResult(WitnessHandle, ZkWitnessMetrics(byteCount = 8))
        }

        override fun prove(
            request: ZkStageRequest,
            witness: WitnessHandle,
        ): ZkProviderProofResult<ProofHandle> = rejectedProof()

        override fun proveClaimProofBundle(
            request: ZkClaimProofBundleProveRequest,
            witnesses: List<WitnessHandle>,
        ): ZkProviderClaimProofBundleResult<ClaimProofBundleHandle> = claimProofBundleResult()

        override fun verifyDiagnosticStage(
            request: ZkStageVerifyRequest,
            proof: ProofHandle,
        ): Boolean = false

        override fun releaseWitness(witness: WitnessHandle): Unit =
            throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
    }

    private class UncheckedReleaseFailingProvider : TestBundleProvider {
        var releaseAttempts: Int = 0
            private set
        private var generatedCount = 0

        override fun generateWitness(request: ZkStageRequest): ZkProviderWitnessResult<WitnessHandle> {
            if (generatedCount == 2) {
                throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
            }
            generatedCount += 1
            return ZkProviderWitnessResult(WitnessHandle, ZkWitnessMetrics(byteCount = 8))
        }

        override fun prove(
            request: ZkStageRequest,
            witness: WitnessHandle,
        ): ZkProviderProofResult<ProofHandle> = rejectedProof()

        override fun proveClaimProofBundle(
            request: ZkClaimProofBundleProveRequest,
            witnesses: List<WitnessHandle>,
        ): ZkProviderClaimProofBundleResult<ClaimProofBundleHandle> = claimProofBundleResult()

        override fun verifyDiagnosticStage(
            request: ZkStageVerifyRequest,
            proof: ProofHandle,
        ): Boolean = false

        override fun releaseWitness(witness: WitnessHandle) {
            releaseAttempts += 1
            if (releaseAttempts == 1) {
                throw ReleaseCrash()
            }
        }
    }

    private object UnsupportedBundleProvider : TestBundleProvider {
        override fun generateWitness(request: ZkStageRequest): TestWitnessResult = providerUnavailable()

        override fun proveClaimProofBundle(
            request: ZkClaimProofBundleProveRequest,
            witnesses: List<WitnessHandle>,
        ): ZkProviderClaimProofBundleResult<ClaimProofBundleHandle> = providerUnavailable()

        override fun verifyPresentationBoundClaimBundle(
            request: ZkPresentationBoundClaimBundleVerifyRequest,
            claimProofBundle: ClaimProofBundleHandle,
        ): ZkPresentationBoundClaimBundleVerification = providerUnavailable()
    }
}

private fun <ProofHandle : Any> rejectedProof(): ZkProviderProofResult<ProofHandle> =
    throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)

private fun <Handle : Any> rejectedBundleProof(): ZkProviderClaimProofBundleResult<Handle> =
    throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)

private fun <Value : Any> providerUnavailable(): Value = throw providerUnavailableException()

private fun providerUnavailableException(): ReallyMeZkProviderException =
    ReallyMeZkProviderException(ZkProviderFailureReason.PROVIDER_UNAVAILABLE)

private fun claimProofBundleResult(): ZkProviderClaimProofBundleResult<ClaimProofBundleHandle> =
    ZkProviderClaimProofBundleResult(
        ClaimProofBundleHandle,
        ZkClaimProofBundleMetrics(
            stageCount = ReallyMeZk.stages.size,
            proofByteCount = 4 * 96,
        ),
    )

private fun verifiedClaimProofBundle(binding: Manifest.ZkSessionBinding): ZkPresentationBoundClaimBundleVerification =
    ZkPresentationBoundClaimBundleVerification(
        ZkPresentationBoundClaimBundleProofShape(
            bundleKind = ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
            verifiedStageCount = ReallyMeZk.stages.size,
        ),
        ZkPresentationBoundClaimBundlePolicyBinding(
            sessionBinding = binding,
            issuer = trustedIssuer(),
            persona = null,
            presentationExpiryUnix = 500L,
        ),
        ZkPresentationBoundClaimBundleSensitiveClaim(
            claimNameHash = ZkSensitiveBytes(ByteArray(32) { 11 }),
            claimValue = ZkSensitiveBytes(byteArrayOf(1, 2, 3)),
            claimValueLength = 3,
            credentialBinding = ZkSensitiveBytes(ByteArray(32) { 13 }),
            sessionLinkCommitment = ZkSensitiveBytes(ByteArray(32) { 12 }),
        ),
    )

private fun trustedIssuer(): Manifest.ZkP256PublicKey =
    Manifest.ZkP256PublicKey
        .newBuilder()
        .setX(ByteString.copyFrom(ByteArray(32) { 8 }))
        .setY(ByteString.copyFrom(ByteArray(32) { 9 }))
        .build()
