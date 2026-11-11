// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.os.Debug
import android.os.SystemClock
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import me.really.zk.JniReallyMeZkPlatformNativeBridge
import me.really.zk.ReallyMeZk
import me.really.zk.ReallyMeZkNativeContextFactory
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkApprovedReleaseIndexPin
import me.really.zk.ZkNativeContextCreateRequest
import me.really.zk.ZkNativeContextOwnedFilePaths
import me.really.zk.ZkNativeCrsMode
import me.really.zk.ZkProviderFailureReason
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.commonroot.ZkCommonCredentialRootPersonaMode
import me.really.zk.demo.shared.ZkSampleResult
import me.really.zk.displayName
import me.really.zk.label
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import reallyme.zk.v1.Manifest
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.system.measureNanoTime

public class ReallyMeZKDemoInstrumentationTest {
    @Test
    public fun personaCredentialEvidenceStagesProveAndVerifyBothModesAndHashChoices() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val runtime = AndroidDemoRuntime(targetContext)

        for (mode in ZkCommonCredentialRootPersonaMode.entries) {
            for (credentialHashAlgorithm in ReallyMeZk.credentialHashAlgorithms) {
                val prepared =
                    try {
                        runtime.preparePersonaSample(mode, credentialHashAlgorithm)
                    } catch (error: ReallyMeZkProviderException) {
                        throw AssertionError(
                            "persona credential evidence stage failed with ${error.reason} " +
                                "for mode=$mode hash=${credentialHashAlgorithm.displayName}",
                            error,
                        )
                    }
                val verificationMilliseconds =
                    runtime.verifyCachedPersonaCredentialEvidenceStages(prepared)

                assertEquals(mode, prepared.mode)
                assertEquals(credentialHashAlgorithm, prepared.credentialHashAlgorithm)
                assertTrue(prepared.generationMilliseconds > 0.0)
                assertTrue(verificationMilliseconds >= 0.0)
                if (mode == ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA) {
                    repeat(2) {
                        val repeatedVerificationMilliseconds =
                            runtime.verifyCachedPersonaCredentialEvidenceStages(prepared)
                        assertTrue(repeatedVerificationMilliseconds >= 0.0)
                    }
                }
                Log.i(
                    MEMORY_EVIDENCE_TAG,
                    "preparedStages mode=$mode hash=${credentialHashAlgorithm.displayName} " +
                        "generationMs=${prepared.generationMilliseconds} " +
                        "verificationMs=$verificationMilliseconds",
                )
            }
        }
    }

    @Test
    public fun commonCredentialRootPreparedSamplesVerifyAllPersonaAndHashChoices() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val runtime = AndroidDemoRuntime(targetContext)

        for (mode in ZkCommonCredentialRootPersonaMode.entries) {
            for (credentialHashAlgorithm in ReallyMeZk.credentialHashAlgorithms) {
                val result = runtime.verifyCommonCredentialRootSample(mode, credentialHashAlgorithm)
                assertEquals("nine exact proofs must verify", 9, result.verifiedProofCount)
                assertTrue("verification must report elapsed time", result.verificationMilliseconds >= 0.0)
            }
        }
    }

    @Test
    public fun commonCredentialRootGeneratedSamplesProveAndVerifyEveryPersonaAndHashChoice() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val runtime = AndroidDemoRuntime(targetContext)
        for (mode in ZkCommonCredentialRootPersonaMode.entries) {
            for (credentialHashAlgorithm in ReallyMeZk.credentialHashAlgorithms) {
                val completedStages = mutableListOf<Int>()
                val sampler = MemorySampler.start()
                val result =
                    try {
                        runtime.generateCommonCredentialRootSample(
                            mode,
                            credentialHashAlgorithm,
                        ) { completedStages.add(it) }
                    } finally {
                        sampler.close()
                    }

                assertEquals((1..9).toList(), completedStages)
                assertEquals(9, result.verifiedProofCount)
                assertTrue(result.generationMilliseconds > 0.0)
                assertTrue(result.verificationMilliseconds >= 0.0)
                Log.i(
                    MEMORY_EVIDENCE_TAG,
                    "commonCredentialRootGenerated releaseIndexSha256=$APPROVED_RELEASE_INDEX_SHA256 " +
                        "mode=$mode hash=${credentialHashAlgorithm.displayName} " +
                        "proofCount=${result.verifiedProofCount} " +
                        "generationMs=${result.generationMilliseconds} " +
                        "verificationMs=${result.verificationMilliseconds} observedPeak=${sampler.maximum}",
                )
                assertTrue(
                    "common-credential-root generated RSS exceeded diagnostic ceiling",
                    sampler.maximum.vmRssKb <= MAX_COMMON_CREDENTIAL_ROOT_GENERATED_VM_RSS_KB,
                )
            }
        }
    }

    @Test
    public fun commonCredentialRootGeneratedSampleRejectsAlteredSessionBinding() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val runtime = AndroidDemoRuntime(targetContext)
        val completedStages = mutableListOf<Int>()

        val result =
            runtime.generateCommonCredentialRootSampleAndRejectAlteredSession(
                ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA,
                ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2,
            ) { completedStages.add(it) }

        assertEquals((1..9).toList(), completedStages)
        assertEquals(9, result.acceptedProofCount)
        assertTrue(result.rejectedAlteredSession)
        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, result.rejectionReason)
        assertTrue(result.generationMilliseconds > 0.0)
        assertTrue(result.verificationMilliseconds >= 0.0)
        assertTrue(result.rejectionMilliseconds >= 0.0)
    }

    @Test
    public fun allProfilesRunWitnessProveVerifyFromApplicationContext() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val runtime = AndroidDemoRuntime(targetContext)

        for (bundleKind in ReallyMeZk.bundleKinds) {
            for (credentialHashAlgorithm in ReallyMeZk.credentialHashAlgorithms) {
                val progress = mutableListOf<String>()
                val checkpointRecorder = MemoryCheckpointRecorder()
                var result: ZkSampleResult? = null
                val totalMilliseconds =
                    elapsedMilliseconds {
                        result =
                            runtime.runFlow(bundleKind, credentialHashAlgorithm) { update ->
                                checkpointRecorder.record()
                                progress.add(update)
                            }
                    }
                val progressEvents = progress.filter { update -> update.startsWith(UI_PROGRESS_PREFIX) }
                val sampleResult = requireSampleResult(result)

                assertEquals(bundleKind, sampleResult.bundleKind)
                assertTrue(sampleResult.fixtureBundleVerified)
                assertEquals(0, sampleResult.publicInputsSize)
                assertTrue(sampleResult.proofSize > 0)
                assertEquals(
                    expectedProgressMessages(),
                    progressEvents.map { update -> progressMessage(update) },
                )
                logFlowTiming(
                    bundleKind,
                    credentialHashAlgorithm,
                    sampleResult,
                    totalMilliseconds,
                    checkpointRecorder.maximum,
                )
                logStageMetrics(
                    bundleKind,
                    credentialHashAlgorithm,
                    progress.filter { update -> update.startsWith(UI_METRIC_PREFIX) },
                )
            }
        }
    }

    @Test
    public fun alteredExpectedSessionBindingRejectsProofFromApplicationContext() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val runtime = AndroidDemoRuntime(targetContext)

        for (credentialHashAlgorithm in ReallyMeZk.credentialHashAlgorithms) {
            for (mutation in AndroidDemoBindingMutation.entries) {
                try {
                    runtime.runFlowWithAlteredExpectedBinding(
                        ReallyMeZk.bundleKinds.first(),
                        credentialHashAlgorithm,
                        mutation,
                    )
                    fail("altered $mutation binding must reject the generated proof for $credentialHashAlgorithm")
                } catch (error: ReallyMeZkProviderException) {
                    assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
                }
            }
        }
    }

    @Test
    public fun repeatedPublicPersonaFlowsKeepMemoryBounded() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val runtime = AndroidDemoRuntime(targetContext)
        val warmupResult =
            runtime.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1) {
                // Warmup isolates one-time native initialization from retained growth.
            }
        assertTrue(warmupResult.fixtureBundleVerified)
        val before = MemorySnapshot.capture()
        val checkpointRecorder = MemoryCheckpointRecorder()

        repeat(REPEATED_MEMORY_FLOW_COUNT) {
            val result =
                runtime.runFlow(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1) {
                    checkpointRecorder.record()
                }
            assertTrue(result.fixtureBundleVerified)
        }

        val after = MemorySnapshot.capture()
        Log.i(MEMORY_EVIDENCE_TAG, "before=$before checkpointMax=${checkpointRecorder.maximum} after=$after")
        assertTrue(
            "Java heap growth exceeded repeated-flow budget",
            after.javaHeapBytes <= before.javaHeapBytes + MAX_JAVA_HEAP_GROWTH_BYTES,
        )
        assertTrue(
            "Native heap growth exceeded repeated-flow budget",
            after.nativeHeapBytes <= before.nativeHeapBytes + MAX_NATIVE_HEAP_GROWTH_BYTES,
        )
        assertTrue(
            "Repeated-flow RSS exceeded reviewed public-persona ceiling",
            checkpointRecorder.maximum.vmRssKb <= MAX_REPEATED_FLOW_VM_RSS_KB,
        )
        assertTrue(
            "Post-run RSS exceeded the observed repeated-flow peak",
            after.vmRssKb <= checkpointRecorder.maximum.vmRssKb,
        )
    }

    @Test
    public fun largestClaimBundle4DiagnosticProveVerifyRecordsPeakMemoryOnDevice() {
        assumeTrue(
            "claim_bundle_4 diagnostic lane is opt-in",
            InstrumentationRegistry
                .getArguments()
                .getString(CLAIM_BUNDLE4_DIAGNOSTIC_ARGUMENT) == "true",
        )
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val targetContext = instrumentation.targetContext.applicationContext
        val diagnosticRoot =
            prepareClaimBundle4DiagnosticRoot(
                instrumentation.context.assets,
                targetContext,
            )
        val demoRoot = AndroidDemoAssetExtraction(targetContext).prepareAssetRoot()
        val proveRequestBytes =
            readAssetBounded(
                instrumentation.context.assets,
                "$CLAIM_BUNDLE4_DIAGNOSTIC_ASSET_ROOT/$CLAIM_BUNDLE4_PROVE_REQUEST_FILE",
                MAX_CLAIM_BUNDLE4_REQUEST_BYTES,
            )
        val proveRequest = Manifest.ZkProviderOperationRequest.parseFrom(proveRequestBytes)
        assertEquals(Manifest.ZkProviderOperationRequest.OperationCase.PROVE_STAGE, proveRequest.operationCase)
        assertEquals(
            Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_CLAIM_BUNDLE_4,
            proveRequest.proveStage.circuitRef.stage,
        )

        val contextHandle = createDiagnosticContext(demoRoot, diagnosticRoot)
        val sampler = MemorySampler.start()
        try {
            val metrics = proveVerifyClaimBundle4(contextHandle, proveRequestBytes, proveRequest)
            val after = MemorySnapshot.capture()
            Log.i(
                MEMORY_EVIDENCE_TAG,
                "claimBundle4Diagnostic proveVerifyMs=${metrics.elapsedMilliseconds} " +
                    "observedPeak=${sampler.maximum} after=$after",
            )
            assertTrue("claim_bundle_4 diagnostic proof should take positive time", metrics.elapsedMilliseconds > 0.0)
            assertTrue(
                "claim_bundle_4 observed RSS exceeded diagnostic ceiling",
                sampler.maximum.vmRssKb <= MAX_CLAIM_BUNDLE4_DIAGNOSTIC_VM_RSS_KB,
            )
        } finally {
            sampler.close()
            JniReallyMeZkPlatformNativeBridge.contextDestroy(contextHandle)
            proveRequestBytes.fill(0)
        }
    }

    private fun expectedProgressMessages(): List<String> =
        ReallyMeZk.stages.map { stage ->
            "Generated ${stage.label} witness."
        } +
            listOf(
                "Generated proof bundle.",
                "Bundle verified.",
            )

    private fun progressMessage(update: String): String {
        val fields = update.split(PROGRESS_FIELD_SEPARATOR)
        assertEquals(PROGRESS_FIELD_COUNT, fields.size)
        return fields[PROGRESS_MESSAGE_FIELD_INDEX]
    }
}

private fun requireSampleResult(result: ZkSampleResult?): ZkSampleResult =
    result ?: throw AssertionError("demo flow did not produce a result")

private data class ClaimBundle4DiagnosticMetrics(
    val elapsedMilliseconds: Double,
)

private fun proveVerifyClaimBundle4(
    contextHandle: Long,
    proveRequestBytes: ByteArray,
    proveRequest: Manifest.ZkProviderOperationRequest,
): ClaimBundle4DiagnosticMetrics {
    val elapsedMilliseconds =
        elapsedMilliseconds {
            val proveResponse = dispatchSuccess(JniReallyMeZkPlatformNativeBridge, contextHandle, proveRequestBytes)
            val result = proveResponse.result
            assertEquals(Manifest.ZkProviderOperationResult.ResultCase.STAGE_PROOF, result.resultCase)
            val proof = result.stageProof
            assertEquals(Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_CLAIM_BUNDLE_4, proof.circuitRef.stage)
            assertTrue(proof.proof.size() > 0)
            assertTrue(proof.publicInputs.encoded.size() > 0)
            val verifyResponse =
                dispatchSuccess(
                    JniReallyMeZkPlatformNativeBridge,
                    contextHandle,
                    verifyRequest(proof, proveRequest.proveStage.sessionBinding).toByteArray(),
                )
            assertEquals(
                Manifest.ZkProviderOperationResult.ResultCase.STAGE_VERIFICATION,
                verifyResponse.result.resultCase,
            )
            logClaimBundle4ProofMetrics(proveRequestBytes.size, proof)
        }
    return ClaimBundle4DiagnosticMetrics(elapsedMilliseconds)
}

private fun verifyRequest(
    proof: Manifest.ZkProofPackage,
    expectedBinding: Manifest.ZkSessionBinding,
): Manifest.ZkProviderOperationRequest {
    val verifyBuilder = Manifest.ZkStageVerifyOperation.newBuilder()
    verifyBuilder.setProof(proof)
    verifyBuilder.setExpectedProofSuite(
        Manifest.ZkProofSuite.ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
    )
    verifyBuilder.setExpectedBinding(expectedBinding)
    val requestBuilder = Manifest.ZkProviderOperationRequest.newBuilder()
    requestBuilder.setVerifyStage(verifyBuilder.build())
    return requestBuilder.build()
}

private fun logClaimBundle4ProofMetrics(
    requestBytes: Int,
    proof: Manifest.ZkProofPackage,
) {
    Log.i(
        MEMORY_EVIDENCE_TAG,
        "claimBundle4Diagnostic circuit=poseidon2/families/private_persona_claim_v1/claim_bundle_4 " +
            "requestBytes=$requestBytes proofBytes=${proof.proof.size()} " +
            "publicInputBytes=${proof.publicInputs.encoded.size()}",
    )
}

private fun logFlowTiming(
    bundleKind: ZkClaimProofBundleKind,
    credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    result: ZkSampleResult,
    totalMilliseconds: Double,
    checkpointMaximum: MemorySnapshot,
) {
    val providerMilliseconds = result.witnessMilliseconds + result.proveMilliseconds + result.verifyMilliseconds
    val setupMilliseconds = (totalMilliseconds - providerMilliseconds).coerceAtLeast(0.0)
    Log.i(
        TIMING_EVIDENCE_TAG,
        "bundleKind=${bundleKind.displayName} hash=${credentialHashAlgorithm.displayName} totalMs=$totalMilliseconds " +
            "residualSetupAndFixtureMs=$setupMilliseconds " +
            "witnessMs=${result.witnessMilliseconds} proveMs=${result.proveMilliseconds} " +
            "verifyMs=${result.verifyMilliseconds} checkpointMax=$checkpointMaximum",
    )
}

private fun logStageMetrics(
    bundleKind: ZkClaimProofBundleKind,
    credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    metrics: List<String>,
) {
    Log.i(
        TIMING_EVIDENCE_TAG,
        "bundleKind=${bundleKind.displayName} hash=${credentialHashAlgorithm.displayName} " +
            "stageMetrics=${metrics.joinToString(
                ";",
            )}",
    )
}

private fun elapsedMilliseconds(block: () -> Unit): Double {
    val elapsedNanos = measureNanoTime(block)
    return elapsedNanos.toDouble() / NANOS_PER_MILLISECOND
}

private data class MemorySnapshot(
    val javaHeapBytes: Long,
    val nativeHeapBytes: Long,
    val vmRssKb: Long,
) {
    companion object {
        fun capture(): MemorySnapshot {
            val runtime = Runtime.getRuntime()
            val javaHeapBytes = runtime.totalMemory() - runtime.freeMemory()
            return MemorySnapshot(
                javaHeapBytes = javaHeapBytes,
                nativeHeapBytes = Debug.getNativeHeapAllocatedSize(),
                vmRssKb = currentVmRssKb(),
            )
        }
    }
}

private class MemoryCheckpointRecorder {
    @Volatile
    var maximum: MemorySnapshot = MemorySnapshot.capture()
        private set

    @Synchronized
    fun record() {
        val current = MemorySnapshot.capture()
        maximum =
            MemorySnapshot(
                javaHeapBytes = maxOf(maximum.javaHeapBytes, current.javaHeapBytes),
                nativeHeapBytes = maxOf(maximum.nativeHeapBytes, current.nativeHeapBytes),
                vmRssKb = maxOf(maximum.vmRssKb, current.vmRssKb),
            )
    }
}

private class MemorySampler private constructor(
    private val running: AtomicBoolean,
    private val recorder: MemoryCheckpointRecorder,
    private val thread: Thread,
) : AutoCloseable {
    val maximum: MemorySnapshot
        get() = recorder.maximum

    override fun close() {
        running.set(false)
        thread.join(MEMORY_SAMPLER_JOIN_MILLISECONDS)
        recorder.record()
    }

    companion object {
        fun start(): MemorySampler {
            val running = AtomicBoolean(true)
            val recorder = MemoryCheckpointRecorder()
            val thread =
                Thread {
                    while (running.get()) {
                        recorder.record()
                        SystemClock.sleep(MEMORY_SAMPLER_INTERVAL_MILLISECONDS)
                    }
                }
            thread.name = "claim-bundle4-memory-sampler"
            thread.isDaemon = true
            thread.start()
            return MemorySampler(running, recorder, thread)
        }
    }
}

private fun prepareClaimBundle4DiagnosticRoot(
    assets: android.content.res.AssetManager,
    targetContext: android.content.Context,
): File {
    val root = File(targetContext.filesDir, CLAIM_BUNDLE4_DIAGNOSTIC_EXTRACTED_ROOT)
    val rootPath = containedPath(targetContext, root)
    if (root.exists()) {
        if (Files.isSymbolicLink(rootPath)) {
            abort("claim_bundle_4 diagnostic root is symbolic")
        }
        if (!root.deleteRecursively()) {
            abort("claim_bundle_4 diagnostic root could not be reset")
        }
    }
    copyDiagnosticAssetTree(
        assets,
        "$CLAIM_BUNDLE4_DIAGNOSTIC_ASSET_ROOT/$CLAIM_BUNDLE4_EXACT_SOURCE_DIRECTORY",
        root,
        DiagnosticExtractionBudget(),
    )
    return root
}

private fun copyDiagnosticAssetTree(
    assets: android.content.res.AssetManager,
    assetPath: String,
    target: File,
    budget: DiagnosticExtractionBudget,
) {
    val entries = assets.list(assetPath) ?: abort("claim_bundle_4 diagnostic assets are unavailable")
    if (entries.isEmpty()) {
        copyDiagnosticAssetFile(assets, assetPath, target, budget)
        return
    }
    if (!target.mkdirs() && !target.isDirectory) {
        abort("claim_bundle_4 diagnostic directory could not be created")
    }
    if (Files.isSymbolicLink(target.toPath())) {
        abort("claim_bundle_4 diagnostic directory is symbolic")
    }
    for (entry in entries.sorted()) {
        validateAssetEntry(entry)
        copyDiagnosticAssetTree(assets, "$assetPath/$entry", File(target, entry), budget)
    }
}

private fun copyDiagnosticAssetFile(
    assets: android.content.res.AssetManager,
    assetPath: String,
    target: File,
    budget: DiagnosticExtractionBudget,
) {
    budget.recordFile()
    val parent = target.parentFile ?: abort("claim_bundle_4 diagnostic path has no parent")
    if (!parent.mkdirs() && !parent.isDirectory) {
        abort("claim_bundle_4 diagnostic parent could not be created")
    }
    assets.open(assetPath).use { input ->
        target.outputStream().use { output ->
            copyDiagnosticBytes(input, output, budget)
        }
    }
}

private fun copyDiagnosticBytes(
    input: InputStream,
    output: OutputStream,
    budget: DiagnosticExtractionBudget,
) {
    val buffer = ByteArray(COPY_BUFFER_BYTES)
    try {
        while (true) {
            val read = input.read(buffer)
            if (read < 0) {
                break
            }
            budget.recordBytes(read)
            output.write(buffer, 0, read)
        }
    } finally {
        buffer.fill(0)
    }
}

private class DiagnosticExtractionBudget {
    private var fileCount = 0
    private var totalBytes = 0L

    fun recordFile() {
        fileCount = checkedAssetRead(fileCount, 1, MAX_CLAIM_BUNDLE4_DIAGNOSTIC_FILES)
    }

    fun recordBytes(read: Int) {
        val next = totalBytes + read.toLong()
        if (next > MAX_CLAIM_BUNDLE4_DIAGNOSTIC_BYTES) {
            abort("claim_bundle_4 diagnostic assets exceeded byte budget")
        }
        totalBytes = next
    }
}

private fun createDiagnosticContext(
    demoRoot: File,
    diagnosticRoot: File,
): Long {
    val releaseIndex = readFileBounded(File(demoRoot, RELEASE_INDEX_FILE_NAME), MAX_RELEASE_INDEX_BYTES)
    val releaseIndexPin = hexDigest(APPROVED_RELEASE_INDEX_SHA256)
    val artifactRootUtf8 = diagnosticRoot.absolutePath.toByteArray(StandardCharsets.UTF_8)
    val crsG1PathUtf8 = File(demoRoot, CRS_G1_FILE_NAME).absolutePath.toByteArray(StandardCharsets.UTF_8)
    val crsG2PathUtf8 = File(demoRoot, CRS_G2_FILE_NAME).absolutePath.toByteArray(StandardCharsets.UTF_8)
    var requestOwnsInputBuffers = false
    try {
        val request =
            ZkNativeContextCreateRequest.fromOwnedFilePaths(
                filePaths =
                    ZkNativeContextOwnedFilePaths(
                        artifactRootUtf8 = artifactRootUtf8,
                        releaseIndex = releaseIndex,
                        crsG1PathUtf8 = crsG1PathUtf8,
                        crsG2PathUtf8 = crsG2PathUtf8,
                    ),
                approvedReleaseIndexPin = ZkApprovedReleaseIndexPin.fromTrustedBytes(releaseIndexPin),
                crsMode = ZkNativeCrsMode.FULL_PROVER,
            )
        requestOwnsInputBuffers = true
        request.use {
            val result = ReallyMeZkNativeContextFactory().createContext(it)
            assertEquals(ASSET_PLATFORM_STATUS_OK, result.statusCode)
            assertTrue(result.contextHandle != 0L)
            return result.contextHandle
        }
    } finally {
        if (!requestOwnsInputBuffers) {
            artifactRootUtf8.fill(0)
            releaseIndex.fill(0)
            crsG1PathUtf8.fill(0)
            crsG2PathUtf8.fill(0)
        }
        releaseIndexPin.fill(0)
    }
}

private fun dispatchSuccess(
    bridge: JniReallyMeZkPlatformNativeBridge,
    contextHandle: Long,
    requestBytes: ByteArray,
): Manifest.ZkProviderOperationResponse {
    val expectedRequestSha256 = sha256(requestBytes)
    val result = bridge.dispatch(contextHandle, requestBytes)
    try {
        assertEquals(ASSET_PLATFORM_STATUS_OK, result.statusCode)
        val response = Manifest.ZkProviderOperationResponse.parseFrom(result.output)
        assertTrue(response.requestSha256.toByteArray().contentEquals(expectedRequestSha256))
        if (response.outcomeCase == Manifest.ZkProviderOperationResponse.OutcomeCase.ERROR) {
            fail("native diagnostic dispatch failed with ${response.error.reason}")
        }
        assertEquals(Manifest.ZkProviderOperationResponse.OutcomeCase.RESULT, response.outcomeCase)
        return response
    } finally {
        expectedRequestSha256.fill(0)
        result.output.fill(0)
    }
}

private fun readAssetBounded(
    assets: android.content.res.AssetManager,
    assetPath: String,
    maximumBytes: Int,
): ByteArray =
    assets.open(assetPath).use { input ->
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(COPY_BUFFER_BYTES)
        var total = 0
        try {
            var read = input.read(buffer)
            while (read >= 0) {
                total = checkedAssetRead(total, read, maximumBytes)
                output.write(buffer, 0, read)
                read = input.read(buffer)
            }
            output.toByteArray()
        } finally {
            buffer.fill(0)
        }
    }

private fun readFileBounded(
    file: File,
    maximumBytes: Int,
): ByteArray {
    if (file.length() > maximumBytes.toLong()) {
        abort("file exceeded maximum byte count")
    }
    val bytes = file.readBytes()
    if (bytes.isEmpty() || bytes.size > maximumBytes) {
        abort("file had invalid byte count")
    }
    return bytes
}

private fun hexDigest(value: String): ByteArray {
    if (value.length != SHA256_HEX_CHARS) {
        abort("digest has invalid length")
    }
    return ByteArray(SHA256_BYTES) { index ->
        val offset = index * HEX_CHARS_PER_BYTE
        val byte =
            value.substring(offset, offset + HEX_CHARS_PER_BYTE).toIntOrNull(HEX_RADIX)
                ?: abort("digest has invalid byte")
        if (byte < 0 || byte > UNSIGNED_BYTE_MAX) {
            abort("digest has invalid byte")
        }
        byte.toByte()
    }
}

private fun abort(message: String): Nothing = throw AssertionError(message)

private fun sha256(bytes: ByteArray): ByteArray =
    MessageDigest
        .getInstance("SHA-256")
        .digest(bytes)

private fun currentVmRssKb(): Long {
    val line =
        File("/proc/self/status")
            .readLines()
            .firstOrNull { value -> value.startsWith(VM_RSS_PREFIX) }
            ?: throw AssertionError("VmRSS was not present in /proc/self/status")
    return parseVmRssLine(line) ?: throw AssertionError("VmRSS line did not contain a numeric value")
}

private fun parseVmRssLine(line: String): Long? {
    val fields = line.split(WHITESPACE_REGEX).filter { field -> field.isNotEmpty() }
    return if (fields.size >= VM_RSS_FIELD_COUNT) {
        fields[VM_RSS_VALUE_FIELD_INDEX].toLongOrNull()
    } else {
        null
    }
}

private const val UI_PROGRESS_PREFIX = "UI_PROGRESS|"
private const val UI_METRIC_PREFIX = "UI_METRIC|"
private const val PROGRESS_FIELD_SEPARATOR = "|"
private const val PROGRESS_FIELD_COUNT = 4
private const val PROGRESS_MESSAGE_FIELD_INDEX = 3
private const val REPEATED_MEMORY_FLOW_COUNT = 2
private const val MAX_JAVA_HEAP_GROWTH_BYTES = 32L * 1_024L * 1_024L
private const val MAX_NATIVE_HEAP_GROWTH_BYTES = 32L * 1_024L * 1_024L

// BB6 uses transient mmap-backed proving workspaces that are outside Android's
// native-heap counter. This ceiling covers the full-suite high-water mark while
// the separate heap-growth assertions continue to reject retained allocations.
private const val MAX_REPEATED_FLOW_VM_RSS_KB = 640L * 1_024L
private const val MAX_COMMON_CREDENTIAL_ROOT_GENERATED_VM_RSS_KB = 2L * 1_024L * 1_024L
private const val VM_RSS_PREFIX = "VmRSS:"
private const val VM_RSS_FIELD_COUNT = 2
private const val VM_RSS_VALUE_FIELD_INDEX = 1
private const val MEMORY_EVIDENCE_TAG = "ReallyMeZKMemory"
private const val TIMING_EVIDENCE_TAG = "ReallyMeZKTiming"
private const val NANOS_PER_MILLISECOND = 1_000_000.0
private const val CLAIM_BUNDLE4_DIAGNOSTIC_ARGUMENT = "reallymeZkClaimBundle4Diagnostic"
private const val CLAIM_BUNDLE4_DIAGNOSTIC_ASSET_ROOT = "diagnostic_claim_bundle4"
private const val CLAIM_BUNDLE4_EXACT_SOURCE_DIRECTORY = "exact_source"
private const val CLAIM_BUNDLE4_PROVE_REQUEST_FILE = "prove_request.pb"
private const val CLAIM_BUNDLE4_DIAGNOSTIC_EXTRACTED_ROOT = "reallyme_zk_claim_bundle4_diagnostic"
private const val MAX_CLAIM_BUNDLE4_REQUEST_BYTES = 8 * 1_024 * 1_024
private const val MAX_CLAIM_BUNDLE4_DIAGNOSTIC_FILES = 64
private const val MAX_CLAIM_BUNDLE4_DIAGNOSTIC_BYTES = 8L * 1_024L * 1_024L
private const val MAX_CLAIM_BUNDLE4_DIAGNOSTIC_VM_RSS_KB = 2L * 1_024L * 1_024L
private const val MEMORY_SAMPLER_INTERVAL_MILLISECONDS = 50L
private const val MEMORY_SAMPLER_JOIN_MILLISECONDS = 5_000L
private val WHITESPACE_REGEX = Regex("\\s+")
