// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import com.google.protobuf.ByteString
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleProveRequest
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import reallyme.zk.v1.Manifest
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ReallyMeZkNativeBridgeTest {
    @Test
    fun contextResultRejectsFailureWithHandle() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkNativeContextResult(
                    statusCode = 1,
                    errorReasonCode = 20,
                    contextHandle = 7,
                )
            }

        assertEquals(ZkProviderFailureReason.INTERNAL_FAILURE, error.reason)
    }

    @Test
    fun dispatchResultRejectsEmptySuccessOutput() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkNativeDispatchResult(
                    statusCode = 0,
                    errorReasonCode = 0,
                    output = ByteArray(0),
                )
            }

        assertEquals(ZkProviderFailureReason.EMPTY_BUFFER, error.reason)
    }

    @Test
    fun dispatchResultStringRedactsOutputBytes() {
        val output = byteArrayOf(101, 102, 103, 104)
        val result =
            ZkNativeDispatchResult(
                statusCode = 0,
                errorReasonCode = 0,
                output = output,
            )

        val rendered = result.toString()

        assertEquals(
            "ZkNativeDispatchResult(statusCode=0, errorReasonCode=0, output=<redacted 4 bytes>)",
            rendered,
        )
        assertFalse(rendered.contains(output.contentToString()))
        assertFalse(rendered.contains("101"))
        assertFalse(rendered.contains(output.toString()))
        assertSame(output, result.output)
    }

    @Test
    fun statusRejectsNegativeCodes() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkNativeStatus(
                    statusCode = -1,
                    errorReasonCode = 0,
                )
            }

        assertEquals(ZkProviderFailureReason.INTERNAL_FAILURE, error.reason)
    }

    @Test
    fun contextFactoryUsesApprovedPinInsteadOfPayloadDerivedDigest() {
        val bridge = RecordingNativeBridge()
        val approvedDigest = ByteArray(32) { 1 }
        val substitutedDigest = ByteArray(32) { 2 }
        val request =
            ZkNativeContextCreateRequest(
                artifactRootUtf8 = byteArrayOf(47, 97),
                releaseIndex = byteArrayOf(9, 9, 9),
                approvedReleaseIndexPin = ZkApprovedReleaseIndexPin.fromTrustedBytes(approvedDigest),
                crsG1 = byteArrayOf(3),
                crsG2 = byteArrayOf(4),
                crsMode = ZkNativeCrsMode.VERIFIER_ONLY,
            )

        val result = ReallyMeZkNativeContextFactory(bridge).createContext(request)

        assertEquals(7L, result.contextHandle)
        assertContentEquals(approvedDigest, bridge.releaseIndexSha256)
        assertContentEquals(byteArrayOf(9, 9, 9), bridge.releaseIndex)
        assertFalse(substitutedDigest.contentEquals(bridge.releaseIndexSha256))
    }

    @Test
    fun contextFactoryMapsNativeLoadFailureToProviderUnavailable() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ReallyMeZkNativeContextFactory(LinkageFailingNativeBridge()).createContext(contextCreateRequest())
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, error.reason)
    }

    @Test
    fun contextFactoryMapsSecurityDeniedNativeLoadToProviderUnavailable() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ReallyMeZkNativeContextFactory(SecurityDeniedNativeBridge()).createContext(contextCreateRequest())
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, error.reason)
    }

    @Test
    fun nativeLibraryLoadStateDoesNotExposeLinkageFailures() {
        assertEquals(
            ZkNativeLibraryLoadState.PROVIDER_UNAVAILABLE,
            detectNativeLibraryLoadState { throw UnsatisfiedLinkError("missing native test library") },
        )
        assertEquals(
            ZkNativeLibraryLoadState.PROVIDER_UNAVAILABLE,
            detectNativeLibraryLoadState { throw NoClassDefFoundError("failed native test library initializer") },
        )
    }

    @Test
    fun nativeLibraryLoadStateDoesNotExposeSecurityDeniedLoad() {
        assertEquals(
            ZkNativeLibraryLoadState.PROVIDER_UNAVAILABLE,
            detectNativeLibraryLoadState { throw SecurityException("native load denied") },
        )
    }

    @Test
    fun nativeLibraryLoadStateAcceptsSuccessfulLoad() {
        assertEquals(
            ZkNativeLibraryLoadState.LOADED,
            detectNativeLibraryLoadState {},
        )
    }

    @Test
    fun nativeLinkageMapperDoesNotExposeSecurityDeniedNativeCalls() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                mapNativeLinkageFailure {
                    throw SecurityException("native call denied")
                }
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, error.reason)
    }

    @Test
    fun contextFactoryMapsRepeatedNativeLinkageFailuresToProviderUnavailable() {
        val bridge = RepeatedLinkageFailingNativeBridge()

        val first =
            assertFailsWith<ReallyMeZkProviderException> {
                ReallyMeZkNativeContextFactory(bridge).createContext(contextCreateRequest())
            }
        val second =
            assertFailsWith<ReallyMeZkProviderException> {
                ReallyMeZkNativeContextFactory(bridge).createContext(contextCreateRequest())
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, first.reason)
        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, second.reason)
        assertEquals(2, bridge.contextCreateCalls)
    }

    @Test
    fun contextFactoryMapsRepeatedSecurityDeniedNativeCallsToProviderUnavailable() {
        val bridge = RepeatedSecurityDeniedNativeBridge()

        val first =
            assertFailsWith<ReallyMeZkProviderException> {
                ReallyMeZkNativeContextFactory(bridge).createContext(contextCreateRequest())
            }
        val second =
            assertFailsWith<ReallyMeZkProviderException> {
                ReallyMeZkNativeContextFactory(bridge).createContext(contextCreateRequest())
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, first.reason)
        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, second.reason)
        assertEquals(2, bridge.contextCreateCalls)
    }

    @Test
    fun ownedContextRequestBorrowsAndZeroizesCallerBuffers() {
        val artifactRoot = byteArrayOf(47, 97)
        val releaseIndex = byteArrayOf(9)
        val crsG1 = byteArrayOf(3)
        val crsG2 = byteArrayOf(4)
        val request =
            ZkNativeContextCreateRequest.fromOwnedBuffers(
                buffers =
                    ZkNativeContextOwnedBuffers(
                        artifactRootUtf8 = artifactRoot,
                        releaseIndex = releaseIndex,
                        crsG1 = crsG1,
                        crsG2 = crsG2,
                    ),
                approvedReleaseIndexPin = ZkApprovedReleaseIndexPin.fromTrustedBytes(ByteArray(32) { 1 }),
                crsMode = ZkNativeCrsMode.VERIFIER_ONLY,
            )
        request.withBorrowedContextCreateBuffers(ByteArray(32) { 2 }) { buffers ->
            assertSame(artifactRoot, buffers[0])
            assertSame(releaseIndex, buffers[1])
            assertSame(crsG1, buffers[3])
            assertSame(crsG2, buffers[4])
        }

        request.close()

        assertContentEquals(byteArrayOf(0, 0), artifactRoot)
        assertContentEquals(byteArrayOf(0), releaseIndex)
        assertContentEquals(byteArrayOf(0), crsG1)
        assertContentEquals(byteArrayOf(0), crsG2)
    }

    @Test
    fun ownedFilePathContextRequestBorrowsAndZeroizesCallerBuffers() {
        val artifactRoot = byteArrayOf(47, 97)
        val releaseIndex = byteArrayOf(9)
        val crsG1Path = byteArrayOf(47, 99, 49)
        val crsG2Path = byteArrayOf(47, 99, 50)
        val request =
            ZkNativeContextCreateRequest.fromOwnedFilePaths(
                filePaths =
                    ZkNativeContextOwnedFilePaths(
                        artifactRootUtf8 = artifactRoot,
                        releaseIndex = releaseIndex,
                        crsG1PathUtf8 = crsG1Path,
                        crsG2PathUtf8 = crsG2Path,
                    ),
                approvedReleaseIndexPin = ZkApprovedReleaseIndexPin.fromTrustedBytes(ByteArray(32) { 1 }),
                crsMode = ZkNativeCrsMode.FULL_PROVER,
            )
        assertTrue(request.usesCrsFilePaths())
        request.withBorrowedContextCreateFilePathBuffers(ByteArray(32) { 2 }) { buffers ->
            assertSame(artifactRoot, buffers[0])
            assertSame(releaseIndex, buffers[1])
            assertSame(crsG1Path, buffers[3])
            assertSame(crsG2Path, buffers[4])
        }

        request.close()

        assertContentEquals(byteArrayOf(0, 0), artifactRoot)
        assertContentEquals(byteArrayOf(0), releaseIndex)
        assertContentEquals(byteArrayOf(0, 0, 0), crsG1Path)
        assertContentEquals(byteArrayOf(0, 0, 0), crsG2Path)
    }

    @Test
    fun contextRequestRejectsMismatchedCrsSourceBorrow() {
        val fileBacked =
            ZkNativeContextCreateRequest.fromOwnedFilePaths(
                filePaths =
                    ZkNativeContextOwnedFilePaths(
                        artifactRootUtf8 = byteArrayOf(47, 97),
                        releaseIndex = byteArrayOf(9),
                        crsG1PathUtf8 = byteArrayOf(47, 99, 49),
                        crsG2PathUtf8 = byteArrayOf(47, 99, 50),
                    ),
                approvedReleaseIndexPin = ZkApprovedReleaseIndexPin.fromTrustedBytes(ByteArray(32) { 1 }),
                crsMode = ZkNativeCrsMode.FULL_PROVER,
            )
        val byteBacked = contextCreateRequest()

        val fileError =
            assertFailsWith<ReallyMeZkProviderException> {
                fileBacked.withBorrowedContextCreateBuffers(ByteArray(32) { 2 }) {}
            }
        val byteError =
            assertFailsWith<ReallyMeZkProviderException> {
                byteBacked.withBorrowedContextCreateFilePathBuffers(ByteArray(32) { 2 }) {}
            }

        assertEquals(ZkProviderFailureReason.INTERNAL_FAILURE, fileError.reason)
        assertEquals(ZkProviderFailureReason.INTERNAL_FAILURE, byteError.reason)
        fileBacked.close()
        byteBacked.close()
    }

    @Test
    fun contextRequestRejectsCloseDuringBorrow() {
        val request = contextCreateRequest()

        request.withBorrowedContextCreateBuffers(ByteArray(32) { 2 }) {
            val error =
                assertFailsWith<ReallyMeZkProviderException> {
                    request.close()
                }
            assertEquals(ZkProviderFailureReason.INTERNAL_FAILURE, error.reason)
        }

        request.close()
    }

    @Test
    fun nativeProviderMapsDispatchLinkageFailureToProviderUnavailable() {
        val provider = ReallyMeZkNativeProvider(contextHandle = 7L, bridge = LinkageFailingNativeBridge())
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

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                provider.generateWitness(request)
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, error.reason)
    }

    @Test
    fun nativeProviderWipesDispatchOutputWhenNativeStatusFails() {
        val bridge = FailingDispatchOutputNativeBridge()
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

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                provider.generateWitness(request)
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_PROOF, error.reason)
        assertContentEquals(ByteArray(bridge.failureOutput.size), bridge.failureOutput)
    }

    @Test
    fun nativeProviderWipesSuccessfulDispatchRequestAndOutputBuffers() {
        val bridge = SuccessfulDispatchBufferRecordingNativeBridge()
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

        val result = provider.generateWitness(request)

        assertEquals(41L, result.handle.handle.nativeHandleId)
        assertTrue(bridge.requestBytes.isNotEmpty())
        assertTrue(bridge.outputBytes.isNotEmpty())
        assertContentEquals(ByteArray(bridge.requestBytes.size), bridge.requestBytes)
        assertContentEquals(ByteArray(bridge.outputBytes.size), bridge.outputBytes)
    }

    @Test
    fun nativeProviderReportsConcurrentDispatchAsBusy() {
        val bridge = FailingDispatchOutputNativeBridge(NATIVE_STATUS_DISPATCH_BUSY)
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

        val error = assertFailsWith<ReallyMeZkProviderException> { provider.generateWitness(request) }

        assertEquals(ZkProviderFailureReason.PROVIDER_BUSY, error.reason)
        assertContentEquals(ByteArray(bridge.failureOutput.size), bridge.failureOutput)
    }

    @Test
    fun nativeProviderReleasesWitnessesWhenBundleCountValidationFailsBeforeDispatch() {
        val bridge = ReleaseRecordingNativeBridge()
        val provider = ReallyMeZkNativeProvider(contextHandle = 7L, bridge = bridge)
        val witnesses =
            listOf(
                nativeWitnessHandle(
                    handleId = 21L,
                    stage = ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                    binding = bundleSessionBinding(),
                ),
            )

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                provider.proveClaimProofBundle(
                    ZkClaimProofBundleProveRequest(
                        bundleKind = ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                        sessionBinding = bundleSessionBinding(),
                    ),
                    witnesses,
                )
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_WITNESS, error.reason)
        assertEquals(listOf(Manifest.ZkProviderOperationRequest.OperationCase.RELEASE_STAGE_WITNESS), bridge.operations)
    }

    @Test
    fun nativeProviderReleasesWitnessesWhenBundleBindingValidationFailsBeforeDispatch() {
        val bridge = ReleaseRecordingNativeBridge()
        val provider = ReallyMeZkNativeProvider(contextHandle = 7L, bridge = bridge)
        val witnesses =
            ReallyMeZk.stages.mapIndexed { index, stage ->
                nativeWitnessHandle(
                    handleId = 31L + index.toLong(),
                    stage = stage,
                    binding = bundleSessionBinding(),
                )
            }
        val mismatchedBinding =
            bundleSessionBinding(
                transactionDataHash = ByteString.copyFrom(ByteArray(32) { 7 }),
            )

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                provider.proveClaimProofBundle(
                    ZkClaimProofBundleProveRequest(
                        bundleKind = ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                        sessionBinding = mismatchedBinding,
                    ),
                    witnesses,
                )
            }

        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
        assertEquals(
            List(ReallyMeZk.stages.size) { Manifest.ZkProviderOperationRequest.OperationCase.RELEASE_STAGE_WITNESS },
            bridge.operations,
        )
    }

    private class RecordingNativeBridge : ReallyMeZkPlatformNativeBridge {
        lateinit var releaseIndex: ByteArray
        lateinit var releaseIndexSha256: ByteArray

        override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult {
            this.releaseIndex = request.releaseIndexCopy()
            this.releaseIndexSha256 = request.approvedReleaseIndexSha256Copy()
            return ZkNativeContextResult(
                statusCode = 0,
                errorReasonCode = 0,
                contextHandle = 7,
            )
        }

        override fun dispatch(
            contextHandle: Long,
            request: ByteArray,
        ): ZkNativeDispatchResult =
            ZkNativeDispatchResult(
                statusCode = 0,
                errorReasonCode = 0,
                output = byteArrayOf(1),
            )

        override fun contextDestroy(contextHandle: Long): ZkNativeStatus =
            ZkNativeStatus(
                statusCode = 0,
                errorReasonCode = 0,
            )
    }

    private class LinkageFailingNativeBridge : ReallyMeZkPlatformNativeBridge {
        override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult = nativeLoadFailure()

        override fun dispatch(
            contextHandle: Long,
            request: ByteArray,
        ): ZkNativeDispatchResult = nativeLoadFailure()

        override fun contextDestroy(contextHandle: Long): ZkNativeStatus =
            ZkNativeStatus(
                statusCode = 0,
                errorReasonCode = 0,
            )

        private fun nativeLoadFailure(): Nothing = throw UnsatisfiedLinkError("missing native test library")
    }

    private class SecurityDeniedNativeBridge : ReallyMeZkPlatformNativeBridge {
        override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult = nativeLoadFailure()

        override fun dispatch(
            contextHandle: Long,
            request: ByteArray,
        ): ZkNativeDispatchResult = nativeLoadFailure()

        override fun contextDestroy(contextHandle: Long): ZkNativeStatus = nativeLoadFailure()

        private fun nativeLoadFailure(): Nothing = throw SecurityException("native load denied")
    }

    private class FailingDispatchOutputNativeBridge(
        private val failureStatusCode: Int = NATIVE_STATUS_INVALID_BUFFER,
    ) : ReallyMeZkPlatformNativeBridge {
        val failureOutput: ByteArray = byteArrayOf(1, 2, 3, 4)

        override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
            ZkNativeContextResult(
                statusCode = 0,
                errorReasonCode = 0,
                contextHandle = 7,
            )

        override fun dispatch(
            contextHandle: Long,
            request: ByteArray,
        ): ZkNativeDispatchResult =
            ZkNativeDispatchResult(
                statusCode = failureStatusCode,
                errorReasonCode = 0,
                output = failureOutput,
            )

        override fun contextDestroy(contextHandle: Long): ZkNativeStatus =
            ZkNativeStatus(
                statusCode = 0,
                errorReasonCode = 0,
            )
    }

    private class SuccessfulDispatchBufferRecordingNativeBridge : ReallyMeZkPlatformNativeBridge {
        lateinit var requestBytes: ByteArray
            private set
        lateinit var outputBytes: ByteArray
            private set

        override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
            ZkNativeContextResult(
                statusCode = 0,
                errorReasonCode = 0,
                contextHandle = 7,
            )

        override fun dispatch(
            contextHandle: Long,
            request: ByteArray,
        ): ZkNativeDispatchResult {
            assertEquals(7L, contextHandle)
            requestBytes = request
            val operation = Manifest.ZkProviderOperationRequest.parseFrom(request)
            val witnessOperation = operation.witnessStage
            val handle =
                Manifest.ZkStageWitnessHandle
                    .newBuilder()
                    .setNativeHandleId(41L)
                    .setCircuitRef(witnessOperation.circuitRef)
                    .setEncoding(Manifest.ZkWitnessEncoding.ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1)
                    .build()
            val binding =
                Manifest.ZkSessionBinding
                    .newBuilder()
                    .setNonceHash(ByteString.copyFrom(ByteArray(32) { 1 }))
                    .setAudienceHash(ByteString.copyFrom(ByteArray(32) { 2 }))
                    .setTransactionDataHash(ByteString.copyFrom(ByteArray(32) { 3 }))
                    .build()
            val stageWitness =
                Manifest.ZkStageWitness
                    .newBuilder()
                    .setWitnessHandle(handle)
                    .setPublicInputs(
                        Manifest.ZkPublicInputs
                            .newBuilder()
                            .setEncoded(ByteString.copyFrom(byteArrayOf(1, 2, 3, 4))),
                    ).setSessionBinding(binding)
                    .build()
            val response =
                Manifest.ZkProviderOperationResponse
                    .newBuilder()
                    .setRequestSha256(ByteString.copyFrom(sha256(request)))
                    .setResult(
                        Manifest.ZkProviderOperationResult
                            .newBuilder()
                            .setStageWitness(stageWitness)
                            .build(),
                    ).build()
            outputBytes = response.toByteArray()
            return ZkNativeDispatchResult(
                statusCode = 0,
                errorReasonCode = 0,
                output = outputBytes,
            )
        }

        override fun contextDestroy(contextHandle: Long): ZkNativeStatus =
            ZkNativeStatus(
                statusCode = 0,
                errorReasonCode = 0,
            )
    }

    private class RepeatedLinkageFailingNativeBridge : ReallyMeZkPlatformNativeBridge {
        var contextCreateCalls: Int = 0
            private set

        override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult {
            contextCreateCalls += 1
            if (contextCreateCalls == 1) {
                throw UnsatisfiedLinkError("missing native test library")
            }
            throw NoClassDefFoundError("failed native test library initializer")
        }

        override fun dispatch(
            contextHandle: Long,
            request: ByteArray,
        ): ZkNativeDispatchResult = throw NoClassDefFoundError("failed native test library initializer")

        override fun contextDestroy(contextHandle: Long): ZkNativeStatus =
            throw NoClassDefFoundError("failed native test library initializer")
    }

    private class RepeatedSecurityDeniedNativeBridge : ReallyMeZkPlatformNativeBridge {
        var contextCreateCalls: Int = 0
            private set

        override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult {
            contextCreateCalls += 1
            throw SecurityException("native load denied")
        }

        override fun dispatch(
            contextHandle: Long,
            request: ByteArray,
        ): ZkNativeDispatchResult = throw SecurityException("native call denied")

        override fun contextDestroy(contextHandle: Long): ZkNativeStatus = throw SecurityException("native call denied")
    }

    private fun contextCreateRequest(): ZkNativeContextCreateRequest =
        ZkNativeContextCreateRequest(
            artifactRootUtf8 = byteArrayOf(47, 97),
            releaseIndex = byteArrayOf(9),
            approvedReleaseIndexPin = ZkApprovedReleaseIndexPin.fromTrustedBytes(ByteArray(32) { 1 }),
            crsG1 = byteArrayOf(3),
            crsG2 = byteArrayOf(4),
            crsMode = ZkNativeCrsMode.VERIFIER_ONLY,
        )

    private fun nativeWitnessHandle(
        handleId: Long,
        stage: ZkClaimProofBundleStage,
        binding: Manifest.ZkSessionBinding,
    ): ZkNativeWitnessHandle =
        ZkNativeWitnessHandle(
            handle =
                Manifest.ZkStageWitnessHandle
                    .newBuilder()
                    .setNativeHandleId(handleId)
                    .setCircuitRef(
                        circuitRef(
                            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
                            stage,
                        ),
                    ).setEncoding(Manifest.ZkWitnessEncoding.ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1)
                    .build(),
            publicInputs = Manifest.ZkPublicInputs.getDefaultInstance(),
            sessionBinding = binding,
        )

    private fun bundleSessionBinding(
        transactionDataHash: ByteString = ByteString.copyFrom(ByteArray(32) { 3 }),
    ): Manifest.ZkSessionBinding =
        Manifest.ZkSessionBinding
            .newBuilder()
            .setNonceHash(ByteString.copyFrom(ByteArray(32) { 1 }))
            .setAudienceHash(ByteString.copyFrom(ByteArray(32) { 2 }))
            .setTransactionDataHash(transactionDataHash)
            .build()

    private class ReleaseRecordingNativeBridge : ReallyMeZkPlatformNativeBridge {
        val operations: MutableList<Manifest.ZkProviderOperationRequest.OperationCase> = mutableListOf()

        override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
            ZkNativeContextResult(
                statusCode = 0,
                errorReasonCode = 0,
                contextHandle = 7L,
            )

        override fun dispatch(
            contextHandle: Long,
            request: ByteArray,
        ): ZkNativeDispatchResult {
            assertEquals(7L, contextHandle)
            val operation = Manifest.ZkProviderOperationRequest.parseFrom(request)
            operations.add(operation.operationCase)
            val response =
                Manifest.ZkProviderOperationResponse
                    .newBuilder()
                    .setRequestSha256(ByteString.copyFrom(sha256(request)))
                    .setResult(
                        Manifest.ZkProviderOperationResult
                            .newBuilder()
                            .setStageWitnessRelease(Manifest.ZkStageWitnessRelease.getDefaultInstance())
                            .build(),
                    ).build()
            return ZkNativeDispatchResult(
                statusCode = 0,
                errorReasonCode = 0,
                output = response.toByteArray(),
            )
        }

        override fun contextDestroy(contextHandle: Long): ZkNativeStatus =
            ZkNativeStatus(
                statusCode = 0,
                errorReasonCode = 0,
            )
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private companion object {
        const val NATIVE_STATUS_INVALID_BUFFER: Int = 6
        const val NATIVE_STATUS_DISPATCH_BUSY: Int = 9
    }
}
