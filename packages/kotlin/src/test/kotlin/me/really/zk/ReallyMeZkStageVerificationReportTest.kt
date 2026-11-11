// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import com.google.protobuf.ByteString
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import reallyme.zk.v1.Manifest
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReallyMeZkStageVerificationReportTest {
    @Test
    fun matchingReportVerifiesDiagnosticStage() {
        assertTrue(verifyDiagnosticStage(StageVerificationReportBridge(StageVerificationReport.MATCHING)))
    }

    @Test
    fun emptyReportIsMalformedProviderResponse() {
        assertMalformedProof(StageVerificationReport.EMPTY)
    }

    @Test
    fun wrongCircuitRefIsMalformedProviderResponse() {
        assertMalformedProof(StageVerificationReport.WRONG_CIRCUIT_REF)
    }

    @Test
    fun wrongProofSuiteIsMalformedProviderResponse() {
        assertMalformedProof(StageVerificationReport.WRONG_PROOF_SUITE)
        assertMalformedProof(StageVerificationReport.UNSPECIFIED_PROOF_SUITE)
    }

    @Test
    fun wrongCircuitIdentityIsMalformedProviderResponse() {
        assertMalformedProof(StageVerificationReport.WRONG_CIRCUIT_ID)
        assertMalformedProof(StageVerificationReport.WRONG_BUNDLE_KIND)
    }

    @Test
    fun unexpectedResultCaseIsMalformedProviderResponse() {
        assertMalformedProof(StageVerificationReport.WRONG_RESULT_CASE)
    }

    @Test
    fun typedProofRejectionStillReportsUnverified() {
        assertFalse(verifyDiagnosticStage(StageVerificationReportBridge(StageVerificationReport.PROOF_REJECTED)))
    }

    @Test
    fun productionTransportRefusalSurfacesTypedError() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                verifyDiagnosticStage(StageVerificationReportBridge(StageVerificationReport.UNSUPPORTED_TRANSPORT))
            }
        assertEquals(ZkProviderFailureReason.UNSUPPORTED_TRANSPORT, error.reason)
    }

    @Test
    fun malformedProofPreservesBooleanRejection() {
        assertFalse(verifyDiagnosticStage(StageVerificationReportBridge(StageVerificationReport.MALFORMED_PROOF)))
    }

    private fun assertMalformedProof(report: StageVerificationReport) {
        val bridge = StageVerificationReportBridge(report)
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                verifyDiagnosticStage(bridge)
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_PROOF, error.reason)
        assertEquals(1, bridge.dispatchCalls)
    }

    private fun verifyDiagnosticStage(bridge: StageVerificationReportBridge): Boolean =
        ReallyMeZkNativeProvider(contextHandle = CONTEXT_HANDLE, bridge = bridge).verifyDiagnosticStage(
            ZkStageVerifyRequest(
                bundleKind = BUNDLE_KIND,
                stage = ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                expectedSessionBinding = sessionBinding(),
            ),
            ZkNativeProofHandle(proof = stageProof()),
        )

    private fun stageProof(): Manifest.ZkProofPackage =
        Manifest.ZkProofPackage
            .newBuilder()
            .setCircuitId(Manifest.ZkCircuitId.ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1)
            .setCircuitRef(
                circuitRef(
                    BUNDLE_KIND,
                    ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
                    ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                ),
            ).setProofSuite(PROOF_SUITE)
            .setProof(ByteString.copyFrom(ByteArray(PROOF_BYTE_COUNT) { 5 }))
            .build()

    private fun sessionBinding(): Manifest.ZkSessionBinding =
        Manifest.ZkSessionBinding
            .newBuilder()
            .setNonceHash(ByteString.copyFrom(ByteArray(BYTES_32) { 1 }))
            .setAudienceHash(ByteString.copyFrom(ByteArray(BYTES_32) { 2 }))
            .build()

    private enum class StageVerificationReport {
        MATCHING,
        EMPTY,
        WRONG_CIRCUIT_REF,
        WRONG_CIRCUIT_ID,
        WRONG_BUNDLE_KIND,
        WRONG_PROOF_SUITE,
        UNSPECIFIED_PROOF_SUITE,
        WRONG_RESULT_CASE,
        PROOF_REJECTED,
        UNSUPPORTED_TRANSPORT,
        MALFORMED_PROOF,
    }

    private class StageVerificationReportBridge(
        private val report: StageVerificationReport,
    ) : ReallyMeZkPlatformNativeBridge {
        var dispatchCalls: Int = 0
            private set

        override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
            ZkNativeContextResult(statusCode = 0, errorReasonCode = 0, contextHandle = CONTEXT_HANDLE)

        override fun dispatch(
            contextHandle: Long,
            request: ByteArray,
        ): ZkNativeDispatchResult {
            assertEquals(CONTEXT_HANDLE, contextHandle)
            dispatchCalls += 1
            val operation = Manifest.ZkProviderOperationRequest.parseFrom(request)
            assertEquals(Manifest.ZkProviderOperationRequest.OperationCase.VERIFY_STAGE, operation.operationCase)
            val response =
                Manifest.ZkProviderOperationResponse
                    .newBuilder()
                    .setRequestSha256(ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(request)))
            when (report) {
                StageVerificationReport.PROOF_REJECTED ->
                    response.setError(
                        Manifest.ZkError
                            .newBuilder()
                            .setReason(Manifest.ZkErrorReason.ZK_ERROR_REASON_INVALID_PROOF),
                    )
                StageVerificationReport.UNSUPPORTED_TRANSPORT ->
                    response.setError(
                        Manifest.ZkError
                            .newBuilder()
                            .setReason(Manifest.ZkErrorReason.ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT),
                    )
                StageVerificationReport.MALFORMED_PROOF ->
                    response.setError(
                        Manifest.ZkError
                            .newBuilder()
                            .setReason(Manifest.ZkErrorReason.ZK_ERROR_REASON_INVALID_PROOF_ENCODING),
                    )
                StageVerificationReport.WRONG_RESULT_CASE ->
                    response.setResult(
                        Manifest.ZkProviderOperationResult
                            .newBuilder()
                            .setStageProof(operation.verifyStage.proof),
                    )
                else ->
                    response.setResult(
                        Manifest.ZkProviderOperationResult
                            .newBuilder()
                            .setStageVerification(verification(operation.verifyStage.proof)),
                    )
            }
            return ZkNativeDispatchResult(statusCode = 0, errorReasonCode = 0, output = response.build().toByteArray())
        }

        override fun contextDestroy(contextHandle: Long): ZkNativeStatus =
            ZkNativeStatus(statusCode = 0, errorReasonCode = 0)

        private fun verification(proof: Manifest.ZkProofPackage): Manifest.ZkVerification {
            if (report == StageVerificationReport.EMPTY) {
                return Manifest.ZkVerification.getDefaultInstance()
            }
            val verification =
                Manifest.ZkVerification
                    .newBuilder()
                    .setCircuitId(proof.circuitId)
                    .setCircuitRef(proof.circuitRef)
                    .setBundleKind(BUNDLE_KIND)
                    .setProofSuite(proof.proofSuite)
            when (report) {
                StageVerificationReport.WRONG_CIRCUIT_REF ->
                    verification.setCircuitRef(
                        proof.circuitRef
                            .toBuilder()
                            .setStage(Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE),
                    )
                StageVerificationReport.WRONG_CIRCUIT_ID ->
                    verification.setCircuitId(Manifest.ZkCircuitId.ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1)
                StageVerificationReport.WRONG_BUNDLE_KIND ->
                    verification.setBundleKind(
                        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
                    )
                StageVerificationReport.WRONG_PROOF_SUITE ->
                    verification.setProofSuite(
                        Manifest.ZkProofSuite.ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_ZK_NO_IPA,
                    )
                StageVerificationReport.UNSPECIFIED_PROOF_SUITE ->
                    verification.setProofSuite(Manifest.ZkProofSuite.ZK_PROOF_SUITE_UNSPECIFIED)
                else -> Unit
            }
            return verification.build()
        }
    }

    private companion object {
        const val CONTEXT_HANDLE: Long = 7L
        const val PROOF_BYTE_COUNT: Int = 96
        val BUNDLE_KIND: ZkClaimProofBundleKind =
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1
    }
}
