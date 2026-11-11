// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import com.google.protobuf.ByteString
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkIssuerStatusPurpose
import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundleVerification
import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundleVerifyRequest
import reallyme.zk.v1.Manifest
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ReallyMeZkStatusQualifiedClaimBundleTest {
    @Test
    fun matchingReportYieldsStatusQualifiedVerification() {
        val bridge = StatusQualifiedBridge(resultOf(verification()))
        val request = verifyRequest()

        val verified = verify(bridge, request)

        assertEquals(1, bridge.dispatchCalls)
        assertEquals(BUNDLE_KIND, verified.bundleKind)
        assertEquals(STATUS_QUALIFIED_PROOF_COUNT, verified.verifiedProofCount)
        assertEquals(ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_REVOCATION, verified.statusPurpose)
        assertEquals(sessionBinding(), verified.sessionBinding)
        assertEquals(issuer(), verified.issuer)
        assertNull(verified.persona)
        assertEquals(CLAIM_VALUE.size, verified.claimValueLength)
        assertEquals(PRESENTATION_EXPIRY_UNIX, verified.presentationExpiryUnix)
        verified.claimNameHash.useBytes { assertContentEquals(ByteArray(BYTES_32) { 11 }, it) }
        verified.claimValue.useBytes { assertContentEquals(CLAIM_VALUE, it) }
        verified.sessionLinkCommitment.useBytes { assertContentEquals(ByteArray(BYTES_32) { 12 }, it) }
        verified.credentialBinding.useBytes { assertContentEquals(ByteArray(BYTES_32) { 13 }, it) }
        verified.close()
        assertEquals(0, verified.claimValue.size)
        assertEquals(0, verified.credentialBinding.size)
    }

    @Test
    fun dispatchedOperationCarriesVerifierPolicyAndProductionSuite() {
        val bridge = StatusQualifiedBridge(resultOf(verification()))
        val request = verifyRequest()

        verify(bridge, request).close()

        val operation = bridge.operations.single()
        assertEquals(statusQualifiedBundle(), operation.statusQualifiedClaimProofBundle)
        assertEquals(sessionBinding(), operation.expectedBinding)
        assertEquals(issuer(), operation.expectedIssuer)
        assertEquals(listOf(issuer()), operation.trustedIssuersList)
        assertEquals(VERIFICATION_TIME_UNIX, operation.verificationTimeUnix)
        assertEquals(
            Manifest.ZkProofSuite.ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            operation.expectedProofSuite,
        )
        assertEquals(issuerStatus(), operation.currentIssuerStatus)
    }

    @Test
    fun suspensionPurposeIsCarriedThroughToResult() {
        val suspension = ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_SUSPENSION
        val bridge = StatusQualifiedBridge(resultOf(verification().toBuilder().setStatusPurpose(suspension).build()))

        val verified = verify(bridge, verifyRequest(status = issuerStatus().toBuilder().setPurpose(suspension).build()))

        assertEquals(suspension, verified.statusPurpose)
    }

    @Test
    fun personaIsSurfacedWhenStatementCarriesOne() {
        val persona = publicKey(21, 22)
        val statement = statement().toBuilder().setPersona(persona).build()
        val bridge = StatusQualifiedBridge(resultOf(verification(statement)))

        assertEquals(persona, verify(bridge, verifyRequest()).persona)
    }

    @Test
    fun requestAndResultToStringRedactPolicyAndClaims() {
        val request = verifyRequest()
        val verified = verify(StatusQualifiedBridge(resultOf(verification())), request)

        val requestDisplay = request.toString()
        val resultDisplay = verified.toString()

        assertTrue(requestDisplay.contains("expectedSessionBinding=<redacted>"))
        assertTrue(requestDisplay.contains("trustedIssuers=<redacted>"))
        assertTrue(requestDisplay.contains("currentIssuerStatus=<redacted>"))
        assertFalse(requestDisplay.contains("nonceHash"))
        assertFalse(requestDisplay.contains("root"))
        assertFalse(requestDisplay.contains("\\"))
        assertTrue(resultDisplay.contains("sensitive=<redacted>"))
        assertFalse(resultDisplay.contains("claimValue"))
        assertFalse(resultDisplay.contains("issuer="))
        assertFalse(resultDisplay.contains("\\"))
    }

    @Test
    fun requestCopiesTrustedIssuers() {
        val issuers = mutableListOf(issuer())
        val request =
            ZkStatusQualifiedClaimBundleVerifyRequest(
                expectedSessionBinding = sessionBinding(),
                expectedIssuer = issuer(),
                trustedIssuers = issuers,
                verificationTimeUnix = VERIFICATION_TIME_UNIX,
                currentIssuerStatus = issuerStatus(),
            )

        issuers.clear()

        assertEquals(listOf(issuer()), request.trustedIssuers)
    }

    @Test
    fun requestRejectsEmptyTrustedIssuers() {
        assertRequestRejected(ZkProviderFailureReason.PROOF_REJECTED) { verifyRequest(trustedIssuers = emptyList()) }
    }

    @Test
    fun requestRejectsExpectedIssuerOutsideTrustPolicy() {
        assertRequestRejected(ZkProviderFailureReason.PROOF_REJECTED) {
            verifyRequest(expectedIssuer = publicKey(21, 22))
        }
    }

    @Test
    fun anotherTrustedIssuerCannotUseTheSelectedStatusFeed() {
        val other = publicKey(21, 22)
        val request = verifyRequest(trustedIssuers = listOf(issuer(), other), expectedIssuer = other)
        val bridge = StatusQualifiedBridge(resultOf(verification()))
        val error = assertFailsWith<ReallyMeZkProviderException> { verify(bridge, request) }
        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
    }

    @Test
    fun requestRejectsNonPositiveVerificationTime() {
        assertRequestRejected(ZkProviderFailureReason.PROOF_REJECTED) { verifyRequest(verificationTimeUnix = 0L) }
        assertRequestRejected(ZkProviderFailureReason.PROOF_REJECTED) { verifyRequest(verificationTimeUnix = -1L) }
    }

    @Test
    fun requestRejectsMalformedSessionBinding() {
        val binding = sessionBinding().toBuilder().setNonceHash(bytes(BYTES_32 - 1, 1)).build()

        assertRequestRejected(ZkProviderFailureReason.MALFORMED_PROOF) { verifyRequest(binding = binding) }
    }

    @Test
    fun requestRejectsMalformedStatusRoot() {
        assertStatusRejected { it.setRoot(bytes(BYTES_32 - 1, 5)) }
        assertStatusRejected { it.setRoot(bytes(BYTES_32 + 1, 5)) }
        assertStatusRejected { it.setRoot(bytes(BYTES_32, 0)) }
        assertStatusRejected { it.clearRoot() }
    }

    @Test
    fun requestRejectsMalformedStatusListId() {
        assertStatusRejected { it.setListId(bytes(BYTES_32 - 1, 6)) }
        assertStatusRejected { it.setListId(bytes(BYTES_32 + 1, 6)) }
        assertStatusRejected { it.setListId(bytes(BYTES_32, 0)) }
        assertStatusRejected { it.clearListId() }
    }

    @Test
    fun requestRejectsMalformedStatusUrlHash() {
        assertStatusRejected { it.setUrlHash(bytes(BYTES_32 - 1, 7)) }
        assertStatusRejected { it.setUrlHash(bytes(BYTES_32 + 1, 7)) }
        assertStatusRejected { it.setUrlHash(bytes(BYTES_32, 0)) }
        assertStatusRejected { it.clearUrlHash() }
    }

    @Test
    fun requestRejectsStatusLengthOutsideBounds() {
        assertStatusRejected { it.setLength(0L) }
        assertStatusRejected { it.setLength(MAX_STATUS_LIST_LENGTH + 1) }
        assertStatusRejected { it.setLength(-1L) }
    }

    @Test
    fun requestAcceptsStatusLengthBounds() {
        verifyRequest(status = issuerStatus().toBuilder().setLength(1L).build())
        verifyRequest(status = issuerStatus().toBuilder().setLength(MAX_STATUS_LIST_LENGTH).build())
    }

    @Test
    fun requestRejectsUnknownStatusPurpose() {
        assertStatusRejected { it.setPurpose(ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_UNSPECIFIED) }
        assertStatusRejected { it.setPurposeValue(UNRECOGNIZED_PURPOSE_NUMBER) }
        assertRequestRejected(ZkProviderFailureReason.PROOF_REJECTED) {
            verifyRequest(status = Manifest.ZkCommonCredentialRootIssuerStatusExpectation.getDefaultInstance())
        }
    }

    @Test
    fun fourProofResultForStatusQualifiedRequestIsMalformed() {
        val fourProof =
            Manifest.ZkPresentationBoundClaimBundleVerification
                .newBuilder()
                .setBundleKind(BUNDLE_KIND)
                .setVerifiedStageCount(NATIVE_PRODUCTION_STAGE_COUNT)
                .setProofSuite(PROOF_SUITE)
                .setStatement(
                    Manifest.ZkPresentationBoundClaimStatement.parseFrom(statement().toByteArray()),
                )
        val result = Manifest.ZkProviderOperationResult.newBuilder().setClaimProofBundleVerification(fourProof)

        assertResponseRejected(ZkProviderFailureReason.MALFORMED_PROOF, result.build())
    }

    @Test
    fun emptyResultIsMalformed() {
        assertResponseRejected(
            ZkProviderFailureReason.MALFORMED_PROOF,
            Manifest.ZkProviderOperationResult.getDefaultInstance(),
        )
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) { it.clear() }
    }

    @Test
    fun wrongProofCountIsMalformed() {
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) {
            it.setVerifiedProofCount(NATIVE_PRODUCTION_STAGE_COUNT)
        }
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) {
            it.setVerifiedProofCount(STATUS_QUALIFIED_PROOF_COUNT + 1)
        }
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) { it.clearVerifiedProofCount() }
    }

    @Test
    fun wrongStatusPurposeIsMalformed() {
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) {
            it.setStatusPurpose(ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_SUSPENSION)
        }
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) { it.clearStatusPurpose() }
    }

    @Test
    fun wrongBundleKindIsMalformed() {
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) {
            it.setBundleKind(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1)
        }
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) { it.clearBundleKind() }
    }

    @Test
    fun wrongProofSuiteIsMalformed() {
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) {
            it.setProofSuite(NON_PRODUCTION_PROOF_SUITE)
        }
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) {
            it.setProofSuite(Manifest.ZkProofSuite.ZK_PROOF_SUITE_UNSPECIFIED)
        }
    }

    @Test
    fun missingStatementIsMalformed() {
        assertReportRejected(ZkProviderFailureReason.MALFORMED_PROOF) { it.clearStatement() }
    }

    @Test
    fun untrustedOrMissingStatementIssuerIsRejected() {
        assertStatementRejected(ZkProviderFailureReason.PROOF_REJECTED) { it.setIssuer(publicKey(8, 9)) }
        assertStatementRejected(ZkProviderFailureReason.PROOF_REJECTED) { it.clearIssuer() }
    }

    @Test
    fun expiredOrOverlongPresentationIsRejected() {
        assertStatementRejected(ZkProviderFailureReason.PROOF_REJECTED) {
            it.setPresentationExpiryUnix(VERIFICATION_TIME_UNIX)
        }
        assertStatementRejected(ZkProviderFailureReason.PROOF_REJECTED) {
            it.setPresentationExpiryUnix(VERIFICATION_TIME_UNIX + MAX_PRESENTATION_LIFETIME_SECONDS + 1)
        }
        assertStatementRejected(ZkProviderFailureReason.PROOF_REJECTED) { it.clearPresentationExpiryUnix() }
        assertStatementRejected(ZkProviderFailureReason.PROOF_REJECTED) { it.setPresentationExpiryUnix(-1L) }
    }

    @Test
    fun presentationAtMaximumWindowIsAccepted() {
        val statement =
            statement()
                .toBuilder()
                .setPresentationExpiryUnix(VERIFICATION_TIME_UNIX + MAX_PRESENTATION_LIFETIME_SECONDS)
                .build()

        verify(StatusQualifiedBridge(resultOf(verification(statement))), verifyRequest()).close()
    }

    @Test
    fun malformedStatementShapeIsMalformed() {
        assertStatementRejected(ZkProviderFailureReason.MALFORMED_PROOF) {
            it.setCredentialBinding(bytes(BYTES_32 - 1, 13))
        }
        assertStatementRejected(ZkProviderFailureReason.MALFORMED_PROOF) { it.clearCredentialBinding() }
        assertStatementRejected(ZkProviderFailureReason.MALFORMED_PROOF) {
            it.setClaimNameHash(bytes(BYTES_32 + 1, 11))
        }
        assertStatementRejected(ZkProviderFailureReason.MALFORMED_PROOF) { it.clearSessionLinkCommitment() }
        assertStatementRejected(ZkProviderFailureReason.MALFORMED_PROOF) {
            it.setClaimValueLength(CLAIM_VALUE.size + 1)
        }
        assertStatementRejected(ZkProviderFailureReason.MALFORMED_PROOF) { it.setClaimValueLength(-1) }
    }

    @Test
    fun sessionBindingMismatchWithDispatchedBundleIsRejected() {
        val otherBinding = sessionBinding().toBuilder().setNonceHash(bytes(BYTES_32, 9)).build()
        val bundle =
            statusQualifiedBundle()
                .toBuilder()
                .setClaimProofBundle(claimProofBundle().toBuilder().setSessionBinding(otherBinding))
                .build()

        assertBundleRejected(ZkProviderFailureReason.PROOF_REJECTED, bundle)
    }

    @Test
    fun incompleteDispatchedBundleIsMalformed() {
        assertBundleRejected(
            ZkProviderFailureReason.MALFORMED_PROOF,
            statusQualifiedBundle().toBuilder().clearIssuerCredentialStatus().build(),
        )
        assertBundleRejected(
            ZkProviderFailureReason.MALFORMED_PROOF,
            statusQualifiedBundle().toBuilder().clearClaimProofBundle().build(),
        )
        assertBundleRejected(
            ZkProviderFailureReason.MALFORMED_PROOF,
            statusQualifiedBundle()
                .toBuilder()
                .setClaimProofBundle(claimProofBundle().toBuilder().removeStages(0))
                .build(),
        )
        assertBundleRejected(
            ZkProviderFailureReason.MALFORMED_PROOF,
            statusQualifiedBundle()
                .toBuilder()
                .setIssuerCredentialStatus(
                    Manifest.ZkCredentialStatusProofPackage.newBuilder().setProofSuite(NON_PRODUCTION_PROOF_SUITE),
                ).build(),
        )
    }

    @Test
    fun typedProviderErrorsPropagateWithStableReasons() {
        mapOf(
            Manifest.ZkErrorReason.ZK_ERROR_REASON_INVALID_PROOF to ZkProviderFailureReason.PROOF_REJECTED,
            Manifest.ZkErrorReason.ZK_ERROR_REASON_BINDING_MISMATCH to ZkProviderFailureReason.PROOF_REJECTED,
            Manifest.ZkErrorReason.ZK_ERROR_REASON_UNTRUSTED_ISSUER to ZkProviderFailureReason.PROOF_REJECTED,
            Manifest.ZkErrorReason.ZK_ERROR_REASON_PRESENTATION_EXPIRED to ZkProviderFailureReason.PROOF_REJECTED,
            Manifest.ZkErrorReason.ZK_ERROR_REASON_INVALID_PROOF_ENCODING to ZkProviderFailureReason.MALFORMED_PROOF,
            Manifest.ZkErrorReason.ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE to ZkProviderFailureReason.UNSUPPORTED_SUITE,
            Manifest.ZkErrorReason.ZK_ERROR_REASON_BACKEND_FAILURE to ZkProviderFailureReason.INTERNAL_FAILURE,
        ).forEach { (wireReason, expected) ->
            val bridge = StatusQualifiedBridge(errorOf(wireReason))
            val error = assertFailsWith<ReallyMeZkProviderException> { verify(bridge, verifyRequest()) }

            assertEquals(expected, error.reason)
            assertEquals(1, bridge.dispatchCalls)
        }
    }

    @Test
    fun missingOutcomeFailsClosed() {
        val bridge = StatusQualifiedBridge { it }
        val error = assertFailsWith<ReallyMeZkProviderException> { verify(bridge, verifyRequest()) }

        assertEquals(ZkProviderFailureReason.EMPTY_BUFFER, error.reason)
    }

    @Test
    fun unsupportedVerifierFailsClosed() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                UnsupportedReallyMeZkStatusQualifiedClaimBundleVerifier.verifyStatusQualifiedClaimBundle(
                    request = verifyRequest(),
                    statusQualifiedClaimProofBundle = UnsupportedStatusQualifiedClaimProofBundleHandle,
                )
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, error.reason)
    }

    @Test
    fun unsupportedBundleProviderFailsClosedForStatusQualifiedVerification() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                UnsupportedReallyMeZkClaimProofBundleProvider.verifyStatusQualifiedClaimBundle(
                    request = verifyRequest(),
                    statusQualifiedClaimProofBundle = UnsupportedStatusQualifiedClaimProofBundleHandle,
                )
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, error.reason)
    }

    private fun assertRequestRejected(
        expected: ZkProviderFailureReason,
        construct: () -> ZkStatusQualifiedClaimBundleVerifyRequest,
    ) {
        val error = assertFailsWith<ReallyMeZkProviderException> { construct() }

        assertEquals(expected, error.reason)
    }

    private fun assertStatusRejected(
        change: (Manifest.ZkCommonCredentialRootIssuerStatusExpectation.Builder) -> Unit,
    ) {
        val status = issuerStatus().toBuilder().also(change).build()

        assertRequestRejected(ZkProviderFailureReason.PROOF_REJECTED) { verifyRequest(status = status) }
    }

    private fun assertReportRejected(
        expected: ZkProviderFailureReason,
        change: (Manifest.ZkStatusQualifiedClaimProofBundleVerification.Builder) -> Unit,
    ) {
        assertResponseRejected(expected, resultOf(verification().toBuilder().also(change).build()))
    }

    private fun assertStatementRejected(
        expected: ZkProviderFailureReason,
        change: (Manifest.ZkStatusQualifiedClaimStatement.Builder) -> Unit,
    ) {
        assertResponseRejected(expected, resultOf(verification(statement().toBuilder().also(change).build())))
    }

    private fun assertResponseRejected(
        expected: ZkProviderFailureReason,
        result: Manifest.ZkProviderOperationResult,
    ) {
        val bridge = StatusQualifiedBridge { it.setResult(result) }
        val error = assertFailsWith<ReallyMeZkProviderException> { verify(bridge, verifyRequest()) }

        assertEquals(expected, error.reason)
        assertEquals(1, bridge.dispatchCalls)
    }

    private fun assertBundleRejected(
        expected: ZkProviderFailureReason,
        bundle: Manifest.ZkStatusQualifiedClaimProofBundle,
    ) {
        val bridge = StatusQualifiedBridge(resultOf(verification()))
        val error = assertFailsWith<ReallyMeZkProviderException> { verify(bridge, verifyRequest(), bundle) }

        assertEquals(expected, error.reason)
    }

    private fun verify(
        bridge: StatusQualifiedBridge,
        request: ZkStatusQualifiedClaimBundleVerifyRequest,
        bundle: Manifest.ZkStatusQualifiedClaimProofBundle = statusQualifiedBundle(),
    ): ZkStatusQualifiedClaimBundleVerification =
        ReallyMeZkNativeProvider(contextHandle = CONTEXT_HANDLE, bridge = bridge).verifyStatusQualifiedClaimBundle(
            request,
            ZkNativeStatusQualifiedClaimProofBundleHandle(bundle),
        )

    private fun verifyRequest(
        binding: Manifest.ZkSessionBinding = sessionBinding(),
        trustedIssuers: List<Manifest.ZkP256PublicKey> = listOf(issuer()),
        expectedIssuer: Manifest.ZkP256PublicKey = issuer(),
        verificationTimeUnix: Long = VERIFICATION_TIME_UNIX,
        status: Manifest.ZkCommonCredentialRootIssuerStatusExpectation = issuerStatus(),
    ): ZkStatusQualifiedClaimBundleVerifyRequest =
        ZkStatusQualifiedClaimBundleVerifyRequest(
            expectedSessionBinding = binding,
            expectedIssuer = expectedIssuer,
            trustedIssuers = trustedIssuers,
            verificationTimeUnix = verificationTimeUnix,
            currentIssuerStatus = status,
        )

    private fun resultOf(
        verification: Manifest.ZkStatusQualifiedClaimProofBundleVerification,
    ): Manifest.ZkProviderOperationResult =
        Manifest.ZkProviderOperationResult
            .newBuilder()
            .setStatusQualifiedClaimProofBundleVerification(verification)
            .build()

    private fun errorOf(
        reason: Manifest.ZkErrorReason,
    ): (Manifest.ZkProviderOperationResponse.Builder) -> Manifest.ZkProviderOperationResponse.Builder =
        { it.setError(Manifest.ZkError.newBuilder().setReason(reason)) }

    private fun verification(
        statement: Manifest.ZkStatusQualifiedClaimStatement = statement(),
    ): Manifest.ZkStatusQualifiedClaimProofBundleVerification =
        Manifest.ZkStatusQualifiedClaimProofBundleVerification
            .newBuilder()
            .setBundleKind(BUNDLE_KIND)
            .setVerifiedProofCount(STATUS_QUALIFIED_PROOF_COUNT)
            .setProofSuite(PROOF_SUITE)
            .setStatement(statement)
            .setStatusPurpose(ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_REVOCATION)
            .build()

    private fun statement(): Manifest.ZkStatusQualifiedClaimStatement =
        Manifest.ZkStatusQualifiedClaimStatement
            .newBuilder()
            .setIssuer(issuer())
            .setClaimNameHash(bytes(BYTES_32, 11))
            .setClaimValue(ByteString.copyFrom(CLAIM_VALUE))
            .setClaimValueLength(CLAIM_VALUE.size)
            .setPresentationExpiryUnix(PRESENTATION_EXPIRY_UNIX)
            .setSessionLinkCommitment(bytes(BYTES_32, 12))
            .setCredentialBinding(bytes(BYTES_32, 13))
            .build()

    private fun statusQualifiedBundle(): Manifest.ZkStatusQualifiedClaimProofBundle =
        Manifest.ZkStatusQualifiedClaimProofBundle
            .newBuilder()
            .setClaimProofBundle(claimProofBundle())
            .setIssuerCredentialStatus(
                Manifest.ZkCredentialStatusProofPackage
                    .newBuilder()
                    .setProofSuite(PROOF_SUITE)
                    .setProof(bytes(PROOF_BYTE_COUNT, 5)),
            ).build()

    private fun claimProofBundle(): Manifest.ZkClaimProofBundle =
        Manifest.ZkClaimProofBundle
            .newBuilder()
            .setFormatVersion(CLAIM_PROOF_BUNDLE_FORMAT_VERSION)
            .setBundleKind(BUNDLE_KIND)
            .setSessionBinding(sessionBinding())
            .setProofSuite(PROOF_SUITE)
            .addAllStages(
                List(NATIVE_PRODUCTION_STAGE_COUNT) {
                    Manifest.ZkClaimProofBundleStageProofPackage.getDefaultInstance()
                },
            ).build()

    private fun issuerStatus(): Manifest.ZkCommonCredentialRootIssuerStatusExpectation =
        Manifest.ZkCommonCredentialRootIssuerStatusExpectation
            .newBuilder()
            .setRoot(bytes(BYTES_32, 5))
            .setLength(STATUS_LIST_LENGTH)
            .setListId(bytes(BYTES_32, 6))
            .setUrlHash(bytes(BYTES_32, 7))
            .setPurpose(ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_REVOCATION)
            .build()

    private fun sessionBinding(): Manifest.ZkSessionBinding =
        Manifest.ZkSessionBinding
            .newBuilder()
            .setNonceHash(bytes(BYTES_32, 1))
            .setAudienceHash(bytes(BYTES_32, 2))
            .build()

    private fun issuer(): Manifest.ZkP256PublicKey = publicKey(3, 4)

    private fun publicKey(
        x: Byte,
        y: Byte,
    ): Manifest.ZkP256PublicKey =
        Manifest.ZkP256PublicKey
            .newBuilder()
            .setX(bytes(BYTES_32, x))
            .setY(bytes(BYTES_32, y))
            .build()

    private fun bytes(
        count: Int,
        value: Byte,
    ): ByteString = ByteString.copyFrom(ByteArray(count) { value })

    private class StatusQualifiedBridge(
        private val outcome: (
            Manifest.ZkProviderOperationResponse.Builder,
        ) -> Manifest.ZkProviderOperationResponse.Builder,
    ) : ReallyMeZkPlatformNativeBridge {
        constructor(result: Manifest.ZkProviderOperationResult) : this({ it.setResult(result) })

        val operations: MutableList<Manifest.ZkStatusQualifiedClaimProofBundleVerifyOperation> = mutableListOf()

        val dispatchCalls: Int
            get() = operations.size

        override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
            ZkNativeContextResult(statusCode = 0, errorReasonCode = 0, contextHandle = CONTEXT_HANDLE)

        override fun dispatch(
            contextHandle: Long,
            request: ByteArray,
        ): ZkNativeDispatchResult {
            assertEquals(CONTEXT_HANDLE, contextHandle)
            val operation = Manifest.ZkProviderOperationRequest.parseFrom(request)
            assertEquals(
                Manifest.ZkProviderOperationRequest.OperationCase.VERIFY_STATUS_QUALIFIED_CLAIM_PROOF_BUNDLE,
                operation.operationCase,
            )
            operations.add(operation.verifyStatusQualifiedClaimProofBundle)
            val response =
                outcome(
                    Manifest.ZkProviderOperationResponse
                        .newBuilder()
                        .setRequestSha256(ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(request))),
                )
            return ZkNativeDispatchResult(statusCode = 0, errorReasonCode = 0, output = response.build().toByteArray())
        }

        override fun contextDestroy(contextHandle: Long): ZkNativeStatus =
            ZkNativeStatus(statusCode = 0, errorReasonCode = 0)
    }

    private companion object {
        const val CONTEXT_HANDLE: Long = 7L
        const val PROOF_BYTE_COUNT: Int = 96
        const val VERIFICATION_TIME_UNIX: Long = 1_000L
        const val PRESENTATION_EXPIRY_UNIX: Long = 1_200L
        const val STATUS_LIST_LENGTH: Long = 4_096L
        const val MAX_STATUS_LIST_LENGTH: Long = 1_000_000L
        const val UNRECOGNIZED_PURPOSE_NUMBER: Int = 99
        val BUNDLE_KIND: ZkClaimProofBundleKind =
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1
        val CLAIM_VALUE: ByteArray = byteArrayOf(1, 2, 3)
        val NON_PRODUCTION_PROOF_SUITE: Manifest.ZkProofSuite =
            Manifest.ZkProofSuite.ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_ZK_NO_IPA
    }
}
