// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import com.google.protobuf.ByteString
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleProveRequest
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerifyRequest
import reallyme.zk.v1.Manifest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReallyMeZkProviderTest {
    @Test
    fun stageRequestToStringRedactsPrivateWitnessMerklePosition() {
        val request =
            ZkStageRequest(
                bundleKind = ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                stage = ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM,
                witnessInput = credentialSubjectClaimWitnessInput(),
            )

        val display = request.toString()
        val directDisplay = "$request"

        assertEquals(display, directDisplay)
        assertTrue(display.contains("witnessInput=<redacted>"))
        assertFalse(display.contains("leafIndex"))
        assertFalse(display.contains("leaf_index"))
        assertFalse(display.contains("pathLength"))
        assertFalse(display.contains("path_length"))
        assertFalse(display.contains("37"))
        assertFalse(display.contains("4"))
    }

    @Test
    fun bundleRequestToStringRedactsBindingsAndIssuers() {
        val binding = sessionBinding()
        val issuer = issuer()
        val proveRequest =
            ZkClaimProofBundleProveRequest(
                bundleKind = ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                sessionBinding = binding,
            )
        val verifyRequest =
            ZkPresentationBoundClaimBundleVerifyRequest(
                expectedSessionBinding = binding,
                trustedIssuers = listOf(issuer),
                verificationTimeUnix = 42,
            )

        assertEquals(
            me.really.zk.circuits.ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
            proveRequest.credentialHashAlgorithm,
        )
        val proveDisplay = proveRequest.toString()
        val verifyDisplay = verifyRequest.toString()

        assertTrue(proveDisplay.contains("sessionBinding=<redacted>"))
        assertTrue(verifyDisplay.contains("trustedIssuers=<redacted>"))
        assertFalse(proveDisplay.contains("nonceHash"))
        assertFalse(verifyDisplay.contains("nonceHash"))
        assertFalse(verifyDisplay.contains("issuer"))
    }

    @Test
    fun bundleVerifyRequestRejectsZeroVerifierTime() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkPresentationBoundClaimBundleVerifyRequest(
                    expectedSessionBinding = sessionBinding(),
                    trustedIssuers = listOf(issuer()),
                    verificationTimeUnix = 0L,
                )
            }

        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
    }

    @Test
    fun unsupportedBundleProviderFailsClosedForVerification() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                UnsupportedReallyMeZkClaimProofBundleProvider.verifyPresentationBoundClaimBundle(
                    request = bundleVerifyRequest(verificationTimeUnix = 100L),
                    claimProofBundle = UnsupportedClaimProofBundleHandle,
                )
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, error.reason)
    }

    @Test
    fun unsupportedBundleVerifierFailsClosedForVerification() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                UnsupportedReallyMeZkPresentationBoundClaimBundleVerifier.verifyPresentationBoundClaimBundle(
                    request = bundleVerifyRequest(verificationTimeUnix = 100L),
                    claimProofBundle = UnsupportedClaimProofBundleHandle,
                )
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, error.reason)
    }

    @Test
    fun unsupportedBundleProviderFailsClosedForStageVerification() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                UnsupportedReallyMeZkClaimProofBundleProvider.verifyDiagnosticStage(
                    request =
                        ZkStageVerifyRequest(
                            bundleKind = ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                            stage = ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                            expectedSessionBinding = sessionBinding(),
                        ),
                    proof = UnsupportedProofHandle,
                )
            }

        assertEquals(ZkProviderFailureReason.PROVIDER_UNAVAILABLE, error.reason)
    }

    @Test
    fun witnessMetricsAdmitLargestExactCircuitTransportBudget() {
        val metrics = ZkWitnessMetrics(byteCount = CLAIM_PROOF_BUNDLE_WITNESS_TRANSPORT_BUDGET_BYTES)

        assertEquals(CLAIM_PROOF_BUNDLE_WITNESS_TRANSPORT_BUDGET_BYTES, metrics.byteCount)
    }

    @Test
    fun witnessMetricsRejectAboveExactCircuitTransportBudget() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkWitnessMetrics(byteCount = CLAIM_PROOF_BUNDLE_WITNESS_TRANSPORT_BUDGET_BYTES + 1)
            }

        assertEquals(ZkProviderFailureReason.OVERSIZED_BUFFER, error.reason)
    }

    @Test
    fun nativeErrorMappingKeepsUnsupportedSuiteDistinctFromCircuitFailures() {
        assertEquals(
            ZkProviderFailureReason.UNSUPPORTED_SUITE,
            providerFailureReason(Manifest.ZkErrorReason.ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE),
        )
        assertEquals(
            ZkProviderFailureReason.UNSUPPORTED_TRANSPORT,
            providerFailureReason(Manifest.ZkErrorReason.ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT),
        )
        assertEquals(
            ZkProviderFailureReason.UNSUPPORTED_CIRCUIT,
            providerFailureReason(Manifest.ZkErrorReason.ZK_ERROR_REASON_UNSUPPORTED_CIRCUIT),
        )
        assertEquals(
            ZkProviderFailureReason.UNSUPPORTED_CIRCUIT,
            providerFailureReason(Manifest.ZkErrorReason.ZK_ERROR_REASON_UNKNOWN_CIRCUIT),
        )
    }

    @Test
    fun nativeErrorMappingKeepsPolicyRejectionsOutOfInternalFailure() {
        listOf(
            Manifest.ZkErrorReason.ZK_ERROR_REASON_UNTRUSTED_ISSUER,
            Manifest.ZkErrorReason.ZK_ERROR_REASON_PRESENTATION_EXPIRED,
            Manifest.ZkErrorReason.ZK_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR,
        ).forEach { reason ->
            assertEquals(ZkProviderFailureReason.PROOF_REJECTED, providerFailureReason(reason))
        }
    }

    @Test
    fun claimProofBundleVerificationRejectsExpiredPresentation() {
        val request = bundleVerifyRequest(verificationTimeUnix = 100L)
        val statement = verifiedClaimStatement(presentationExpiryUnix = 100L)

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                requireFreshPresentation(statement, request)
            }

        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
    }

    @Test
    fun claimProofBundleVerificationRejectsPresentationBeyondWindow() {
        val request = bundleVerifyRequest(verificationTimeUnix = 100L)
        val statement = verifiedClaimStatement(presentationExpiryUnix = 401L)

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                requireFreshPresentation(statement, request)
            }

        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
    }

    @Test
    fun claimProofBundleVerificationAcceptsPresentationAtMaximumWindow() {
        val request = bundleVerifyRequest(verificationTimeUnix = 100L)
        val statement = verifiedClaimStatement(presentationExpiryUnix = 400L)

        requireFreshPresentation(statement, request)
    }

    @Test
    fun claimProofBundleVerificationSurfacesCredentialBindingAndClosesStorage() {
        val verified =
            verifiedClaimProofBundle(
                verification = claimProofBundleVerification(verifiedClaimStatement(presentationExpiryUnix = 400L)),
                request = bundleVerifyRequest(verificationTimeUnix = 100L),
                claimProofBundle = claimProofBundle(),
            )

        verified.credentialBinding.useBytes { bytes ->
            assertContentEquals(ByteArray(BYTES_32) { 13 }, bytes)
        }
        verified.close()

        assertEquals(0, verified.credentialBinding.size)
    }

    @Test
    fun claimProofBundleVerificationRejectsMalformedCredentialBinding() {
        val statement =
            verifiedClaimStatement(presentationExpiryUnix = 400L)
                .toBuilder()
                .setCredentialBinding(ByteString.copyFrom(ByteArray(BYTES_32 - 1) { 13 }))
                .build()

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                verifiedClaimProofBundle(
                    verification = claimProofBundleVerification(statement),
                    request = bundleVerifyRequest(verificationTimeUnix = 100L),
                    claimProofBundle = claimProofBundle(),
                )
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_PROOF, error.reason)
    }

    @Test
    fun claimProofBundleVerificationRejectsMissingCredentialBinding() {
        val statement =
            verifiedClaimStatement(presentationExpiryUnix = 400L)
                .toBuilder()
                .clearCredentialBinding()
                .build()

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                verifiedClaimProofBundle(
                    verification = claimProofBundleVerification(statement),
                    request = bundleVerifyRequest(verificationTimeUnix = 100L),
                    claimProofBundle = claimProofBundle(),
                )
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_PROOF, error.reason)
    }

    @Test
    fun stageVerifyRequestToStringRedactsSessionBinding() {
        val request =
            ZkStageVerifyRequest(
                bundleKind = ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                stage = ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                expectedSessionBinding = sessionBinding(),
            )

        val display = request.toString()

        assertTrue(display.contains("expectedSessionBinding=<redacted>"))
        assertFalse(display.contains("nonceHash"))
        assertFalse(display.contains("audienceHash"))
    }

    @Test
    fun sensitiveBytesWipesScopedCopiesAndRejectsUseAfterClose() {
        val ownedBytes = byteArrayOf(1, 2, 3)
        val sensitive = ZkSensitiveBytes(ownedBytes)
        lateinit var scopedCopy: ByteArray

        val sum =
            sensitive.useBytes { bytes ->
                scopedCopy = bytes
                bytes.sum()
            }

        assertEquals(6, sum)
        assertContentEquals(byteArrayOf(0, 0, 0), scopedCopy)
        assertEquals("ZkSensitiveBytes(<redacted>)", sensitive.toString())
        sensitive.close()
        assertContentEquals(byteArrayOf(0, 0, 0), ownedBytes)
        sensitive.close()
        assertEquals(0, sensitive.size)
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                sensitive.useBytes { bytes -> bytes.size }
            }
        assertEquals(ZkProviderFailureReason.CLEANUP_FAILED, error.reason)
    }

    private fun credentialSubjectClaimWitnessInput(): Manifest.ZkStageWitnessInput =
        Manifest.ZkStageWitnessInput
            .newBuilder()
            .setCredentialSubjectClaim(
                Manifest.ZkCredentialSubjectClaimInput
                    .newBuilder()
                    .setProof(
                        Manifest.ZkInputMerkleClaimProof
                            .newBuilder()
                            .setLeafIndex(PRIVATE_LEAF_INDEX)
                            .setPath(
                                Manifest.ZkInputMerklePath
                                    .newBuilder()
                                    .setPathLength(PRIVATE_PATH_LENGTH),
                            ),
                    ),
            ).build()

    private fun sessionBinding(): Manifest.ZkSessionBinding =
        Manifest.ZkSessionBinding
            .newBuilder()
            .setNonceHash(
                ByteString.copyFrom(ByteArray(32) { 1 }),
            ).setAudienceHash(
                ByteString.copyFrom(ByteArray(32) { 2 }),
            ).build()

    private fun bundleVerifyRequest(verificationTimeUnix: Long): ZkPresentationBoundClaimBundleVerifyRequest =
        ZkPresentationBoundClaimBundleVerifyRequest(
            expectedSessionBinding = sessionBinding(),
            trustedIssuers = listOf(issuer()),
            verificationTimeUnix = verificationTimeUnix,
        )

    private fun claimProofBundleVerification(
        statement: Manifest.ZkPresentationBoundClaimStatement,
    ): Manifest.ZkPresentationBoundClaimBundleVerification =
        Manifest.ZkPresentationBoundClaimBundleVerification
            .newBuilder()
            .setBundleKind(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1)
            .setVerifiedStageCount(NATIVE_PRODUCTION_STAGE_COUNT)
            .setProofSuite(PROOF_SUITE)
            .setStatement(statement)
            .build()

    private fun claimProofBundle(): Manifest.ZkClaimProofBundle =
        Manifest.ZkClaimProofBundle
            .newBuilder()
            .setFormatVersion(1)
            .setBundleKind(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1)
            .setSessionBinding(sessionBinding())
            .setProofSuite(PROOF_SUITE)
            .addAllStages(
                List(NATIVE_PRODUCTION_STAGE_COUNT) {
                    Manifest.ZkClaimProofBundleStageProofPackage.getDefaultInstance()
                },
            ).build()

    private fun verifiedClaimStatement(presentationExpiryUnix: Long): Manifest.ZkPresentationBoundClaimStatement =
        Manifest.ZkPresentationBoundClaimStatement
            .newBuilder()
            .setIssuer(issuer())
            .setClaimNameHash(ByteString.copyFrom(ByteArray(BYTES_32) { 11 }))
            .setClaimValue(ByteString.copyFrom(byteArrayOf(1, 2, 3)))
            .setClaimValueLength(3)
            .setCredentialBinding(ByteString.copyFrom(ByteArray(BYTES_32) { 13 }))
            .setSessionLinkCommitment(ByteString.copyFrom(ByteArray(BYTES_32) { 12 }))
            .setPresentationExpiryUnix(presentationExpiryUnix)
            .build()

    private fun issuer(): Manifest.ZkP256PublicKey =
        Manifest.ZkP256PublicKey
            .newBuilder()
            .setX(
                ByteString.copyFrom(ByteArray(32) { 3 }),
            ).setY(
                ByteString.copyFrom(ByteArray(32) { 4 }),
            ).build()

    private companion object {
        const val PRIVATE_LEAF_INDEX: Int = 37
        const val PRIVATE_PATH_LENGTH: Int = 4
        const val CLAIM_PROOF_BUNDLE_WITNESS_TRANSPORT_BUDGET_BYTES: Int = 4 * 1_024 * 1_024
    }
}
