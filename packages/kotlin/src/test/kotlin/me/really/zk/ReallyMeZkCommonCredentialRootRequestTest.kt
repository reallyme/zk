// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import com.google.protobuf.ByteString
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.commonroot.COMMON_CREDENTIAL_ROOT_PROOF_COUNT
import me.really.zk.commonroot.ZkCommonCredentialRootPersonaMode
import me.really.zk.commonroot.ZkCommonCredentialRootPresentationProveRequest
import me.really.zk.commonroot.ZkCommonCredentialRootStageProveRequest
import me.really.zk.commonroot.ZkCommonCredentialRootVerifyRequest
import reallyme.zk.v1.Manifest
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private typealias RootSlot = Manifest.ZkCommonCredentialRootProofSlot
private typealias RootStageOperation = Manifest.ZkCommonCredentialRootStageProveOperation
private typealias RootPresentationOperation = Manifest.ZkCommonCredentialRootPresentationProveOperation

class ReallyMeZkCommonCredentialRootRequestTest {
    @Test
    fun admitsOrderedNineSlotShapeWithoutRenderingPrivatePolicy() {
        val (presentation, policy) = commonCredentialRootInput()
        val request =
            ZkCommonCredentialRootVerifyRequest(
                ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA,
                presentation,
                policy,
            )

        assertEquals(COMMON_CREDENTIAL_ROOT_PROOF_COUNT, request.presentation.proofsCount)
        assertTrue(request.toString().contains("<redacted>"))
        assertFalse(request.toString().contains("claimValue"))
    }

    @Test
    fun rejectsReorderedProofSlots() {
        val (presentation, policy) = commonCredentialRootInput()
        val proofs = presentation.proofsList.toMutableList()
        val firstLineage = proofs[2]
        proofs[2] = proofs[3]
        proofs[3] = firstLineage
        val reordered =
            presentation
                .toBuilder()
                .clearProofs()
                .addAllProofs(proofs)
                .build()

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkCommonCredentialRootVerifyRequest(
                    ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA,
                    reordered,
                    policy,
                )
            }
        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
    }

    @Test
    fun rejectsVerifierBindingMismatch() {
        val (presentation, policy) = commonCredentialRootInput()
        val changed = policy.toBuilder().setChallenge(ByteString.copyFrom(ByteArray(BYTES_32) { 9 })).build()

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkCommonCredentialRootVerifyRequest(
                    ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA,
                    presentation,
                    changed,
                )
            }
        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
    }

    @Test
    fun rejectsOversizedProofBeforeNativeDispatch() {
        val (presentation, policy) = commonCredentialRootInput()
        val proofs = presentation.proofsList.toMutableList()
        proofs[0] =
            proofs[0]
                .toBuilder()
                .setProof(ByteString.copyFrom(ByteArray(256 * 1_024 + 1)))
                .build()
        val oversized =
            presentation
                .toBuilder()
                .clearProofs()
                .addAllProofs(proofs)
                .build()

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkCommonCredentialRootVerifyRequest(
                    ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA,
                    oversized,
                    policy,
                )
            }
        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
    }

    @Test
    fun nativeProviderAdmitsOnlyNineProofVerificationResult() {
        val (presentation, policy) = commonCredentialRootInput()
        val request =
            ZkCommonCredentialRootVerifyRequest(
                ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA,
                presentation,
                policy,
            )
        val bridge = CommonCredentialRootRecordingBridge(COMMON_CREDENTIAL_ROOT_PROOF_COUNT)
        val provider = ReallyMeZkNativeProvider(7L, bridge)

        val result = provider.verifyCommonCredentialRoot(request)

        assertEquals(ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA, result.mode)
        assertEquals(COMMON_CREDENTIAL_ROOT_PROOF_COUNT, result.verifiedProofCount)
        assertEquals(1, bridge.verifyCalls)
    }

    @Test
    fun nativeProviderRejectsIncompleteVerificationResult() {
        val (presentation, policy) = commonCredentialRootInput()
        val request =
            ZkCommonCredentialRootVerifyRequest(
                ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA,
                presentation,
                policy,
            )
        val bridge = CommonCredentialRootRecordingBridge(COMMON_CREDENTIAL_ROOT_PROOF_COUNT - 1)
        val provider = ReallyMeZkNativeProvider(7L, bridge)

        val error = assertFailsWith<ReallyMeZkProviderException> { provider.verifyCommonCredentialRoot(request) }

        assertEquals(ZkProviderFailureReason.MALFORMED_PROOF, error.reason)
    }

    @Test
    fun rejectsMissingIssuerStatusPolicyBeforeNativeDispatch() {
        val (presentation, policy) = commonCredentialRootInput()
        val changed = policy.toBuilder().removeIssuerStatus(1).build()

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkCommonCredentialRootVerifyRequest(
                    ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA,
                    presentation,
                    changed,
                )
            }
        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
    }

    @Test
    fun rejectsMalformedIssuerStatusPolicyBeforeNativeDispatch() {
        val (presentation, policy) = commonCredentialRootInput()
        val invalidStatus =
            policy
                .getIssuerStatus(0)
                .toBuilder()
                .clearListId()
                .build()
        val changed =
            policy
                .toBuilder()
                .setIssuerStatus(0, invalidStatus)
                .build()

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkCommonCredentialRootVerifyRequest(
                    ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA,
                    presentation,
                    changed,
                )
            }
        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
    }

    @Test
    fun typedStageRequestRejectsWrongCircuitAndInputBeforeDispatch() {
        val valid = commonCredentialRootStageOperation()
        val wrongStage =
            valid
                .toBuilder()
                .setCircuitRef(
                    valid.circuitRef
                        .toBuilder()
                        .setStage(Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_LINEAGE),
                ).build()
        val wrongInput =
            valid
                .toBuilder()
                .clearRootAttestation()
                .setRootStatus(Manifest.ZkCommonCredentialRootStatusInput.getDefaultInstance())
                .build()

        for (operation in listOf(wrongStage, wrongInput)) {
            val error =
                assertFailsWith<ReallyMeZkProviderException> {
                    ZkCommonCredentialRootStageProveRequest(operation)
                }
            assertEquals(ZkProviderFailureReason.MALFORMED_WITNESS, error.reason)
        }
    }

    @Test
    fun typedStageRequestRejectsMalformedBindingAndRedactsInput() {
        val valid = commonCredentialRootStageOperation()
        val accepted = ZkCommonCredentialRootStageProveRequest(valid)
        assertTrue(accepted.toString().contains("<redacted>"))
        val malformed =
            valid
                .toBuilder()
                .setExpectedBinding(valid.expectedBinding.toBuilder().clearNonceHash())
                .build()
        val error = assertFailsWith<ReallyMeZkProviderException> { ZkCommonCredentialRootStageProveRequest(malformed) }
        assertEquals(ZkProviderFailureReason.MALFORMED_WITNESS, error.reason)
    }

    @Test
    fun issuerCredentialStatusStageRequiresMatchingInput() {
        val baseline = commonCredentialRootStageOperation()
        val operation =
            baseline
                .toBuilder()
                .setSlot(
                    Manifest.ZkCommonCredentialRootProofSlot
                        .ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0,
                ).setCircuitRef(
                    baseline.circuitRef
                        .toBuilder()
                        .setStage(Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_ISSUER_CREDENTIAL_STATUS),
                ).setIssuerCredentialStatus(
                    Manifest.ZkCommonCredentialRootIssuerCredentialStatusInput.getDefaultInstance(),
                ).build()
        ZkCommonCredentialRootStageProveRequest(operation)

        val wrongInput =
            operation
                .toBuilder()
                .setRootAttestation(Manifest.ZkCommonCredentialRootAttestationInput.getDefaultInstance())
                .build()
        val error = assertFailsWith<ReallyMeZkProviderException> { ZkCommonCredentialRootStageProveRequest(wrongInput) }
        assertEquals(ZkProviderFailureReason.MALFORMED_WITNESS, error.reason)
    }

    @Test
    fun canonicalStageRequestDispatchesExactBytesAndWipesTransport() {
        val operation = commonCredentialRootStageOperation()
        val canonicalBytes = commonCredentialRootStageRequestBytes(operation)
        val expectedBytes = canonicalBytes.copyOf()
        val request = ZkCommonCredentialRootStageProveRequest.fromCanonicalRequestBytes(canonicalBytes)
        val bridge = CommonCredentialRootStageProofRecordingBridge(operation)
        val provider = ReallyMeZkNativeProvider(7L, bridge)

        val proof = provider.proveCommonCredentialRootStage(request)

        assertEquals(operation.slot, proof.proofPackage.slot)
        assertContentEquals(expectedBytes, bridge.requestBytes)
        assertContentEquals(ByteArray(canonicalBytes.size), canonicalBytes)
    }

    @Test
    fun canonicalStageRequestCloseWipesUndispatchedBytes() {
        val canonicalBytes = commonCredentialRootStageRequestBytes(commonCredentialRootStageOperation())
        val request = ZkCommonCredentialRootStageProveRequest.fromCanonicalRequestBytes(canonicalBytes)

        request.close()

        assertContentEquals(ByteArray(canonicalBytes.size), canonicalBytes)
    }

    @Test
    fun canonicalStageRequestRejectsMutatedTransportBeforeDispatch() {
        val canonicalBytes = commonCredentialRootStageRequestBytes(commonCredentialRootStageOperation())
        val request = ZkCommonCredentialRootStageProveRequest.fromCanonicalRequestBytes(canonicalBytes)
        canonicalBytes[0] = (canonicalBytes[0].toInt() xor 0x01).toByte()
        val bridge = CommonCredentialRootStageProofRecordingBridge(commonCredentialRootStageOperation())
        val provider = ReallyMeZkNativeProvider(7L, bridge)

        val error = assertFailsWith<ReallyMeZkProviderException> { provider.proveCommonCredentialRootStage(request) }

        assertEquals(ZkProviderFailureReason.MALFORMED_WITNESS, error.reason)
        assertEquals(0, bridge.dispatchCalls)
        assertContentEquals(ByteArray(canonicalBytes.size), canonicalBytes)
    }

    @Test
    fun objectConstructedCommonCredentialRootStageProvingFailsClosedBeforeNativeDispatch() {
        val request = ZkCommonCredentialRootStageProveRequest(issuerCredentialStatusStageOperation())
        val bridge = CommonCredentialRootStageProofRecordingBridge(request.operation)
        val provider = ReallyMeZkNativeProvider(7L, bridge)

        val error = assertFailsWith<ReallyMeZkProviderException> { provider.proveCommonCredentialRootStage(request) }

        assertEquals(ZkProviderFailureReason.UNSUPPORTED_TRANSPORT, error.reason)
        assertEquals(0, bridge.dispatchCalls)
    }

    @Test
    fun canonicalPresentationRequestDispatchesExactBytesAndWipesTransport() {
        val operation = commonCredentialRootPresentationOperation()
        val canonicalBytes = commonCredentialRootPresentationRequestBytes(operation)
        val expectedBytes = canonicalBytes.copyOf()
        val request = ZkCommonCredentialRootPresentationProveRequest.fromCanonicalRequestBytes(canonicalBytes)
        val bridge = CommonCredentialRootPresentationRecordingBridge(operation)
        val provider = ReallyMeZkNativeProvider(7L, bridge)

        val proof = provider.proveCommonCredentialRootPresentation(request)

        assertEquals(COMMON_CREDENTIAL_ROOT_PROOF_COUNT, proof.presentation.proofsCount)
        assertContentEquals(expectedBytes, bridge.requestBytes)
        assertContentEquals(ByteArray(canonicalBytes.size), canonicalBytes)
    }

    @Test
    fun canonicalPresentationRequestCloseWipesUndispatchedBytes() {
        val canonicalBytes = commonCredentialRootPresentationRequestBytes(commonCredentialRootPresentationOperation())
        val request = ZkCommonCredentialRootPresentationProveRequest.fromCanonicalRequestBytes(canonicalBytes)

        request.close()

        assertContentEquals(ByteArray(canonicalBytes.size), canonicalBytes)
    }

    @Test
    fun canonicalPresentationRequestRejectsMutatedTransportBeforeDispatch() {
        val canonicalBytes = commonCredentialRootPresentationRequestBytes(commonCredentialRootPresentationOperation())
        val request = ZkCommonCredentialRootPresentationProveRequest.fromCanonicalRequestBytes(canonicalBytes)
        canonicalBytes[0] = (canonicalBytes[0].toInt() xor 0x01).toByte()
        val bridge = CommonCredentialRootPresentationRecordingBridge(commonCredentialRootPresentationOperation())
        val provider = ReallyMeZkNativeProvider(7L, bridge)

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                provider.proveCommonCredentialRootPresentation(request)
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_WITNESS, error.reason)
        assertEquals(0, bridge.dispatchCalls)
        assertContentEquals(ByteArray(canonicalBytes.size), canonicalBytes)
    }

    @Test
    fun objectConstructedCommonCredentialRootPresentationProvingFailsClosedBeforeNativeDispatch() {
        val request = ZkCommonCredentialRootPresentationProveRequest(commonCredentialRootPresentationOperation())
        val bridge = CommonCredentialRootPresentationRecordingBridge(request.operation)
        val provider = ReallyMeZkNativeProvider(7L, bridge)

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                provider.proveCommonCredentialRootPresentation(request)
            }

        assertEquals(ZkProviderFailureReason.UNSUPPORTED_TRANSPORT, error.reason)
        assertEquals(0, bridge.dispatchCalls)
    }
}

private fun commonCredentialRootStageRequestBytes(operation: RootStageOperation): ByteArray =
    Manifest.ZkProviderOperationRequest
        .newBuilder()
        .setProveCommonCredentialRootStage(operation)
        .build()
        .toByteArray()

private fun commonCredentialRootPresentationRequestBytes(operation: RootPresentationOperation): ByteArray =
    Manifest.ZkProviderOperationRequest
        .newBuilder()
        .setProveCommonCredentialRootPresentation(operation)
        .build()
        .toByteArray()

private fun commonCredentialRootStageOperation(): Manifest.ZkCommonCredentialRootStageProveOperation {
    val bindingBytes = ByteString.copyFrom(ByteArray(BYTES_32) { 1 })
    val binding =
        Manifest.ZkSessionBinding
            .newBuilder()
            .setNonceHash(bindingBytes)
            .setAudienceHash(bindingBytes)
            .setTransactionDataHash(bindingBytes)
            .build()
    val circuitRef =
        Manifest.ZkCircuitRef
            .newBuilder()
            .setCredentialHashAlgorithm(Manifest.ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256)
            .setFamily(Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_COMMON_CREDENTIAL_ROOT_V1)
            .setStage(Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_ROOT_ATTESTATION)
            .setCircuitRevision(CIRCUIT_VERSION)
            .build()
    return Manifest.ZkCommonCredentialRootStageProveOperation
        .newBuilder()
        .setPersonaMode(
            Manifest.ZkCommonCredentialRootPersonaMode.ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1,
        ).setSlot(Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_ATTESTATION)
        .setCircuitRef(circuitRef)
        .setProofSuite(PROOF_SUITE)
        .setExpectedBinding(binding)
        .setRootAttestation(Manifest.ZkCommonCredentialRootAttestationInput.getDefaultInstance())
        .build()
}

private fun issuerCredentialStatusStageOperation(): Manifest.ZkCommonCredentialRootStageProveOperation {
    val baseline = commonCredentialRootStageOperation()
    return baseline
        .toBuilder()
        .setSlot(
            Manifest.ZkCommonCredentialRootProofSlot
                .ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0,
        ).setCircuitRef(
            baseline.circuitRef
                .toBuilder()
                .setStage(Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_ISSUER_CREDENTIAL_STATUS),
        ).setIssuerCredentialStatus(
            Manifest.ZkCommonCredentialRootIssuerCredentialStatusInput.getDefaultInstance(),
        ).build()
}

private fun commonCredentialRootPresentationOperation(): Manifest.ZkCommonCredentialRootPresentationProveOperation {
    val rootAttestation =
        commonCredentialRootStageOperationForSlot(
            Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_ATTESTATION,
        )
    return Manifest.ZkCommonCredentialRootPresentationProveOperation
        .newBuilder()
        .setPersonaMode(rootAttestation.personaMode)
        .setProofSuite(PROOF_SUITE)
        .setExpectedBinding(rootAttestation.expectedBinding)
        .setRootAttestation(rootAttestation)
        .setRootStatus(
            commonCredentialRootStageOperationForSlot(
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_STATUS,
            ),
        ).setLineage0(
            commonCredentialRootStageOperationForSlot(
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_0,
            ),
        ).setLineage1(
            commonCredentialRootStageOperationForSlot(
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_1,
            ),
        ).setSelectedClaim0(
            commonCredentialRootStageOperationForSlot(
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_0,
            ),
        ).setSelectedClaim1(
            commonCredentialRootStageOperationForSlot(
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_1,
            ),
        ).setSession(
            commonCredentialRootStageOperationForSlot(
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION,
            ),
        ).setIssuerCredentialStatus0(
            commonCredentialRootStageOperationForSlot(
                Manifest.ZkCommonCredentialRootProofSlot
                    .ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0,
            ),
        ).setIssuerCredentialStatus1(
            commonCredentialRootStageOperationForSlot(
                Manifest.ZkCommonCredentialRootProofSlot
                    .ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_1,
            ),
        ).build()
}

private fun commonCredentialRootStageOperationForSlot(slot: RootSlot): RootStageOperation {
    val baseline = commonCredentialRootStageOperation()
    val builder =
        baseline
            .toBuilder()
            .setSlot(slot)
            .setCircuitRef(
                baseline.circuitRef
                    .toBuilder()
                    .setFamily(commonCredentialRootCircuitFamily(slot))
                    .setStage(commonCredentialRootCircuitStage(slot)),
            )
    setCommonCredentialRootStageInput(builder, slot)
    return builder.build()
}

private fun commonCredentialRootCircuitFamily(slot: RootSlot): Manifest.ZkCircuitFamily =
    if (slot == Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION) {
        Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1
    } else {
        Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_COMMON_CREDENTIAL_ROOT_V1
    }

private fun commonCredentialRootCircuitStage(slot: Manifest.ZkCommonCredentialRootProofSlot): Manifest.ZkCircuitStage =
    when (slot) {
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_ATTESTATION ->
            Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_ROOT_ATTESTATION
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_STATUS ->
            Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_ROOT_STATUS
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_0,
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_1,
        -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_LINEAGE
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_0,
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_1,
        -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_PRIVATE_PERSONA_CLAIM
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION ->
            Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_SESSION
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0,
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_1,
        -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_ISSUER_CREDENTIAL_STATUS
        else -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_UNSPECIFIED
    }

private fun setCommonCredentialRootStageInput(
    builder: Manifest.ZkCommonCredentialRootStageProveOperation.Builder,
    slot: Manifest.ZkCommonCredentialRootProofSlot,
) {
    when (slot) {
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_ATTESTATION ->
            builder.setRootAttestation(Manifest.ZkCommonCredentialRootAttestationInput.getDefaultInstance())
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_STATUS ->
            builder.setRootStatus(Manifest.ZkCommonCredentialRootStatusInput.getDefaultInstance())
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_0,
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_1,
        -> builder.setLineage(Manifest.ZkCommonCredentialRootLineageInput.getDefaultInstance())
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_0,
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_1,
        -> builder.setPrivatePersonaClaim(Manifest.ZkCommonCredentialRootPrivatePersonaClaimInput.getDefaultInstance())
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION ->
            builder.setPrivatePersonaSession(Manifest.ZkPrivatePersonaSessionInput.getDefaultInstance())
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0,
        Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_1,
        ->
            builder.setIssuerCredentialStatus(
                Manifest.ZkCommonCredentialRootIssuerCredentialStatusInput.getDefaultInstance(),
            )
        else -> builder.clearRootAttestation()
    }
}

private class CommonCredentialRootStageProofRecordingBridge(
    private val operation: Manifest.ZkCommonCredentialRootStageProveOperation,
) : ReallyMeZkPlatformNativeBridge {
    lateinit var requestBytes: ByteArray
        private set
    var dispatchCalls: Int = 0
        private set

    override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
        ZkNativeContextResult(statusCode = 0, errorReasonCode = 0, contextHandle = 7L)

    override fun dispatch(
        contextHandle: Long,
        request: ByteArray,
    ): ZkNativeDispatchResult {
        assertEquals(7L, contextHandle)
        dispatchCalls += 1
        requestBytes = request.copyOf()
        val artifactDigest =
            Manifest.ZkArtifactSetIdentity
                .newBuilder()
                .setValue(ByteString.copyFrom(ByteArray(BYTES_32) { 7 }))
                .build()
        val proof =
            commonCredentialRootProof(
                operation.slot,
                operation.personaMode,
                operation.circuitRef,
                artifactDigest,
            )
        val response =
            Manifest.ZkProviderOperationResponse
                .newBuilder()
                .setRequestSha256(ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(request)))
                .setResult(
                    Manifest.ZkProviderOperationResult
                        .newBuilder()
                        .setCommonCredentialRootStageProof(proof)
                        .build(),
                ).build()
        return ZkNativeDispatchResult(statusCode = 0, errorReasonCode = 0, output = response.toByteArray())
    }

    override fun contextDestroy(contextHandle: Long) = ZkNativeStatus(statusCode = 0, errorReasonCode = 0)
}

private class CommonCredentialRootPresentationRecordingBridge(
    private val operation: Manifest.ZkCommonCredentialRootPresentationProveOperation,
) : ReallyMeZkPlatformNativeBridge {
    lateinit var requestBytes: ByteArray
        private set
    var dispatchCalls: Int = 0
        private set

    override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
        ZkNativeContextResult(statusCode = 0, errorReasonCode = 0, contextHandle = 7L)

    override fun dispatch(
        contextHandle: Long,
        request: ByteArray,
    ): ZkNativeDispatchResult {
        assertEquals(7L, contextHandle)
        dispatchCalls += 1
        requestBytes = request.copyOf()
        val providerRequest = Manifest.ZkProviderOperationRequest.parseFrom(request)
        assertEquals(
            Manifest.ZkProviderOperationRequest.OperationCase.PROVE_COMMON_CREDENTIAL_ROOT_PRESENTATION,
            providerRequest.operationCase,
        )
        val presentation = commonCredentialRootPresentationFromOperation(operation)
        val response =
            Manifest.ZkProviderOperationResponse
                .newBuilder()
                .setRequestSha256(ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(request)))
                .setResult(
                    Manifest.ZkProviderOperationResult
                        .newBuilder()
                        .setCommonCredentialRootPresentation(presentation)
                        .build(),
                ).build()
        return ZkNativeDispatchResult(statusCode = 0, errorReasonCode = 0, output = response.toByteArray())
    }

    override fun contextDestroy(contextHandle: Long) = ZkNativeStatus(statusCode = 0, errorReasonCode = 0)
}

private data class CommonCredentialRootFixture(
    val presentation: Manifest.ZkCommonCredentialRootPresentation,
    val policy: Manifest.ZkCommonCredentialRootJoinPolicy,
)

private fun commonCredentialRootInput(): CommonCredentialRootFixture {
    val digest = ByteString.copyFrom(ByteArray(BYTES_32) { 1 })
    val artifactDigest =
        Manifest.ZkArtifactSetIdentity
            .newBuilder()
            .setValue(digest)
            .build()
    return CommonCredentialRootFixture(
        commonCredentialRootPresentation(digest, artifactDigest),
        commonCredentialRootPolicy(digest),
    )
}

private fun commonCredentialRootPresentation(
    digest: ByteString,
    artifactDigest: Manifest.ZkArtifactSetIdentity,
): Manifest.ZkCommonCredentialRootPresentation {
    val slots =
        listOf(
            Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_ATTESTATION,
            Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_STATUS,
            Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_0,
            Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_1,
            Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_0,
            Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_1,
            Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION,
            Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0,
            Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_1,
        )
    val circuitRef =
        Manifest.ZkCircuitRef
            .newBuilder()
            .setCredentialHashAlgorithm(Manifest.ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256)
            .setFamily(Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_COMMON_CREDENTIAL_ROOT_V1)
            .setStage(Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_ROOT_ATTESTATION)
            .setCircuitRevision(1)
            .build()
    val personaMode =
        Manifest.ZkCommonCredentialRootPersonaMode.ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1
    val sessionBinding =
        Manifest.ZkSessionBinding
            .newBuilder()
            .setNonceHash(digest)
            .setAudienceHash(digest)
            .setTransactionDataHash(digest)
            .build()
    val presentation =
        Manifest.ZkCommonCredentialRootPresentation
            .newBuilder()
            .setPersonaMode(personaMode)
            .setCredentialHashAlgorithm(Manifest.ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256)
            .setProofSuite(PROOF_SUITE)
            .setSessionBinding(sessionBinding)
            .addAllProofs(
                slots.map { slot ->
                    commonCredentialRootProof(slot, personaMode, circuitRef, artifactDigest)
                },
            ).build()
    return presentation
}

private fun commonCredentialRootPresentationFromOperation(
    operation: Manifest.ZkCommonCredentialRootPresentationProveOperation,
): Manifest.ZkCommonCredentialRootPresentation {
    val artifactDigest =
        Manifest.ZkArtifactSetIdentity
            .newBuilder()
            .setValue(ByteString.copyFrom(ByteArray(BYTES_32) { 7 }))
            .build()
    val stages =
        listOf(
            operation.rootAttestation,
            operation.rootStatus,
            operation.lineage0,
            operation.lineage1,
            operation.selectedClaim0,
            operation.selectedClaim1,
            operation.session,
            operation.issuerCredentialStatus0,
            operation.issuerCredentialStatus1,
        )
    return Manifest.ZkCommonCredentialRootPresentation
        .newBuilder()
        .setPersonaMode(operation.personaMode)
        .setCredentialHashAlgorithm(operation.rootAttestation.circuitRef.credentialHashAlgorithm)
        .setProofSuite(operation.proofSuite)
        .setSessionBinding(operation.expectedBinding)
        .addAllProofs(
            stages.map { stage ->
                commonCredentialRootProof(stage.slot, stage.personaMode, stage.circuitRef, artifactDigest)
            },
        ).build()
}

private fun commonCredentialRootProof(
    slot: Manifest.ZkCommonCredentialRootProofSlot,
    personaMode: Manifest.ZkCommonCredentialRootPersonaMode,
    circuitRef: Manifest.ZkCircuitRef,
    artifactDigest: Manifest.ZkArtifactSetIdentity,
): Manifest.ZkCommonCredentialRootRawProofPackage {
    val inputs =
        Manifest.ZkCommonCredentialRootRawPublicInputs
            .newBuilder()
            .setPersonaMode(personaMode)
            .setSlot(slot)
            .setCircuitRef(circuitRef)
            .setRawFields(ByteString.copyFrom(ByteArray(BYTES_32)))
            .build()
    return Manifest.ZkCommonCredentialRootRawProofPackage
        .newBuilder()
        .setPersonaMode(personaMode)
        .setSlot(slot)
        .setCircuitRef(circuitRef)
        .setPublicInputs(inputs)
        .setProof(ByteString.copyFrom(byteArrayOf(1)))
        .setProofSuite(PROOF_SUITE)
        .setArtifactSetIdentitySha256(artifactDigest)
        .build()
}

private fun commonCredentialRootPolicy(digest: ByteString): Manifest.ZkCommonCredentialRootJoinPolicy {
    val signer =
        Manifest.ZkP256PublicKey
            .newBuilder()
            .setX(digest)
            .setY(digest)
            .build()
    return Manifest.ZkCommonCredentialRootJoinPolicy
        .newBuilder()
        .setChallenge(digest)
        .setAudienceHash(digest)
        .setTransactionDataHash(digest)
        .setRequestTimeUnix(1)
        .setAttestationSigner(signer)
        .setAssurancePolicyId(digest)
        .setStatusRoot(digest)
        .addAllClaims(
            (0 until 2).map {
                Manifest.ZkCommonCredentialRootClaimExpectation
                    .newBuilder()
                    .setIssuer(signer)
                    .setClaimNameHash(digest)
                    .setClaimValue(ByteString.copyFrom(byteArrayOf(1)))
                    .setClaimValueLength(1)
                    .build()
            },
        ).addAllIssuerStatus(
            (0 until 2).map {
                Manifest.ZkCommonCredentialRootIssuerStatusExpectation
                    .newBuilder()
                    .setRoot(digest)
                    .setLength(1)
                    .setListId(digest)
                    .setUrlHash(digest)
                    .setPurpose(Manifest.ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_REVOCATION)
                    .build()
            },
        ).build()
}
