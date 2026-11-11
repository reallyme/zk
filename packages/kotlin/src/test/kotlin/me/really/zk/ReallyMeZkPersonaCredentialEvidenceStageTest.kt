// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import com.google.protobuf.ByteString
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.personaevidence.ZkPersonaCredentialEvidenceStageProveRequest
import me.really.zk.personaevidence.evidenceStageForCircuitStage
import reallyme.zk.v1.Manifest
import reallyme.zk.v1.Manifest.ZkPersonaCredentialEvidenceProofSlot
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ReallyMeZkPersonaCredentialEvidenceStageTest {
    @Test
    fun personaCredentialEvidenceRequestAdmitsEveryProofStageForBothPersonaModes() {
        val sharedStages =
            listOf(
                Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_ISSUER_ENVELOPE,
                Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_CLAIM_ROOT,
                Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_SIGNED_VALIDITY,
                Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_CURRENT_STATE,
            )
        val profiles =
            listOf(
                Manifest.ZkPersonaCredentialEvidenceMode.ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1,
                Manifest.ZkPersonaCredentialEvidenceMode
                    .ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1,
            )
        for (mode in profiles) {
            for (stage in sharedStages) {
                val reference =
                    Manifest.ZkCircuitRef
                        .newBuilder()
                        .setFamily(Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PERSONA_CREDENTIAL_EVIDENCE_V1)
                        .setStage(stage)
                        .setCredentialHashAlgorithm(
                            Manifest.ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
                        ).setCircuitRevision(1)
                        .build()
                ZkPersonaCredentialEvidenceStageProveRequest(byteArrayOf(1), mode, reference).use { request ->
                    assertEquals(stage, request.circuitRef.stage)
                }
            }
        }
    }

    @Test
    fun personaCredentialEvidenceRequestRejectsClaimFromAnotherPersonaMode() {
        val reference =
            Manifest.ZkCircuitRef
                .newBuilder()
                .setFamily(Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PERSONA_CREDENTIAL_EVIDENCE_V1)
                .setStage(Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_PRIVATE_CLAIM)
                .setCredentialHashAlgorithm(Manifest.ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256)
                .setCircuitRevision(1)
                .build()
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                ZkPersonaCredentialEvidenceStageProveRequest(
                    byteArrayOf(1),
                    Manifest.ZkPersonaCredentialEvidenceMode
                        .ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1,
                    reference,
                )
            }
        assertEquals(ZkProviderFailureReason.MALFORMED_WITNESS, error.reason)
    }

    @Test
    fun everyEvidenceSourceStageHasItsExactResponseStage() {
        val pairs =
            listOf(
                Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_ISSUER_ENVELOPE to
                    ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE,
                Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_CLAIM_ROOT to
                    Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT,
                Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_SIGNED_VALIDITY to
                    ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY,
                Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_PUBLIC_CLAIM to
                    ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM,
                Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_PRIVATE_CLAIM to
                    ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM,
                Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_CURRENT_STATE to
                    ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE,
            )
        for ((circuitStage, evidenceStage) in pairs) {
            assertEquals(evidenceStage, evidenceStageForCircuitStage(circuitStage))
        }
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                evidenceStageForCircuitStage(Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_SESSION)
            }
        assertEquals(ZkProviderFailureReason.MALFORMED_PROOF, error.reason)
    }

    @Test
    fun personaCredentialEvidenceProveDispatchesOnceAndAdmitsMatchingStage() {
        val bridge = PersonaCredentialEvidenceStageRecordingBridge(matchingStage = true, prove = true)
        val provider = ReallyMeZkNativeProvider(7L, bridge)
        val request = personaCredentialEvidenceStageProveRequest()

        val proof = request.use { provider.provePersonaCredentialEvidenceStage(it) }

        assertEquals(
            Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM,
            proof.proofSlot,
        )
        assertEquals(1, bridge.dispatchCalls)
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                provider.provePersonaCredentialEvidenceStage(request)
            }
        assertEquals(ZkProviderFailureReason.UNSUPPORTED_TRANSPORT, error.reason)
    }

    @Test
    fun personaCredentialEvidenceProveRejectsSubstitutedStage() {
        val provider =
            ReallyMeZkNativeProvider(
                7L,
                PersonaCredentialEvidenceStageRecordingBridge(matchingStage = false, prove = true),
            )
        val request = personaCredentialEvidenceStageProveRequest()

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                request.use { provider.provePersonaCredentialEvidenceStage(it) }
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_PROOF, error.reason)
    }

    @Test
    fun dispatchesPersonaCredentialEvidenceStageAndChecksNativeReport() {
        val bridge = PersonaCredentialEvidenceStageRecordingBridge(matchingStage = true)
        val provider = ReallyMeZkNativeProvider(7L, bridge)
        val proof = personaCredentialEvidenceStageProof()

        val report = provider.verifyPersonaCredentialEvidenceStage(proof)

        assertEquals(proof.mode, report.mode)
        assertEquals(proof.proofSlot, report.proofSlot)
        assertEquals(proof.circuitRef, report.circuitRef)
        assertEquals(1, bridge.dispatchCalls)
    }

    @Test
    fun rejectsSubstitutedNativeStageReport() {
        val provider =
            ReallyMeZkNativeProvider(
                7L,
                PersonaCredentialEvidenceStageRecordingBridge(matchingStage = false),
            )

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                provider.verifyPersonaCredentialEvidenceStage(personaCredentialEvidenceStageProof())
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_PROOF, error.reason)
    }

    @Test
    fun rejectsInconsistentPackageBeforeNativeDispatch() {
        val bridge = PersonaCredentialEvidenceStageRecordingBridge(matchingStage = true)
        val provider = ReallyMeZkNativeProvider(7L, bridge)
        val proof =
            personaCredentialEvidenceStageProof()
                .toBuilder()
                .setPublicInputs(
                    personaCredentialEvidenceStageProof()
                        .publicInputs
                        .toBuilder()
                        .setProofSlot(
                            Manifest.ZkPersonaCredentialEvidenceProofSlot
                                .ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE,
                        ).build(),
                ).build()

        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                provider.verifyPersonaCredentialEvidenceStage(proof)
            }

        assertEquals(ZkProviderFailureReason.MALFORMED_PROOF, error.reason)
        assertEquals(0, bridge.dispatchCalls)
    }

    @Test
    fun protectedKeySigningAndAssemblyUseDistinctCanonicalOperations() {
        val bridge = PreparedSigningRecordingBridge()
        val provider = ReallyMeZkNativeProvider(7L, bridge)
        val evidence = Manifest.ZkPersonaCredentialEvidenceProofSet.getDefaultInstance()
        val status = Manifest.ZkPersonaCredentialEvidenceStageProof.getDefaultInstance()
        val request = Manifest.ZkPersonaCredentialEvidenceVerifierRequestV1.getDefaultInstance()
        val signature = ByteArray(64) { 9 }

        val digest = provider.preparePersonaCredentialEvidencePresentationSigning(evidence, status, request, 10L)
        assertContentEquals(ByteArray(32) { 7 }, digest)
        val presentation =
            provider.assemblePersonaCredentialEvidencePresentation(
                evidence,
                status,
                request,
                10L,
                signature,
            )
        assertContentEquals(signature, presentation.holderSignatureP256Raw.toByteArray())
        assertEquals(
            listOf(
                Manifest.ZkProviderOperationRequest.OperationCase
                    .PREPARE_PERSONA_CREDENTIAL_EVIDENCE_PRESENTATION_SIGNING,
                Manifest.ZkProviderOperationRequest.OperationCase.ASSEMBLE_PERSONA_CREDENTIAL_EVIDENCE_PRESENTATION,
            ),
            bridge.operationCases,
        )
    }

    @Test
    fun assemblyRejectsWrongSignatureLengthBeforeDispatch() {
        val bridge = PreparedSigningRecordingBridge()
        val provider = ReallyMeZkNativeProvider(7L, bridge)
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                provider.assemblePersonaCredentialEvidencePresentation(
                    Manifest.ZkPersonaCredentialEvidenceProofSet.getDefaultInstance(),
                    Manifest.ZkPersonaCredentialEvidenceStageProof.getDefaultInstance(),
                    Manifest.ZkPersonaCredentialEvidenceVerifierRequestV1.getDefaultInstance(),
                    10L,
                    ByteArray(63),
                )
            }
        assertEquals(ZkProviderFailureReason.MALFORMED_PROOF, error.reason)
        assertEquals(emptyList(), bridge.operationCases)
    }
}

private class PreparedSigningRecordingBridge : ReallyMeZkPlatformNativeBridge {
    val operationCases = mutableListOf<Manifest.ZkProviderOperationRequest.OperationCase>()

    override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
        ZkNativeContextResult(statusCode = 0, errorReasonCode = 0, contextHandle = 7L)

    override fun dispatch(
        contextHandle: Long,
        request: ByteArray,
    ): ZkNativeDispatchResult {
        assertEquals(7L, contextHandle)
        val operation = Manifest.ZkProviderOperationRequest.parseFrom(request)
        operationCases += operation.operationCase
        val result =
            when (operation.operationCase) {
                Manifest.ZkProviderOperationRequest.OperationCase
                    .PREPARE_PERSONA_CREDENTIAL_EVIDENCE_PRESENTATION_SIGNING,
                -> {
                    val challenge =
                        Manifest.ZkPersonaCredentialEvidencePresentationSigningChallenge
                            .newBuilder()
                            .setDigestSha256(ByteString.copyFrom(ByteArray(32) { 7 }))
                            .build()
                    Manifest.ZkProviderOperationResult
                        .newBuilder()
                        .setPersonaCredentialEvidencePresentationSigningChallenge(challenge)
                        .build()
                }
                Manifest.ZkProviderOperationRequest.OperationCase.ASSEMBLE_PERSONA_CREDENTIAL_EVIDENCE_PRESENTATION -> {
                    val assembly = operation.assemblePersonaCredentialEvidencePresentation
                    val presentation =
                        Manifest.ZkPersonaCredentialEvidencePresentation
                            .newBuilder()
                            .setVerifierRequest(assembly.verifierRequest)
                            .setHolderSignatureP256Raw(assembly.holderSignatureP256Raw)
                            .build()
                    Manifest.ZkProviderOperationResult
                        .newBuilder()
                        .setPersonaCredentialEvidencePresentation(presentation)
                        .build()
                }
                else -> throw AssertionError("unexpected operation")
            }
        val response =
            Manifest.ZkProviderOperationResponse
                .newBuilder()
                .setRequestSha256(ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(request)))
                .setResult(result)
                .build()
        return ZkNativeDispatchResult(statusCode = 0, errorReasonCode = 0, output = response.toByteArray())
    }

    override fun contextDestroy(contextHandle: Long): ZkNativeStatus = ZkNativeStatus(0, 0)
}

private fun personaCredentialEvidenceStageProveRequest(): ZkPersonaCredentialEvidenceStageProveRequest {
    val reference = personaCredentialEvidenceStageProof().circuitRef
    val witness =
        Manifest.ZkWitness
            .newBuilder()
            .setCircuitRef(reference)
            .setEncoding(Manifest.ZkWitnessEncoding.ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1)
            .setEncoded(ByteString.copyFrom(byteArrayOf(1, 2, 3)))
            .build()
    val operation =
        Manifest.ZkPersonaCredentialEvidenceStageProveOperation
            .newBuilder()
            .setMode(
                Manifest.ZkPersonaCredentialEvidenceMode
                    .ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1,
            ).setCircuitRef(reference)
            .setProofSuite(PROOF_SUITE)
            .setWitness(witness)
            .build()
    val request =
        Manifest.ZkProviderOperationRequest
            .newBuilder()
            .setProvePersonaCredentialEvidenceStage(operation)
            .build()
    return ZkPersonaCredentialEvidenceStageProveRequest(
        request.toByteArray(),
        Manifest.ZkPersonaCredentialEvidenceMode
            .ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1,
        reference,
    )
}

private fun personaCredentialEvidenceStageProof(): Manifest.ZkPersonaCredentialEvidenceStageProof {
    val reference =
        Manifest.ZkCircuitRef
            .newBuilder()
            .setFamily(Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PERSONA_CREDENTIAL_EVIDENCE_V1)
            .setStage(Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_PUBLIC_CLAIM)
            .setCredentialHashAlgorithm(Manifest.ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256)
            .setCircuitRevision(1)
            .build()
    val inputs =
        Manifest.ZkPersonaCredentialEvidenceRawPublicInputs
            .newBuilder()
            .setMode(
                Manifest.ZkPersonaCredentialEvidenceMode
                    .ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1,
            ).setProofSlot(
                Manifest.ZkPersonaCredentialEvidenceProofSlot
                    .ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM,
            ).setCircuitRef(reference)
            .setRawFields(ByteString.copyFrom(ByteArray(BYTES_32) { 1 }))
            .build()
    val digest =
        Manifest.ZkArtifactSetIdentity
            .newBuilder()
            .setValue(ByteString.copyFrom(ByteArray(BYTES_32) { 2 }))
            .build()
    return Manifest.ZkPersonaCredentialEvidenceStageProof
        .newBuilder()
        .setMode(inputs.mode)
        .setProofSlot(inputs.proofSlot)
        .setCircuitRef(reference)
        .setProof(ByteString.copyFrom(ByteArray(96) { 3 }))
        .setPublicInputs(inputs)
        .setArtifactSetIdentitySha256(digest)
        .setProofSuite(PROOF_SUITE)
        .build()
}

private class PersonaCredentialEvidenceStageRecordingBridge(
    private val matchingStage: Boolean,
    private val prove: Boolean = false,
) : ReallyMeZkPlatformNativeBridge {
    var dispatchCalls: Int = 0
        private set

    override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
        ZkNativeContextResult(statusCode = 0, errorReasonCode = 0, contextHandle = 7L)

    override fun dispatch(
        contextHandle: Long,
        request: ByteArray,
    ): ZkNativeDispatchResult {
        assertEquals(7L, contextHandle)
        val operation = Manifest.ZkProviderOperationRequest.parseFrom(request)
        assertEquals(
            if (prove) {
                Manifest.ZkProviderOperationRequest.OperationCase.PROVE_PERSONA_CREDENTIAL_EVIDENCE_STAGE
            } else {
                Manifest.ZkProviderOperationRequest.OperationCase.VERIFY_PERSONA_CREDENTIAL_EVIDENCE_STAGE
            },
            operation.operationCase,
        )
        dispatchCalls += 1
        val proof =
            if (prove) {
                personaCredentialEvidenceStageProof()
            } else {
                operation.verifyPersonaCredentialEvidenceStage.proof
            }
        val stage =
            if (matchingStage) {
                proof.proofSlot
            } else {
                Manifest.ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_UNSPECIFIED
            }
        val report =
            Manifest.ZkPersonaCredentialEvidenceStageVerification
                .newBuilder()
                .setMode(proof.mode)
                .setProofSlot(stage)
                .setCircuitRef(proof.circuitRef)
                .setProofSuite(proof.proofSuite)
                .build()
        val result =
            if (prove) {
                Manifest.ZkProviderOperationResult
                    .newBuilder()
                    .setPersonaCredentialEvidenceStageProof(proof.toBuilder().setProofSlot(stage).build())
                    .build()
            } else {
                Manifest.ZkProviderOperationResult
                    .newBuilder()
                    .setPersonaCredentialEvidenceStageVerification(report)
                    .build()
            }
        val response =
            Manifest.ZkProviderOperationResponse
                .newBuilder()
                .setRequestSha256(ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(request)))
                .setResult(result)
                .build()
        return ZkNativeDispatchResult(statusCode = 0, errorReasonCode = 0, output = response.toByteArray())
    }

    override fun contextDestroy(contextHandle: Long): ZkNativeStatus = ZkNativeStatus(0, 0)
}
