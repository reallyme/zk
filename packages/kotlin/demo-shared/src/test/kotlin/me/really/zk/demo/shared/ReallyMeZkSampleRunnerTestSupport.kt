// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.shared

import com.google.protobuf.ByteString
import me.really.zk.ReallyMeZk
import me.really.zk.ReallyMeZkPlatformNativeBridge
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkNativeContextCreateRequest
import me.really.zk.ZkNativeContextResult
import me.really.zk.ZkNativeDispatchResult
import me.really.zk.ZkNativeStatus
import me.really.zk.ZkProviderFailureReason
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import reallyme.zk.v1.Manifest
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.assertEquals

internal fun fixtureData(
    bundleKind: ZkClaimProofBundleKind,
    credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    stage: ZkClaimProofBundleStage,
): ByteArray {
    val resourceName =
        ReallyMeZkDemoFixtureWitnessInputs.fixtureResourceName(
            bundleKind,
            credentialHashAlgorithm,
            stage,
        )
    return Files.readAllBytes(fixtureDirectory().resolve("$resourceName.pb"))
}

internal fun demoFixtureCoordinates(): List<DemoFixtureCoordinate> =
    ReallyMeZk.bundleKinds.flatMap { bundleKind ->
        ReallyMeZk.credentialHashAlgorithms.flatMap { credentialHashAlgorithm ->
            ReallyMeZk.stages.map { stage ->
                DemoFixtureCoordinate(bundleKind, credentialHashAlgorithm, stage)
            }
        }
    }

internal data class DemoFixtureCoordinate(
    val bundleKind: ZkClaimProofBundleKind,
    val credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    val stage: ZkClaimProofBundleStage,
)

private fun fixtureDirectory(): Path =
    locateFixtureDirectory(
        Path
            .of("")
            .toAbsolutePath()
            .normalize(),
    )

private fun locateFixtureDirectory(start: Path): Path {
    var cursor: Path? = start
    while (cursor != null) {
        val candidate = cursor.resolve("vectors").resolve("demo-flow-inputs").resolve("v1")
        if (Files.isDirectory(candidate)) {
            return candidate
        }
        cursor = cursor.parent
    }
    return start.resolve("vectors").resolve("demo-flow-inputs").resolve("v1")
}

internal class RecordingBridge : ReallyMeZkPlatformNativeBridge {
    val operationCases: MutableList<NativeOperationKind> = mutableListOf()
    val verifyExpectedBindings: MutableList<Manifest.ZkSessionBinding> = mutableListOf()

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
        operationCases.add(nativeOperationKind(operation))
        return ZkNativeDispatchResult(
            statusCode = 0,
            errorReasonCode = 0,
            output = responseFor(operation, request),
        )
    }

    override fun contextDestroy(contextHandle: Long): ZkNativeStatus =
        ZkNativeStatus(
            statusCode = 0,
            errorReasonCode = 0,
        )

    private fun responseFor(
        operation: Manifest.ZkProviderOperationRequest,
        requestBytes: ByteArray,
    ): ByteArray {
        val result = Manifest.ZkProviderOperationResult.newBuilder()
        when (operation.operationCase) {
            Manifest.ZkProviderOperationRequest.OperationCase.WITNESS_STAGE ->
                result.setStageWitness(witnessResponse(operation.witnessStage))
            Manifest.ZkProviderOperationRequest.OperationCase.PROVE_STAGE ->
                result.setStageProof(proofResponse(operation.proveStage))
            Manifest.ZkProviderOperationRequest.OperationCase.VERIFY_STAGE ->
                return verificationResponse(operation.verifyStage, requestBytes)
            Manifest.ZkProviderOperationRequest.OperationCase.RELEASE_STAGE_WITNESS -> {
                result.setStageWitnessRelease(Manifest.ZkStageWitnessRelease.getDefaultInstance())
            }
            else -> throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        return Manifest.ZkProviderOperationResponse
            .newBuilder()
            .setRequestSha256(ByteString.copyFrom(sha256(requestBytes)))
            .setResult(result.build())
            .build()
            .toByteArray()
    }

    private fun verificationResponse(
        operation: Manifest.ZkStageVerifyOperation,
        requestBytes: ByteArray,
    ): ByteArray {
        verifyExpectedBindings.add(operation.expectedBinding)
        val response =
            Manifest.ZkProviderOperationResponse
                .newBuilder()
                .setRequestSha256(ByteString.copyFrom(sha256(requestBytes)))
        if (operation.expectedBinding.transactionDataHash.size() == 0) {
            response.setResult(
                Manifest.ZkProviderOperationResult
                    .newBuilder()
                    .setStageVerification(matchingStageVerification(operation.proof))
                    .build(),
            )
        } else {
            response.setError(
                Manifest.ZkError
                    .newBuilder()
                    .setReason(Manifest.ZkErrorReason.ZK_ERROR_REASON_BINDING_MISMATCH)
                    .build(),
            )
        }
        return response.build().toByteArray()
    }

    private fun witnessResponse(operation: Manifest.ZkStageWitnessOperation): Manifest.ZkStageWitness =
        Manifest.ZkStageWitness
            .newBuilder()
            .setWitnessHandle(witnessHandle(operation.circuitRef))
            .setPublicInputs(
                Manifest.ZkPublicInputs
                    .newBuilder()
                    .setEncoded(ByteString.copyFrom(byteArrayOf(1, 2, 3, 4)))
                    .build(),
            ).setSessionBinding(sessionBinding())
            .build()

    private fun witnessHandle(circuitRef: Manifest.ZkCircuitRef): Manifest.ZkStageWitnessHandle =
        Manifest.ZkStageWitnessHandle
            .newBuilder()
            .setNativeHandleId(9L)
            .setCircuitRef(circuitRef)
            .setEncoding(Manifest.ZkWitnessEncoding.ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1)
            .build()

    private fun matchingStageVerification(proof: Manifest.ZkProofPackage): Manifest.ZkVerification =
        Manifest.ZkVerification
            .newBuilder()
            .setCircuitId(proof.circuitId)
            .setCircuitRef(proof.circuitRef)
            .setBundleKind(bundleKindFor(proof.circuitRef.family))
            .setProofSuite(proof.proofSuite)
            .build()

    private fun circuitIdFor(family: Manifest.ZkCircuitFamily): Manifest.ZkCircuitId =
        when (family) {
            Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1 ->
                Manifest.ZkCircuitId.ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1
            Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1 ->
                Manifest.ZkCircuitId.ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1
            else -> Manifest.ZkCircuitId.ZK_CIRCUIT_ID_UNSPECIFIED
        }

    private fun bundleKindFor(family: Manifest.ZkCircuitFamily): Manifest.ZkClaimProofBundleKind =
        when (family) {
            Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1 ->
                Manifest.ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1
            Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1 ->
                Manifest.ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1
            else -> Manifest.ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_UNSPECIFIED
        }

    private fun proofResponse(operation: Manifest.ZkStageProveOperation): Manifest.ZkProofPackage =
        Manifest.ZkProofPackage
            .newBuilder()
            .setCircuitId(circuitIdFor(operation.circuitRef.family))
            .setCircuitRef(operation.circuitRef)
            .setProofSuite(operation.proofSuite)
            .setPublicInputs(operation.publicInputs)
            .setProof(ByteString.copyFrom(ByteArray(96) { 5 }))
            .setArtifactManifestSha256(
                Manifest.ZkArtifactManifestDigest
                    .newBuilder()
                    .setValue(ByteString.copyFrom(ByteArray(32) { 4 }))
                    .build(),
            ).build()

    private fun sessionBinding(): Manifest.ZkSessionBinding =
        Manifest.ZkSessionBinding
            .newBuilder()
            .setNonceHash(ByteString.copyFrom(ByteArray(32) { 1 }))
            .setAudienceHash(ByteString.copyFrom(ByteArray(32) { 2 }))
            .setTransactionDataHash(ByteString.copyFrom(ByteArray(32) { 3 }))
            .build()

    private fun nativeOperationKind(operation: Manifest.ZkProviderOperationRequest): NativeOperationKind =
        when (operation.operationCase) {
            Manifest.ZkProviderOperationRequest.OperationCase.WITNESS_STAGE -> NativeOperationKind.WITNESS
            Manifest.ZkProviderOperationRequest.OperationCase.PROVE_STAGE -> NativeOperationKind.PROVE
            Manifest.ZkProviderOperationRequest.OperationCase.VERIFY_STAGE -> NativeOperationKind.VERIFY
            Manifest.ZkProviderOperationRequest.OperationCase.RELEASE_STAGE_WITNESS -> NativeOperationKind.RELEASE
            else -> throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}

internal enum class NativeOperationKind {
    WITNESS,
    PROVE,
    VERIFY,
    RELEASE,
}
