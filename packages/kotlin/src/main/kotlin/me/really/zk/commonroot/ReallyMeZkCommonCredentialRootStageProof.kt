// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.commonroot

import com.google.protobuf.InvalidProtocolBufferException
import me.really.zk.BYTES_32
import me.really.zk.CIRCUIT_VERSION
import me.really.zk.PROOF_SUITE
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.circuitRef
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import reallyme.zk.v1.Manifest

/** A single, exact common-credential-root v1 stage request. The input contains private witness material. */
public class ZkCommonCredentialRootStageProveRequest private constructor(
    public val operation: Manifest.ZkCommonCredentialRootStageProveOperation,
    private var canonicalRequestBytes: ByteArray? = null,
) : AutoCloseable {
    public constructor(operation: Manifest.ZkCommonCredentialRootStageProveOperation) : this(operation, null)

    init {
        val slot = operation.slot
        val personaMode = operation.personaMode
        val expectedFamily =
            if (slot == Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION &&
                personaMode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA.protoPersonaMode
            ) {
                Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1
            } else {
                Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_COMMON_CREDENTIAL_ROOT_V1
            }
        val expectedStage =
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
                ->
                    if (personaMode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA.protoPersonaMode) {
                        Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_PRIVATE_PERSONA_CLAIM
                    } else {
                        Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_PUBLIC_PERSONA_CLAIM
                    }
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION ->
                    if (personaMode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA.protoPersonaMode) {
                        Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_SESSION
                    } else {
                        Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_PUBLIC_SESSION
                    }
                Manifest.ZkCommonCredentialRootProofSlot
                    .ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0,
                Manifest.ZkCommonCredentialRootProofSlot
                    .ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_1,
                -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_ISSUER_CREDENTIAL_STATUS
                else -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_UNSPECIFIED
            }
        val validInput =
            when (slot) {
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_ATTESTATION ->
                    operation.hasRootAttestation()
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_STATUS ->
                    operation.hasRootStatus()
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_0,
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_1,
                -> operation.hasLineage()
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_0,
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_1,
                ->
                    if (personaMode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA.protoPersonaMode) {
                        operation.hasPrivatePersonaClaim()
                    } else {
                        operation.hasPublicPersonaClaim()
                    }
                Manifest.ZkCommonCredentialRootProofSlot.ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION ->
                    if (personaMode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA.protoPersonaMode) {
                        operation.hasPrivatePersonaSession()
                    } else {
                        operation.hasPublicPersonaSession()
                    }
                Manifest.ZkCommonCredentialRootProofSlot
                    .ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0,
                Manifest.ZkCommonCredentialRootProofSlot
                    .ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_1,
                -> operation.hasIssuerCredentialStatus()
                else -> false
            }
        val validPersonaMode =
            personaMode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA.protoPersonaMode ||
                personaMode == ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA.protoPersonaMode
        val validCredentialHashAlgorithm =
            operation.circuitRef.credentialHashAlgorithm ==
                ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256 ||
                operation.circuitRef.credentialHashAlgorithm ==
                ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2
        val validCircuit =
            operation.hasCircuitRef() &&
                operation.circuitRef.family == expectedFamily &&
                operation.circuitRef.stage == expectedStage &&
                operation.circuitRef.circuitRevision == CIRCUIT_VERSION &&
                validCredentialHashAlgorithm
        val validBinding =
            operation.hasExpectedBinding() &&
                operation.expectedBinding.nonceHash.size() == BYTES_32 &&
                operation.expectedBinding.audienceHash.size() == BYTES_32 &&
                operation.expectedBinding.transactionDataHash.size() == BYTES_32
        val validStage = validPersonaMode && validInput && operation.proofSuite == PROOF_SUITE
        if (!validStage || !validCircuit || !validBinding) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
    }

    internal fun takeCanonicalRequestBytes(): ByteArray? {
        val bytes = canonicalRequestBytes
        canonicalRequestBytes = null
        if (bytes != null) {
            validateCanonicalRequestBytes(bytes)
        }
        return bytes
    }

    override fun close() {
        val bytes = canonicalRequestBytes
        canonicalRequestBytes = null
        bytes?.fill(0)
    }

    override fun toString(): String = "ZkCommonCredentialRootStageProveRequest(input=<redacted>)"

    private fun validateCanonicalRequestBytes(bytes: ByteArray) {
        val request = parseCanonicalRequestOrNull(bytes)
        if (request == null ||
            !request.hasProveCommonCredentialRootStage() ||
            request.proveCommonCredentialRootStage != operation
        ) {
            bytes.fill(0)
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
    }

    public companion object {
        /**
         * Transfers canonical Buffa request bytes into the native transport owner.
         *
         * Kotlin/JVM protobuf re-encoding is not the canonical byte transport
         * required by the native verifier boundary. This factory keeps the
         * exact admitted bytes until first dispatch and wipes them on dispatch
         * or explicit close.
         */
        public fun fromCanonicalRequestBytes(
            ownedCanonicalProviderOperationRequestBytes: ByteArray,
        ): ZkCommonCredentialRootStageProveRequest {
            val request = parseCanonicalRequestOrNull(ownedCanonicalProviderOperationRequestBytes)
            if (request == null || !request.hasProveCommonCredentialRootStage()) {
                ownedCanonicalProviderOperationRequestBytes.fill(0)
                throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
            }
            return ZkCommonCredentialRootStageProveRequest(
                operation = request.proveCommonCredentialRootStage,
                canonicalRequestBytes = ownedCanonicalProviderOperationRequestBytes,
            )
        }
    }
}

private fun parseCanonicalRequestOrNull(bytes: ByteArray): Manifest.ZkProviderOperationRequest? =
    try {
        Manifest.ZkProviderOperationRequest.parseFrom(bytes)
    } catch (ignored: InvalidProtocolBufferException) {
        null
    } catch (ignored: RuntimeException) {
        null
    }

/** Exact raw proof produced and internally verified by the linked native provider. */
public class ZkCommonCredentialRootStageProof internal constructor(
    public val proofPackage: Manifest.ZkCommonCredentialRootRawProofPackage,
) {
    override fun toString(): String = "ZkCommonCredentialRootStageProof(package=<redacted>)"
}
