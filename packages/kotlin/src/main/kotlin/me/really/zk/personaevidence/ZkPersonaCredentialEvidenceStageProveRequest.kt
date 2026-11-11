// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.personaevidence

import me.really.zk.CIRCUIT_VERSION
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.circuitRef
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import reallyme.zk.v1.Manifest

/** Copies and clears the caller buffer, then owns one secret-bearing request until dispatch. */
public class ZkPersonaCredentialEvidenceStageProveRequest(
    canonicalRequestBytes: ByteArray,
    public val mode: Manifest.ZkPersonaCredentialEvidenceMode,
    public val circuitRef: Manifest.ZkCircuitRef,
) : AutoCloseable {
    private var ownedBytes: ByteArray? = takeOwnedCopy(canonicalRequestBytes)

    init {
        try {
            val publicMode =
                Manifest.ZkPersonaCredentialEvidenceMode
                    .ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1
            val privateOneTimeMode =
                Manifest.ZkPersonaCredentialEvidenceMode
                    .ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
            val validMode =
                mode == publicMode || mode == privateOneTimeMode
            val validClaim =
                mode == publicMode &&
                    circuitRef.stage == Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_PUBLIC_CLAIM ||
                    mode == privateOneTimeMode &&
                    circuitRef.stage == Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_PRIVATE_CLAIM
            val validStage =
                validClaim ||
                    circuitRef.stage == Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_ISSUER_ENVELOPE ||
                    circuitRef.stage == Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_CLAIM_ROOT ||
                    circuitRef.stage == Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_SIGNED_VALIDITY ||
                    circuitRef.stage == Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_CURRENT_STATE
            val validReference =
                circuitRef.family == Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PERSONA_CREDENTIAL_EVIDENCE_V1 &&
                    circuitRef.circuitRevision == CIRCUIT_VERSION &&
                    (
                        circuitRef.credentialHashAlgorithm ==
                            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256 ||
                            circuitRef.credentialHashAlgorithm ==
                            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2
                    )
            if (!validMode || !validStage || !validReference) {
                fail(ZkProviderFailureReason.MALFORMED_WITNESS)
            }
        } catch (failure: ReallyMeZkProviderException) {
            close()
            throw failure
        }
    }

    @Synchronized
    internal fun takeCanonicalRequestBytes(): ByteArray {
        val bytes = ownedBytes ?: fail(ZkProviderFailureReason.UNSUPPORTED_TRANSPORT)
        ownedBytes = null
        return bytes
    }

    @Synchronized
    override fun close() {
        ownedBytes?.fill(0)
        ownedBytes = null
    }

    override fun toString(): String = "ZkPersonaCredentialEvidenceStageProveRequest(input=<redacted>)"
}

private const val MAX_REQUEST_BYTES: Int = 1_024 * 1_024

private fun takeOwnedCopy(input: ByteArray): ByteArray {
    if (input.isEmpty() || input.size > MAX_REQUEST_BYTES) {
        val reason =
            if (input.isEmpty()) {
                ZkProviderFailureReason.EMPTY_BUFFER
            } else {
                ZkProviderFailureReason.OVERSIZED_BUFFER
            }
        input.fill(0)
        fail(reason)
    }
    return try {
        input.copyOf()
    } finally {
        input.fill(0)
    }
}

private fun fail(reason: ZkProviderFailureReason): Nothing = throw ReallyMeZkProviderException(reason)
