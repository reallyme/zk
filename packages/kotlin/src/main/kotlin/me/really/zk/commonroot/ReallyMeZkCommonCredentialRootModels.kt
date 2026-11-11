// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.commonroot

import com.google.protobuf.InvalidProtocolBufferException
import me.really.zk.BYTES_32
import me.really.zk.PROOF_SUITE
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.circuitRef
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.commonCredentialRootArtifactIdentityIsValid
import reallyme.zk.v1.Manifest

public enum class ZkCommonCredentialRootPersonaMode(
    internal val protoPersonaMode: Manifest.ZkCommonCredentialRootPersonaMode,
) {
    PRIVATE_PERSONA(
        Manifest.ZkCommonCredentialRootPersonaMode.ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1,
    ),
    PUBLIC_PERSONA(Manifest.ZkCommonCredentialRootPersonaMode.ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PUBLIC_PERSONA_V1),
}

internal val COMMON_CREDENTIAL_ROOT_PROOF_SLOTS: List<Manifest.ZkCommonCredentialRootProofSlot> =
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

/** The policy comes from the verifier's active request and authenticated trust state. */
public class ZkCommonCredentialRootVerifyRequest(
    public val mode: ZkCommonCredentialRootPersonaMode,
    public val presentation: Manifest.ZkCommonCredentialRootPresentation,
    public val policy: Manifest.ZkCommonCredentialRootJoinPolicy,
) {
    init {
        val validProofs =
            presentation.proofsList.map { it.slot } == COMMON_CREDENTIAL_ROOT_PROOF_SLOTS &&
                presentation.proofsList.all { proof ->
                    proof.personaMode == presentation.personaMode &&
                        proof.publicInputs.personaMode == presentation.personaMode &&
                        proof.publicInputs.slot == proof.slot &&
                        proof.publicInputs.circuitRef == proof.circuitRef &&
                        proof.circuitRef.credentialHashAlgorithm == presentation.credentialHashAlgorithm &&
                        proof.circuitRef.circuitRevision == 1 &&
                        proof.proofSuite == presentation.proofSuite &&
                        commonCredentialRootArtifactIdentityIsValid(proof) &&
                        proof.proof.size() > 0 &&
                        proof.proof.size() <= COMMON_CREDENTIAL_ROOT_MAX_PROOF_BYTES &&
                        proof.publicInputs.rawFields.size() > 0 &&
                        proof.publicInputs.rawFields.size() <= COMMON_CREDENTIAL_ROOT_MAX_RAW_PUBLIC_INPUT_BYTES
                }
        val validPolicy =
            policy.challenge.size() == BYTES_32 &&
                policy.audienceHash.size() == BYTES_32 &&
                policy.transactionDataHash.size() == BYTES_32 &&
                policy.assurancePolicyId.size() == BYTES_32 &&
                policy.statusRoot.size() == BYTES_32 &&
                policy.attestationSigner.x.size() == BYTES_32 &&
                policy.attestationSigner.y.size() == BYTES_32 &&
                policy.requestTimeUnix > 0 &&
                policy.claimsCount == COMMON_CREDENTIAL_ROOT_CREDENTIAL_COUNT &&
                policy.issuerStatusCount == COMMON_CREDENTIAL_ROOT_CREDENTIAL_COUNT &&
                policy.claimsList.all { claim ->
                    claim.issuer.x.size() == BYTES_32 &&
                        claim.issuer.y.size() == BYTES_32 &&
                        claim.claimNameHash.size() == BYTES_32 &&
                        claim.claimValue.size() in 1..COMMON_CREDENTIAL_ROOT_MAX_CLAIM_BYTES &&
                        claim.claimValueLength == claim.claimValue.size()
                } &&
                policy.issuerStatusList.all { status ->
                    status.root.size() == BYTES_32 &&
                        status.length > 0 &&
                        status.listId.size() == BYTES_32 &&
                        status.urlHash.size() == BYTES_32 &&
                        (
                            status.purpose == Manifest.ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_REVOCATION ||
                                status.purpose == Manifest.ZkIssuerStatusPurpose.ZK_ISSUER_STATUS_PURPOSE_SUSPENSION
                        )
                }
        val validBinding =
            presentation.sessionBinding.nonceHash == policy.challenge &&
                presentation.sessionBinding.audienceHash == policy.audienceHash &&
                presentation.sessionBinding.transactionDataHash == policy.transactionDataHash
        val validCredentialHashAlgorithm =
            presentation.credentialHashAlgorithm ==
                ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256 ||
                presentation.credentialHashAlgorithm ==
                ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2
        val validPresentation =
            presentation.personaMode == mode.protoPersonaMode &&
                validCredentialHashAlgorithm &&
                presentation.proofSuite == PROOF_SUITE &&
                presentation.proofsCount == COMMON_CREDENTIAL_ROOT_PROOF_SLOTS.size
        val validRequest = validPresentation && validProofs && validPolicy && validBinding
        if (!validRequest) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED)
        }
    }

    override fun toString(): String =
        "ZkCommonCredentialRootVerifyRequest(mode=$mode, " +
            "presentation=<redacted>, policy=<redacted>)"
}

/** Complete common-credential-root presentation proving request. Inputs contain private witness material. */
public class ZkCommonCredentialRootPresentationProveRequest private constructor(
    public val operation: Manifest.ZkCommonCredentialRootPresentationProveOperation,
    private var canonicalRequestBytes: ByteArray? = null,
) : AutoCloseable {
    public constructor(operation: Manifest.ZkCommonCredentialRootPresentationProveOperation) : this(operation, null)

    init {
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
        val validPresence =
            operation.hasExpectedBinding() &&
                operation.hasRootAttestation() &&
                operation.hasRootStatus() &&
                operation.hasLineage0() &&
                operation.hasLineage1() &&
                operation.hasSelectedClaim0() &&
                operation.hasSelectedClaim1() &&
                operation.hasSession() &&
                operation.hasIssuerCredentialStatus0() &&
                operation.hasIssuerCredentialStatus1()
        val validParent =
            (
                operation.personaMode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA.protoPersonaMode ||
                    operation.personaMode == ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA.protoPersonaMode
            ) &&
                operation.proofSuite == PROOF_SUITE &&
                operation.expectedBinding.nonceHash.size() == BYTES_32 &&
                operation.expectedBinding.audienceHash.size() == BYTES_32 &&
                operation.expectedBinding.transactionDataHash.size() == BYTES_32
        val validStages =
            stages.zip(COMMON_CREDENTIAL_ROOT_PROOF_SLOTS).all { (stage, slot) ->
                stage.personaMode == operation.personaMode &&
                    stage.slot == slot &&
                    stage.proofSuite == operation.proofSuite &&
                    stage.expectedBinding == operation.expectedBinding
            }
        if (!validPresence || !validParent || !validStages) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
        stages.forEach { ZkCommonCredentialRootStageProveRequest(it) }
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

    override fun toString(): String = "ZkCommonCredentialRootPresentationProveRequest(input=<redacted>)"

    private fun validateCanonicalRequestBytes(bytes: ByteArray) {
        val request = parseCommonCredentialRootPresentationCanonicalRequestOrNull(bytes)
        if (request == null ||
            !request.hasProveCommonCredentialRootPresentation() ||
            request.proveCommonCredentialRootPresentation != operation
        ) {
            bytes.fill(0)
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
    }

    public companion object {
        /**
         * Transfers canonical Buffa request bytes into the native transport owner.
         *
         * Full common-credential-root proving carries every private stage input, so the
         * platform boundary must dispatch the exact canonical bytes admitted at
         * construction. Re-encoding through Kotlin protobuf would change the
         * transport contract and may be rejected by the native Buffa decoder.
         */
        public fun fromCanonicalRequestBytes(
            ownedCanonicalProviderOperationRequestBytes: ByteArray,
        ): ZkCommonCredentialRootPresentationProveRequest {
            val request =
                parseCommonCredentialRootPresentationCanonicalRequestOrNull(
                    ownedCanonicalProviderOperationRequestBytes,
                )
            if (request == null || !request.hasProveCommonCredentialRootPresentation()) {
                ownedCanonicalProviderOperationRequestBytes.fill(0)
                throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
            }
            return ZkCommonCredentialRootPresentationProveRequest(
                operation = request.proveCommonCredentialRootPresentation,
                canonicalRequestBytes = ownedCanonicalProviderOperationRequestBytes,
            )
        }
    }
}

private typealias ProviderOperationRequest = Manifest.ZkProviderOperationRequest

private fun parseCommonCredentialRootPresentationCanonicalRequestOrNull(bytes: ByteArray): ProviderOperationRequest? =
    try {
        Manifest.ZkProviderOperationRequest.parseFrom(bytes)
    } catch (ignored: InvalidProtocolBufferException) {
        null
    } catch (ignored: RuntimeException) {
        null
    }

public class ZkCommonCredentialRootPresentationProof internal constructor(
    public val presentation: Manifest.ZkCommonCredentialRootPresentation,
) {
    override fun toString(): String = "ZkCommonCredentialRootPresentationProof(presentation=<redacted>)"
}

public class ZkVerifiedCommonCredentialRoot internal constructor(
    public val mode: ZkCommonCredentialRootPersonaMode,
    public val verifiedProofCount: Int,
) {
    override fun toString(): String = "ZkVerifiedCommonCredentialRoot($mode, proofs=$verifiedProofCount)"
}

internal const val COMMON_CREDENTIAL_ROOT_PROOF_COUNT: Int = 9
private const val COMMON_CREDENTIAL_ROOT_MAX_PROOF_BYTES: Int = 256 * 1_024
private const val COMMON_CREDENTIAL_ROOT_MAX_RAW_PUBLIC_INPUT_BYTES: Int = 418 * BYTES_32
private const val COMMON_CREDENTIAL_ROOT_CREDENTIAL_COUNT: Int = 2
private const val COMMON_CREDENTIAL_ROOT_MAX_CLAIM_BYTES: Int = 64
