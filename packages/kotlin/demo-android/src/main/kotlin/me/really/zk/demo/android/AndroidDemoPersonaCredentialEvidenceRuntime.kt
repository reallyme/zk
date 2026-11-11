// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import me.really.zk.ReallyMeZkNativeProvider
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.commonroot.ZkCommonCredentialRootPersonaMode
import reallyme.zk.v1.Manifest
import reallyme.zk.v1.Manifest.ZkPersonaCredentialEvidenceProofSlot

internal class AndroidDemoPersonaCredentialEvidenceRuntime(
    private val assets: AndroidDemoAssetStore,
) {
    fun prepareSample(
        mode: ZkCommonCredentialRootPersonaMode,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    ): PersonaCredentialEvidenceSampleProofs {
        val handle = assets.createContext()
        var result: PersonaCredentialEvidenceSampleProofs? = null
        var primaryFailure: ReallyMeZkProviderException? = null
        try {
            val provider = ReallyMeZkNativeProvider(handle)
            val started = System.nanoTime()
            val issuer = proveStage(provider, mode, credentialHashAlgorithm, PersonaCredentialEvidenceSamplePart.ISSUER)
            val root = proveStage(provider, mode, credentialHashAlgorithm, PersonaCredentialEvidenceSamplePart.ROOT)
            val validity =
                proveStage(provider, mode, credentialHashAlgorithm, PersonaCredentialEvidenceSamplePart.VALIDITY)
            val claim = proveStage(provider, mode, credentialHashAlgorithm, PersonaCredentialEvidenceSamplePart.CLAIM)
            val status = proveStage(provider, mode, credentialHashAlgorithm, PersonaCredentialEvidenceSamplePart.STATUS)
            if (!personaCredentialEvidenceStagesJoin(issuer, root, validity, claim, status)) {
                fail(ZkProviderFailureReason.PROOF_REJECTED)
            }
            result =
                PersonaCredentialEvidenceSampleProofs(
                    mode,
                    credentialHashAlgorithm,
                    issuer,
                    root,
                    validity,
                    claim,
                    status,
                    (System.nanoTime() - started).toDouble() / NANOS_PER_MILLISECOND,
                )
        } catch (error: ReallyMeZkProviderException) {
            primaryFailure = error
        } catch (ignored: RuntimeException) {
            primaryFailure = ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        val cleanupFailure = destroyAndroidDemoContext(handle)
        if (primaryFailure != null) throw primaryFailure
        if (cleanupFailure != null) throw cleanupFailure
        return result ?: fail(ZkProviderFailureReason.INTERNAL_FAILURE)
    }

    fun verifyCachedStages(proofs: PersonaCredentialEvidenceSampleProofs): Double {
        if (!personaCredentialEvidenceStagesJoin(
                proofs.issuer,
                proofs.root,
                proofs.validity,
                proofs.claim,
                proofs.status,
            )
        ) {
            fail(ZkProviderFailureReason.PROOF_REJECTED)
        }
        val handle = assets.createContext()
        var result: Double? = null
        var primaryFailure: ReallyMeZkProviderException? = null
        try {
            val provider = ReallyMeZkNativeProvider(handle)
            val started = System.nanoTime()
            val issuer = provider.verifyPersonaCredentialEvidenceStage(proofs.issuer)
            val root = provider.verifyPersonaCredentialEvidenceStage(proofs.root)
            val validity = provider.verifyPersonaCredentialEvidenceStage(proofs.validity)
            val claim = provider.verifyPersonaCredentialEvidenceStage(proofs.claim)
            val status = provider.verifyPersonaCredentialEvidenceStage(proofs.status)
            val credentialSlots =
                issuer.proofSlot ==
                    ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE &&
                    root.proofSlot ==
                    ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT &&
                    validity.proofSlot ==
                    ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY
            val presentationSlots =
                claim.proofSlot ==
                    ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM &&
                    status.proofSlot ==
                    ZkPersonaCredentialEvidenceProofSlot.ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE
            val matchingProfileAndLane =
                listOf(issuer, root, validity, claim, status).all {
                    it.mode == claim.mode && it.circuitRef.credentialHashAlgorithm == proofs.credentialHashAlgorithm
                }
            if (!credentialSlots || !presentationSlots || !matchingProfileAndLane) {
                fail(ZkProviderFailureReason.PROOF_REJECTED)
            }
            result = (System.nanoTime() - started).toDouble() / NANOS_PER_MILLISECOND
        } catch (error: ReallyMeZkProviderException) {
            primaryFailure = error
        } catch (ignored: RuntimeException) {
            primaryFailure = ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        val cleanupFailure = destroyAndroidDemoContext(handle)
        if (primaryFailure != null) throw primaryFailure
        if (cleanupFailure != null) throw cleanupFailure
        return result ?: fail(ZkProviderFailureReason.INTERNAL_FAILURE)
    }

    private fun proveStage(
        provider: ReallyMeZkNativeProvider,
        mode: ZkCommonCredentialRootPersonaMode,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
        part: PersonaCredentialEvidenceSamplePart,
    ): Manifest.ZkPersonaCredentialEvidenceStageProof {
        val request = assets.personaCredentialEvidenceRequest(mode, credentialHashAlgorithm, part)
        return request.use { provider.provePersonaCredentialEvidenceStage(it) }
    }
}

internal data class PersonaCredentialEvidenceSampleProofs(
    val mode: ZkCommonCredentialRootPersonaMode,
    val credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    val issuer: Manifest.ZkPersonaCredentialEvidenceStageProof,
    val root: Manifest.ZkPersonaCredentialEvidenceStageProof,
    val validity: Manifest.ZkPersonaCredentialEvidenceStageProof,
    val claim: Manifest.ZkPersonaCredentialEvidenceStageProof,
    val status: Manifest.ZkPersonaCredentialEvidenceStageProof,
    val generationMilliseconds: Double,
)

private const val NANOS_PER_MILLISECOND = 1_000_000.0
