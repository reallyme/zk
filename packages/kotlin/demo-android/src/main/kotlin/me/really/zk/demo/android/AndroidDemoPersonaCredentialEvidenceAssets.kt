// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.commonroot.ZkCommonCredentialRootPersonaMode
import me.really.zk.personaevidence.ZkPersonaCredentialEvidenceStageProveRequest
import reallyme.zk.v1.Manifest
import java.nio.charset.StandardCharsets

private typealias PersonaEvidenceMode = Manifest.ZkPersonaCredentialEvidenceMode

internal fun AndroidDemoAssetStore.personaCredentialEvidenceRequest(
    mode: ZkCommonCredentialRootPersonaMode,
    credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    part: PersonaCredentialEvidenceSamplePart,
): ZkPersonaCredentialEvidenceStageProveRequest {
    val lane =
        when (credentialHashAlgorithm) {
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256 -> "sha256"
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2 -> "poseidon2"
            else -> fail(ZkProviderFailureReason.UNSUPPORTED_CIRCUIT)
        }
    val persona = if (mode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA) "private" else "public"
    val name = "$lane-$persona-${part.fileName}.pb"
    val digest = personaCredentialEvidenceDigests()[name] ?: fail(ZkProviderFailureReason.MALFORMED_WITNESS)
    val bytes =
        reader.readAssetBounded(
            "$PERSONA_CREDENTIAL_EVIDENCE_SAMPLE_ROOT/$name",
            MAX_PERSONA_CREDENTIAL_EVIDENCE_REQUEST_BYTES,
        )
    var transferred = false
    return try {
        if (sha256Hex(bytes) != digest) {
            fail(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
        val expectedMode = personaCredentialEvidenceMode(mode)
        val stage = personaCredentialEvidenceStage(mode, part)
        val reference =
            Manifest.ZkCircuitRef
                .newBuilder()
                .setFamily(Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PERSONA_CREDENTIAL_EVIDENCE_V1)
                .setStage(stage)
                .setCredentialHashAlgorithm(credentialHashAlgorithm)
                .setCircuitRevision(1)
                .build()
        val request = ZkPersonaCredentialEvidenceStageProveRequest(bytes, expectedMode, reference)
        transferred = true
        request
    } catch (error: ReallyMeZkProviderException) {
        throw error
    } catch (ignored: RuntimeException) {
        fail(ZkProviderFailureReason.MALFORMED_WITNESS)
    } finally {
        if (!transferred) {
            bytes.fill(0)
        }
    }
}

private fun AndroidDemoAssetStore.personaCredentialEvidenceDigests(): Map<String, String> {
    val bytes =
        reader.readAssetBounded(
            "$PERSONA_CREDENTIAL_EVIDENCE_SAMPLE_ROOT/sha256.tsv",
            MAX_PERSONA_CREDENTIAL_EVIDENCE_MANIFEST_BYTES,
        )
    return try {
        if (sha256Hex(bytes) != PERSONA_CREDENTIAL_EVIDENCE_MANIFEST_SHA256) {
            fail(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
        val lines = bytes.toString(StandardCharsets.UTF_8).trimEnd().lines()
        if (
            lines.firstOrNull() != "filename\tsha256" ||
            lines.size != PERSONA_CREDENTIAL_EVIDENCE_REQUEST_COUNT + 1
        ) {
            fail(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
        val digests = HashMap<String, String>(PERSONA_CREDENTIAL_EVIDENCE_REQUEST_COUNT)
        for (line in lines.drop(1)) {
            val fields = line.split('\t')
            if (fields.size != 2) {
                fail(ZkProviderFailureReason.MALFORMED_WITNESS)
            }
            val validName = fields[0].matches(PERSONA_CREDENTIAL_EVIDENCE_NAME_PATTERN)
            val validDigest = fields[1].matches(PERSONA_CREDENTIAL_EVIDENCE_DIGEST_PATTERN)
            if (!validName || !validDigest || digests.put(fields[0], fields[1]) != null) {
                fail(ZkProviderFailureReason.MALFORMED_WITNESS)
            }
        }
        digests
    } finally {
        bytes.fill(0)
    }
}

private fun personaCredentialEvidenceMode(mode: ZkCommonCredentialRootPersonaMode): PersonaEvidenceMode =
    when (mode) {
        ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA ->
            Manifest.ZkPersonaCredentialEvidenceMode
                .ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
        ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA ->
            Manifest.ZkPersonaCredentialEvidenceMode.ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1
    }

private fun personaCredentialEvidenceStage(
    mode: ZkCommonCredentialRootPersonaMode,
    part: PersonaCredentialEvidenceSamplePart,
): Manifest.ZkCircuitStage =
    when (part) {
        PersonaCredentialEvidenceSamplePart.ISSUER -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_ISSUER_ENVELOPE
        PersonaCredentialEvidenceSamplePart.ROOT -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_CLAIM_ROOT
        PersonaCredentialEvidenceSamplePart.VALIDITY ->
            Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_SIGNED_VALIDITY
        PersonaCredentialEvidenceSamplePart.STATUS -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_CURRENT_STATE
        PersonaCredentialEvidenceSamplePart.CLAIM ->
            when (mode) {
                ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA ->
                    Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_PRIVATE_CLAIM
                ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA ->
                    Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_EVIDENCE_PUBLIC_CLAIM
            }
    }

internal enum class PersonaCredentialEvidenceSamplePart(
    internal val fileName: String,
) {
    ISSUER("issuer"),
    ROOT("root"),
    VALIDITY("validity"),
    CLAIM("claim"),
    STATUS("status"),
}

private const val PERSONA_CREDENTIAL_EVIDENCE_SAMPLE_ROOT =
    "$ZK_DEMO_ASSET_ROOT/persona-credential-evidence-mobile-requests-v1"
private const val PERSONA_CREDENTIAL_EVIDENCE_REQUEST_COUNT = 20
private const val MAX_PERSONA_CREDENTIAL_EVIDENCE_MANIFEST_BYTES = 2 * 1_024
private const val MAX_PERSONA_CREDENTIAL_EVIDENCE_REQUEST_BYTES = 1 * 1_024 * 1_024
private const val PERSONA_CREDENTIAL_EVIDENCE_MANIFEST_SHA256 =
    "83d1a4fea99dc405936b99e42af80452c22df2141bef48761931dc47346e6df8"
private val PERSONA_CREDENTIAL_EVIDENCE_NAME_PATTERN =
    Regex("(sha256|poseidon2)-(private|public)-(issuer|root|validity|claim|status)\\.pb")
private val PERSONA_CREDENTIAL_EVIDENCE_DIGEST_PATTERN = Regex("[a-f0-9]{64}")
