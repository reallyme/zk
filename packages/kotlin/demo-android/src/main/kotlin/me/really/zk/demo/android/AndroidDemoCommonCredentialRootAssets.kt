// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import com.google.protobuf.InvalidProtocolBufferException
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.commonroot.ZkCommonCredentialRootPersonaMode
import me.really.zk.commonroot.ZkCommonCredentialRootStageProveRequest
import me.really.zk.commonroot.ZkCommonCredentialRootVerifyRequest
import reallyme.zk.v1.Manifest
import java.nio.charset.StandardCharsets

internal fun AndroidDemoAssetStore.commonCredentialRootVerifyRequest(
    mode: ZkCommonCredentialRootPersonaMode,
    credentialHashAlgorithm: ZkCredentialHashAlgorithm,
): ZkCommonCredentialRootVerifyRequest {
    val lane = commonCredentialRootLaneName(credentialHashAlgorithm)
    val persona = commonCredentialRootPersonaName(mode)
    val name = "common-credential-root-$lane-$persona.pb"
    val expectedDigest = commonCredentialRootFixtureDigests[name] ?: fail(ZkProviderFailureReason.INTERNAL_FAILURE)
    val bytes = reader.readAssetBounded("$ZK_DEMO_ASSET_ROOT/$name", MAX_COMMON_CREDENTIAL_ROOT_FIXTURE_BYTES)
    return try {
        if (sha256Hex(bytes) != expectedDigest) {
            fail(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        val operation = Manifest.ZkProviderOperationRequest.parseFrom(bytes)
        if (!operation.hasVerifyCommonCredentialRoot()) {
            fail(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        ZkCommonCredentialRootVerifyRequest(
            mode = mode,
            presentation = operation.verifyCommonCredentialRoot.presentation,
            policy = operation.verifyCommonCredentialRoot.joinPolicy,
        )
    } catch (error: ReallyMeZkProviderException) {
        throw error
    } catch (ignored: InvalidProtocolBufferException) {
        fail(ZkProviderFailureReason.MALFORMED_PROOF)
    } catch (ignored: RuntimeException) {
        fail(ZkProviderFailureReason.MALFORMED_PROOF)
    } finally {
        bytes.fill(0)
    }
}

internal fun AndroidDemoAssetStore.commonCredentialRootStageRequest(
    mode: ZkCommonCredentialRootPersonaMode,
    credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    slotIndex: Int,
): ZkCommonCredentialRootStageProveRequest {
    if (slotIndex !in 0 until COMMON_CREDENTIAL_ROOT_STAGE_COUNT) {
        fail(ZkProviderFailureReason.UNSUPPORTED_CIRCUIT)
    }
    val lane = commonCredentialRootLaneName(credentialHashAlgorithm)
    val persona = commonCredentialRootPersonaName(mode)
    val expectedPersonaMode =
        if (mode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA) {
            Manifest.ZkCommonCredentialRootPersonaMode.ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1
        } else {
            Manifest.ZkCommonCredentialRootPersonaMode.ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PUBLIC_PERSONA_V1
        }
    val name = "$lane-$persona-$slotIndex.pb"
    val expectedDigest = commonCredentialRootStageDigests()[name] ?: fail(ZkProviderFailureReason.INTERNAL_FAILURE)
    val bytes =
        reader.readAssetBounded(
            "$ZK_DEMO_ASSET_ROOT/common-credential-root-stage-requests-v1/$name",
            MAX_COMMON_CREDENTIAL_ROOT_STAGE_REQUEST_BYTES,
        )
    var transferredRequestBytes = false
    return try {
        if (sha256Hex(bytes) != expectedDigest) {
            fail(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
        val message = Manifest.ZkProviderOperationRequest.parseFrom(bytes)
        val validStage =
            message.hasProveCommonCredentialRootStage() &&
                message.proveCommonCredentialRootStage.personaMode == expectedPersonaMode &&
                message.proveCommonCredentialRootStage.circuitRef.credentialHashAlgorithm == credentialHashAlgorithm &&
                message.proveCommonCredentialRootStage.slot.number ==
                slotIndex + FIRST_COMMON_CREDENTIAL_ROOT_SLOT_NUMBER
        if (!validStage) {
            fail(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
        val request = ZkCommonCredentialRootStageProveRequest.fromCanonicalRequestBytes(bytes)
        transferredRequestBytes = true
        request
    } catch (error: ReallyMeZkProviderException) {
        throw error
    } catch (ignored: InvalidProtocolBufferException) {
        fail(ZkProviderFailureReason.MALFORMED_WITNESS)
    } catch (ignored: RuntimeException) {
        fail(ZkProviderFailureReason.MALFORMED_WITNESS)
    } finally {
        if (!transferredRequestBytes) {
            bytes.fill(0)
        }
    }
}

private fun AndroidDemoAssetStore.commonCredentialRootStageDigests(): Map<String, String> {
    val bytes =
        reader.readAssetBounded(
            "$ZK_DEMO_ASSET_ROOT/common-credential-root-stage-requests-v1/sha256.tsv",
            MAX_COMMON_CREDENTIAL_ROOT_STAGE_MANIFEST_BYTES,
        )
    return try {
        if (sha256Hex(bytes) != COMMON_CREDENTIAL_ROOT_STAGE_MANIFEST_SHA256) {
            fail(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
        val lines = bytes.toString(StandardCharsets.UTF_8).trimEnd().lines()
        if (lines.firstOrNull() != "filename\tsha256" ||
            lines.size !=
            COMMON_CREDENTIAL_ROOT_STAGE_COUNT * COMMON_CREDENTIAL_ROOT_VARIANT_COUNT +
            MANIFEST_HEADER_ROW_COUNT
        ) {
            fail(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
        val digests = mutableMapOf<String, String>()
        for (line in lines.drop(MANIFEST_HEADER_ROW_COUNT)) {
            val fields = line.split('\t')
            if (fields.size != MANIFEST_FIELD_COUNT) {
                fail(ZkProviderFailureReason.MALFORMED_WITNESS)
            }
            val validEntry =
                fields[0].matches(STAGE_REQUEST_NAME_PATTERN) &&
                    fields[1].matches(SHA256_HEX_PATTERN) &&
                    digests.put(fields[0], fields[1]) == null
            if (!validEntry) {
                fail(ZkProviderFailureReason.MALFORMED_WITNESS)
            }
        }
        digests
    } finally {
        bytes.fill(0)
    }
}

private fun commonCredentialRootLaneName(credentialHashAlgorithm: ZkCredentialHashAlgorithm): String =
    when (credentialHashAlgorithm) {
        ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256 -> "sha256"
        ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2 -> "poseidon2"
        else -> fail(ZkProviderFailureReason.UNSUPPORTED_CIRCUIT)
    }

private fun commonCredentialRootPersonaName(mode: ZkCommonCredentialRootPersonaMode): String =
    when (mode) {
        ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA -> "private"
        ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA -> "public"
    }

private const val MAX_COMMON_CREDENTIAL_ROOT_FIXTURE_BYTES = 256 * 1_024
private const val MAX_COMMON_CREDENTIAL_ROOT_STAGE_REQUEST_BYTES = 16 * 1_024
private const val MAX_COMMON_CREDENTIAL_ROOT_STAGE_MANIFEST_BYTES = 4 * 1_024
private const val COMMON_CREDENTIAL_ROOT_STAGE_COUNT = 9
private const val COMMON_CREDENTIAL_ROOT_VARIANT_COUNT = 4
private const val MANIFEST_HEADER_ROW_COUNT = 1
private const val MANIFEST_FIELD_COUNT = 2
private const val FIRST_COMMON_CREDENTIAL_ROOT_SLOT_NUMBER = 1
private const val COMMON_CREDENTIAL_ROOT_STAGE_MANIFEST_SHA256 =
    "46939ce0bdac43a132b45707f22b8f3c838ed8325714e16a01a769daebc39afa"
private val STAGE_REQUEST_NAME_PATTERN = Regex("(sha256|poseidon2)-(private|public)-[0-8]\\.pb")
private val SHA256_HEX_PATTERN = Regex("[a-f0-9]{64}")
private val commonCredentialRootFixtureDigests =
    mapOf(
        Pair(
            "common-credential-root-sha256-private.pb",
            "8eff0e80317c7eda620a35f5beb4b63b7dd5162a2cf2ab8fad3be4d74e18c8d4",
        ),
        "common-credential-root-sha256-public.pb" to "77b4a74aedadfb0df3c8c4a8b3fb2d8253b32d29f3b298d938c5a342f426931a",
        Pair(
            "common-credential-root-poseidon2-private.pb",
            "0ca57395f3a6d5124433ba932e93bed467dc56be2764b3c5a6b2c2513d547b2a",
        ),
        Pair(
            "common-credential-root-poseidon2-public.pb",
            "4bdd5f4fdc2cbcd71b54ecbc543ca7b3d84efe729aa444b01fcf018376f99a2c",
        ),
    )
