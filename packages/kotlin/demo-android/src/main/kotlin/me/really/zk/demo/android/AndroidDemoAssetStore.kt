// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.content.Context
import me.really.zk.ReallyMeZkNativeContextFactory
import me.really.zk.ZkApprovedReleaseIndexPin
import me.really.zk.ZkNativeContextCreateRequest
import me.really.zk.ZkNativeContextOwnedFilePaths
import me.really.zk.ZkNativeCrsMode
import me.really.zk.ZkProviderFailureReason
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import me.really.zk.demo.shared.ReallyMeZkDemoFixtureWitnessInputs
import reallyme.zk.v1.Manifest
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal class AndroidDemoAssetStore(
    context: Context,
) {
    private val extraction = AndroidDemoAssetExtraction(context)
    internal val reader = AndroidDemoAssetReader(context)

    fun createContext(): Long {
        val root = extraction.prepareAssetRoot()
        return createContext(root)
    }

    fun fixtureWitnessInput(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm =
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        stage: ZkClaimProofBundleStage,
    ): Manifest.ZkStageWitnessInput {
        val resourceName =
            ReallyMeZkDemoFixtureWitnessInputs.fixtureResourceName(
                bundleKind,
                credentialHashAlgorithm,
                stage,
            )
        val bytes = reader.readAssetBounded("$FIXTURE_ASSET_ROOT/$resourceName.pb", MAX_FIXTURE_PROTOBUF_BYTES)
        return try {
            validatePinnedFixture("$resourceName.pb", bytes)
            ReallyMeZkDemoFixtureWitnessInputs.witnessInput(bundleKind, stage, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun createContext(root: File): Long {
        val artifactRoot = File(root, ARTIFACT_DIRECTORY_NAME)
        val crsG1 = File(root, CRS_G1_FILE_NAME)
        val crsG2 = File(root, CRS_G2_FILE_NAME)
        val artifactRootUtf8 = artifactRoot.absolutePath.toByteArray(StandardCharsets.UTF_8)
        val releaseIndex = reader.readFileBounded(File(root, RELEASE_INDEX_FILE_NAME), MAX_RELEASE_INDEX_BYTES)
        val releaseIndexPin = hexDigest(APPROVED_RELEASE_INDEX_SHA256)
        validatePinnedCrsFile(crsG1, EXACT_CRS_G1_BYTES, APPROVED_CRS_G1_SHA256)
        validatePinnedCrsFile(crsG2, EXACT_CRS_G2_BYTES, APPROVED_CRS_G2_SHA256)
        val crsG1PathUtf8 = crsG1.absolutePath.toByteArray(StandardCharsets.UTF_8)
        val crsG2PathUtf8 = crsG2.absolutePath.toByteArray(StandardCharsets.UTF_8)
        var requestOwnsInputBuffers = false
        try {
            val request =
                ZkNativeContextCreateRequest.fromOwnedFilePaths(
                    filePaths =
                        ZkNativeContextOwnedFilePaths(
                            artifactRootUtf8 = artifactRootUtf8,
                            releaseIndex = releaseIndex,
                            crsG1PathUtf8 = crsG1PathUtf8,
                            crsG2PathUtf8 = crsG2PathUtf8,
                        ),
                    approvedReleaseIndexPin = ZkApprovedReleaseIndexPin.fromTrustedBytes(releaseIndexPin),
                    crsMode = ZkNativeCrsMode.FULL_PROVER,
                )
            requestOwnsInputBuffers = true
            request.use {
                val result = ReallyMeZkNativeContextFactory().createContext(it)
                if (result.statusCode != ASSET_PLATFORM_STATUS_OK || result.contextHandle == 0L) {
                    fail(ZkProviderFailureReason.PROVIDER_UNAVAILABLE)
                }
                return result.contextHandle
            }
        } finally {
            if (!requestOwnsInputBuffers) {
                artifactRootUtf8.fill(0)
                releaseIndex.fill(0)
                crsG1PathUtf8.fill(0)
                crsG2PathUtf8.fill(0)
            }
            releaseIndexPin.fill(0)
        }
    }

    private fun validatePinnedCrsFile(
        file: File,
        expectedBytes: Int,
        expectedSha256: String,
    ) {
        mapIoFailures {
            requireExpectedSize(file.length(), expectedBytes)
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(COPY_BUFFER_BYTES)
            var total = 0L
            try {
                file.inputStream().use { input ->
                    var reading = true
                    while (reading) {
                        val read = input.read(buffer)
                        if (read < 0) {
                            reading = false
                        } else {
                            total = checkedCrsRead(total, read, expectedBytes)
                            digest.update(buffer, 0, read)
                        }
                    }
                }
                if (total != expectedBytes.toLong() || digest.digest().toHexString() != expectedSha256) {
                    fail(ZkProviderFailureReason.CRS_HASH_MISMATCH)
                }
            } finally {
                buffer.fill(0)
            }
        }
    }

    private fun validatePinnedFixture(
        fileName: String,
        bytes: ByteArray,
    ) {
        val manifestBytes =
            reader.readAssetBounded(
                "$FIXTURE_ASSET_ROOT/$FIXTURE_MANIFEST_FILE_NAME",
                MAX_FIXTURE_MANIFEST_BYTES,
            )
        val manifest =
            try {
                manifestBytes.toString(StandardCharsets.UTF_8)
            } finally {
                manifestBytes.fill(0)
            }
        val pin = fixturePin(fileName, manifest) ?: fail(ZkProviderFailureReason.MALFORMED_WITNESS)
        if (pin.byteCount != bytes.size || pin.sha256 != sha256Hex(bytes)) {
            fail(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
    }

    private fun fixturePin(
        fileName: String,
        manifest: String,
    ): FixturePin? =
        manifest
            .lineSequence()
            .filter { it.isNotEmpty() }
            .map { line -> parseFixturePinLine(fileName, line) }
            .firstOrNull { pin -> pin != null }

    private fun parseFixturePinLine(
        fileName: String,
        line: String,
    ): FixturePin? =
        line
            .split(' ')
            .filter { it.isNotEmpty() }
            .takeIf { fields -> fields.size == FIXTURE_MANIFEST_FIELD_COUNT }
            ?.let { fields -> fixturePinFromFields(fileName, fields) }

    private fun fixturePinFromFields(
        fileName: String,
        fields: List<String>,
    ): FixturePin? {
        val isHeader = fields[0] == "sha256" && fields[1] == "bytes" && fields[2] == "file"
        val byteCount = fields[1].toIntOrNull()
        val isMatchingPin =
            !isHeader &&
                fields[2] == fileName &&
                fields[0].length == SHA256_HEX_CHARS &&
                byteCount != null
        return if (isMatchingPin) {
            FixturePin(fields[0], byteCount)
        } else {
            null
        }
    }

    private fun hexDigest(value: String): ByteArray {
        if (value.length != SHA256_HEX_CHARS) {
            fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        return ByteArray(SHA256_BYTES) { index ->
            val offset = index * HEX_CHARS_PER_BYTE
            val byte = value.substring(offset, offset + HEX_CHARS_PER_BYTE).toIntOrNull(HEX_RADIX)
            if (byte == null || byte < 0 || byte > UNSIGNED_BYTE_MAX) {
                fail(ZkProviderFailureReason.INTERNAL_FAILURE)
            }
            byte.toByte()
        }
    }

    internal fun sha256Hex(bytes: ByteArray): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(bytes)
            .toHexString()
}

private fun checkedCrsRead(
    current: Long,
    read: Int,
    expectedBytes: Int,
): Long {
    val next = current + read.toLong()
    if (next > expectedBytes.toLong()) {
        fail(ZkProviderFailureReason.OVERSIZED_BUFFER)
    }
    return next
}

internal fun ByteArray.toHexString(): String = joinToString(separator = "") { byte -> "%02x".format(byte) }

private data class FixturePin(
    val sha256: String,
    val byteCount: Int,
)
