// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.content.Context
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import java.io.File
import java.io.IOException
import java.nio.file.Path

internal fun <T> mapIoFailures(block: () -> T): T =
    try {
        block()
    } catch (ignored: IOException) {
        fail(ZkProviderFailureReason.PROVIDER_UNAVAILABLE)
    } catch (ignored: SecurityException) {
        fail(ZkProviderFailureReason.INTERNAL_FAILURE)
    }

internal fun validateAssetEntry(entry: String) {
    val reservedEntry = entry == "." || entry == ".."
    if (entry.isEmpty() || reservedEntry || entry.contains('/')) {
        fail(ZkProviderFailureReason.INTERNAL_FAILURE)
    }
}

internal fun containedPath(
    context: Context,
    file: File,
): Path {
    val filesRoot =
        context.filesDir
            .toPath()
            .toAbsolutePath()
            .normalize()
    val target = file.toPath().toAbsolutePath().normalize()
    if (!target.startsWith(filesRoot)) {
        fail(ZkProviderFailureReason.INTERNAL_FAILURE)
    }
    return target
}

internal fun checkedAssetRead(
    current: Int,
    read: Int,
    maximumBytes: Int,
): Int {
    val next = current.toLong() + read.toLong()
    if (next > maximumBytes.toLong() || next > Int.MAX_VALUE) {
        fail(ZkProviderFailureReason.OVERSIZED_BUFFER)
    }
    return next.toInt()
}

internal fun requireNonEmpty(bytes: ByteArray) {
    if (bytes.isEmpty()) {
        fail(ZkProviderFailureReason.EMPTY_BUFFER)
    }
}

internal fun requireExpectedSize(
    actualBytes: Long,
    expectedBytes: Int,
) {
    if (actualBytes != expectedBytes.toLong()) {
        fail(ZkProviderFailureReason.OVERSIZED_BUFFER)
    }
}

internal fun typedFailure(error: ReallyMeZkProviderException): Nothing = throw error

internal fun fail(reason: ZkProviderFailureReason): Nothing = throw ReallyMeZkProviderException(reason)

internal const val ASSET_PLATFORM_STATUS_OK = 0
internal const val ZK_DEMO_ASSET_ROOT = "zk_demo"
internal const val FIXTURE_ASSET_ROOT = "flow_inputs"
internal const val EXTRACTED_ASSET_ROOT_NAME = "reallyme_zk_demo_assets"
internal const val EXTRACTION_STAMP_FILE_NAME = ".release-index.sha256"
internal const val ARTIFACT_DIRECTORY_NAME = "artifacts"
internal const val RELEASE_INDEX_FILE_NAME = "release-index.pb"
internal const val CRS_G1_FILE_NAME = "crs/bn254_g1.prover"
internal const val CRS_G2_FILE_NAME = "crs/bn254_g2"
internal const val APPROVED_RELEASE_INDEX_SHA256 =
    "9260afdb9a3a0133a679af141a310b6aacbf2e814724692ca964d2711ae49ce7"
internal const val APPROVED_CRS_G1_SHA256 =
    "0f238856e55722f15a4d64ef0de12b4260e218245590bd3a6c900aee188de8e5"
internal const val APPROVED_CRS_G2_SHA256 =
    "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f"
internal const val COPY_BUFFER_BYTES = 16 * 1_024
internal const val MAX_FIXTURE_PROTOBUF_BYTES = 16 * 1_024
internal const val MAX_FIXTURE_MANIFEST_BYTES = 4 * 1_024
internal const val MAX_RELEASE_INDEX_BYTES = 1 * 1_024 * 1_024
internal const val EXACT_CRS_G1_BYTES = 67_108_928
internal const val EXACT_CRS_G2_BYTES = 128

// The sealed matrix includes the common-credential-root programs and package metadata.
// Keep a bounded margin while rejecting unexpectedly large extracted trees.
internal const val MAX_EXTRACTED_FILES = 192
internal const val MAX_EXTRACTED_BYTES = 350L * 1_024L * 1_024L
internal const val SHA256_BYTES = 32
internal const val SHA256_HEX_CHARS = 64
internal const val FIXTURE_MANIFEST_FIELD_COUNT = 3
internal const val FIXTURE_MANIFEST_FILE_NAME = "SHA256SUMS"
internal const val HEX_CHARS_PER_BYTE = 2
internal const val HEX_RADIX = 16
internal const val UNSIGNED_BYTE_MAX = 255
internal const val END_OF_STREAM = -1
