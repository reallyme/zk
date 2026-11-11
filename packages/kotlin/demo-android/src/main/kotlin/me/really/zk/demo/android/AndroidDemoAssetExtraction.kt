// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.content.Context
import me.really.zk.ZkProviderFailureReason
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

internal class AndroidDemoAssetExtraction(
    private val context: Context,
) {
    fun prepareAssetRoot(): File =
        mapIoFailures {
            val root = File(context.filesDir, EXTRACTED_ASSET_ROOT_NAME)
            val rootPath = containedPath(context, root)
            if (isExtractionCurrent(rootPath)) {
                return@mapIoFailures root
            }
            if (root.exists()) {
                rejectSymbolicPathTree(root)
                if (!root.deleteRecursively()) {
                    fail(ZkProviderFailureReason.INTERNAL_FAILURE)
                }
            }
            val budget = ExtractionBudget()
            copyAssetTree(ZK_DEMO_ASSET_ROOT, root, budget)
            File(root, EXTRACTION_STAMP_FILE_NAME).writeText(APPROVED_RELEASE_INDEX_SHA256, StandardCharsets.UTF_8)
            root
        }

    private fun rejectSymbolicPathTree(file: File) {
        val path = containedPath(context, file)
        if (Files.exists(path) && Files.isSymbolicLink(path)) {
            fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        if (!file.isDirectory) {
            return
        }
        val children = file.listFiles() ?: fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        for (child in children) {
            rejectSymbolicPathTree(child)
        }
    }

    private fun validateWritablePath(file: File) {
        val path = containedPath(context, file)
        if (Files.isSymbolicLink(path)) {
            fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        val parent = file.parentFile ?: fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        val parentPath = containedPath(context, parent)
        if (Files.exists(parentPath) && Files.isSymbolicLink(parentPath)) {
            fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
    }

    private fun ensureDirectory(targetPath: Path) {
        if (!targetPath.toFile().mkdirs() && !targetPath.toFile().isDirectory) {
            fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        if (Files.isSymbolicLink(targetPath)) {
            fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
    }

    private fun copyAssetTree(
        assetPath: String,
        target: File,
        budget: ExtractionBudget,
    ) {
        val targetPath = containedPath(context, target)
        val entries = context.assets.list(assetPath) ?: fail(ZkProviderFailureReason.PROVIDER_UNAVAILABLE)
        if (entries.isEmpty()) {
            copyAssetFile(assetPath, targetPath.toFile(), budget)
            return
        }
        ensureDirectory(targetPath)
        for (entry in entries.sorted()) {
            validateAssetEntry(entry)
            copyAssetTree("$assetPath/$entry", File(targetPath.toFile(), entry), budget)
        }
    }

    private fun copyAssetFile(
        assetPath: String,
        target: File,
        budget: ExtractionBudget,
    ) {
        budget.recordFile()
        val parent = target.parentFile ?: fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        if (!parent.mkdirs() && !parent.isDirectory) {
            fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        validateWritablePath(target)
        context.assets.open(assetPath).use { input ->
            target.outputStream().use { output ->
                copyAssetBytes(input, output, budget)
            }
        }
    }

    private fun copyAssetBytes(
        input: InputStream,
        output: OutputStream,
        budget: ExtractionBudget,
    ) {
        val buffer = ByteArray(COPY_BUFFER_BYTES)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read < 0) {
                    break
                }
                budget.recordBytes(read)
                output.write(buffer, 0, read)
            }
        } finally {
            buffer.fill(0)
        }
    }

    private fun isExtractionCurrent(rootPath: Path): Boolean {
        val root = rootPath.toFile()
        val requiredFilesPresent =
            File(root, RELEASE_INDEX_FILE_NAME).isFile &&
                File(root, CRS_G1_FILE_NAME).isFile &&
                File(root, CRS_G2_FILE_NAME).isFile
        if (!root.isDirectory || Files.isSymbolicLink(rootPath) || !requiredFilesPresent) {
            return false
        }
        val stamp = File(root, EXTRACTION_STAMP_FILE_NAME)
        return stamp.isFile && stamp.readText(StandardCharsets.UTF_8) == APPROVED_RELEASE_INDEX_SHA256
    }
}

private class ExtractionBudget {
    private var fileCount = 0
    private var totalBytes = 0L

    fun recordFile() {
        fileCount = checkedAssetRead(fileCount, 1, MAX_EXTRACTED_FILES)
    }

    fun recordBytes(read: Int) {
        val next = totalBytes + read.toLong()
        if (next > MAX_EXTRACTED_BYTES) {
            fail(ZkProviderFailureReason.OVERSIZED_BUFFER)
        }
        totalBytes = next
    }
}
