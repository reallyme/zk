// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.content.Context
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import java.io.File
import java.io.IOException
import java.io.InputStream

internal class AndroidDemoAssetReader(
    private val context: Context,
) {
    fun readAssetBounded(
        assetPath: String,
        maximumBytes: Int,
    ): ByteArray =
        mapIoFailures {
            context.assets.open(assetPath).use { input ->
                readStreamBounded(input, maximumBytes)
            }
        }

    fun readFileBounded(
        file: File,
        maximumBytes: Int,
    ): ByteArray =
        mapIoFailures {
            file.inputStream().use { input ->
                readStreamBounded(input, maximumBytes)
            }
        }

    fun readFileExactLength(
        file: File,
        expectedBytes: Int,
    ): ByteArray =
        mapIoFailures {
            val size = file.length()
            requireExpectedSize(size, expectedBytes)
            val bytes = ByteArray(expectedBytes)
            try {
                file.inputStream().use { input ->
                    var offset = 0
                    while (offset < expectedBytes) {
                        val read = input.read(bytes, offset, expectedBytes - offset)
                        if (read < 0) {
                            fail(ZkProviderFailureReason.OVERSIZED_BUFFER)
                        }
                        offset = checkedAssetRead(offset, read, expectedBytes)
                    }
                    if (input.read() >= 0) {
                        fail(ZkProviderFailureReason.OVERSIZED_BUFFER)
                    }
                }
                bytes
            } catch (error: ReallyMeZkProviderException) {
                bytes.fill(0)
                typedFailure(error)
            } catch (ignored: IOException) {
                bytes.fill(0)
                fail(ZkProviderFailureReason.PROVIDER_UNAVAILABLE)
            } catch (ignored: SecurityException) {
                bytes.fill(0)
                fail(ZkProviderFailureReason.INTERNAL_FAILURE)
            }
        }

    private fun readStreamBounded(
        input: InputStream,
        maximumBytes: Int,
    ): ByteArray {
        if (maximumBytes <= 0) {
            fail(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        val buffer = ByteArray(maximumBytes)
        try {
            var total = 0
            var reading = true
            while (reading) {
                val read = readNextChunk(input, buffer, total, maximumBytes)
                if (read < 0) {
                    reading = false
                } else {
                    total = checkedAssetRead(total, read, maximumBytes)
                }
            }
            val bytes = buffer.copyOf(total)
            requireNonEmpty(bytes)
            return bytes
        } catch (error: ReallyMeZkProviderException) {
            typedFailure(error)
        } finally {
            buffer.fill(0)
        }
    }

    private fun readNextChunk(
        input: InputStream,
        buffer: ByteArray,
        total: Int,
        maximumBytes: Int,
    ): Int {
        val remaining = maximumBytes - total
        return if (remaining == 0) {
            readEndOfStream(input)
        } else {
            input.read(buffer, total, remaining)
        }
    }

    private fun readEndOfStream(input: InputStream): Int {
        if (input.read() >= 0) {
            fail(ZkProviderFailureReason.OVERSIZED_BUFFER)
        }
        return END_OF_STREAM
    }
}
