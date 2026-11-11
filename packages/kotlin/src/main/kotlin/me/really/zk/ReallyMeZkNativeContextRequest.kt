// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

/**
 * Approved release-index trust anchor supplied by the embedding app.
 *
 * Callers must construct this from reviewed build configuration or
 * authenticated release metadata. It must not be computed from the same
 * release-index bytes being opened.
 */
public class ZkApprovedReleaseIndexPin private constructor(
    private val digestBytes: ByteArray,
) {
    public fun copyBytes(): ByteArray = digestBytes.copyOf()

    public companion object {
        public fun fromTrustedBytes(bytes: ByteArray): ZkApprovedReleaseIndexPin {
            validateExactDigest(bytes)
            return ZkApprovedReleaseIndexPin(bytes.copyOf())
        }
    }
}

/**
 * Buffers transferred into a native context request without copying.
 *
 * The arrays remain mutable because JNI needs stable byte-array references
 * during synchronous context creation. Callers hand ownership to
 * [ZkNativeContextCreateRequest.fromOwnedBuffers] and must not read, mutate,
 * or zeroize them afterward.
 */
public class ZkNativeContextOwnedBuffers(
    internal val artifactRootUtf8: ByteArray,
    internal val releaseIndex: ByteArray,
    internal val crsG1: ByteArray,
    internal val crsG2: ByteArray,
) {
    internal fun zeroize() {
        artifactRootUtf8.fill(0)
        releaseIndex.fill(0)
        crsG1.fill(0)
        crsG2.fill(0)
    }
}

/**
 * File-path backed CRS inputs transferred into a native context request.
 *
 * The platform bridge opens CRS files natively so mobile callers do not need
 * to materialize prover-sized CRS bytes on the managed heap. The paths are
 * still owned mutable byte arrays because JNI borrows them synchronously.
 */
public class ZkNativeContextOwnedFilePaths(
    internal val artifactRootUtf8: ByteArray,
    internal val releaseIndex: ByteArray,
    internal val crsG1PathUtf8: ByteArray,
    internal val crsG2PathUtf8: ByteArray,
) {
    internal fun zeroize() {
        artifactRootUtf8.fill(0)
        releaseIndex.fill(0)
        crsG1PathUtf8.fill(0)
        crsG2PathUtf8.fill(0)
    }
}

internal enum class ZkNativeContextCrsSource {
    BYTE_BUFFERS,
    FILE_PATHS,
}

public class ZkNativeContextCreateRequest private constructor(
    buffers: ZkNativeContextOwnedBuffers,
    approvedReleaseIndexPin: ZkApprovedReleaseIndexPin,
    public val crsMode: ZkNativeCrsMode,
    copyInputBuffers: Boolean,
    private val crsSource: ZkNativeContextCrsSource,
) : AutoCloseable {
    public constructor(
        artifactRootUtf8: ByteArray,
        releaseIndex: ByteArray,
        approvedReleaseIndexPin: ZkApprovedReleaseIndexPin,
        crsG1: ByteArray,
        crsG2: ByteArray,
        crsMode: ZkNativeCrsMode,
    ) : this(
        buffers =
            ZkNativeContextOwnedBuffers(
                artifactRootUtf8 = artifactRootUtf8,
                releaseIndex = releaseIndex,
                crsG1 = crsG1,
                crsG2 = crsG2,
            ),
        approvedReleaseIndexPin = approvedReleaseIndexPin,
        crsMode = crsMode,
        copyInputBuffers = true,
        crsSource = ZkNativeContextCrsSource.BYTE_BUFFERS,
    )

    private val artifactRootUtf8Bytes: ByteArray = ownedOrCopied(buffers.artifactRootUtf8, copyInputBuffers)
    private val releaseIndexBytes: ByteArray = ownedOrCopied(buffers.releaseIndex, copyInputBuffers)
    private val crsG1Bytes: ByteArray = ownedOrCopied(buffers.crsG1, copyInputBuffers)
    private val crsG2Bytes: ByteArray = ownedOrCopied(buffers.crsG2, copyInputBuffers)
    private val releaseIndexPin: ZkApprovedReleaseIndexPin = approvedReleaseIndexPin
    private val lock: Any = Any()
    private var closed: Boolean = false
    private var activeBorrows: Int = 0

    init {
        validateContextNonEmpty(artifactRootUtf8Bytes)
        validateContextNonEmpty(releaseIndexBytes)
        validateContextNonEmpty(crsG1Bytes)
        validateContextNonEmpty(crsG2Bytes)
    }

    internal fun releaseIndexCopy(): ByteArray {
        synchronized(lock) {
            checkOpenLocked()
            return releaseIndexBytes.copyOf()
        }
    }

    internal fun usesCrsFilePaths(): Boolean {
        synchronized(lock) {
            checkOpenLocked()
            return crsSource == ZkNativeContextCrsSource.FILE_PATHS
        }
    }

    internal fun approvedReleaseIndexSha256Copy(): ByteArray {
        synchronized(lock) {
            checkOpenLocked()
            return releaseIndexPin.copyBytes()
        }
    }

    internal fun <Value> withBorrowedContextCreateBuffers(
        releaseIndexSha256: ByteArray,
        operation: (Array<ByteArray>) -> Value,
    ): Value {
        val buffers =
            synchronized(lock) {
                checkOpenLocked()
                requireSourceLocked(ZkNativeContextCrsSource.BYTE_BUFFERS)
                if (activeBorrows == Int.MAX_VALUE) {
                    throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
                }
                activeBorrows += 1
                arrayOf(
                    artifactRootUtf8Bytes,
                    releaseIndexBytes,
                    releaseIndexSha256,
                    crsG1Bytes,
                    crsG2Bytes,
                )
            }
        try {
            return operation(buffers)
        } finally {
            synchronized(lock) {
                activeBorrows -= 1
            }
        }
    }

    internal fun <Value> withBorrowedContextCreateFilePathBuffers(
        releaseIndexSha256: ByteArray,
        operation: (Array<ByteArray>) -> Value,
    ): Value {
        val buffers =
            synchronized(lock) {
                checkOpenLocked()
                requireSourceLocked(ZkNativeContextCrsSource.FILE_PATHS)
                if (activeBorrows == Int.MAX_VALUE) {
                    throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
                }
                activeBorrows += 1
                arrayOf(
                    artifactRootUtf8Bytes,
                    releaseIndexBytes,
                    releaseIndexSha256,
                    crsG1Bytes,
                    crsG2Bytes,
                )
            }
        try {
            return operation(buffers)
        } finally {
            synchronized(lock) {
                activeBorrows -= 1
            }
        }
    }

    override fun close() {
        synchronized(lock) {
            if (closed) {
                return
            }
            if (activeBorrows != 0) {
                throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
            }
            artifactRootUtf8Bytes.fill(0)
            releaseIndexBytes.fill(0)
            crsG1Bytes.fill(0)
            crsG2Bytes.fill(0)
            closed = true
        }
    }

    private fun checkOpenLocked() {
        if (closed) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
    }

    private fun requireSourceLocked(expected: ZkNativeContextCrsSource) {
        if (crsSource != expected) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
    }

    public companion object {
        /**
         * Constructs a context request by taking ownership of caller-provided
         * mutable buffers. The request zeroizes these buffers on close; callers
         * must not read, mutate, or zeroize them after this method returns.
         */
        public fun fromOwnedBuffers(
            buffers: ZkNativeContextOwnedBuffers,
            approvedReleaseIndexPin: ZkApprovedReleaseIndexPin,
            crsMode: ZkNativeCrsMode,
        ): ZkNativeContextCreateRequest =
            try {
                validateContextNonEmpty(buffers.artifactRootUtf8)
                validateContextNonEmpty(buffers.releaseIndex)
                validateContextNonEmpty(buffers.crsG1)
                validateContextNonEmpty(buffers.crsG2)
                ZkNativeContextCreateRequest(
                    buffers = buffers,
                    approvedReleaseIndexPin = approvedReleaseIndexPin,
                    crsMode = crsMode,
                    copyInputBuffers = false,
                    crsSource = ZkNativeContextCrsSource.BYTE_BUFFERS,
                )
            } catch (error: ReallyMeZkProviderException) {
                buffers.zeroize()
                throw error
            }

        /**
         * Constructs a context request by taking ownership of UTF-8 CRS file
         * paths. The native bridge opens and verifies the CRS files; callers
         * must not read, mutate, or zeroize these arrays after this method
         * returns.
         */
        public fun fromOwnedFilePaths(
            filePaths: ZkNativeContextOwnedFilePaths,
            approvedReleaseIndexPin: ZkApprovedReleaseIndexPin,
            crsMode: ZkNativeCrsMode,
        ): ZkNativeContextCreateRequest =
            try {
                validateContextNonEmpty(filePaths.artifactRootUtf8)
                validateContextNonEmpty(filePaths.releaseIndex)
                validateContextNonEmpty(filePaths.crsG1PathUtf8)
                validateContextNonEmpty(filePaths.crsG2PathUtf8)
                ZkNativeContextCreateRequest(
                    buffers =
                        ZkNativeContextOwnedBuffers(
                            artifactRootUtf8 = filePaths.artifactRootUtf8,
                            releaseIndex = filePaths.releaseIndex,
                            crsG1 = filePaths.crsG1PathUtf8,
                            crsG2 = filePaths.crsG2PathUtf8,
                        ),
                    approvedReleaseIndexPin = approvedReleaseIndexPin,
                    crsMode = crsMode,
                    copyInputBuffers = false,
                    crsSource = ZkNativeContextCrsSource.FILE_PATHS,
                )
            } catch (error: ReallyMeZkProviderException) {
                filePaths.zeroize()
                throw error
            }
    }
}

private fun ownedOrCopied(
    bytes: ByteArray,
    copyInputBuffers: Boolean,
): ByteArray =
    if (copyInputBuffers) {
        bytes.copyOf()
    } else {
        bytes
    }

private fun validateContextNonEmpty(bytes: ByteArray) {
    if (bytes.isEmpty()) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.EMPTY_BUFFER)
    }
}

private fun validateExactDigest(bytes: ByteArray) {
    validateContextNonEmpty(bytes)
    if (bytes.size != DIGEST_SHA256_BYTES) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
    }
}

private const val DIGEST_SHA256_BYTES = 32
