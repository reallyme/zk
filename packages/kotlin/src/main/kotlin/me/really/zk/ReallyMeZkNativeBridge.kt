// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

public enum class ZkNativeCrsMode(
    public val code: Int,
) {
    VERIFIER_ONLY(1),
    FULL_PROVER(2),
}

public data class ZkNativeContextResult(
    public val statusCode: Int,
    public val errorReasonCode: Int,
    public val contextHandle: Long,
) {
    init {
        validateNativeCode(statusCode)
        validateNativeCode(errorReasonCode)
        if (statusCode != REALLYME_ZK_PLATFORM_STATUS_OK && contextHandle != 0L) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
    }
}

/**
 * Result of one native dispatch call.
 *
 * [output] carries the serialized provider response, which can contain proof and public-input
 * bytes. This is deliberately not a data class: the caller owns and clears [output], instances
 * compare by identity, and [toString] never renders the bytes.
 */
public class ZkNativeDispatchResult(
    public val statusCode: Int,
    public val errorReasonCode: Int,
    public val output: ByteArray,
) {
    init {
        validateNativeCode(statusCode)
        validateNativeCode(errorReasonCode)
        if (statusCode == REALLYME_ZK_PLATFORM_STATUS_OK && output.isEmpty()) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.EMPTY_BUFFER)
        }
        if (output.size > MAX_PROVIDER_OPERATION_RESPONSE_BYTES) {
            output.fill(0)
            throw ReallyMeZkProviderException(ZkProviderFailureReason.OVERSIZED_BUFFER)
        }
    }

    override fun toString(): String =
        "ZkNativeDispatchResult(" +
            "statusCode=$statusCode, " +
            "errorReasonCode=$errorReasonCode, " +
            "output=<redacted ${output.size} bytes>" +
            ")"
}

public data class ZkNativeStatus(
    public val statusCode: Int,
    public val errorReasonCode: Int,
) {
    init {
        validateNativeCode(statusCode)
        validateNativeCode(errorReasonCode)
    }
}

public interface ReallyMeZkPlatformNativeBridge {
    public fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult

    /**
     * Dispatches one canonical operation request.
     *
     * Implementations must treat [request] as borrowed for the duration of the call, must not
     * retain it, and must not log it. [ReallyMeZkNativeProvider] clears the serialized request
     * owner after this method returns.
     */
    public fun dispatch(
        contextHandle: Long,
        request: ByteArray,
    ): ZkNativeDispatchResult

    public fun contextDestroy(contextHandle: Long): ZkNativeStatus
}

public class ReallyMeZkNativeContextFactory private constructor(
    private val bridgeProvider: () -> ReallyMeZkPlatformNativeBridge,
) {
    public constructor() : this({ JniReallyMeZkPlatformNativeBridge })

    public constructor(bridge: ReallyMeZkPlatformNativeBridge) : this({ bridge })

    public fun createContext(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
        mapNativeLinkageFailure {
            bridgeProvider().contextCreate(request)
        }
}

public object JniReallyMeZkPlatformNativeBridge : ReallyMeZkPlatformNativeBridge {
    private val loadState: ZkNativeLibraryLoadState =
        detectNativeLibraryLoadState {
            System.loadLibrary("reallyme_zk_platform_jni")
        }

    override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult {
        requireNativeLibraryLoaded(loadState)
        val releaseIndexSha256 = request.approvedReleaseIndexSha256Copy()
        try {
            val raw =
                mapNativeLinkageFailure {
                    if (request.usesCrsFilePaths()) {
                        request.withBorrowedContextCreateFilePathBuffers(releaseIndexSha256) { inputBuffers ->
                            nativeContextCreateWithCrsFiles(inputBuffers, request.crsMode.code)
                        }
                    } else {
                        request.withBorrowedContextCreateBuffers(releaseIndexSha256) { inputBuffers ->
                            nativeContextCreate(inputBuffers, request.crsMode.code)
                        }
                    }
                }
            return contextResultFromRaw(raw)
        } finally {
            releaseIndexSha256.fill(0)
        }
    }

    override fun dispatch(
        contextHandle: Long,
        request: ByteArray,
    ): ZkNativeDispatchResult {
        if (contextHandle == 0L) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        validateNonEmpty(request)
        requireNativeLibraryLoaded(loadState)
        return mapNativeLinkageFailure {
            nativeDispatch(contextHandle, request)
        }
    }

    override fun contextDestroy(contextHandle: Long): ZkNativeStatus {
        requireNativeLibraryLoaded(loadState)
        val raw =
            mapNativeLinkageFailure {
                nativeContextDestroy(contextHandle)
            }
        if (raw.size != NATIVE_STATUS_FIELD_COUNT) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        return ZkNativeStatus(
            statusCode = checkedLongToInt(raw[NATIVE_STATUS_INDEX_STATUS]),
            errorReasonCode = checkedLongToInt(raw[NATIVE_STATUS_INDEX_REASON]),
        )
    }

    private external fun nativeContextCreate(
        inputBuffers: Array<ByteArray>,
        crsModeCode: Int,
    ): LongArray

    private external fun nativeContextCreateWithCrsFiles(
        inputBuffers: Array<ByteArray>,
        crsModeCode: Int,
    ): LongArray

    private external fun nativeDispatch(
        contextHandle: Long,
        request: ByteArray,
    ): ZkNativeDispatchResult

    private external fun nativeContextDestroy(contextHandle: Long): LongArray
}

internal enum class ZkNativeLibraryLoadState {
    LOADED,
    PROVIDER_UNAVAILABLE,
}

internal fun detectNativeLibraryLoadState(loadLibrary: () -> Unit): ZkNativeLibraryLoadState =
    try {
        loadLibrary()
        ZkNativeLibraryLoadState.LOADED
    } catch (ignored: LinkageError) {
        ZkNativeLibraryLoadState.PROVIDER_UNAVAILABLE
    } catch (ignored: SecurityException) {
        ZkNativeLibraryLoadState.PROVIDER_UNAVAILABLE
    }

internal inline fun <Value> mapNativeLinkageFailure(operation: () -> Value): Value =
    try {
        operation()
    } catch (ignored: LinkageError) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROVIDER_UNAVAILABLE)
    } catch (ignored: SecurityException) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROVIDER_UNAVAILABLE)
    }

private fun requireNativeLibraryLoaded(loadState: ZkNativeLibraryLoadState) {
    if (loadState != ZkNativeLibraryLoadState.LOADED) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.PROVIDER_UNAVAILABLE)
    }
}

private fun contextResultFromRaw(raw: LongArray): ZkNativeContextResult {
    if (raw.size != NATIVE_CONTEXT_RESULT_FIELD_COUNT) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
    }
    return ZkNativeContextResult(
        statusCode = checkedLongToInt(raw[NATIVE_CONTEXT_INDEX_STATUS]),
        errorReasonCode = checkedLongToInt(raw[NATIVE_CONTEXT_INDEX_REASON]),
        contextHandle = raw[NATIVE_CONTEXT_INDEX_HANDLE],
    )
}

private fun checkedLongToInt(value: Long): Int {
    if (value < 0 || value > Int.MAX_VALUE) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
    }
    return value.toInt()
}

private fun validateNativeCode(value: Int) {
    if (value < 0) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
    }
}

private fun validateNonEmpty(bytes: ByteArray) {
    if (bytes.isEmpty()) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.EMPTY_BUFFER)
    }
}

private const val REALLYME_ZK_PLATFORM_STATUS_OK = 0
private const val MAX_PROVIDER_OPERATION_RESPONSE_BYTES = 4 * 1024 * 1024
private const val NATIVE_STATUS_FIELD_COUNT = 2
private const val NATIVE_STATUS_INDEX_STATUS = 0
private const val NATIVE_STATUS_INDEX_REASON = 1
private const val NATIVE_CONTEXT_RESULT_FIELD_COUNT = 3
private const val NATIVE_CONTEXT_INDEX_STATUS = 0
private const val NATIVE_CONTEXT_INDEX_REASON = 1
private const val NATIVE_CONTEXT_INDEX_HANDLE = 2
