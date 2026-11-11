// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import reallyme.zk.v1.Manifest

internal fun dispatchNativeOperation(
    contextHandle: Long,
    bridgeProvider: () -> ReallyMeZkPlatformNativeBridge,
    request: Manifest.ZkProviderOperationRequest,
): Manifest.ZkProviderOperationResponse = dispatchEncodedRequest(contextHandle, bridgeProvider, request.toByteArray())

internal fun dispatchEncodedRequest(
    contextHandle: Long,
    bridgeProvider: () -> ReallyMeZkPlatformNativeBridge,
    requestBytes: ByteArray,
): Manifest.ZkProviderOperationResponse {
    try {
        val requestSha256 = sha256(requestBytes)
        try {
            val result =
                mapNativeLinkageFailure {
                    bridgeProvider().dispatch(contextHandle, requestBytes)
                }
            return try {
                validateNativeDispatchStatus(result.statusCode)
                val response = parseOperationResponse(result.output)
                validateResponseHash(response, requestSha256)
                response
            } finally {
                result.output.fill(0)
            }
        } finally {
            requestSha256.fill(0)
        }
    } finally {
        requestBytes.fill(0)
    }
}

internal fun validateNativeDispatchStatus(statusCode: Int) {
    if (statusCode != REALLYME_ZK_PLATFORM_STATUS_OK) {
        val reason =
            when (statusCode) {
                REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT -> ZkProviderFailureReason.PROVIDER_UNAVAILABLE
                REALLYME_ZK_PLATFORM_STATUS_DISPATCH_BUSY -> ZkProviderFailureReason.PROVIDER_BUSY
                REALLYME_ZK_PLATFORM_STATUS_REQUEST_TOO_LARGE -> ZkProviderFailureReason.OVERSIZED_BUFFER
                REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER -> ZkProviderFailureReason.MALFORMED_PROOF
                else -> ZkProviderFailureReason.INTERNAL_FAILURE
            }
        throw ReallyMeZkProviderException(reason)
    }
}

private const val REALLYME_ZK_PLATFORM_STATUS_OK: Int = 0
private const val REALLYME_ZK_PLATFORM_STATUS_REQUEST_TOO_LARGE: Int = 3
private const val REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER: Int = 6
private const val REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT: Int = 7
private const val REALLYME_ZK_PLATFORM_STATUS_DISPATCH_BUSY: Int = 9
