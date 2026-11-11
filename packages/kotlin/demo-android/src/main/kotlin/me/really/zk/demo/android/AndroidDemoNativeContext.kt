// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import me.really.zk.JniReallyMeZkPlatformNativeBridge
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason

internal fun destroyAndroidDemoContext(handle: Long): ReallyMeZkProviderException? {
    val statusCode =
        try {
            JniReallyMeZkPlatformNativeBridge.contextDestroy(handle).statusCode
        } catch (ignored: ReallyMeZkProviderException) {
            PLATFORM_STATUS_INTERNAL_FAILURE
        } catch (ignored: RuntimeException) {
            PLATFORM_STATUS_INTERNAL_FAILURE
        }
    return if (statusCode == PLATFORM_STATUS_OK) {
        null
    } else {
        ReallyMeZkProviderException(ZkProviderFailureReason.CLEANUP_FAILED)
    }
}

private const val PLATFORM_STATUS_OK = 0
private const val PLATFORM_STATUS_INTERNAL_FAILURE = 255
