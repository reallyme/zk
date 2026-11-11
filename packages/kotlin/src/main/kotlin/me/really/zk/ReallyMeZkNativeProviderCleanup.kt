// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

internal fun ReallyMeZkNativeProvider.preDispatchBundleFailure(
    reason: ZkProviderFailureReason,
    witnesses: List<ZkNativeWitnessHandle>,
): ReallyMeZkProviderException {
    val failure = ReallyMeZkProviderException(reason)
    for (witness in witnesses) {
        val cleanup = runCatching { releaseWitness(witness) }
        val cleanupFailure = cleanup.exceptionOrNull()
        if (cleanupFailure != null) {
            failure.addSuppressed(cleanupFailure)
        }
    }
    return failure
}
