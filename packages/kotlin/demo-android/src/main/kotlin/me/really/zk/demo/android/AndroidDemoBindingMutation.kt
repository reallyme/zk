// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import com.google.protobuf.ByteString
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import reallyme.zk.v1.Manifest

internal enum class AndroidDemoBindingMutation {
    NONCE,
    AUDIENCE,
    TRANSACTION_DATA,
}

internal fun alteredBinding(
    binding: Manifest.ZkSessionBinding,
    mutation: AndroidDemoBindingMutation,
): Manifest.ZkSessionBinding {
    val digest =
        when (mutation) {
            AndroidDemoBindingMutation.NONCE -> binding.nonceHash
            AndroidDemoBindingMutation.AUDIENCE -> binding.audienceHash
            AndroidDemoBindingMutation.TRANSACTION_DATA -> binding.transactionDataHash
        }
    val alteredDigest = digest.toByteArray()
    try {
        if (alteredDigest.isEmpty()) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
        }
        alteredDigest[0] = (alteredDigest[0].toInt() xor 0x01).toByte()
        val builder = binding.toBuilder()
        when (mutation) {
            AndroidDemoBindingMutation.NONCE -> builder.setNonceHash(ByteString.copyFrom(alteredDigest))
            AndroidDemoBindingMutation.AUDIENCE -> builder.setAudienceHash(ByteString.copyFrom(alteredDigest))
            AndroidDemoBindingMutation.TRANSACTION_DATA ->
                builder.setTransactionDataHash(ByteString.copyFrom(alteredDigest))
        }
        return builder.build()
    } finally {
        alteredDigest.fill(0)
    }
}
