// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import reallyme.zk.v1.Manifest

internal fun validateSessionBinding(binding: Manifest.ZkSessionBinding) {
    validateSessionBindingDigestByteCount(binding.nonceHash.size(), required = true)
    validateSessionBindingDigestByteCount(binding.audienceHash.size(), required = true)
    validateSessionBindingDigestByteCount(binding.transactionDataHash.size(), required = false)
}

private fun validateSessionBindingDigestByteCount(
    byteCount: Int,
    required: Boolean,
) {
    if (!required && byteCount == 0) {
        return
    }
    if (byteCount != SESSION_BINDING_DIGEST_BYTES) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
}

private const val SESSION_BINDING_DIGEST_BYTES = 32
