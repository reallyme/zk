// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import java.security.MessageDigest

internal fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance(SHA_256).digest(bytes)

private const val SHA_256: String = "SHA-256"
