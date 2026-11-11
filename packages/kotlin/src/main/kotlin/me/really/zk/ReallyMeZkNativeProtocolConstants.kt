// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import reallyme.zk.v1.Manifest

// These values are protocol boundaries shared by the provider, validators, and
// typed request owners. Keeping them together prevents platform paths from
// silently accepting different circuit or byte-length contracts.
internal val PROOF_SUITE: Manifest.ZkProofSuite =
    Manifest.ZkProofSuite.ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA
internal const val CIRCUIT_VERSION: Int = 1
internal const val NATIVE_PRODUCTION_STAGE_COUNT: Int = 4
internal const val BYTES_32: Int = 32
internal const val SHA256_DIGEST_BYTE_COUNT: Int = 32
internal const val P256_RAW_SIGNATURE_BYTE_COUNT: Int = 64

internal const val CLAIM_PROOF_BUNDLE_FORMAT_VERSION = 1
