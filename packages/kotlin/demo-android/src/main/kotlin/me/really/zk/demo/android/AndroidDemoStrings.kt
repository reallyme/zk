// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import me.really.zk.ZkProviderFailureReason
import me.really.zk.claimbundle.ZkClaimProofBundleKind

public object AndroidDemoStrings {
    public const val title: String = "Zero-Knowledge Proofs"
    public const val subtitle: String = "Generate request-bound proofs directly on your device."
    public const val navigationTitle: String = "ReallyMeZK Demo"
    public const val readyHeadline: String = "Ready to generate proof"
    public const val readyDetail: String = "Choose a proof type and continue."
    public const val runningHeadline: String = "Generating proof..."
    public const val runningDetail: String = "Preparing secure proving context."
    public const val successHeadline: String = "Claim proofs verified"
    public const val failureHeadline: String = "Could not generate proof"
    public const val failureDetail: String = "Please try again."
    public const val providerUnavailableDetail: String = "ZK provider is unavailable."
    public const val operationCancelledDetail: String = "Proof generation was cancelled."

    public fun buttonTitle(bundleKind: ZkClaimProofBundleKind): String =
        when (bundleKind) {
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1 ->
                "Generate Credential subject claim ZKP"
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1 ->
                "Generate Private Persona ZKP"
            else -> "Generate Proof"
        }

    public fun timingSummary(
        witnessMilliseconds: Double,
        proveMilliseconds: Double,
        verifyMilliseconds: Double,
    ): String =
        "Witness %.2f s · proving %.2f s · verification %.2f ms".format(
            witnessMilliseconds / millisecondsPerSecond,
            proveMilliseconds / millisecondsPerSecond,
            verifyMilliseconds,
        )

    public fun providerFailureDetail(reason: ZkProviderFailureReason): String =
        when (reason) {
            ZkProviderFailureReason.PROVIDER_UNAVAILABLE -> providerUnavailableDetail
            ZkProviderFailureReason.OPERATION_CANCELLED -> operationCancelledDetail
            ZkProviderFailureReason.PROOF_REJECTED -> "The generated proof was rejected."
            ZkProviderFailureReason.MALFORMED_WITNESS -> "The demo fixture is malformed."
            ZkProviderFailureReason.MALFORMED_PROOF -> "The generated proof is malformed."
            ZkProviderFailureReason.OVERSIZED_BUFFER -> "The proof request exceeded the supported size."
            ZkProviderFailureReason.CRS_MISSING -> providerUnavailableDetail
            ZkProviderFailureReason.CRS_HASH_MISMATCH -> providerUnavailableDetail
            ZkProviderFailureReason.UNSUPPORTED_CIRCUIT -> "The selected circuit is not supported."
            ZkProviderFailureReason.UNSUPPORTED_SUITE -> "The selected proof suite is not supported."
            ZkProviderFailureReason.CLEANUP_FAILED -> providerUnavailableDetail
            else -> failureDetail
        }

    private const val millisecondsPerSecond: Double = 1_000.0
}
