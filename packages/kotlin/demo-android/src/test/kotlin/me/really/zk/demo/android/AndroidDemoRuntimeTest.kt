// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import me.really.zk.ReallyMeZk
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.demo.shared.ReallyMeZkDemoFixtureWitnessInputs
import me.really.zk.demo.shared.ZkSampleResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

public class AndroidDemoRuntimeTest {
    @Test
    public fun cleanupFailureIsReportedAfterSuccessfulRun() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                resolveRunOutcome(
                    result = sampleResult(),
                    primaryFailure = null,
                    cleanupFailure = ReallyMeZkProviderException(ZkProviderFailureReason.CLEANUP_FAILED),
                )
            }

        assertEquals(ZkProviderFailureReason.CLEANUP_FAILED, error.reason)
    }

    @Test
    public fun cleanupFailureIsReportedWhenRunAndCleanupBothFail() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                resolveRunOutcome(
                    result = null,
                    primaryFailure = ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED),
                    cleanupFailure = ReallyMeZkProviderException(ZkProviderFailureReason.CLEANUP_FAILED),
                )
            }

        assertEquals(ZkProviderFailureReason.CLEANUP_FAILED, error.reason)
    }

    @Test
    public fun commonCredentialRootFailureKeepsPrimaryReasonAndRecordsCleanupFailure() {
        val error =
            assertFailsWith<ReallyMeZkProviderException> {
                resolveCommonCredentialRootOutcome<CommonCredentialRootSampleResult>(
                    result = null,
                    primaryFailure = ReallyMeZkProviderException(ZkProviderFailureReason.PROOF_REJECTED),
                    cleanupFailure = ReallyMeZkProviderException(ZkProviderFailureReason.CLEANUP_FAILED),
                )
            }

        assertEquals(ZkProviderFailureReason.PROOF_REJECTED, error.reason)
        assertEquals(1, error.suppressed.size)
    }

    @Test
    public fun fixtureManifestLimitCoversAllModernDemoInputs() {
        val manifestBytes =
            FIXTURE_MANIFEST_HEADER_BYTES +
                ReallyMeZk.bundleKinds.sumOf { bundleKind ->
                    ReallyMeZk.credentialHashAlgorithms.sumOf { credentialHashAlgorithm ->
                        ReallyMeZk.stages.sumOf { stage ->
                            pinnedManifestLineByteCount(
                                ReallyMeZkDemoFixtureWitnessInputs.fixtureResourceName(
                                    bundleKind,
                                    credentialHashAlgorithm,
                                    stage,
                                ),
                            )
                        }
                    }
                }

        assertTrue(manifestBytes <= MAX_FIXTURE_MANIFEST_BYTES)
    }
}

private fun sampleResult(): ZkSampleResult =
    ZkSampleResult(
        bundleKind = ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
        verificationKeySize = 1,
        publicInputsSize = 1,
        proofSize = 1,
        witnessMilliseconds = 1.0,
        proveMilliseconds = 1.0,
        verifyMilliseconds = 1.0,
        fixtureBundleVerified = true,
    )

private fun pinnedManifestLineByteCount(resourceName: String): Int =
    SHA256_HEX_CHARS +
        PINNED_MANIFEST_SEPARATOR_BYTES +
        MAX_FIXTURE_PROTOBUF_BYTES.toString().length +
        PINNED_MANIFEST_SEPARATOR_BYTES +
        resourceName.length +
        PROTOBUF_EXTENSION_BYTES +
        LINE_FEED_BYTES

private const val FIXTURE_MANIFEST_HEADER_BYTES = 18
private const val PINNED_MANIFEST_SEPARATOR_BYTES = 2
private const val PROTOBUF_EXTENSION_BYTES = 3
private const val LINE_FEED_BYTES = 1
