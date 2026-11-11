// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.shared

import me.really.zk.ReallyMeZk
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals

class ReallyMeZkDemoFixtureWitnessInputsTest {
    @Test
    fun sessionBindingIncludesTransactionDataHash() {
        for (bundleKind in ReallyMeZk.bundleKinds) {
            for (credentialHashAlgorithm in ReallyMeZk.credentialHashAlgorithms) {
                assertSessionBindingIncludesTransactionDataHash(bundleKind, credentialHashAlgorithm)
            }
        }
    }

    private fun assertSessionBindingIncludesTransactionDataHash(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    ) {
        val data = fixtureData(bundleKind, credentialHashAlgorithm)
        try {
            val input =
                ReallyMeZkDemoFixtureWitnessInputs.witnessInput(
                    bundleKind,
                    ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
                    data,
                )
            val binding = ReallyMeZkDemoFixtureWitnessInputs.sessionBinding(input)

            assertEquals(DIGEST_BYTES, binding.nonceHash.size())
            assertEquals(DIGEST_BYTES, binding.audienceHash.size())
            assertEquals(DIGEST_BYTES, binding.transactionDataHash.size())
        } finally {
            data.fill(0)
        }
    }

    private fun fixtureData(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    ): ByteArray {
        val resourceName =
            ReallyMeZkDemoFixtureWitnessInputs.fixtureResourceName(
                bundleKind,
                credentialHashAlgorithm,
                ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
            )
        return Files.readAllBytes(fixtureDirectory().resolve("$resourceName.pb"))
    }

    private fun fixtureDirectory(): Path = locateFixtureDirectory(Path.of("").toAbsolutePath().normalize())

    private fun locateFixtureDirectory(start: Path): Path {
        var cursor: Path? = start
        while (cursor != null) {
            val candidate = cursor.resolve("vectors").resolve("demo-flow-inputs").resolve("v1")
            if (Files.isDirectory(candidate)) {
                return candidate
            }
            cursor = cursor.parent
        }
        return start.resolve("vectors").resolve("demo-flow-inputs").resolve("v1")
    }
}

private const val DIGEST_BYTES = 32
