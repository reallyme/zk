// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo

import kotlin.test.Test
import kotlin.test.assertEquals
import me.really.zk.claimbundle.ZkClaimProofBundleKind

class ReallyMeZkDemoTest {
    @Test
    fun progressModelShowsBundleFixtureOperations() {
        val updates =
            ReallyMeZkDemo.progressFor(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1)

        assertEquals(6, updates.size)
        assertEquals("Generated session witness.", updates.first().message)
        assertEquals("Bundle verified.", updates.last().message)
        assertEquals(6, updates.last().plannedStep)
        assertEquals(6, updates.last().totalSteps)
    }
}
