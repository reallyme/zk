// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.shared

import me.really.zk.ReallyMeZk
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.label

public data class DemoProgress(
    public val plannedStep: Int,
    public val totalSteps: Int,
    public val message: String,
)

public object ReallyMeZkDemoPlan {
    public fun progressFor(bundleKind: ZkClaimProofBundleKind): List<DemoProgress> {
        if (bundleKind !in ReallyMeZk.bundleKinds) {
            return emptyList()
        }
        val witnessSteps =
            ReallyMeZk.stages.mapIndexed { stageIndex, stage ->
                DemoProgress(
                    plannedStep = stageIndex + WITNESS_STEP_OFFSET,
                    totalSteps = TOTAL_PROGRESS_STEPS,
                    message = "Generated ${stage.label} witness.",
                )
            }
        return witnessSteps +
            listOf(
                DemoProgress(
                    plannedStep = ReallyMeZk.stages.size + BUNDLE_PROOF_STEP_OFFSET,
                    totalSteps = TOTAL_PROGRESS_STEPS,
                    message = "Generated proof bundle.",
                ),
                DemoProgress(
                    plannedStep = ReallyMeZk.stages.size + BUNDLE_VERIFY_STEP_OFFSET,
                    totalSteps = TOTAL_PROGRESS_STEPS,
                    message = "Bundle verified.",
                ),
            )
    }

    private val TOTAL_PROGRESS_STEPS: Int = ReallyMeZk.stages.size + BUNDLE_OPERATION_COUNT
    private const val WITNESS_STEP_OFFSET = 1
    private const val BUNDLE_PROOF_STEP_OFFSET = 1
    private const val BUNDLE_VERIFY_STEP_OFFSET = 2
    private const val BUNDLE_OPERATION_COUNT = 2
}
