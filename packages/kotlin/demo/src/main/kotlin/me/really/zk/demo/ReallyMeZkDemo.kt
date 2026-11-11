// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo

import me.really.zk.demo.shared.DemoProgress
import me.really.zk.demo.shared.ReallyMeZkDemoPlan
import me.really.zk.claimbundle.ZkClaimProofBundleKind

public object ReallyMeZkDemo {
    public fun progressFor(bundleKind: ZkClaimProofBundleKind): List<DemoProgress> =
        ReallyMeZkDemoPlan.progressFor(bundleKind)
}

public fun main() {
    for (update in ReallyMeZkDemo.progressFor(
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
    )) {
        println("UI_PLAN|${update.plannedStep}|${update.totalSteps}|${update.message}")
    }
}
