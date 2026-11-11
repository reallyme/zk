// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import me.really.zk.ZkProviderFailureReason
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import kotlin.test.Test
import kotlin.test.assertEquals

internal class AndroidDemoStringsTest {
    @Test
    internal fun buttonTitlesMatchRequestBoundProofTypes() {
        assertEquals(
            "Generate Credential subject claim ZKP",
            AndroidDemoStrings.buttonTitle(
                ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ),
        )
        assertEquals(
            "Generate Private Persona ZKP",
            AndroidDemoStrings.buttonTitle(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1),
        )
    }

    @Test
    internal fun unavailableProviderStateDoesNotClaimProofSuccess() {
        assertEquals(
            "ZK provider is unavailable.",
            AndroidDemoStrings.providerUnavailableDetail,
        )
    }

    @Test
    internal fun cancellationStateDoesNotClaimBackendFailure() {
        assertEquals(
            "Proof generation was cancelled.",
            AndroidDemoStrings.providerFailureDetail(ZkProviderFailureReason.OPERATION_CANCELLED),
        )
    }
}
