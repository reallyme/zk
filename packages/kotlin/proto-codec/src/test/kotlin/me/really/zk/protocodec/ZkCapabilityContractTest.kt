// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.protocodec

import me.really.zk.protocodec.capabilities.ZkCapabilityContract
import reallyme.zk.v1.Capabilities
import kotlin.test.Test
import kotlin.test.assertEquals

class ZkCapabilityContractTest {
    @Test fun disclosureAndPredicatesRoundTripSeparately() {
        val capabilities =
            validCapabilities()
                .addPredicateTypes(
                    Capabilities.ZkPredicateType.ZK_PREDICATE_TYPE_RANGE,
                ).build()
        val decoded = Capabilities.ZkCircuitCapabilities.parseFrom(capabilities.toByteArray())
        assertEquals(ZkProtoCodecResult.Success(Unit), ZkCapabilityContract.validate(decoded))
        assertEquals(listOf(Capabilities.ZkDisclosureMode.ZK_DISCLOSURE_MODE_REVEAL), decoded.disclosureModesList)
        assertEquals(listOf(Capabilities.ZkPredicateType.ZK_PREDICATE_TYPE_RANGE), decoded.predicateTypesList)
    }

    @Test fun unknownCodesFailClosed() {
        val rejected = ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.INVALID_CAPABILITIES)
        for (code in listOf(0, 3, 4, 5, 99)) {
            val capabilities = validCapabilities().clearDisclosureModes().addDisclosureModesValue(code).build()
            assertEquals(rejected, ZkCapabilityContract.validate(capabilities))
        }
        for (code in listOf(0, 99)) {
            val capabilities = validCapabilities().addSemanticGuaranteesValue(code).build()
            assertEquals(rejected, ZkCapabilityContract.validate(capabilities))
        }
        for (code in listOf(0, 99)) {
            val capabilities = validCapabilities().addPredicateTypesValue(code).build()
            assertEquals(rejected, ZkCapabilityContract.validate(capabilities))
        }
        assertEquals(rejected, ZkCapabilityContract.validate(Capabilities.ZkCircuitCapabilities.getDefaultInstance()))
    }

    private fun validCapabilities(): Capabilities.ZkCircuitCapabilities.Builder =
        Capabilities.ZkCircuitCapabilities
            .newBuilder()
            .setSubjectBinding(Capabilities.ZkSubjectBinding.ZK_SUBJECT_BINDING_REQUIRED)
            .setPersonaBinding(Capabilities.ZkPersonaBinding.ZK_PERSONA_BINDING_FORBIDDEN)
            .setMayBeCorrelated(true)
            .addDisclosureModes(Capabilities.ZkDisclosureMode.ZK_DISCLOSURE_MODE_REVEAL)
            .addSemanticGuarantees(Capabilities.ZkSemanticGuarantee.ZK_SEMANTIC_GUARANTEE_SESSION_BOUND)
}
