// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.protocodec.capabilities

import me.really.zk.protocodec.ZkProtoCodecErrorReason
import me.really.zk.protocodec.ZkProtoCodecResult
import reallyme.zk.v1.Capabilities

/** Validates vocabulary only; per-circuit support is checked by the canonical Rust registry. */
public object ZkCapabilityContract {
    public fun validate(capabilities: Capabilities.ZkCircuitCapabilities): ZkProtoCodecResult<Unit> {
        val knownSubjectBinding =
            capabilities.subjectBinding != Capabilities.ZkSubjectBinding.ZK_SUBJECT_BINDING_UNSPECIFIED &&
                capabilities.subjectBinding != Capabilities.ZkSubjectBinding.UNRECOGNIZED
        val knownPersonaBinding =
            capabilities.personaBinding != Capabilities.ZkPersonaBinding.ZK_PERSONA_BINDING_UNSPECIFIED &&
                capabilities.personaBinding != Capabilities.ZkPersonaBinding.UNRECOGNIZED
        val knownDisclosure =
            capabilities.disclosureModesList.all {
                it != Capabilities.ZkDisclosureMode.ZK_DISCLOSURE_MODE_UNSPECIFIED &&
                    it != Capabilities.ZkDisclosureMode.UNRECOGNIZED
            }
        val knownPredicates =
            capabilities.predicateTypesList.all {
                it != Capabilities.ZkPredicateType.ZK_PREDICATE_TYPE_UNSPECIFIED &&
                    it != Capabilities.ZkPredicateType.UNRECOGNIZED
            }
        val knownGuarantees =
            capabilities.semanticGuaranteesList.all {
                it != Capabilities.ZkSemanticGuarantee.ZK_SEMANTIC_GUARANTEE_UNSPECIFIED &&
                    it != Capabilities.ZkSemanticGuarantee.UNRECOGNIZED
            }
        val knownBindings = knownSubjectBinding && knownPersonaBinding
        val knownClaimModes = knownDisclosure && knownPredicates
        val knownCapabilities = knownBindings && knownClaimModes && knownGuarantees
        return if (knownCapabilities) {
            ZkProtoCodecResult.Success(Unit)
        } else {
            ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.INVALID_CAPABILITIES)
        }
    }
}
