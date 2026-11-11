// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleStage

public object ReallyMeZk {
    public val credentialHashAlgorithms: List<ZkCredentialHashAlgorithm> =
        listOf(
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2,
        )

    public val bundleKinds: List<ZkClaimProofBundleKind> =
        listOf(
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
        )
    public val stages: List<ZkClaimProofBundleStage> =
        listOf(
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION,
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE,
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT,
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM,
        )
}

public val ZkCredentialHashAlgorithm.displayName: String
    get() =
        when (this) {
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256 -> "SHA-256"
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2 -> "Poseidon2"
            else -> "Unsupported Hash"
        }

public val ZkCredentialHashAlgorithm.fixturePrefix: String
    get() =
        when (this) {
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256 -> "sha256"
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2 -> "poseidon2"
            else -> "unsupported"
        }

public val ZkClaimProofBundleKind.displayName: String
    get() =
        when (this) {
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1 -> "Credential subject claim"
            ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1 -> "Private Persona"
            else -> "Unsupported bundle kind"
        }

public val ZkClaimProofBundleStage.label: String
    get() =
        when (this) {
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION -> "session"
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE -> "credential envelope"
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT -> "credential root"
            ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM -> "claim"
            else -> "unsupported stage"
        }

public data class ZkStageSelection(
    public val bundleKind: ZkClaimProofBundleKind,
    public val credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    public val stage: ZkClaimProofBundleStage,
)
