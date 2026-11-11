// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import reallyme.zk.v1.Manifest

internal fun circuitRef(request: ZkStageRequest): Manifest.ZkCircuitRef =
    circuitRef(
        bundleKind = request.bundleKind,
        credentialHashAlgorithm = request.credentialHashAlgorithm,
        stage = request.stage,
    )

internal fun circuitRef(
    bundleKind: ZkClaimProofBundleKind,
    credentialHashAlgorithm: ZkCredentialHashAlgorithm,
    stage: ZkClaimProofBundleStage,
): Manifest.ZkCircuitRef =
    Manifest.ZkCircuitRef
        .newBuilder()
        .setCredentialHashAlgorithm(credentialHashAlgorithm)
        .setFamily(circuitFamily(bundleKind))
        .setStage(circuitStage(stage))
        .setCircuitRevision(CIRCUIT_VERSION)
        .build()

private fun circuitFamily(bundleKind: ZkClaimProofBundleKind): Manifest.ZkCircuitFamily =
    when (bundleKind) {
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1 ->
            Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1 ->
            Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1
        else -> throw ReallyMeZkProviderException(ZkProviderFailureReason.UNSUPPORTED_CIRCUIT)
    }

private fun circuitStage(stage: ZkClaimProofBundleStage): Manifest.ZkCircuitStage =
    when (stage) {
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_SESSION
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE ->
            Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT ->
            Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_CREDENTIAL_ROOT
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM -> Manifest.ZkCircuitStage.ZK_CIRCUIT_STAGE_CLAIM
        else -> throw ReallyMeZkProviderException(ZkProviderFailureReason.UNSUPPORTED_CIRCUIT)
    }
