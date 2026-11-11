// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.shared

import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason.MALFORMED_WITNESS
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import reallyme.zk.v1.Manifest

internal fun validateDemoFixtureInput(
    input: Manifest.ZkStageWitnessInput,
    bundleKind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
) {
    if (input.inputCase != expectedDemoFixtureInputCase(bundleKind, stage)) {
        malformedDemoFixtureWitness()
    }
}

internal fun demoFixtureSessionContext(input: Manifest.ZkStageWitnessInput): Manifest.ZkInputSessionContext =
    when (input.inputCase) {
        Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_SUBJECT_CLAIM_SESSION ->
            input.credentialSubjectClaimSession.sessionContext
        Manifest.ZkStageWitnessInput.InputCase.PRIVATE_PERSONA_SESSION ->
            input.privatePersonaSession.sessionContext
        else -> malformedDemoFixtureWitness()
    }

internal fun demoFixtureIssuerContext(input: Manifest.ZkStageWitnessInput): Manifest.ZkInputIssuerContext =
    when (input.inputCase) {
        Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_ENVELOPE ->
            input.credentialEnvelope.issuerContext
        Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_ROOT ->
            input.credentialRoot.issuerContext
        Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_SUBJECT_CLAIM ->
            input.credentialSubjectClaim.issuerContext
        Manifest.ZkStageWitnessInput.InputCase.PRIVATE_PERSONA_CLAIM ->
            input.privatePersonaClaim.issuerContext
        else -> malformedDemoFixtureWitness()
    }

internal fun validateDemoFixtureBytes32(bytes: Manifest.ZkInputBytes32) {
    if (bytes.value.size() != DIGEST_BYTES) {
        malformedDemoFixtureWitness()
    }
}

internal fun demoFixtureProfileName(bundleKind: ZkClaimProofBundleKind): String =
    when (bundleKind) {
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1 ->
            "flow_credential_subject_claim_v1"
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1 -> "flow_private_persona_claim_v1"
        else -> malformedDemoFixtureWitness()
    }

internal fun demoFixtureStageName(stage: ZkClaimProofBundleStage): String =
    when (stage) {
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION -> "session"
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE -> "credential_envelope"
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT -> "credential_root"
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM -> "claim"
        else -> malformedDemoFixtureWitness()
    }

private fun expectedDemoFixtureInputCase(
    bundleKind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
): Manifest.ZkStageWitnessInput.InputCase =
    when (stage) {
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION -> expectedDemoFixtureSessionInputCase(bundleKind)
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE ->
            Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_ENVELOPE
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT ->
            Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_ROOT
        ZkClaimProofBundleStage.ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM -> expectedDemoFixtureClaimInputCase(bundleKind)
        else -> malformedDemoFixtureWitness()
    }

private fun expectedDemoFixtureSessionInputCase(
    bundleKind: ZkClaimProofBundleKind,
): Manifest.ZkStageWitnessInput.InputCase =
    when (bundleKind) {
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1 ->
            Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_SUBJECT_CLAIM_SESSION
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1 ->
            Manifest.ZkStageWitnessInput.InputCase.PRIVATE_PERSONA_SESSION
        else -> malformedDemoFixtureWitness()
    }

private fun expectedDemoFixtureClaimInputCase(
    bundleKind: ZkClaimProofBundleKind,
): Manifest.ZkStageWitnessInput.InputCase =
    when (bundleKind) {
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1 ->
            Manifest.ZkStageWitnessInput.InputCase.CREDENTIAL_SUBJECT_CLAIM
        ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1 ->
            Manifest.ZkStageWitnessInput.InputCase.PRIVATE_PERSONA_CLAIM
        else -> malformedDemoFixtureWitness()
    }

internal fun malformedDemoFixtureWitness(): Nothing = throw ReallyMeZkProviderException(MALFORMED_WITNESS)

private const val DIGEST_BYTES = 32
