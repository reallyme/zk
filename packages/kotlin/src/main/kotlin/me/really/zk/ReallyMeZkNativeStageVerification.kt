// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import reallyme.zk.v1.Manifest

/**
 * Accepts a stage-verification report only when it names the exact proof that was dispatched.
 *
 * A report with absent, unknown, or mismatched identity fields is a malformed provider response,
 * never a verification outcome: the circuit reference, circuit identifier, bundle kind, and proof
 * suite must all be present and equal to the values sent in [operation].
 */
internal fun requireStageVerificationReport(
    report: Manifest.ZkVerification,
    operation: Manifest.ZkStageVerifyOperation,
) {
    val proof = operation.proof
    if (!proof.hasCircuitRef() || !report.hasCircuitRef() || report.circuitRef != proof.circuitRef) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
    val identity = stageVerificationIdentity(proof.circuitRef.family)
    val circuitIdMatches = report.circuitId == identity.circuitId && proof.circuitId == identity.circuitId
    val bundleKindMatches = report.bundleKind == identity.bundleKind
    val proofSuiteMatches =
        isKnownProofSuite(report.proofSuite) &&
            report.proofSuite == operation.expectedProofSuite &&
            report.proofSuite == proof.proofSuite
    if (!circuitIdMatches || !bundleKindMatches || !proofSuiteMatches) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }
}

private class ZkStageVerificationIdentity(
    val circuitId: Manifest.ZkCircuitId,
    val bundleKind: Manifest.ZkClaimProofBundleKind,
)

private fun stageVerificationIdentity(family: Manifest.ZkCircuitFamily): ZkStageVerificationIdentity =
    when (family) {
        Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1 ->
            ZkStageVerificationIdentity(
                circuitId = Manifest.ZkCircuitId.ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1,
                bundleKind = Manifest.ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            )
        Manifest.ZkCircuitFamily.ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1 ->
            ZkStageVerificationIdentity(
                circuitId = Manifest.ZkCircuitId.ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1,
                bundleKind = Manifest.ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1,
            )
        else -> throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
    }

private fun isKnownProofSuite(proofSuite: Manifest.ZkProofSuite): Boolean =
    proofSuite != Manifest.ZkProofSuite.ZK_PROOF_SUITE_UNSPECIFIED &&
        proofSuite != Manifest.ZkProofSuite.UNRECOGNIZED
