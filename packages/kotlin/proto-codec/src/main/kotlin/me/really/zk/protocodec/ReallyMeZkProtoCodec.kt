// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.protocodec

import me.really.zk.protocodec.capabilities.ZkCapabilityContract
import reallyme.zk.v1.Manifest.ZkArtifactManifest
import reallyme.zk.v1.Manifest.ZkErrorReason
import reallyme.zk.v1.Manifest.ZkProofSuite
import reallyme.zk.v1.Manifest.ZkProviderOperationRequest
import reallyme.zk.v1.Manifest.ZkProviderOperationResponse
import reallyme.zk.v1.Manifest.ZkProviderOperationResult

public enum class ZkProtoCodecErrorReason {
    INVALID_CAPABILITIES,
    MISSING_ERROR_REASON,
    MISSING_OPERATION,
    MISSING_OUTCOME,
    MISSING_RESULT,
    PROVIDER_FAILURE,
    UNSUPPORTED_OPERATION,
    UNSUPPORTED_PROOF_SUITE,
}

public sealed interface ZkProtoCodecResult<out Value> {
    public data class Success<Value>(
        public val value: Value,
    ) : ZkProtoCodecResult<Value>

    public data class Failure(
        public val reason: ZkProtoCodecErrorReason,
    ) : ZkProtoCodecResult<Nothing>
}

public enum class ZkProofSuiteId {
    BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
}

public sealed interface ZkProviderOperation {
    public data class ArtifactManifestRequest(
        public val proofSuite: ZkProofSuiteId,
    ) : ZkProviderOperation

    public data class StageWitnessRequest(
        public val proofSuite: ZkProofSuiteId,
    ) : ZkProviderOperation

    public data object StageWitnessRelease : ZkProviderOperation
}

public sealed interface ZkProviderResponse {
    public data object Admitted : ZkProviderResponse
}

public object ReallyMeZkProtoCodec {
    public fun admitProviderOperation(request: ZkProviderOperationRequest): ZkProtoCodecResult<ZkProviderOperation> =
        when (request.operationCase) {
            ZkProviderOperationRequest.OperationCase.GET_ARTIFACT_MANIFEST ->
                when (val proofSuite = requireProofSuite(request.getArtifactManifest.proofSuite)) {
                    is ZkProtoCodecResult.Success ->
                        ZkProtoCodecResult.Success(
                            ZkProviderOperation.ArtifactManifestRequest(
                                proofSuite = proofSuite.value,
                            ),
                        )
                    is ZkProtoCodecResult.Failure -> proofSuite
                }
            ZkProviderOperationRequest.OperationCase.WITNESS_STAGE ->
                when (val proofSuite = requireProofSuite(request.witnessStage.proofSuite)) {
                    is ZkProtoCodecResult.Success ->
                        ZkProtoCodecResult.Success(
                            ZkProviderOperation.StageWitnessRequest(
                                proofSuite = proofSuite.value,
                            ),
                        )
                    is ZkProtoCodecResult.Failure -> proofSuite
                }
            ZkProviderOperationRequest.OperationCase.RELEASE_STAGE_WITNESS ->
                ZkProtoCodecResult.Success(ZkProviderOperation.StageWitnessRelease)
            ZkProviderOperationRequest.OperationCase.PROVE_CLAIM_PROOF_BUNDLE,
            ZkProviderOperationRequest.OperationCase.PROVE_RETAINED_CLAIM_PROOF_BUNDLE,
            ZkProviderOperationRequest.OperationCase.VERIFY_CLAIM_PROOF_BUNDLE,
            ZkProviderOperationRequest.OperationCase.VERIFY_STATUS_QUALIFIED_CLAIM_PROOF_BUNDLE,
            ZkProviderOperationRequest.OperationCase.PROVE_STAGE,
            ZkProviderOperationRequest.OperationCase.VERIFY_STAGE,
            ZkProviderOperationRequest.OperationCase.VERIFY_COMMON_CREDENTIAL_ROOT,
            ZkProviderOperationRequest.OperationCase.PROVE_COMMON_CREDENTIAL_ROOT_STAGE,
            ZkProviderOperationRequest.OperationCase.PROVE_COMMON_CREDENTIAL_ROOT_PRESENTATION,
            ZkProviderOperationRequest.OperationCase.VERIFY_PERSONA_CREDENTIAL_EVIDENCE_STAGE,
            ZkProviderOperationRequest.OperationCase.PROVE_PERSONA_CREDENTIAL_EVIDENCE_STAGE,
            ZkProviderOperationRequest.OperationCase.PROVE_PERSONA_CREDENTIAL_EVIDENCE_CURRENT_STATE,
            ZkProviderOperationRequest.OperationCase.PROVE_PERSONA_CREDENTIAL_EVIDENCE_ISSUER_ENVELOPE,
            ZkProviderOperationRequest.OperationCase.PROVE_PERSONA_CREDENTIAL_EVIDENCE_CLAIM_ROOT,
            ZkProviderOperationRequest.OperationCase.PROVE_PERSONA_CREDENTIAL_EVIDENCE_SIGNED_VALIDITY,
            ZkProviderOperationRequest.OperationCase.PROVE_PERSONA_CREDENTIAL_EVIDENCE_SELECTED_CLAIM,
            ZkProviderOperationRequest.OperationCase.PREPARE_PERSONA_CREDENTIAL_EVIDENCE_PRESENTATION_SIGNING,
            ZkProviderOperationRequest.OperationCase.ASSEMBLE_PERSONA_CREDENTIAL_EVIDENCE_PRESENTATION,
            -> ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.UNSUPPORTED_OPERATION)
            ZkProviderOperationRequest.OperationCase.OPERATION_NOT_SET ->
                ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.MISSING_OPERATION)
        }

    /**
     * Admits only a provider response that carries a populated result.
     *
     * A provider error, an error without a known reason, and a result with no
     * payload are failures. Only a populated result is ever reported as
     * [ZkProviderResponse.Admitted].
     */
    public fun admitProviderResponse(response: ZkProviderOperationResponse): ZkProtoCodecResult<ZkProviderResponse> =
        when (response.outcomeCase) {
            ZkProviderOperationResponse.OutcomeCase.RESULT -> admitProviderResult(response.result)
            ZkProviderOperationResponse.OutcomeCase.ERROR ->
                when (response.error.reason) {
                    ZkErrorReason.ZK_ERROR_REASON_UNSPECIFIED,
                    ZkErrorReason.UNRECOGNIZED,
                    -> ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.MISSING_ERROR_REASON)
                    else -> ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.PROVIDER_FAILURE)
                }
            ZkProviderOperationResponse.OutcomeCase.OUTCOME_NOT_SET ->
                ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.MISSING_OUTCOME)
        }

    private fun admitProviderResult(result: ZkProviderOperationResult): ZkProtoCodecResult<ZkProviderResponse> =
        when (result.resultCase) {
            ZkProviderOperationResult.ResultCase.RESULT_NOT_SET ->
                ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.MISSING_RESULT)
            ZkProviderOperationResult.ResultCase.ARTIFACT_MANIFEST -> admitArtifactManifest(result.artifactManifest)
            else -> ZkProtoCodecResult.Success(ZkProviderResponse.Admitted)
        }

    private fun admitArtifactManifest(manifest: ZkArtifactManifest): ZkProtoCodecResult<ZkProviderResponse> =
        if (!manifest.hasCapabilities()) {
            ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.INVALID_CAPABILITIES)
        } else {
            when (val capabilities = ZkCapabilityContract.validate(manifest.capabilities)) {
                is ZkProtoCodecResult.Failure -> capabilities
                is ZkProtoCodecResult.Success -> ZkProtoCodecResult.Success(ZkProviderResponse.Admitted)
            }
        }

    private fun requireProofSuite(suite: ZkProofSuite): ZkProtoCodecResult<ZkProofSuiteId> =
        when (suite) {
            ZkProofSuite.ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA ->
                ZkProtoCodecResult.Success(ZkProofSuiteId.BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA)
            else -> ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.UNSUPPORTED_PROOF_SUITE)
        }
}
