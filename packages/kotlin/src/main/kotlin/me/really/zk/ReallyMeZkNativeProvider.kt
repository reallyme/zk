// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import com.google.protobuf.ByteString
import me.really.zk.claimbundle.ReallyMeZkClaimProofBundleProvider
import me.really.zk.claimbundle.ReallyMeZkStatusQualifiedClaimBundleVerifier
import me.really.zk.claimbundle.ZkClaimProofBundleMetrics
import me.really.zk.claimbundle.ZkClaimProofBundleProveRequest
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerification
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerifyRequest
import me.really.zk.claimbundle.ZkProviderClaimProofBundleResult
import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundleVerification
import me.really.zk.claimbundle.ZkStatusQualifiedClaimBundleVerifyRequest
import me.really.zk.commonroot.COMMON_CREDENTIAL_ROOT_PROOF_COUNT
import me.really.zk.commonroot.ZkCommonCredentialRootPresentationProof
import me.really.zk.commonroot.ZkCommonCredentialRootPresentationProveRequest
import me.really.zk.commonroot.ZkCommonCredentialRootStageProof
import me.really.zk.commonroot.ZkCommonCredentialRootStageProveRequest
import me.really.zk.commonroot.ZkCommonCredentialRootVerifyRequest
import me.really.zk.commonroot.ZkVerifiedCommonCredentialRoot
import me.really.zk.personaevidence.ZkPersonaCredentialEvidenceStageProveRequest
import reallyme.zk.v1.Manifest

public data class ZkNativeWitnessHandle(
    public val handle: Manifest.ZkStageWitnessHandle,
    public val publicInputs: Manifest.ZkPublicInputs,
    public val sessionBinding: Manifest.ZkSessionBinding,
)

public data class ZkNativeProofHandle(
    public val proof: Manifest.ZkProofPackage,
)

public data class ZkNativeClaimProofBundleHandle(
    public val claimProofBundle: Manifest.ZkClaimProofBundle,
)

public data class ZkNativeStatusQualifiedClaimProofBundleHandle(
    public val statusQualifiedClaimProofBundle: Manifest.ZkStatusQualifiedClaimProofBundle,
)

public class ReallyMeZkNativeProvider private constructor(
    private val contextHandle: Long,
    private val bridgeProvider: () -> ReallyMeZkPlatformNativeBridge,
) : ReallyMeZkProvider<ZkNativeWitnessHandle, ZkNativeProofHandle>,
    ReallyMeZkClaimProofBundleProvider<ZkNativeWitnessHandle, ZkNativeProofHandle, ZkNativeClaimProofBundleHandle>,
    ReallyMeZkStatusQualifiedClaimBundleVerifier<ZkNativeStatusQualifiedClaimProofBundleHandle> {
    public constructor(contextHandle: Long) : this(contextHandle, { JniReallyMeZkPlatformNativeBridge })

    public constructor(
        contextHandle: Long,
        bridge: ReallyMeZkPlatformNativeBridge,
    ) : this(contextHandle, { bridge })

    init {
        if (contextHandle == 0L) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.PROVIDER_UNAVAILABLE)
        }
    }

    override fun generateWitness(request: ZkStageRequest): ZkProviderWitnessResult<ZkNativeWitnessHandle> {
        val witnessInput = request.witnessInputForProvider
        if (witnessInput.inputCase == Manifest.ZkStageWitnessInput.InputCase.INPUT_NOT_SET) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
        val operation =
            Manifest.ZkStageWitnessOperation
                .newBuilder()
                .setCircuitRef(circuitRef(request))
                .setProofSuite(PROOF_SUITE)
                .setInput(witnessInput)
                .build()
        val providerRequest =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setWitnessStage(operation)
                .build()
        val response = dispatchNativeOperation(contextHandle, bridgeProvider, providerRequest)
        val witness = requireStageWitness(response)
        return ZkProviderWitnessResult(
            ZkNativeWitnessHandle(
                handle = witness.witnessHandle,
                publicInputs = witness.publicInputs,
                sessionBinding = witness.sessionBinding,
            ),
            ZkWitnessMetrics(),
        )
    }

    override fun prove(
        request: ZkStageRequest,
        witness: ZkNativeWitnessHandle,
    ): ZkProviderProofResult<ZkNativeProofHandle> {
        val operation =
            Manifest.ZkStageProveOperation
                .newBuilder()
                .setCircuitRef(circuitRef(request))
                .setProofSuite(PROOF_SUITE)
                .setWitnessHandle(witness.handle)
                .setPublicInputs(witness.publicInputs)
                .setSessionBinding(witness.sessionBinding)
                .build()
        val providerRequest =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setProveStage(operation)
                .build()
        val response = dispatchNativeOperation(contextHandle, bridgeProvider, providerRequest)
        val proof = requireStageProof(response)
        return ZkProviderProofResult(
            ZkNativeProofHandle(
                proof = proof,
            ),
            ZkProofMetrics(
                publicInputByteCount = proof.publicInputs.encoded.size(),
                proofByteCount = proof.proof.size(),
            ),
        )
    }

    override fun verifyDiagnosticStage(
        request: ZkStageVerifyRequest,
        proof: ZkNativeProofHandle,
    ): Boolean {
        val expectedCircuitRef = circuitRef(request.bundleKind, request.credentialHashAlgorithm, request.stage)
        if (proof.proof.circuitRef != expectedCircuitRef) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        val operation =
            Manifest.ZkStageVerifyOperation
                .newBuilder()
                .setProof(proof.proof)
                .setExpectedBinding(request.expectedSessionBinding)
                .setExpectedProofSuite(PROOF_SUITE)
                .build()
        val providerRequest =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setVerifyStage(operation)
                .build()
        val response = dispatchNativeOperation(contextHandle, bridgeProvider, providerRequest)
        return isSuccessfulStageVerification(response, operation)
    }

    override fun proveClaimProofBundle(
        request: ZkClaimProofBundleProveRequest,
        witnesses: List<ZkNativeWitnessHandle>,
    ): ZkProviderClaimProofBundleResult<ZkNativeClaimProofBundleHandle> {
        if (witnesses.size != NATIVE_PRODUCTION_STAGE_COUNT) {
            throw preDispatchBundleFailure(ZkProviderFailureReason.MALFORMED_WITNESS, witnesses)
        }
        if (witnesses.any { it.sessionBinding != request.sessionBinding }) {
            throw preDispatchBundleFailure(ZkProviderFailureReason.PROOF_REJECTED, witnesses)
        }
        val witnessBundle =
            Manifest.ZkRetainedClaimProofBundleWitness
                .newBuilder()
                .setBundleKind(request.bundleKind)
                .setCredentialHashAlgorithm(request.credentialHashAlgorithm)
                .addAllStageWitnessHandles(witnesses.map { it.handle })
                .build()
        val operation =
            Manifest.ZkRetainedClaimProofBundleProveOperation
                .newBuilder()
                .setBundleKind(request.bundleKind)
                .setCredentialHashAlgorithm(request.credentialHashAlgorithm)
                .setSessionBinding(request.sessionBinding)
                .setWitnessBundle(witnessBundle)
                .setProofSuite(PROOF_SUITE)
                .build()
        val providerRequest =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setProveRetainedClaimProofBundle(operation)
                .build()
        val claimProofBundle =
            requireClaimProofBundle(dispatchNativeOperation(contextHandle, bridgeProvider, providerRequest))
        return ZkProviderClaimProofBundleResult(
            ZkNativeClaimProofBundleHandle(claimProofBundle),
            ZkClaimProofBundleMetrics(
                stageCount = claimProofBundle.stagesCount,
                proofByteCount = claimProofBundleByteCount(claimProofBundle),
            ),
        )
    }

    override fun verifyPresentationBoundClaimBundle(
        request: ZkPresentationBoundClaimBundleVerifyRequest,
        claimProofBundle: ZkNativeClaimProofBundleHandle,
    ): ZkPresentationBoundClaimBundleVerification {
        val operation =
            Manifest.ZkClaimProofBundleVerifyOperation
                .newBuilder()
                .setClaimProofBundle(claimProofBundle.claimProofBundle)
                .setExpectedBinding(request.expectedSessionBinding)
                .addAllTrustedIssuers(request.trustedIssuers)
                .setVerificationTimeUnix(request.verificationTimeUnix)
                .setExpectedProofSuite(PROOF_SUITE)
                .build()
        val providerRequest =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setVerifyClaimProofBundle(operation)
                .build()
        val verification =
            requireClaimProofBundleVerification(
                dispatchNativeOperation(contextHandle, bridgeProvider, providerRequest),
            )
        return verifiedClaimProofBundle(verification, request, claimProofBundle.claimProofBundle)
    }

    override fun verifyStatusQualifiedClaimBundle(
        request: ZkStatusQualifiedClaimBundleVerifyRequest,
        statusQualifiedClaimProofBundle: ZkNativeStatusQualifiedClaimProofBundleHandle,
    ): ZkStatusQualifiedClaimBundleVerification {
        val operation =
            Manifest.ZkStatusQualifiedClaimProofBundleVerifyOperation
                .newBuilder()
                .setStatusQualifiedClaimProofBundle(statusQualifiedClaimProofBundle.statusQualifiedClaimProofBundle)
                .setExpectedBinding(request.expectedSessionBinding)
                .setExpectedIssuer(request.expectedIssuer)
                .addAllTrustedIssuers(request.trustedIssuers)
                .setVerificationTimeUnix(request.verificationTimeUnix)
                .setExpectedProofSuite(PROOF_SUITE)
                .setCurrentIssuerStatus(request.currentIssuerStatus)
                .build()
        val providerRequest =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setVerifyStatusQualifiedClaimProofBundle(operation)
                .build()
        val verification =
            requireStatusQualifiedClaimProofBundleVerification(
                dispatchNativeOperation(contextHandle, bridgeProvider, providerRequest),
            )
        return verifiedStatusQualifiedClaimProofBundle(
            verification,
            request,
            statusQualifiedClaimProofBundle.statusQualifiedClaimProofBundle,
        )
    }

    public fun verifyCommonCredentialRoot(
        commonCredentialRootRequest: ZkCommonCredentialRootVerifyRequest,
    ): ZkVerifiedCommonCredentialRoot {
        val operation =
            Manifest.ZkCommonCredentialRootVerifyOperation
                .newBuilder()
                .setPresentation(commonCredentialRootRequest.presentation)
                .setJoinPolicy(commonCredentialRootRequest.policy)
                .setExpectedProofSuite(PROOF_SUITE)
                .build()
        val providerRequest =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setVerifyCommonCredentialRoot(operation)
                .build()
        val verification = rootVerification(dispatchNativeOperation(contextHandle, bridgeProvider, providerRequest))
        if (verification.personaMode != commonCredentialRootRequest.mode.protoPersonaMode ||
            verification.verifiedProofCount != COMMON_CREDENTIAL_ROOT_PROOF_COUNT ||
            verification.proofSuite != PROOF_SUITE
        ) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        return ZkVerifiedCommonCredentialRoot(commonCredentialRootRequest.mode, COMMON_CREDENTIAL_ROOT_PROOF_COUNT)
    }

    /** Verify one persona-credential-evidence proof under the sealed native verification key.
     * Complete acceptance also requires all four credential stages, a current-status
     * proof, trusted status, authenticated request, holder signature, and durable
     * nonce consumption.
     */
    public fun verifyPersonaCredentialEvidenceStage(
        proof: Manifest.ZkPersonaCredentialEvidenceStageProof,
    ): Manifest.ZkPersonaCredentialEvidenceStageVerification {
        if (!isEvidenceStageProofWellFormed(proof)) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        val operation =
            Manifest.ZkPersonaCredentialEvidenceStageVerifyOperation
                .newBuilder()
                .setProof(proof)
                .build()
        val request =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setVerifyPersonaCredentialEvidenceStage(operation)
                .build()
        val result = requireResult(dispatchNativeOperation(contextHandle, bridgeProvider, request))
        return requirePersonaCredentialEvidenceStageVerification(result, proof)
    }

    /** Generate one persona-credential-evidence stage from a single-use private request owner.
     * Native code verifies the returned proof. Presentation acceptance also
     * requires trusted current status and a fresh holder signature.
     */
    public fun provePersonaCredentialEvidenceStage(
        request: ZkPersonaCredentialEvidenceStageProveRequest,
    ): Manifest.ZkPersonaCredentialEvidenceStageProof {
        val result =
            requireResult(
                dispatchEncodedRequest(contextHandle, bridgeProvider, request.takeCanonicalRequestBytes()),
            )
        val isStageProof =
            result.resultCase ==
                Manifest.ZkProviderOperationResult.ResultCase.PERSONA_CREDENTIAL_EVIDENCE_STAGE_PROOF
        if (!isStageProof) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        val proof = result.personaCredentialEvidenceStageProof
        if (!isProducedEvidenceStageProofWellFormed(proof, request)) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        return proof
    }

    /** Return the canonical digest for a protected holder key to sign.
     * Private callers must durably burn the selected one-time token first.
     */
    public fun preparePersonaCredentialEvidencePresentationSigning(
        evidence: Manifest.ZkPersonaCredentialEvidenceProofSet,
        currentState: Manifest.ZkPersonaCredentialEvidenceStageProof,
        verifiedRequest: Manifest.ZkPersonaCredentialEvidenceVerifierRequestV1,
        nowUnix: Long,
    ): ByteArray {
        if (nowUnix < 0) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        val operation =
            Manifest.ZkPersonaCredentialEvidencePresentationSigningOperation
                .newBuilder()
                .setEvidenceProofSet(evidence)
                .setCurrentState(currentState)
                .setVerifierRequest(verifiedRequest)
                .setNowUnix(nowUnix)
                .build()
        val request =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setPreparePersonaCredentialEvidencePresentationSigning(operation)
                .build()
        val result = requireResult(dispatchNativeOperation(contextHandle, bridgeProvider, request))
        val isSigningChallenge =
            result.resultCase ==
                Manifest.ZkProviderOperationResult.ResultCase.PERSONA_CREDENTIAL_EVIDENCE_PRESENTATION_SIGNING_CHALLENGE
        if (!isSigningChallenge ||
            result.personaCredentialEvidencePresentationSigningChallenge.digestSha256.size() != SHA256_DIGEST_BYTE_COUNT
        ) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        return result.personaCredentialEvidencePresentationSigningChallenge.digestSha256.toByteArray()
    }

    /** Recompute the challenge and assemble a signed presentation only when
     * the selected claim proof authenticates the key that supplied the signature.
     */
    public fun assemblePersonaCredentialEvidencePresentation(
        evidence: Manifest.ZkPersonaCredentialEvidenceProofSet,
        currentState: Manifest.ZkPersonaCredentialEvidenceStageProof,
        verifiedRequest: Manifest.ZkPersonaCredentialEvidenceVerifierRequestV1,
        nowUnix: Long,
        holderSignatureP256Raw: ByteArray,
    ): Manifest.ZkPersonaCredentialEvidencePresentation {
        if (nowUnix < 0 || holderSignatureP256Raw.size != P256_RAW_SIGNATURE_BYTE_COUNT) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        val operation =
            Manifest.ZkPersonaCredentialEvidencePresentationAssembleOperation
                .newBuilder()
                .setEvidenceProofSet(evidence)
                .setCurrentState(currentState)
                .setVerifierRequest(verifiedRequest)
                .setNowUnix(nowUnix)
                .setHolderSignatureP256Raw(ByteString.copyFrom(holderSignatureP256Raw))
                .build()
        val request =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setAssemblePersonaCredentialEvidencePresentation(operation)
                .build()
        val result = requireResult(dispatchNativeOperation(contextHandle, bridgeProvider, request))
        val isPersonaCredentialEvidencePresentation =
            result.resultCase ==
                Manifest.ZkProviderOperationResult.ResultCase.PERSONA_CREDENTIAL_EVIDENCE_PRESENTATION
        val hasExpectedHolderSignature =
            result.personaCredentialEvidencePresentation.holderSignatureP256Raw ==
                ByteString.copyFrom(holderSignatureP256Raw)
        if (!isPersonaCredentialEvidencePresentation ||
            !hasExpectedHolderSignature ||
            result.personaCredentialEvidencePresentation.verifierRequest != verifiedRequest
        ) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_PROOF)
        }
        return result.personaCredentialEvidencePresentation
    }

    public fun proveCommonCredentialRootStage(
        commonCredentialRootStageRequest: ZkCommonCredentialRootStageProveRequest,
    ): ZkCommonCredentialRootStageProof {
        val canonicalRequestBytes = commonCredentialRootStageRequest.takeCanonicalRequestBytes()
        if (canonicalRequestBytes != null) {
            return requireCommonCredentialRootStageProof(
                dispatchEncodedRequest(contextHandle, bridgeProvider, canonicalRequestBytes),
                commonCredentialRootStageRequest.operation,
            )
        }
        throw ReallyMeZkProviderException(ZkProviderFailureReason.UNSUPPORTED_TRANSPORT)
    }

    public fun proveCommonCredentialRootPresentation(
        request: ZkCommonCredentialRootPresentationProveRequest,
    ): ZkCommonCredentialRootPresentationProof {
        val canonicalRequestBytes = request.takeCanonicalRequestBytes()
        if (canonicalRequestBytes != null) {
            return requireCommonCredentialRootPresentation(
                dispatchEncodedRequest(contextHandle, bridgeProvider, canonicalRequestBytes),
                request.operation,
            )
        }
        throw ReallyMeZkProviderException(ZkProviderFailureReason.UNSUPPORTED_TRANSPORT)
    }

    override fun releaseWitness(witness: ZkNativeWitnessHandle) {
        val operation =
            Manifest.ZkStageWitnessReleaseOperation
                .newBuilder()
                .setWitnessHandle(witness.handle)
                .build()
        val providerRequest =
            Manifest.ZkProviderOperationRequest
                .newBuilder()
                .setReleaseStageWitness(operation)
                .build()
        requireStageWitnessRelease(dispatchNativeOperation(contextHandle, bridgeProvider, providerRequest))
    }
}
