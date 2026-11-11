// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import ReallyMeZKProtoCodec
import ReallyMeZkProtoGenerated
import SwiftProtobuf

public struct ReallyMeZKNativeWitnessHandle: Sendable {
  fileprivate let handle: Reallyme_Zk_V1_ZkStageWitnessHandle
  fileprivate let publicInputs: Reallyme_Zk_V1_ZkPublicInputs
  fileprivate let sessionBinding: Reallyme_Zk_V1_ZkSessionBinding
}

public struct ReallyMeZKNativeProofHandle: Sendable {
  fileprivate let proof: Reallyme_Zk_V1_ZkProofPackage
}

public struct ReallyMeZKNativeProvider<Transport: ReallyMeZKNativeTransport>:
  ReallyMeZKProvider, ReallyMeZKClaimProofBundleProvider,
  ReallyMeZKStatusQualifiedClaimBundleVerifier
{
  public typealias WitnessHandle = ReallyMeZKNativeWitnessHandle
  public typealias ProofHandle = ReallyMeZKNativeProofHandle
  public typealias ClaimProofBundleHandle = ReallyMeZKNativeClaimProofBundleHandle
  public typealias StatusQualifiedClaimProofBundleHandle =
    ReallyMeZKNativeStatusQualifiedClaimProofBundleHandle

  private let contextHandle: UInt64
  private let transport: Transport

  public init(
    contextHandle: UInt64,
    transport: Transport
  ) throws(ReallyMeZKError) {
    guard contextHandle > 0 else {
      throw ReallyMeZKError.providerUnavailable
    }
    self.contextHandle = contextHandle
    self.transport = transport
  }

  public func generateWitness(
    request: ReallyMeZKWitnessRequest
  ) async throws(ReallyMeZKError) -> ZKProviderWitnessResult<WitnessHandle> {
    guard request.input.input != nil else {
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
    var operation = Reallyme_Zk_V1_ZkStageWitnessOperation()
    operation.circuitRef = request.coordinate.circuitRef
    operation.proofSuite = request.coordinate.proofSuite
    operation.input = request.input

    var providerRequest = Reallyme_Zk_V1_ZkProviderOperationRequest()
    providerRequest.witnessStage = operation
    let response = try await dispatch(providerRequest)
    let witness = try response.requireStageWitness()
    return ZKProviderWitnessResult(
      handle: ReallyMeZKNativeWitnessHandle(
        handle: witness.witnessHandle,
        publicInputs: witness.publicInputs,
        sessionBinding: witness.sessionBinding
      ),
      metrics: ZKWitnessMetrics()
    )
  }

  public func prove(
    request: ReallyMeZKStageProveRequest,
    witness: WitnessHandle
  ) async throws(ReallyMeZKError) -> ZKProviderProofResult<ProofHandle> {
    var operation = Reallyme_Zk_V1_ZkStageProveOperation()
    operation.circuitRef = request.coordinate.circuitRef
    operation.proofSuite = request.coordinate.proofSuite
    operation.witnessHandle = witness.handle
    operation.publicInputs = witness.publicInputs
    operation.sessionBinding = witness.sessionBinding

    var providerRequest = Reallyme_Zk_V1_ZkProviderOperationRequest()
    providerRequest.proveStage = operation
    let response = try await dispatch(providerRequest)
    let proof = try response.requireStageProof()
    return try ZKProviderProofResult(
      handle: ReallyMeZKNativeProofHandle(proof: proof),
      metrics: ZKProofMetrics(
        publicInputByteCount: ZKPublicInputByteCount(proof.publicInputs.encoded.count),
        proofByteCount: ZKProofByteCount(proof.proof.count)
      )
    )
  }

  public func verifyDiagnosticStage(
    request: ReallyMeZKStageVerifyRequest,
    proof: ProofHandle
  ) async throws(ReallyMeZKError) -> Bool {
    guard proof.proof.circuitRef == request.coordinate.circuitRef else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    var operation = Reallyme_Zk_V1_ZkStageVerifyOperation()
    operation.proof = proof.proof
    operation.expectedBinding = request.expectedSessionBinding
    operation.expectedProofSuite = request.coordinate.proofSuite

    var providerRequest = Reallyme_Zk_V1_ZkProviderOperationRequest()
    providerRequest.verifyStage = operation
    let response = try await dispatch(providerRequest)
    return try response.isSuccessfulStageVerification(for: operation)
  }

  public func proveClaimProofBundle(
    request: ReallyMeZKClaimProofBundleProveRequest,
    witnesses: [WitnessHandle]
  ) async throws(ReallyMeZKError) -> ZKProviderClaimProofBundleResult<ClaimProofBundleHandle> {
    guard witnesses.count == ZKClaimProofBundleStage.allCases.count else {
      await releasePreDispatchWitnesses(witnesses)
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
    for witness in witnesses {
      guard witness.sessionBinding == request.sessionBinding else {
        await releasePreDispatchWitnesses(witnesses)
        throw ReallyMeZKError.providerRejected(.proofRejected)
      }
    }
    var witnessBundle = Reallyme_Zk_V1_ZkRetainedClaimProofBundleWitness()
    witnessBundle.bundleKind = request.bundleKind.protoBundleKind
    witnessBundle.credentialHashAlgorithm =
      request.credentialHashAlgorithm.protoCredentialHashAlgorithm
    witnessBundle.stageWitnessHandles = witnesses.map(\.handle)

    var operation = Reallyme_Zk_V1_ZkRetainedClaimProofBundleProveOperation()
    operation.bundleKind = request.bundleKind.protoBundleKind
    operation.credentialHashAlgorithm = request.credentialHashAlgorithm.protoCredentialHashAlgorithm
    operation.sessionBinding = request.sessionBinding
    operation.witnessBundle = witnessBundle
    operation.proofSuite = .barretenbergUltraHonkKeccakZkNoIpa

    var providerRequest = Reallyme_Zk_V1_ZkProviderOperationRequest()
    providerRequest.proveRetainedClaimProofBundle = operation
    let response = try await dispatch(providerRequest)
    let claimProofBundle = try response.requireClaimProofBundle()
    let proofByteCount = try ZKClaimProofBundleByteCount(bundleProofByteCount(claimProofBundle))
    return ZKProviderClaimProofBundleResult(
      handle: ReallyMeZKNativeClaimProofBundleHandle(claimProofBundle: claimProofBundle),
      metrics: ZKClaimProofBundleMetrics(
        stageCount: claimProofBundle.stages.count,
        proofByteCount: proofByteCount
      )
    )
  }

  public func verifyPresentationBoundClaimBundle(
    request: ReallyMeZKPresentationBoundClaimBundleVerifyRequest,
    claimProofBundle: ClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerification {
    var operation = Reallyme_Zk_V1_ZkClaimProofBundleVerifyOperation()
    operation.claimProofBundle = claimProofBundle.claimProofBundle
    operation.expectedBinding = request.expectedSessionBinding
    operation.trustedIssuers = request.trustedIssuers
    operation.verificationTimeUnix = request.verificationTimeUnix
    operation.expectedProofSuite = .barretenbergUltraHonkKeccakZkNoIpa

    var providerRequest = Reallyme_Zk_V1_ZkProviderOperationRequest()
    providerRequest.verifyClaimProofBundle = operation
    let response = try await dispatch(providerRequest)
    let verification = try response.requireClaimProofBundleVerification()
    return try verifiedClaimProofBundle(
      from: verification,
      request: request,
      claimProofBundle: claimProofBundle.claimProofBundle
    )
  }

  /// Verifies all five proofs against the verifier's current issuer status
  /// list. The result does not consume the session; the verifier must
  /// atomically accept the active session exactly once before granting access.
  public func verifyStatusQualifiedClaimBundle(
    request: ReallyMeZKStatusQualifiedClaimBundleVerifyRequest,
    statusQualifiedClaimProofBundle: StatusQualifiedClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKStatusQualifiedClaimBundleVerification {
    var operation = Reallyme_Zk_V1_ZkStatusQualifiedClaimProofBundleVerifyOperation()
    operation.statusQualifiedClaimProofBundle =
      statusQualifiedClaimProofBundle.statusQualifiedClaimProofBundle
    operation.expectedBinding = request.expectedSessionBinding
    operation.expectedIssuer = request.expectedIssuer
    operation.trustedIssuers = request.trustedIssuers
    operation.verificationTimeUnix = request.verificationTimeUnix
    operation.expectedProofSuite = .barretenbergUltraHonkKeccakZkNoIpa
    operation.currentIssuerStatus = request.currentIssuerStatus

    var providerRequest = Reallyme_Zk_V1_ZkProviderOperationRequest()
    providerRequest.verifyStatusQualifiedClaimProofBundle = operation
    let response = try await dispatch(providerRequest)
    let verification = try response.requireStatusQualifiedClaimProofBundleVerification()
    return try verifiedStatusQualifiedClaimProofBundle(
      from: verification,
      request: request,
      statusQualifiedClaimProofBundle:
        statusQualifiedClaimProofBundle.statusQualifiedClaimProofBundle
    )
  }

  public func verifyCommonCredentialRoot(
    request: ReallyMeZKCommonCredentialRootVerifyRequest
  ) async throws(ReallyMeZKError) -> ReallyMeZKVerifiedCommonCredentialRoot {
    var operation = Reallyme_Zk_V1_ZkCommonCredentialRootVerifyOperation()
    operation.presentation = request.presentation
    operation.joinPolicy = request.policy
    operation.expectedProofSuite = .barretenbergUltraHonkKeccakZkNoIpa

    var providerRequest = Reallyme_Zk_V1_ZkProviderOperationRequest()
    providerRequest.verifyCommonCredentialRoot = operation
    let response = try await dispatch(providerRequest)
    let verification = try response.requireCommonCredentialRootVerification()
    guard verification.personaMode == request.mode.protoPersonaMode,
      verification.verifiedProofCount == UInt32(commonCredentialRootProofSlots.count),
      verification.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa
    else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return ReallyMeZKVerifiedCommonCredentialRoot(
      mode: request.mode, verifiedProofCount: commonCredentialRootProofSlots.count)
  }

  /// Verifies one persona-credential-evidence proof against the sealed native verification key.
  /// Complete acceptance also needs all four credential stages, a current-status
  /// proof, trusted status, a verified request, holder signature, and nonce consumption.
  public func verifyPersonaCredentialEvidenceStage(
    proof: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof
  ) async throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageVerification {
    guard proof.hasPublicInputs,
      proof.hasArtifactSetIdentitySha256,
      proof.artifactSetIdentitySha256.value.count == 32,
      proof.proof.isEmpty == false,
      proof.publicInputs.rawFields.isEmpty == false,
      proof.publicInputs.mode == proof.mode,
      proof.publicInputs.proofSlot == proof.proofSlot,
      proof.publicInputs.circuitRef == proof.circuitRef,
      proof.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa
    else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    var operation = Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageVerifyOperation()
    operation.proof = proof
    var request = Reallyme_Zk_V1_ZkProviderOperationRequest()
    request.verifyPersonaCredentialEvidenceStage = operation
    let response = try await dispatch(request)
    let verification = try response.requirePersonaCredentialEvidenceStageVerification()
    guard verification.mode == proof.mode,
      verification.proofSlot == proof.proofSlot,
      verification.circuitRef == proof.circuitRef,
      verification.proofSuite == proof.proofSuite
    else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return verification
  }

  /// Generates one persona-credential-evidence proof from a single-use private request owner.
  /// Native code independently verifies the proof before returning it. A complete
  /// presentation additionally requires current status and holder authentication.
  public func provePersonaCredentialEvidenceStage(
    request: ReallyMeZKPersonaCredentialEvidenceStageProveRequest
  ) async throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof {
    let response = try await dispatchBytes(request.takeCanonicalRequestBytes())
    let proof = try response.requirePersonaCredentialEvidenceStageProof()
    let expectedStage = try personaCredentialEvidenceStage(for: request.circuitRef.stage)
    guard proof.mode == request.mode,
      proof.circuitRef == request.circuitRef,
      proof.proofSlot == expectedStage,
      proof.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa,
      proof.hasPublicInputs,
      proof.publicInputs.mode == proof.mode,
      proof.publicInputs.circuitRef == proof.circuitRef,
      proof.publicInputs.proofSlot == proof.proofSlot,
      proof.proof.isEmpty == false,
      proof.publicInputs.rawFields.isEmpty == false,
      proof.hasArtifactSetIdentitySha256,
      proof.artifactSetIdentitySha256.value.count == 32
    else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return proof
  }

  /// Return the canonical digest for a protected holder key to sign.
  /// Private callers must durably burn their selected token before this call.
  public func preparePersonaCredentialEvidencePresentationSigning(
    evidence: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceProofSet,
    currentState: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof,
    verifiedRequest: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceVerifierRequestV1,
    nowUnix: UInt64
  ) async throws(ReallyMeZKError) -> Data {
    var operation = Reallyme_Zk_V1_ZkPersonaCredentialEvidencePresentationSigningOperation()
    operation.evidenceProofSet = evidence
    operation.currentState = currentState
    operation.verifierRequest = verifiedRequest
    operation.nowUnix = nowUnix
    var request = Reallyme_Zk_V1_ZkProviderOperationRequest()
    request.preparePersonaCredentialEvidencePresentationSigning = operation
    let response = try await dispatch(request)
    let challenge = try response.requirePersonaCredentialEvidencePresentationSigningChallenge()
    guard challenge.digestSha256.count == 32 else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return challenge.digestSha256
  }

  /// Assemble the exact signed presentation after a protected P-256 key signs
  /// the challenge returned by `preparePersonaCredentialEvidencePresentationSigning`.
  public func assemblePersonaCredentialEvidencePresentation(
    evidence: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceProofSet,
    currentState: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof,
    verifiedRequest: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceVerifierRequestV1,
    nowUnix: UInt64,
    holderSignatureP256Raw: Data
  ) async throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkPersonaCredentialEvidencePresentation {
    guard holderSignatureP256Raw.count == 64 else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    var operation = Reallyme_Zk_V1_ZkPersonaCredentialEvidencePresentationAssembleOperation()
    operation.evidenceProofSet = evidence
    operation.currentState = currentState
    operation.verifierRequest = verifiedRequest
    operation.nowUnix = nowUnix
    operation.holderSignatureP256Raw = holderSignatureP256Raw
    var request = Reallyme_Zk_V1_ZkProviderOperationRequest()
    request.assemblePersonaCredentialEvidencePresentation = operation
    let response = try await dispatch(request)
    let presentation = try response.requirePersonaCredentialEvidencePresentation()
    guard presentation.holderSignatureP256Raw == holderSignatureP256Raw,
      presentation.verifierRequest == verifiedRequest
    else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return presentation
  }

  public func proveCommonCredentialRootStage(
    request: ReallyMeZKCommonCredentialRootStageProveRequest
  ) async throws(ReallyMeZKError) -> ReallyMeZKCommonCredentialRootStageProof {
    let response = try await dispatchBytes(request.takeCanonicalRequestBytes())
    let proof = try response.requireCommonCredentialRootStageProof()
    guard proof.personaMode == request.personaMode,
      proof.slot == request.slot,
      proof.circuitRef == request.circuitRef,
      proof.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa,
      proof.hasPublicInputs,
      proof.publicInputs.personaMode == proof.personaMode,
      proof.publicInputs.slot == proof.slot,
      proof.publicInputs.circuitRef == proof.circuitRef,
      proof.proof.isEmpty == false,
      commonCredentialRootArtifactIdentityIsValid(proof)
    else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return ReallyMeZKCommonCredentialRootStageProof(package: proof)
  }

  public func proveCommonCredentialRootPresentation(
    request: ReallyMeZKCommonCredentialRootPresentationProveRequest
  ) async throws(ReallyMeZKError) -> ReallyMeZKCommonCredentialRootPresentationProof {
    let response = try await dispatchBytes(request.takeCanonicalRequestBytes())
    let presentation = try response.requireCommonCredentialRootPresentation()
    guard presentation.personaMode == request.personaMode,
      presentation.proofSuite == request.proofSuite,
      presentation.sessionBinding.nonceHash == request.expectedBinding.nonceHash,
      presentation.sessionBinding.audienceHash == request.expectedBinding.audienceHash,
      presentation.sessionBinding.transactionDataHash
        == request.expectedBinding.transactionDataHash,
      presentation.proofs.count == commonCredentialRootProofSlots.count,
      presentation.proofs.map(\.slot) == commonCredentialRootProofSlots,
      presentation.proofs.allSatisfy({ proof in
        proof.personaMode == presentation.personaMode
          && proof.proofSuite == presentation.proofSuite
          && proof.circuitRef.credentialHashAlgorithm == presentation.credentialHashAlgorithm
          && proof.publicInputs.personaMode == proof.personaMode
          && proof.publicInputs.slot == proof.slot
          && proof.publicInputs.circuitRef == proof.circuitRef
          && proof.proof.isEmpty == false
          && commonCredentialRootArtifactIdentityIsValid(proof)
      })
    else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return ReallyMeZKCommonCredentialRootPresentationProof(presentation: presentation)
  }

  public func releaseWitness(
    _ witness: WitnessHandle
  ) async throws(ReallyMeZKError) {
    var operation = Reallyme_Zk_V1_ZkStageWitnessReleaseOperation()
    operation.witnessHandle = witness.handle

    var providerRequest = Reallyme_Zk_V1_ZkProviderOperationRequest()
    providerRequest.releaseStageWitness = operation
    let response = try await dispatch(providerRequest)
    try response.requireStageWitnessRelease()
  }

  private func releasePreDispatchWitnesses(
    _ witnesses: [WitnessHandle]
  ) async {
    for witness in witnesses {
      do {
        try await releaseWitness(witness)
      } catch {
        continue
      }
    }
  }

  private func dispatch(
    _ request: Reallyme_Zk_V1_ZkProviderOperationRequest
  ) async throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkProviderOperationResponse {
    try await dispatchBytes(serialize(request))
  }

  /// Takes ownership of the serialized request so this function holds its only
  /// reference. Clearing a `Data` value that shares storage with a caller's
  /// copy would write zeros into a fresh copy and leave the original intact,
  /// so callers must pass a value they do not keep.
  private func dispatchBytes(
    _ bytes: consuming Data
  ) async throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkProviderOperationResponse {
    var requestBytes = consume bytes
    var requestDigest = sha256(requestBytes)
    defer {
      zeroize(&requestDigest)
    }
    var responseBytes: Data
    do {
      responseBytes = try await transport.dispatch(
        contextHandle: contextHandle,
        request: requestBytes
      )
    } catch {
      zeroize(&requestBytes)
      throw error
    }
    zeroize(&requestBytes)
    defer {
      zeroize(&responseBytes)
    }
    return try decodeResponse(responseBytes, expectedRequestSha256: requestDigest)
  }
}

extension ReallyMeZKStageCoordinate {
  fileprivate var circuitRef: Reallyme_Zk_V1_ZkCircuitRef {
    var circuitRef = Reallyme_Zk_V1_ZkCircuitRef()
    circuitRef.credentialHashAlgorithm = credentialHashAlgorithm
    circuitRef.family = family
    circuitRef.stage = stage
    circuitRef.circuitRevision = circuitRevision
    return circuitRef
  }
}

private func serialize<Message: SwiftProtobuf.Message>(
  _ message: Message
) throws(ReallyMeZKError) -> Data {
  do {
    return try message.serializedData()
  } catch {
    throw ReallyMeZKError.invalidProviderResponse(.internalFailure)
  }
}

private func decodeResponse(
  _ responseBytes: Data,
  expectedRequestSha256: Data
) throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkProviderOperationResponse {
  do {
    let response = try Reallyme_Zk_V1_ZkProviderOperationResponse(serializedBytes: responseBytes)
    guard response.requestSha256 == expectedRequestSha256 else {
      throw ReallyMeZKError.providerRejected(.malformedProof)
    }
    return response
  } catch let error as ReallyMeZKError {
    throw error
  } catch {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
}

private func sha256(_ data: Data) -> Data {
  Data(SHA256.hash(data: data))
}
