// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import ReallyMeZkProtoGenerated
import Testing

@testable import ReallyMeZKKit

/// Shape of the stage-verification report the recording transport returns.
enum RecordingStageVerificationReport: Sendable {
  case matching
  case empty
  case wrongCircuitRef
  case wrongCircuitID
  case wrongBundleKind
  case wrongProofSuite
  case unspecifiedProofSuite
  case unsupportedTransport
  case malformedProof
}

/// Shape of the status-qualified verification report the recording transport returns.
enum RecordingStatusQualifiedVerificationReport: Sendable {
  case matching
  case fourProofResult
  case fourVerifiedProofs
  case wrongStatusPurpose
  case unspecifiedStatusPurpose
  case wrongBundleKind
  case wrongProofSuite
  case missingStatement
  case untrustedStatementIssuer
}

actor RecordingNativeTransport: ReallyMeZKNativeTransport {
  private(set) var operationCases: [NativeOperationKind] = []
  private(set) var statusQualifiedVerifyOperations:
    [Reallyme_Zk_V1_ZkStatusQualifiedClaimProofBundleVerifyOperation] = []
  private(set) var verifyExpectedBindings: [Reallyme_Zk_V1_ZkSessionBinding] = []
  private var nextHandleID: UInt64 = 9
  private let bundlePresentationExpiryUnix: UInt64
  private let bundleCredentialBinding: Data
  private let commonCredentialRootVerifiedProofCount: UInt32
  private let evidenceStageResponseMatches: Bool
  private let stageVerificationReport: RecordingStageVerificationReport
  private let statusQualifiedVerificationReport: RecordingStatusQualifiedVerificationReport

  init(
    bundlePresentationExpiryUnix: UInt64 = 400,
    bundleCredentialBinding: Data = Data(repeating: 13, count: 32),
    commonCredentialRootVerifiedProofCount: UInt32 = 9,
    evidenceStageResponseMatches: Bool = true,
    stageVerificationReport: RecordingStageVerificationReport = .matching,
    statusQualifiedVerificationReport: RecordingStatusQualifiedVerificationReport = .matching
  ) {
    self.bundlePresentationExpiryUnix = bundlePresentationExpiryUnix
    self.bundleCredentialBinding = bundleCredentialBinding
    self.commonCredentialRootVerifiedProofCount = commonCredentialRootVerifiedProofCount
    self.evidenceStageResponseMatches = evidenceStageResponseMatches
    self.stageVerificationReport = stageVerificationReport
    self.statusQualifiedVerificationReport = statusQualifiedVerificationReport
  }

  func dispatch(
    contextHandle: UInt64,
    request: Data
  ) async throws(ReallyMeZKError) -> Data {
    #expect(contextHandle == 7)
    let operationRequest: Reallyme_Zk_V1_ZkProviderOperationRequest
    do {
      operationRequest = try Reallyme_Zk_V1_ZkProviderOperationRequest(serializedBytes: request)
    } catch {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    guard let operation = operationRequest.operation else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    operationCases.append(try nativeOperationKind(operation))
    return try response(for: operation, request: request)
  }

  private func response(
    for operation: Reallyme_Zk_V1_ZkProviderOperationRequest.OneOf_Operation,
    request: Data
  ) throws(ReallyMeZKError) -> Data {
    var result = Reallyme_Zk_V1_ZkProviderOperationResult()
    switch operation {
    case .witnessStage(let witnessOperation):
      var handle = Reallyme_Zk_V1_ZkStageWitnessHandle()
      handle.nativeHandleID = nextHandleID
      nextHandleID += 1
      handle.circuitRef = witnessOperation.circuitRef
      handle.encoding = .noirWitnessStackV1
      var publicInputs = Reallyme_Zk_V1_ZkPublicInputs()
      publicInputs.encoded = Data([1, 2, 3, 4])
      var binding = Reallyme_Zk_V1_ZkSessionBinding()
      binding.nonceHash = Data(repeating: 1, count: 32)
      binding.audienceHash = Data(repeating: 2, count: 32)
      binding.transactionDataHash = Data(repeating: 3, count: 32)
      var witness = Reallyme_Zk_V1_ZkStageWitness()
      witness.witnessHandle = handle
      witness.publicInputs = publicInputs
      witness.sessionBinding = binding
      result.stageWitness = witness
    case .proveStage(let proveOperation):
      var digest = Reallyme_Zk_V1_ZkArtifactManifestDigest()
      digest.value = Data(repeating: 4, count: 32)
      var proof = Reallyme_Zk_V1_ZkProofPackage()
      proof.circuitID = recordingCircuitID(for: proveOperation.circuitRef.family)
      proof.circuitRef = proveOperation.circuitRef
      proof.proofSuite = proveOperation.proofSuite
      proof.publicInputs = proveOperation.publicInputs
      proof.proof = Data(repeating: 5, count: 96)
      proof.artifactManifestSha256 = digest
      result.stageProof = proof
    case .verifyStage(let verifyOperation):
      verifyExpectedBindings.append(verifyOperation.expectedBinding)
      let failure: Reallyme_Zk_V1_ZkErrorReason? =
        switch stageVerificationReport {
        case .unsupportedTransport: .unsupportedTransport
        case .malformedProof: .invalidProofEncoding
        default:
          verifyOperation.expectedBinding.transactionDataHash.isEmpty ? nil : .bindingMismatch
        }
      if let failure {
        var error = Reallyme_Zk_V1_ZkError()
        error.reason = failure
        var response = Reallyme_Zk_V1_ZkProviderOperationResponse()
        response.requestSha256 = Data(SHA256.hash(data: request))
        response.error = error
        return try serializeTestResponse(response)
      }
      result.stageVerification = recordingStageVerification(
        for: verifyOperation.proof,
        report: stageVerificationReport
      )
    case .releaseStageWitness:
      result.stageWitnessRelease = Reallyme_Zk_V1_ZkStageWitnessRelease()
    case .proveRetainedClaimProofBundle(let proveOperation):
      var bundle = Reallyme_Zk_V1_ZkClaimProofBundle()
      bundle.formatVersion = 1
      bundle.bundleKind = proveOperation.bundleKind
      bundle.formatVersion = 1
      bundle.sessionBinding = proveOperation.sessionBinding
      bundle.credentialHashAlgorithm = proveOperation.credentialHashAlgorithm
      bundle.proofSuite = proveOperation.proofSuite
      bundle.stages = proveOperation.witnessBundle.stageWitnessHandles.map { handle in
        var digest = Reallyme_Zk_V1_ZkArtifactManifestDigest()
        digest.value = Data(repeating: 4, count: 32)
        var proof = Reallyme_Zk_V1_ZkProofPackage()
        proof.circuitRef = handle.circuitRef
        proof.proofSuite = proveOperation.proofSuite
        proof.proof = Data(repeating: 5, count: 96)
        proof.artifactManifestSha256 = digest
        var stage = Reallyme_Zk_V1_ZkClaimProofBundleStageProofPackage()
        stage.bundleKind = proveOperation.bundleKind
        stage.stage = productionStage(for: handle.circuitRef.stage)
        stage.proof = proof
        return stage
      }
      result.claimProofBundle = bundle
    case .verifyClaimProofBundle(let verifyOperation):
      guard verifyOperation.trustedIssuers.contains(trustedIssuer()) else {
        var error = Reallyme_Zk_V1_ZkError()
        error.reason = .untrustedIssuer
        var response = Reallyme_Zk_V1_ZkProviderOperationResponse()
        response.requestSha256 = Data(SHA256.hash(data: request))
        response.error = error
        return try serializeTestResponse(response)
      }
      var statement = Reallyme_Zk_V1_ZkPresentationBoundClaimStatement()
      statement.issuer = trustedIssuer()
      statement.claimNameHash = Data(repeating: 11, count: 32)
      statement.claimValue = Data([1, 2, 3]) + Data(repeating: 0, count: 61)
      statement.claimValueLength = 3
      statement.presentationExpiryUnix = bundlePresentationExpiryUnix
      statement.credentialBinding = bundleCredentialBinding
      statement.sessionLinkCommitment = Data(repeating: 12, count: 32)
      var verification = Reallyme_Zk_V1_ZkPresentationBoundClaimBundleVerification()
      verification.bundleKind = verifyOperation.claimProofBundle.bundleKind
      verification.verifiedStageCount = 4
      verification.proofSuite = verifyOperation.expectedProofSuite
      verification.statement = statement
      result.claimProofBundleVerification = verification
    case .verifyStatusQualifiedClaimProofBundle(let verifyOperation):
      statusQualifiedVerifyOperations.append(verifyOperation)
      guard verifyOperation.trustedIssuers.contains(trustedIssuer()) else {
        var error = Reallyme_Zk_V1_ZkError()
        error.reason = .untrustedIssuer
        var response = Reallyme_Zk_V1_ZkProviderOperationResponse()
        response.requestSha256 = Data(SHA256.hash(data: request))
        response.error = error
        return try serializeTestResponse(response)
      }
      let bundleKind = verifyOperation.statusQualifiedClaimProofBundle.claimProofBundle.bundleKind
      if statusQualifiedVerificationReport == .fourProofResult {
        var statement = Reallyme_Zk_V1_ZkPresentationBoundClaimStatement()
        statement.issuer = trustedIssuer()
        statement.claimNameHash = Data(repeating: 11, count: 32)
        statement.claimValue = Data([1, 2, 3]) + Data(repeating: 0, count: 61)
        statement.claimValueLength = 3
        statement.presentationExpiryUnix = bundlePresentationExpiryUnix
        statement.credentialBinding = bundleCredentialBinding
        statement.sessionLinkCommitment = Data(repeating: 12, count: 32)
        var verification = Reallyme_Zk_V1_ZkPresentationBoundClaimBundleVerification()
        verification.bundleKind = bundleKind
        verification.verifiedStageCount = 4
        verification.proofSuite = verifyOperation.expectedProofSuite
        verification.statement = statement
        result.claimProofBundleVerification = verification
      } else {
        var statement = Reallyme_Zk_V1_ZkStatusQualifiedClaimStatement()
        statement.issuer = trustedIssuer()
        statement.claimNameHash = Data(repeating: 11, count: 32)
        statement.claimValue = Data([1, 2, 3]) + Data(repeating: 0, count: 61)
        statement.claimValueLength = 3
        statement.presentationExpiryUnix = bundlePresentationExpiryUnix
        statement.credentialBinding = bundleCredentialBinding
        statement.sessionLinkCommitment = Data(repeating: 12, count: 32)
        var verification = Reallyme_Zk_V1_ZkStatusQualifiedClaimProofBundleVerification()
        verification.bundleKind = bundleKind
        verification.verifiedProofCount = 5
        verification.proofSuite = verifyOperation.expectedProofSuite
        verification.statusPurpose = verifyOperation.currentIssuerStatus.purpose
        switch statusQualifiedVerificationReport {
        case .matching, .fourProofResult:
          break
        case .fourVerifiedProofs:
          verification.verifiedProofCount = 4
        case .wrongStatusPurpose:
          verification.statusPurpose =
            verifyOperation.currentIssuerStatus.purpose == .revocation ? .suspension : .revocation
        case .unspecifiedStatusPurpose:
          verification.statusPurpose = .unspecified
        case .wrongBundleKind:
          verification.bundleKind =
            bundleKind == .privatePersonaClaimV1
            ? .credentialSubjectClaimV1 : .privatePersonaClaimV1
        case .wrongProofSuite:
          verification.proofSuite = .barretenbergUltraHonkPoseidon2ZkNoIpa
        case .missingStatement:
          break
        case .untrustedStatementIssuer:
          statement.issuer = wrongIssuer()
        }
        if statusQualifiedVerificationReport != .missingStatement {
          verification.statement = statement
        }
        result.statusQualifiedClaimProofBundleVerification = verification
      }
    case .verifyCommonCredentialRoot(let verifyOperation):
      var verification = Reallyme_Zk_V1_ZkCommonCredentialRootVerification()
      verification.personaMode = verifyOperation.presentation.personaMode
      verification.verifiedProofCount = commonCredentialRootVerifiedProofCount
      verification.proofSuite = verifyOperation.expectedProofSuite
      result.commonCredentialRootVerification = verification
    case .verifyPersonaCredentialEvidenceStage(let verifyOperation):
      var verification = Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageVerification()
      verification.mode = verifyOperation.proof.mode
      if evidenceStageResponseMatches {
        verification.proofSlot = verifyOperation.proof.proofSlot
      } else {
        verification.proofSlot = .unspecified
      }
      verification.circuitRef = verifyOperation.proof.circuitRef
      verification.proofSuite = verifyOperation.proof.proofSuite
      result.personaCredentialEvidenceStageVerification = verification
    case .provePersonaCredentialEvidenceStage(let proveOperation):
      var digest = Reallyme_Zk_V1_ZkArtifactSetIdentity()
      digest.value = Data(repeating: 2, count: 32)
      var inputs = Reallyme_Zk_V1_ZkPersonaCredentialEvidenceRawPublicInputs()
      inputs.mode = proveOperation.mode
      if proveOperation.circuitRef.stage == .evidenceCurrentState {
        inputs.proofSlot = .currentState
      } else {
        inputs.proofSlot = .selectedClaim
      }
      inputs.circuitRef = proveOperation.circuitRef
      inputs.rawFields = Data(repeating: 1, count: 32)
      var proof = Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof()
      proof.mode = proveOperation.mode
      proof.proofSlot = evidenceStageResponseMatches ? inputs.proofSlot : .unspecified
      proof.circuitRef = proveOperation.circuitRef
      proof.proofSuite = proveOperation.proofSuite
      proof.proof = Data(repeating: 3, count: 96)
      proof.publicInputs = inputs
      proof.artifactSetIdentitySha256 = digest
      result.personaCredentialEvidenceStageProof = proof
    case .preparePersonaCredentialEvidencePresentationSigning:
      var challenge = Reallyme_Zk_V1_ZkPersonaCredentialEvidencePresentationSigningChallenge()
      challenge.digestSha256 = Data(repeating: 7, count: 32)
      result.personaCredentialEvidencePresentationSigningChallenge = challenge
    case .assemblePersonaCredentialEvidencePresentation(let assembly):
      var presentation = Reallyme_Zk_V1_ZkPersonaCredentialEvidencePresentation()
      presentation.verifierRequest = assembly.verifierRequest
      presentation.holderSignatureP256Raw = assembly.holderSignatureP256Raw
      result.personaCredentialEvidencePresentation = presentation
    default:
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }

    var response = Reallyme_Zk_V1_ZkProviderOperationResponse()
    response.requestSha256 = Data(SHA256.hash(data: request))
    response.result = result
    return try serializeTestResponse(response)
  }
}

enum NativeOperationKind: Equatable, Sendable {
  case nativeWitness
  case nativeProve
  case nativeVerify
  case nativeRelease
  case nativeBundleProve
  case nativeBundleVerify
  case nativeStatusQualifiedBundleVerify
  case nativeCommonCredentialRootVerify
  case nativePersonaCredentialEvidenceStageVerify
  case nativePersonaCredentialEvidenceStageProve
  case nativePreparedSigning
  case nativePreparedAssembly
}

func nativeOperationKind(
  _ operation: Reallyme_Zk_V1_ZkProviderOperationRequest.OneOf_Operation
) throws(ReallyMeZKError) -> NativeOperationKind {
  switch operation {
  case .witnessStage:
    return .nativeWitness
  case .proveStage:
    return .nativeProve
  case .verifyStage:
    return .nativeVerify
  case .releaseStageWitness:
    return .nativeRelease
  case .proveRetainedClaimProofBundle:
    return .nativeBundleProve
  case .verifyClaimProofBundle:
    return .nativeBundleVerify
  case .verifyStatusQualifiedClaimProofBundle:
    return .nativeStatusQualifiedBundleVerify
  case .verifyCommonCredentialRoot:
    return .nativeCommonCredentialRootVerify
  case .verifyPersonaCredentialEvidenceStage:
    return .nativePersonaCredentialEvidenceStageVerify
  case .provePersonaCredentialEvidenceStage:
    return .nativePersonaCredentialEvidenceStageProve
  case .preparePersonaCredentialEvidencePresentationSigning:
    return .nativePreparedSigning
  case .assemblePersonaCredentialEvidencePresentation:
    return .nativePreparedAssembly
  default:
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
}

func serializeTestResponse(
  _ response: Reallyme_Zk_V1_ZkProviderOperationResponse
) throws(ReallyMeZKError) -> Data {
  do {
    return try response.serializedData()
  } catch {
    throw ReallyMeZKError.invalidProviderResponse(.internalFailure)
  }
}

private func recordingCircuitID(
  for family: Reallyme_Zk_V1_ZkCircuitFamily
) -> Reallyme_Zk_V1_ZkCircuitId {
  switch family {
  case .credentialSubjectClaimV1: return .credentialSubjectClaimV1
  case .privatePersonaClaimV1: return .privatePersonaClaimV1
  default: return .unspecified
  }
}

private func recordingBundleKind(
  for family: Reallyme_Zk_V1_ZkCircuitFamily
) -> Reallyme_Zk_V1_ZkClaimProofBundleKind {
  switch family {
  case .credentialSubjectClaimV1: return .credentialSubjectClaimV1
  case .privatePersonaClaimV1: return .privatePersonaClaimV1
  default: return .unspecified
  }
}

private func recordingStageVerification(
  for proof: Reallyme_Zk_V1_ZkProofPackage,
  report: RecordingStageVerificationReport
) -> Reallyme_Zk_V1_ZkVerification {
  var verification = Reallyme_Zk_V1_ZkVerification()
  if report == .empty {
    return verification
  }
  verification.circuitID = proof.circuitID
  verification.circuitRef = proof.circuitRef
  verification.bundleKind = recordingBundleKind(for: proof.circuitRef.family)
  verification.proofSuite = proof.proofSuite
  switch report {
  case .matching, .empty, .unsupportedTransport, .malformedProof:
    break
  case .wrongCircuitRef:
    verification.circuitRef.stage = .credentialEnvelope
  case .wrongCircuitID:
    verification.circuitID = .privatePersonaClaimV1
  case .wrongBundleKind:
    verification.bundleKind = .privatePersonaClaimV1
  case .wrongProofSuite:
    verification.proofSuite = .barretenbergUltraHonkPoseidon2ZkNoIpa
  case .unspecifiedProofSuite:
    verification.proofSuite = .unspecified
  }
  return verification
}
