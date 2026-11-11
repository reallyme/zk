// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZkProtoGenerated

public enum ReallyMeZKProtoCodecError: Equatable, Error, Sendable {
  case invalidCapabilities
  case missingOperation
  case missingOutcome
  case missingResult
  case missingErrorReason
  case unsupportedOperation
  case unsupportedProofSuite
  case unrecognizedErrorReason
}

public enum ReallyMeZKProofSuiteId: Equatable, Sendable {
  case barretenbergUltraHonkKeccakZkNoIpa
}

public struct ReallyMeZKStageCoordinate: CustomStringConvertible, CustomDebugStringConvertible,
  Equatable, Sendable
{
  public let credentialHashAlgorithm: Reallyme_Zk_V1_ZkCredentialHashAlgorithm
  public let family: Reallyme_Zk_V1_ZkCircuitFamily
  public let stage: Reallyme_Zk_V1_ZkCircuitStage
  public let circuitRevision: UInt32
  public let proofSuite: Reallyme_Zk_V1_ZkProofSuite

  public var description: String {
    "ReallyMeZKStageCoordinate(credentialHashAlgorithm: \(credentialHashAlgorithm), family: \(family), stage: \(stage), circuitRevision: \(circuitRevision), proofSuite: \(proofSuite))"
  }

  public var debugDescription: String {
    description
  }

  public init(
    credentialHashAlgorithm: Reallyme_Zk_V1_ZkCredentialHashAlgorithm,
    family: Reallyme_Zk_V1_ZkCircuitFamily,
    stage: Reallyme_Zk_V1_ZkCircuitStage,
    circuitRevision: UInt32,
    proofSuite: Reallyme_Zk_V1_ZkProofSuite
  ) {
    self.credentialHashAlgorithm = credentialHashAlgorithm
    self.family = family
    self.stage = stage
    self.circuitRevision = circuitRevision
    self.proofSuite = proofSuite
  }
}

public struct ReallyMeZKWitnessRequest: CustomStringConvertible, CustomDebugStringConvertible,
  Equatable, Sendable
{
  public let coordinate: ReallyMeZKStageCoordinate
  public let input: Reallyme_Zk_V1_ZkStageWitnessInput

  public var description: String {
    "ReallyMeZKWitnessRequest(coordinate: \(coordinate), input: <redacted>)"
  }

  public var debugDescription: String {
    description
  }

  public init(
    coordinate: ReallyMeZKStageCoordinate,
    input: Reallyme_Zk_V1_ZkStageWitnessInput
  ) {
    self.coordinate = coordinate
    self.input = input
  }
}

public struct ReallyMeZKStageProveRequest: CustomStringConvertible, CustomDebugStringConvertible,
  Equatable, Sendable
{
  public let coordinate: ReallyMeZKStageCoordinate

  public var description: String {
    "ReallyMeZKStageProveRequest(coordinate: \(coordinate))"
  }

  public var debugDescription: String {
    description
  }

  public init(coordinate: ReallyMeZKStageCoordinate) {
    self.coordinate = coordinate
  }
}

public struct ReallyMeZKStageVerifyRequest: CustomStringConvertible, CustomDebugStringConvertible,
  Equatable, Sendable
{
  public let coordinate: ReallyMeZKStageCoordinate
  public let expectedSessionBinding: Reallyme_Zk_V1_ZkSessionBinding

  public var description: String {
    "ReallyMeZKStageVerifyRequest(coordinate: \(coordinate), expectedSessionBinding: <redacted>)"
  }

  public var debugDescription: String {
    description
  }

  public init(
    coordinate: ReallyMeZKStageCoordinate,
    expectedSessionBinding: Reallyme_Zk_V1_ZkSessionBinding
  ) {
    self.coordinate = coordinate
    self.expectedSessionBinding = expectedSessionBinding
  }
}

public enum ReallyMeZKProviderOperation: Equatable, Sendable {
  case artifactManifestRequest(proofSuite: ReallyMeZKProofSuiteId)
  case stageWitnessRequest(proofSuite: ReallyMeZKProofSuiteId)
  case stageWitnessRelease

  public init(
    request: Reallyme_Zk_V1_ZkProviderOperationRequest
  ) throws(ReallyMeZKProtoCodecError) {
    switch request.operation {
    case .getArtifactManifest(let operation):
      self = .artifactManifestRequest(
        proofSuite: try Self.requireProofSuite(operation.proofSuite)
      )
    case .witnessStage(let operation):
      self = .stageWitnessRequest(
        proofSuite: try Self.requireProofSuite(operation.proofSuite)
      )
    case .releaseStageWitness:
      self = .stageWitnessRelease
    case .proveClaimProofBundle, .proveRetainedClaimProofBundle, .verifyClaimProofBundle,
      .verifyStatusQualifiedClaimProofBundle,
      .proveStage, .verifyStage,
      .verifyCommonCredentialRoot, .proveCommonCredentialRootStage,
      .proveCommonCredentialRootPresentation,
      .verifyPersonaCredentialEvidenceStage, .provePersonaCredentialEvidenceStage,
      .provePersonaCredentialEvidenceCurrentState,
      .provePersonaCredentialEvidenceIssuerEnvelope, .provePersonaCredentialEvidenceClaimRoot,
      .provePersonaCredentialEvidenceSignedValidity, .provePersonaCredentialEvidenceSelectedClaim,
      .preparePersonaCredentialEvidencePresentationSigning,
      .assemblePersonaCredentialEvidencePresentation:
      throw ReallyMeZKProtoCodecError.unsupportedOperation
    case .none:
      throw ReallyMeZKProtoCodecError.missingOperation
    }
  }

  private static func requireProofSuite(
    _ suite: Reallyme_Zk_V1_ZkProofSuite
  ) throws(ReallyMeZKProtoCodecError) -> ReallyMeZKProofSuiteId {
    guard suite == .barretenbergUltraHonkKeccakZkNoIpa else {
      throw ReallyMeZKProtoCodecError.unsupportedProofSuite
    }
    return .barretenbergUltraHonkKeccakZkNoIpa
  }
}

public enum ReallyMeZKProviderResponse: Equatable, Sendable {
  case success(ReallyMeZKProviderResponseValue)
  case failure(ReallyMeZKProviderFailureReason)

  public init(
    response: Reallyme_Zk_V1_ZkProviderOperationResponse
  ) throws(ReallyMeZKProtoCodecError) {
    switch response.outcome {
    case .result(let result):
      self = .success(try ReallyMeZKProviderResponseValue(result: result))
    case .error(let error):
      self = .failure(try ReallyMeZKProviderFailureReason(reason: error.reason))
    case .none:
      throw ReallyMeZKProtoCodecError.missingOutcome
    }
  }
}

public enum ReallyMeZKProviderResponseValue: Equatable, Sendable {
  case claimProofBundle
  case claimProofBundleVerification
  case stageProof
  case stageVerification
  case artifactManifest
  case stageWitness
  case stageWitnessRelease
  case commonCredentialRootVerification
  case commonCredentialRootStageProof
  case commonCredentialRootPresentation
  case personaCredentialEvidenceStageVerification
  case personaCredentialEvidenceStageProof
  case personaCredentialEvidencePresentationSigningChallenge
  case personaCredentialEvidencePresentation
  case statusQualifiedClaimProofBundleVerification

  fileprivate init(
    result: Reallyme_Zk_V1_ZkProviderOperationResult
  ) throws(ReallyMeZKProtoCodecError) {
    switch result.result {
    case .claimProofBundle:
      self = .claimProofBundle
    case .claimProofBundleVerification:
      self = .claimProofBundleVerification
    case .stageProof:
      self = .stageProof
    case .stageVerification:
      self = .stageVerification
    case .artifactManifest(let manifest):
      guard manifest.hasCapabilities else { throw .invalidCapabilities }
      try ReallyMeZKCapabilityContract.validate(manifest.capabilities)
      self = .artifactManifest
    case .stageWitness:
      self = .stageWitness
    case .stageWitnessRelease:
      self = .stageWitnessRelease
    case .commonCredentialRootVerification:
      self = .commonCredentialRootVerification
    case .commonCredentialRootStageProof:
      self = .commonCredentialRootStageProof
    case .commonCredentialRootPresentation:
      self = .commonCredentialRootPresentation
    case .personaCredentialEvidenceStageVerification:
      self = .personaCredentialEvidenceStageVerification
    case .personaCredentialEvidenceStageProof:
      self = .personaCredentialEvidenceStageProof
    case .personaCredentialEvidencePresentationSigningChallenge:
      self = .personaCredentialEvidencePresentationSigningChallenge
    case .personaCredentialEvidencePresentation:
      self = .personaCredentialEvidencePresentation
    case .statusQualifiedClaimProofBundleVerification:
      self = .statusQualifiedClaimProofBundleVerification
    case .none:
      throw ReallyMeZKProtoCodecError.missingResult
    }
  }
}

public enum ReallyMeZKProviderFailureReason: Equatable, Sendable {
  case unknownCircuit
  case unsupportedCircuit
  case emptyInput
  case proofTooLarge
  case publicInputsTooLarge
  case lengthOverflow
  case invalidProofEncoding
  case invalidProof
  case bindingMismatch
  case artifactMismatch
  case backendUnavailable
  case backendFailure
  case invalidPublicInputName
  case publicKeyTooLarge
  case claimPayloadTooLarge
  case invalidClaimProofBundle
  case duplicateStage
  case missingStage
  case stageMismatch
  case witnessTooLarge
  case malformedProtobuf
  case malformedJson
  case missingOperation
  case unsupportedTransport
  case messageTooLarge
  case artifactTooLarge
  case unsupportedProofSuite
  case untrustedIssuer
  case presentationExpired
  case presentationExpiryTooFar
  case resourceExhausted

  fileprivate init(
    reason: Reallyme_Zk_V1_ZkErrorReason
  ) throws(ReallyMeZKProtoCodecError) {
    switch reason {
    case .unspecified:
      throw ReallyMeZKProtoCodecError.missingErrorReason
    case .unknownCircuit:
      self = .unknownCircuit
    case .unsupportedCircuit:
      self = .unsupportedCircuit
    case .emptyInput:
      self = .emptyInput
    case .proofTooLarge:
      self = .proofTooLarge
    case .publicInputsTooLarge:
      self = .publicInputsTooLarge
    case .lengthOverflow:
      self = .lengthOverflow
    case .invalidProofEncoding:
      self = .invalidProofEncoding
    case .invalidProof:
      self = .invalidProof
    case .bindingMismatch:
      self = .bindingMismatch
    case .artifactMismatch:
      self = .artifactMismatch
    case .backendUnavailable:
      self = .backendUnavailable
    case .backendFailure:
      self = .backendFailure
    case .invalidPublicInputName:
      self = .invalidPublicInputName
    case .publicKeyTooLarge:
      self = .publicKeyTooLarge
    case .claimPayloadTooLarge:
      self = .claimPayloadTooLarge
    case .invalidClaimProofBundle:
      self = .invalidClaimProofBundle
    case .duplicateStage:
      self = .duplicateStage
    case .missingStage:
      self = .missingStage
    case .stageMismatch:
      self = .stageMismatch
    case .witnessTooLarge:
      self = .witnessTooLarge
    case .malformedProtobuf:
      self = .malformedProtobuf
    case .malformedJson:
      self = .malformedJson
    case .missingOperation:
      self = .missingOperation
    case .unsupportedTransport:
      self = .unsupportedTransport
    case .messageTooLarge:
      self = .messageTooLarge
    case .artifactTooLarge:
      self = .artifactTooLarge
    case .unsupportedProofSuite:
      self = .unsupportedProofSuite
    case .untrustedIssuer:
      self = .untrustedIssuer
    case .presentationExpired:
      self = .presentationExpired
    case .presentationExpiryTooFar:
      self = .presentationExpiryTooFar
    case .resourceExhausted:
      self = .resourceExhausted
    case .UNRECOGNIZED:
      throw ReallyMeZKProtoCodecError.unrecognizedErrorReason
    }
  }
}
