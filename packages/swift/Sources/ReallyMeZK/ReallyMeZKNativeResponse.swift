// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeZkProtoGenerated

extension Reallyme_Zk_V1_ZkProviderOperationResponse {
  func requireStageWitness() throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkStageWitness {
    let result = try requireResult()
    guard case .stageWitness(let witness)? = result.result,
      witness.hasWitnessHandle,
      witness.hasPublicInputs,
      witness.hasSessionBinding
    else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedWitness)
    }
    return witness
  }

  func requireStageProof() throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkProofPackage {
    let result = try requireResult()
    guard case .stageProof(let proof)? = result.result else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return proof
  }

  func requireClaimProofBundle() throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkClaimProofBundle {
    let result = try requireResult()
    guard case .claimProofBundle(let bundle)? = result.result else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return bundle
  }

  func requireClaimProofBundleVerification() throws(ReallyMeZKError)
    -> Reallyme_Zk_V1_ZkPresentationBoundClaimBundleVerification
  {
    let result = try requireResult()
    guard case .claimProofBundleVerification(let verification)? = result.result else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return verification
  }

  /// Accepts only the five-proof status-qualified report. A four-proof
  /// presentation-bound report is a malformed response to this operation.
  func requireStatusQualifiedClaimProofBundleVerification() throws(ReallyMeZKError)
    -> Reallyme_Zk_V1_ZkStatusQualifiedClaimProofBundleVerification
  {
    let result = try requireResult()
    guard case .statusQualifiedClaimProofBundleVerification(let verification)? = result.result
    else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return verification
  }

  func requireCommonCredentialRootVerification() throws(ReallyMeZKError)
    -> Reallyme_Zk_V1_ZkCommonCredentialRootVerification
  {
    let result = try requireResult()
    guard case .commonCredentialRootVerification(let verification)? = result.result else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return verification
  }

  func requireCommonCredentialRootStageProof() throws(ReallyMeZKError)
    -> Reallyme_Zk_V1_ZkCommonCredentialRootRawProofPackage
  {
    let result = try requireResult()
    guard case .commonCredentialRootStageProof(let proof)? = result.result else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return proof
  }

  func requireCommonCredentialRootPresentation() throws(ReallyMeZKError)
    -> Reallyme_Zk_V1_ZkCommonCredentialRootPresentation
  {
    let result = try requireResult()
    guard case .commonCredentialRootPresentation(let presentation)? = result.result else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return presentation
  }

  func requirePersonaCredentialEvidenceStageVerification() throws(ReallyMeZKError)
    -> Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageVerification
  {
    let result = try requireResult()
    guard case .personaCredentialEvidenceStageVerification(let verification)? = result.result else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return verification
  }

  func requirePersonaCredentialEvidenceStageProof() throws(ReallyMeZKError)
    -> Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof
  {
    let result = try requireResult()
    guard case .personaCredentialEvidenceStageProof(let proof)? = result.result else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return proof
  }

  func requirePersonaCredentialEvidencePresentationSigningChallenge() throws(ReallyMeZKError)
    -> Reallyme_Zk_V1_ZkPersonaCredentialEvidencePresentationSigningChallenge
  {
    let result = try requireResult()
    guard
      case .personaCredentialEvidencePresentationSigningChallenge(let challenge)? = result.result
    else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return challenge
  }

  func requirePersonaCredentialEvidencePresentation() throws(ReallyMeZKError)
    -> Reallyme_Zk_V1_ZkPersonaCredentialEvidencePresentation
  {
    let result = try requireResult()
    guard case .personaCredentialEvidencePresentation(let presentation)? = result.result else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
    }
    return presentation
  }

  /// Accepts a stage-verification report only when it names the exact proof that was dispatched.
  ///
  /// A report with absent, unknown, or mismatched identity fields is a malformed provider
  /// response, never a verification outcome.
  func isSuccessfulStageVerification(
    for operation: Reallyme_Zk_V1_ZkStageVerifyOperation
  ) throws(ReallyMeZKError) -> Bool {
    switch outcome {
    case .result(let result):
      guard case .stageVerification(let report)? = result.result else {
        throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
      }
      try requireStageVerificationReport(report, matches: operation)
      return true
    case .error(let error):
      let reason = providerFailureReason(from: error.reason)
      if reason == .proofRejected || reason == .malformedProof {
        return false
      }
      throw ReallyMeZKError.providerRejected(reason)
    case .none:
      throw ReallyMeZKError.invalidProviderResponse(.emptyBuffer)
    }
  }

  func requireStageWitnessRelease() throws(ReallyMeZKError) {
    let result = try requireResult()
    guard case .stageWitnessRelease? = result.result else {
      throw ReallyMeZKError.invalidProviderResponse(.malformedWitness)
    }
  }

  private func requireResult() throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkProviderOperationResult {
    switch outcome {
    case .result(let result):
      return result
    case .error(let error):
      throw ReallyMeZKError.providerRejected(providerFailureReason(from: error.reason))
    case .none:
      throw ReallyMeZKError.invalidProviderResponse(.emptyBuffer)
    }
  }
}

/// The circuit reference, circuit identifier, bundle kind, and proof suite must all be present
/// and equal to the values sent in the verify operation.
private func requireStageVerificationReport(
  _ report: Reallyme_Zk_V1_ZkVerification,
  matches operation: Reallyme_Zk_V1_ZkStageVerifyOperation
) throws(ReallyMeZKError) {
  let proof = operation.proof
  guard proof.hasCircuitRef, report.hasCircuitRef, report.circuitRef == proof.circuitRef else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  let expectedCircuitID: Reallyme_Zk_V1_ZkCircuitId
  let expectedBundleKind: Reallyme_Zk_V1_ZkClaimProofBundleKind
  switch proof.circuitRef.family {
  case .credentialSubjectClaimV1:
    expectedCircuitID = .credentialSubjectClaimV1
    expectedBundleKind = .credentialSubjectClaimV1
  case .privatePersonaClaimV1:
    expectedCircuitID = .privatePersonaClaimV1
    expectedBundleKind = .privatePersonaClaimV1
  default:
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  guard report.circuitID == expectedCircuitID, proof.circuitID == expectedCircuitID,
    report.bundleKind == expectedBundleKind
  else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  switch report.proofSuite {
  case .unspecified, .UNRECOGNIZED:
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  default:
    break
  }
  guard report.proofSuite == operation.expectedProofSuite,
    report.proofSuite == proof.proofSuite
  else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
}

func providerFailureReason(
  from reason: Reallyme_Zk_V1_ZkErrorReason
) -> ZKProviderFailureReason {
  switch reason {
  case .unsupportedCircuit, .unknownCircuit:
    return .unsupportedCircuit
  case .unsupportedProofSuite:
    return .unsupportedSuite
  case .unsupportedTransport:
    return .unsupportedTransport
  case .emptyInput:
    return .emptyBuffer
  case .proofTooLarge, .publicInputsTooLarge, .messageTooLarge, .artifactTooLarge, .witnessTooLarge:
    return .oversizedBuffer
  case .lengthOverflow, .resourceExhausted:
    return .arithmeticOverflow
  case .invalidProofEncoding, .malformedProtobuf, .malformedJson:
    return .malformedProof
  case .invalidProof, .bindingMismatch, .artifactMismatch:
    return .proofRejected
  case .untrustedIssuer, .presentationExpired, .presentationExpiryTooFar:
    return .proofRejected
  case .backendUnavailable:
    return .crsMissing
  case .backendFailure:
    return .internalFailure
  case .unspecified, .invalidPublicInputName, .publicKeyTooLarge, .claimPayloadTooLarge,
    .invalidClaimProofBundle, .duplicateStage, .missingStage, .stageMismatch, .missingOperation,
    .UNRECOGNIZED:
    return .internalFailure
  }
}
