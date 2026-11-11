// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKProtoCodec
import ReallyMeZkProtoGenerated

func verifiedClaimProofBundle(
  from verificationInput: Reallyme_Zk_V1_ZkPresentationBoundClaimBundleVerification,
  request: ReallyMeZKPresentationBoundClaimBundleVerifyRequest,
  claimProofBundle: Reallyme_Zk_V1_ZkClaimProofBundle
) throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerification {
  var verification = verificationInput
  guard verification.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa,
    claimProofBundle.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa
  else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  guard claimProofBundle.formatVersion == reallyMeZKClaimProofBundleFormatVersion,
    verification.verifiedStageCount == UInt32(ZKClaimProofBundleStage.allCases.count),
    claimProofBundle.stages.count == ZKClaimProofBundleStage.allCases.count
  else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  guard claimProofBundle.sessionBinding == request.expectedSessionBinding else {
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }
  guard verification.statement.hasIssuer,
    trustedIssuersContain(verification.statement.issuer, request.trustedIssuers)
  else {
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }
  let remainingLifetime = verification.statement.presentationExpiryUnix
    .subtractingReportingOverflow(request.verificationTimeUnix)
  guard remainingLifetime.overflow == false, remainingLifetime.partialValue > 0 else {
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }
  guard remainingLifetime.partialValue <= reallyMeZKMaxPresentationLifetimeSeconds else {
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }
  guard verification.statement.claimNameHash.count == 32,
    verification.statement.credentialBinding.count == 32,
    verification.statement.sessionLinkCommitment.count == 32,
    UInt64(verification.statement.claimValueLength)
      <= UInt64(verification.statement.claimValue.count)
  else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  let bundleKind = try flowBundleKind(from: verification.bundleKind)
  guard claimProofBundle.bundleKind == verification.bundleKind else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  let persona = verification.statement.hasPersona ? verification.statement.persona : nil
  let claimNameHash = try ReallyMeZKSensitiveBytes(verification.statement.claimNameHash)
  let claimValue = try ReallyMeZKSensitiveBytes(verification.statement.claimValue)
  let credentialBinding = try ReallyMeZKSensitiveBytes(verification.statement.credentialBinding)
  let sessionLinkCommitment = try ReallyMeZKSensitiveBytes(
    verification.statement.sessionLinkCommitment
  )
  zeroize(&verification.statement.claimNameHash)
  zeroize(&verification.statement.claimValue)
  zeroize(&verification.statement.credentialBinding)
  zeroize(&verification.statement.sessionLinkCommitment)
  return ReallyMeZKPresentationBoundClaimBundleVerification(
    bundleKind: bundleKind,
    verifiedStageCount: Int(verification.verifiedStageCount),
    sessionBinding: request.expectedSessionBinding,
    issuer: verification.statement.issuer,
    persona: persona,
    claimNameHash: claimNameHash,
    claimValue: claimValue,
    claimValueLength: verification.statement.claimValueLength,
    credentialBinding: credentialBinding,
    sessionLinkCommitment: sessionLinkCommitment,
    presentationExpiryUnix: verification.statement.presentationExpiryUnix
  )
}

/// Accepts a five-proof report only when it agrees with the bundle that was
/// dispatched and with the verifier's request. Every failure is typed; no
/// partially validated value is returned.
func verifiedStatusQualifiedClaimProofBundle(
  from verificationInput: Reallyme_Zk_V1_ZkStatusQualifiedClaimProofBundleVerification,
  request: ReallyMeZKStatusQualifiedClaimBundleVerifyRequest,
  statusQualifiedClaimProofBundle: Reallyme_Zk_V1_ZkStatusQualifiedClaimProofBundle
) throws(ReallyMeZKError) -> ReallyMeZKStatusQualifiedClaimBundleVerification {
  var verification = verificationInput
  guard statusQualifiedClaimProofBundle.hasClaimProofBundle,
    statusQualifiedClaimProofBundle.hasIssuerCredentialStatus,
    verification.hasStatement
  else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  let claimProofBundle = statusQualifiedClaimProofBundle.claimProofBundle
  guard verification.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa,
    claimProofBundle.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa,
    statusQualifiedClaimProofBundle.issuerCredentialStatus.proofSuite
      == .barretenbergUltraHonkKeccakZkNoIpa
  else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  guard claimProofBundle.formatVersion == reallyMeZKClaimProofBundleFormatVersion,
    verification.verifiedProofCount == reallyMeZKStatusQualifiedVerifiedProofCount,
    claimProofBundle.stages.count == ZKClaimProofBundleStage.allCases.count
  else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  switch verification.statusPurpose {
  case .revocation, .suspension:
    break
  case .unspecified, .UNRECOGNIZED:
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  guard verification.statusPurpose == request.currentIssuerStatus.purpose else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  guard claimProofBundle.sessionBinding == request.expectedSessionBinding else {
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }
  guard verification.statement.hasIssuer,
    verification.statement.issuer == request.expectedIssuer,
    trustedIssuersContain(verification.statement.issuer, request.trustedIssuers)
  else {
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }
  let remainingLifetime = verification.statement.presentationExpiryUnix
    .subtractingReportingOverflow(request.verificationTimeUnix)
  guard remainingLifetime.overflow == false, remainingLifetime.partialValue > 0 else {
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }
  guard remainingLifetime.partialValue <= reallyMeZKMaxPresentationLifetimeSeconds else {
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }
  guard verification.statement.claimNameHash.count == 32,
    verification.statement.credentialBinding.count == 32,
    verification.statement.sessionLinkCommitment.count == 32,
    UInt64(verification.statement.claimValueLength)
      <= UInt64(verification.statement.claimValue.count)
  else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  let bundleKind = try flowBundleKind(from: verification.bundleKind)
  guard claimProofBundle.bundleKind == verification.bundleKind else {
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
  let persona = verification.statement.hasPersona ? verification.statement.persona : nil
  let claimNameHash = try ReallyMeZKSensitiveBytes(verification.statement.claimNameHash)
  let claimValue = try ReallyMeZKSensitiveBytes(verification.statement.claimValue)
  let credentialBinding = try ReallyMeZKSensitiveBytes(verification.statement.credentialBinding)
  let sessionLinkCommitment = try ReallyMeZKSensitiveBytes(
    verification.statement.sessionLinkCommitment
  )
  zeroize(&verification.statement.claimNameHash)
  zeroize(&verification.statement.claimValue)
  zeroize(&verification.statement.credentialBinding)
  zeroize(&verification.statement.sessionLinkCommitment)
  return ReallyMeZKStatusQualifiedClaimBundleVerification(
    bundleKind: bundleKind,
    verifiedProofCount: Int(verification.verifiedProofCount),
    statusPurpose: verification.statusPurpose,
    sessionBinding: request.expectedSessionBinding,
    issuer: verification.statement.issuer,
    persona: persona,
    claimNameHash: claimNameHash,
    claimValue: claimValue,
    claimValueLength: verification.statement.claimValueLength,
    credentialBinding: credentialBinding,
    sessionLinkCommitment: sessionLinkCommitment,
    presentationExpiryUnix: verification.statement.presentationExpiryUnix
  )
}

private func trustedIssuersContain(
  _ issuer: Reallyme_Zk_V1_ZkP256PublicKey,
  _ trustedIssuers: [Reallyme_Zk_V1_ZkP256PublicKey]
) -> Bool {
  trustedIssuers.contains { trusted in
    trusted.x == issuer.x && trusted.y == issuer.y
  }
}

private func flowBundleKind(
  from bundleKind: Reallyme_Zk_V1_ZkClaimProofBundleKind
) throws(ReallyMeZKError) -> ZKClaimProofBundleKind {
  switch bundleKind {
  case .credentialSubjectClaimV1:
    return .credentialSubjectClaim
  case .privatePersonaClaimV1:
    return .privatePersona
  case .unspecified, .UNRECOGNIZED:
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
}

/// The source circuit and response stage must describe the same verified fact.
func personaCredentialEvidenceStage(
  for stage: Reallyme_Zk_V1_ZkCircuitStage
) throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkPersonaCredentialEvidenceProofSlot {
  switch stage {
  case .evidenceIssuerEnvelope: return .issuerEnvelope
  case .evidenceClaimRoot: return .claimRoot
  case .evidenceSignedValidity: return .signedValidity
  case .evidencePublicClaim, .evidencePrivateClaim: return .selectedClaim
  case .evidenceCurrentState: return .currentState
  default: throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }
}

func zeroize(_ data: inout Data) {
  _ = data.withUnsafeMutableBytes { bytes in
    bytes.initializeMemory(as: UInt8.self, repeating: 0)
  }
  data.removeAll(keepingCapacity: false)
}

func bundleProofByteCount(
  _ bundle: Reallyme_Zk_V1_ZkClaimProofBundle
) throws(ReallyMeZKError) -> Int {
  var total = 0
  for stage in bundle.stages {
    let (updated, overflow) = total.addingReportingOverflow(stage.proof.proof.count)
    guard overflow == false else {
      throw ReallyMeZKError.invalidProviderResponse(.arithmeticOverflow)
    }
    total = updated
  }
  return total
}
