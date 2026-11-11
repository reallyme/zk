// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZkProtoGenerated
import Synchronization

public enum ZKCommonCredentialRootPersonaMode: CaseIterable, Hashable, Sendable {
  case privatePersona
  case publicPersona

  var protoPersonaMode: Reallyme_Zk_V1_ZkCommonCredentialRootPersonaMode {
    switch self {
    case .privatePersona: .privatePersonaV1
    case .publicPersona: .publicPersonaV1
    }
  }

  init?(protoPersonaMode: Reallyme_Zk_V1_ZkCommonCredentialRootPersonaMode) {
    switch protoPersonaMode {
    case .privatePersonaV1: self = .privatePersona
    case .publicPersonaV1: self = .publicPersona
    case .unspecified, .UNRECOGNIZED: return nil
    }
  }
}

// The order is part of the common-credential-root v1 proof contract.
let commonCredentialRootProofSlots: [Reallyme_Zk_V1_ZkCommonCredentialRootProofSlot] = [
  .rootAttestation, .rootStatus, .lineage0, .lineage1,
  .selectedClaim0, .selectedClaim1, .session,
  .issuerCredentialStatus0, .issuerCredentialStatus1,
]

private func commonCredentialRootBindingMatches(
  _ lhs: Reallyme_Zk_V1_ZkSessionBinding,
  _ rhs: Reallyme_Zk_V1_ZkSessionBinding
) -> Bool {
  lhs.nonceHash == rhs.nonceHash
    && lhs.audienceHash == rhs.audienceHash
    && lhs.transactionDataHash == rhs.transactionDataHash
}

/// The policy is supplied by the verifier from its active request and trust
/// state. It must not be reconstructed from fields in the holder's proof.
public struct ReallyMeZKCommonCredentialRootVerifyRequest: CustomStringConvertible,
  CustomDebugStringConvertible, Sendable
{
  public let mode: ZKCommonCredentialRootPersonaMode
  public let presentation: Reallyme_Zk_V1_ZkCommonCredentialRootPresentation
  public let policy: Reallyme_Zk_V1_ZkCommonCredentialRootJoinPolicy

  public var description: String {
    "ReallyMeZKCommonCredentialRootVerifyRequest(mode: \(mode), presentation: <redacted>, policy: <redacted>)"
  }

  public var debugDescription: String { description }

  public init(
    mode: ZKCommonCredentialRootPersonaMode,
    presentation: Reallyme_Zk_V1_ZkCommonCredentialRootPresentation,
    policy: Reallyme_Zk_V1_ZkCommonCredentialRootJoinPolicy
  ) throws(ReallyMeZKError) {
    guard presentation.personaMode == mode.protoPersonaMode,
      presentation.credentialHashAlgorithm == .sha256
        || presentation.credentialHashAlgorithm == .poseidon2,
      presentation.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa,
      presentation.proofs.count == commonCredentialRootProofSlots.count,
      presentation.proofs.map(\.slot) == commonCredentialRootProofSlots,
      presentation.proofs.allSatisfy({ proof in
        proof.personaMode == presentation.personaMode
          && proof.publicInputs.personaMode == presentation.personaMode
          && proof.publicInputs.slot == proof.slot
          && proof.publicInputs.circuitRef == proof.circuitRef
          && proof.circuitRef.credentialHashAlgorithm == presentation.credentialHashAlgorithm
          && proof.circuitRef.circuitRevision == 1 && proof.proofSuite == presentation.proofSuite
          && commonCredentialRootArtifactIdentityIsValid(proof) && proof.proof.isEmpty == false
          && proof.proof.count <= commonCredentialRootMaxProofBytes
          && proof.publicInputs.rawFields.isEmpty == false
          && proof.publicInputs.rawFields.count <= commonCredentialRootMaxRawPublicInputBytes
      }),
      policy.challenge.count == 32,
      policy.audienceHash.count == 32,
      policy.transactionDataHash.count == 32,
      policy.assurancePolicyID.count == 32,
      policy.statusRoot.count == 32,
      policy.attestationSigner.x.count == 32,
      policy.attestationSigner.y.count == 32,
      policy.requestTimeUnix > 0,
      policy.claims.count == 2,
      policy.issuerStatus.count == 2,
      presentation.sessionBinding.nonceHash == policy.challenge,
      presentation.sessionBinding.audienceHash == policy.audienceHash,
      presentation.sessionBinding.transactionDataHash == policy.transactionDataHash
    else {
      throw ReallyMeZKError.providerRejected(.proofRejected)
    }
    for claim in policy.claims {
      guard claim.issuer.x.count == 32,
        claim.issuer.y.count == 32,
        claim.claimNameHash.count == 32,
        claim.claimValue.isEmpty == false,
        claim.claimValue.count <= 64,
        claim.claimValueLength == UInt32(claim.claimValue.count)
      else {
        throw ReallyMeZKError.providerRejected(.proofRejected)
      }
    }
    for status in policy.issuerStatus {
      guard status.root.count == 32,
        status.length > 0,
        status.listID.count == 32,
        status.urlHash.count == 32,
        status.purpose == .revocation || status.purpose == .suspension
      else {
        throw ReallyMeZKError.providerRejected(.proofRejected)
      }
    }
    self.mode = mode
    self.presentation = presentation
    self.policy = policy
  }
}

/// Complete common-credential-root presentation proving request. The nine typed stage
/// inputs remain inside the native provider; Swift receives only the final
/// presentation proof package.
public struct ReallyMeZKCommonCredentialRootPresentationProveRequest: CustomStringConvertible,
  CustomDebugStringConvertible, Sendable
{
  private static let maximumCanonicalRequestBytes = 10 * 1_024 * 1_024

  public let personaMode: Reallyme_Zk_V1_ZkCommonCredentialRootPersonaMode
  public let proofSuite: Reallyme_Zk_V1_ZkProofSuite
  public let expectedBinding: Reallyme_Zk_V1_ZkSessionBinding
  private let canonicalRequest = CommonCredentialRootCanonicalRequestOwner()

  public var description: String {
    "ReallyMeZKCommonCredentialRootPresentationProveRequest(input: <redacted>)"
  }
  public var debugDescription: String { description }

  public init(
    operation: Reallyme_Zk_V1_ZkCommonCredentialRootPresentationProveOperation
  ) throws(ReallyMeZKError) {
    let mode = ZKCommonCredentialRootPersonaMode(protoPersonaMode: operation.personaMode)
    guard mode != nil,
      operation.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa,
      operation.hasExpectedBinding,
      operation.expectedBinding.nonceHash.count == 32,
      operation.expectedBinding.audienceHash.count == 32,
      operation.expectedBinding.transactionDataHash.count == 32,
      operation.hasRootAttestation,
      operation.hasRootStatus,
      operation.hasLineage0,
      operation.hasLineage1,
      operation.hasSelectedClaim0,
      operation.hasSelectedClaim1,
      operation.hasSession,
      operation.hasIssuerCredentialStatus0,
      operation.hasIssuerCredentialStatus1
    else {
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
    let stages = [
      operation.rootAttestation, operation.rootStatus, operation.lineage0, operation.lineage1,
      operation.selectedClaim0, operation.selectedClaim1, operation.session,
      operation.issuerCredentialStatus0, operation.issuerCredentialStatus1,
    ]
    for (index, stage) in stages.enumerated() {
      guard stage.personaMode == operation.personaMode,
        stage.slot == commonCredentialRootProofSlots[index],
        stage.proofSuite == operation.proofSuite,
        commonCredentialRootBindingMatches(stage.expectedBinding, operation.expectedBinding)
      else {
        throw ReallyMeZKError.providerRejected(.malformedWitness)
      }
      _ = try ReallyMeZKCommonCredentialRootStageProveRequest(operation: stage)
    }
    self.personaMode = operation.personaMode
    self.proofSuite = operation.proofSuite
    self.expectedBinding = operation.expectedBinding
  }

  /// Accepts the exact Buffa-canonical request bytes for one native dispatch.
  /// The native boundary performs the final canonical admission check.
  public init(canonicalRequestBytes: Data) throws(ReallyMeZKError) {
    let providerRequest = try parseCommonCredentialRootCanonicalRequest(
      canonicalRequestBytes, maximumBytes: Self.maximumCanonicalRequestBytes
    )
    guard case .proveCommonCredentialRootPresentation(let operation)? = providerRequest.operation
    else {
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
    try self.init(operation: operation)
    canonicalRequest.store(canonicalRequestBytes)
  }

  public func close() {
    canonicalRequest.close()
  }

  func takeCanonicalRequestBytes() throws(ReallyMeZKError) -> Data {
    try canonicalRequest.take()
  }
}

private let commonCredentialRootMaxProofBytes = 256 * 1_024
private let commonCredentialRootMaxRawPublicInputBytes = 418 * 32

/// One private common-credential-root stage request. The native provider destroys its
/// witness before returning the independently verified raw proof.
public final class ReallyMeZKCommonCredentialRootStageProveRequest: CustomStringConvertible,
  CustomDebugStringConvertible, Sendable
{
  private static let maximumCanonicalRequestBytes = 1_024 * 1_024

  public let personaMode: Reallyme_Zk_V1_ZkCommonCredentialRootPersonaMode
  public let slot: Reallyme_Zk_V1_ZkCommonCredentialRootProofSlot
  public let circuitRef: Reallyme_Zk_V1_ZkCircuitRef
  public let expectedBinding: Reallyme_Zk_V1_ZkSessionBinding
  private let canonicalRequest = CommonCredentialRootCanonicalRequestOwner()

  public var description: String {
    "ReallyMeZKCommonCredentialRootStageProveRequest(input: <redacted>)"
  }
  public var debugDescription: String { description }

  public init(
    operation: Reallyme_Zk_V1_ZkCommonCredentialRootStageProveOperation
  ) throws(ReallyMeZKError) {
    let mode = ZKCommonCredentialRootPersonaMode(protoPersonaMode: operation.personaMode)
    let expectedFamily: Reallyme_Zk_V1_ZkCircuitFamily
    let expectedStage: Reallyme_Zk_V1_ZkCircuitStage
    let validInput: Bool
    switch operation.slot {
    case .rootAttestation:
      expectedFamily = .commonCredentialRootV1
      expectedStage = .rootAttestation
      if case .rootAttestation? = operation.input { validInput = true } else { validInput = false }
    case .rootStatus:
      expectedFamily = .commonCredentialRootV1
      expectedStage = .rootStatus
      if case .rootStatus? = operation.input { validInput = true } else { validInput = false }
    case .lineage0, .lineage1:
      expectedFamily = .commonCredentialRootV1
      expectedStage = .lineage
      if case .lineage? = operation.input { validInput = true } else { validInput = false }
    case .selectedClaim0, .selectedClaim1:
      expectedFamily = .commonCredentialRootV1
      if mode == .privatePersona {
        expectedStage = .privatePersonaClaim
        if case .privatePersonaClaim? = operation.input {
          validInput = true
        } else {
          validInput = false
        }
      } else {
        expectedStage = .publicPersonaClaim
        if case .publicPersonaClaim? = operation.input {
          validInput = true
        } else {
          validInput = false
        }
      }
    case .session:
      if mode == .privatePersona {
        expectedFamily = .privatePersonaClaimV1
        expectedStage = .session
        if case .privatePersonaSession? = operation.input {
          validInput = true
        } else {
          validInput = false
        }
      } else {
        expectedFamily = .commonCredentialRootV1
        expectedStage = .publicSession
        if case .publicPersonaSession? = operation.input {
          validInput = true
        } else {
          validInput = false
        }
      }
    case .issuerCredentialStatus0, .issuerCredentialStatus1:
      expectedFamily = .commonCredentialRootV1
      expectedStage = .issuerCredentialStatus
      if case .issuerCredentialStatus? = operation.input {
        validInput = true
      } else {
        validInput = false
      }
    case .unspecified, .UNRECOGNIZED:
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
    let validCredentialHashAlgorithm =
      operation.circuitRef.credentialHashAlgorithm == .sha256
      || operation.circuitRef.credentialHashAlgorithm == .poseidon2
    guard mode != nil,
      validInput,
      operation.proofSuite == .barretenbergUltraHonkKeccakZkNoIpa,
      operation.hasCircuitRef,
      operation.circuitRef.family == expectedFamily,
      operation.circuitRef.stage == expectedStage,
      operation.circuitRef.circuitRevision == 1,
      validCredentialHashAlgorithm,
      operation.hasExpectedBinding,
      operation.expectedBinding.nonceHash.count == 32,
      operation.expectedBinding.audienceHash.count == 32,
      operation.expectedBinding.transactionDataHash.count == 32
    else {
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
    self.personaMode = operation.personaMode
    self.slot = operation.slot
    self.circuitRef = operation.circuitRef
    self.expectedBinding = operation.expectedBinding
  }

  /// Admits an encoded request for native canonical validation. The original
  /// bytes are dispatched once; SwiftProtobuf re-encoding can change Buffa's
  /// field order and must not be used for private stage inputs.
  public convenience init(canonicalRequestBytes: Data) throws(ReallyMeZKError) {
    let providerRequest = try parseCommonCredentialRootCanonicalRequest(
      canonicalRequestBytes, maximumBytes: Self.maximumCanonicalRequestBytes
    )
    guard case .proveCommonCredentialRootStage(let operation)? = providerRequest.operation else {
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
    try self.init(operation: operation)
    canonicalRequest.store(canonicalRequestBytes)
  }

  /// Destroys an unused encoded request, including cancellation before dispatch.
  public func close() {
    canonicalRequest.close()
  }

  func takeCanonicalRequestBytes() throws(ReallyMeZKError) -> Data {
    try canonicalRequest.take()
  }
}

private final class CommonCredentialRootCanonicalRequestOwner: Sendable {
  private let storage = Mutex<Data?>(nil)

  func store(_ bytes: Data) {
    storage.withLock { stored in
      stored = bytes
    }
  }

  func take() throws(ReallyMeZKError) -> Data {
    let bytes = storage.withLock { stored -> Data? in
      defer { stored = nil }
      return stored
    }
    guard let bytes else {
      throw ReallyMeZKError.providerRejected(.unsupportedTransport)
    }
    return bytes
  }

  func close() {
    storage.withLock { stored in
      if var bytes = stored {
        stored = nil
        zeroizeCommonCredentialRootRequestBytes(&bytes)
      }
    }
  }

  deinit {
    close()
  }
}

private func parseCommonCredentialRootCanonicalRequest(
  _ bytes: Data,
  maximumBytes: Int
) throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkProviderOperationRequest {
  guard bytes.isEmpty == false, bytes.count <= maximumBytes else {
    throw ReallyMeZKError.providerRejected(bytes.isEmpty ? .emptyBuffer : .oversizedBuffer)
  }
  do {
    return try Reallyme_Zk_V1_ZkProviderOperationRequest(serializedBytes: bytes)
  } catch {
    throw ReallyMeZKError.providerRejected(.malformedWitness)
  }
}

private func zeroizeCommonCredentialRootRequestBytes(_ data: inout Data) {
  _ = data.withUnsafeMutableBytes { bytes in
    bytes.initializeMemory(as: UInt8.self, repeating: 0)
  }
  data.removeAll(keepingCapacity: false)
}

public struct ReallyMeZKCommonCredentialRootStageProof: CustomStringConvertible,
  CustomDebugStringConvertible, Sendable
{
  public let package: Reallyme_Zk_V1_ZkCommonCredentialRootRawProofPackage

  public var description: String { "ReallyMeZKCommonCredentialRootStageProof(package: <redacted>)" }
  public var debugDescription: String { description }

  init(package: Reallyme_Zk_V1_ZkCommonCredentialRootRawProofPackage) {
    self.package = package
  }
}

public struct ReallyMeZKCommonCredentialRootPresentationProof: CustomStringConvertible,
  CustomDebugStringConvertible, Sendable
{
  public let presentation: Reallyme_Zk_V1_ZkCommonCredentialRootPresentation

  public var description: String {
    "ReallyMeZKCommonCredentialRootPresentationProof(presentation: <redacted>)"
  }
  public var debugDescription: String { description }

  init(presentation: Reallyme_Zk_V1_ZkCommonCredentialRootPresentation) {
    self.presentation = presentation
  }
}

public struct ReallyMeZKVerifiedCommonCredentialRoot: CustomStringConvertible,
  CustomDebugStringConvertible, Sendable
{
  public let mode: ZKCommonCredentialRootPersonaMode
  public let verifiedProofCount: Int

  public var description: String {
    "ReallyMeZKVerifiedCommonCredentialRoot(mode: \(mode), verifiedProofCount: \(verifiedProofCount))"
  }

  public var debugDescription: String { description }

  init(mode: ZKCommonCredentialRootPersonaMode, verifiedProofCount: Int) {
    self.mode = mode
    self.verifiedProofCount = verifiedProofCount
  }
}

/// Preserve which identity construction the native verifier must resolve.
func commonCredentialRootArtifactIdentityIsValid(
  _ proof: Reallyme_Zk_V1_ZkCommonCredentialRootRawProofPackage
) -> Bool {
  switch proof.artifactIdentity {
  case .artifactManifestSha256(let digest):
    digest.value.count == 32 && digest.value.contains(where: { $0 != 0 })
  case .artifactSetIdentitySha256(let identity):
    identity.value.count == 32 && identity.value.contains(where: { $0 != 0 })
  case nil:
    false
  }
}
