// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKProtoCodec
import ReallyMeZkProtoGenerated

/// UI selection for a generated `ZkClaimProofBundleKind`.
///
/// The display names remain app-facing, but the identity carried into provider
/// requests is the protobuf enum generated from `crates/proto`.
public struct ZKClaimProofBundleKind: CaseIterable, Equatable, Hashable, Identifiable, Sendable {
  public static let credentialSubjectClaim = ZKClaimProofBundleKind(
    protoBundleKind: .credentialSubjectClaimV1,
    rawValue: "credential_subject_claim",
    displayName: "Credential subject claim"
  )
  public static let privatePersona = ZKClaimProofBundleKind(
    protoBundleKind: .privatePersonaClaimV1,
    rawValue: "private_persona",
    displayName: "Private Persona"
  )
  public static let allCases: [ZKClaimProofBundleKind] = [
    .credentialSubjectClaim,
    .privatePersona,
  ]

  public let protoBundleKind: Reallyme_Zk_V1_ZkClaimProofBundleKind
  public let rawValue: String
  public let displayName: String

  public var id: String { rawValue }

  private init(
    protoBundleKind: Reallyme_Zk_V1_ZkClaimProofBundleKind,
    rawValue: String,
    displayName: String
  ) {
    self.protoBundleKind = protoBundleKind
    self.rawValue = rawValue
    self.displayName = displayName
  }
}

/// UI selection for a generated `ZkClaimProofBundleStage`.
///
/// Stage labels preserve the existing demo flow while the stage value itself is
/// generated from the protobuf contract.
public struct ZKClaimProofBundleStage: CaseIterable, Equatable, Hashable, Sendable {
  public static let session = ZKClaimProofBundleStage(
    protoStage: .session,
    rawValue: "session",
    label: "session"
  )
  public static let credentialEnvelope = ZKClaimProofBundleStage(
    protoStage: .credentialEnvelope,
    rawValue: "credential_envelope",
    label: "credential envelope"
  )
  public static let credentialRoot = ZKClaimProofBundleStage(
    protoStage: .credentialRoot,
    rawValue: "credential_root",
    label: "credential root"
  )
  public static let claim = ZKClaimProofBundleStage(
    protoStage: .claim,
    rawValue: "claim",
    label: "claim"
  )

  public static let allCases: [ZKClaimProofBundleStage] = [
    .session,
    .credentialEnvelope,
    .credentialRoot,
    .claim,
  ]

  public let protoStage: Reallyme_Zk_V1_ZkClaimProofBundleStage
  public let rawValue: String
  public let label: String

  private init(
    protoStage: Reallyme_Zk_V1_ZkClaimProofBundleStage,
    rawValue: String,
    label: String
  ) {
    self.protoStage = protoStage
    self.rawValue = rawValue
    self.label = label
  }
}

public struct ZKCredentialHashAlgorithm: CaseIterable, Equatable, Hashable, Identifiable, Sendable {
  public static let sha256 = ZKCredentialHashAlgorithm(
    protoCredentialHashAlgorithm: .sha256,
    rawValue: "sha256",
    displayName: "SHA-256"
  )
  public static let poseidon2 = ZKCredentialHashAlgorithm(
    protoCredentialHashAlgorithm: .poseidon2,
    rawValue: "poseidon2",
    displayName: "Poseidon2"
  )

  public static let allCases: [ZKCredentialHashAlgorithm] = [.sha256, .poseidon2]

  public let protoCredentialHashAlgorithm: Reallyme_Zk_V1_ZkCredentialHashAlgorithm
  public let rawValue: String
  public let displayName: String

  public var id: String { rawValue }

  private init(
    protoCredentialHashAlgorithm: Reallyme_Zk_V1_ZkCredentialHashAlgorithm,
    rawValue: String,
    displayName: String
  ) {
    self.protoCredentialHashAlgorithm = protoCredentialHashAlgorithm
    self.rawValue = rawValue
    self.displayName = displayName
  }
}

public struct ZKStageRequest: CustomStringConvertible, CustomDebugStringConvertible, Equatable,
  Sendable
{
  public let bundleKind: ZKClaimProofBundleKind
  public let credentialHashAlgorithm: ZKCredentialHashAlgorithm
  public let stage: ZKClaimProofBundleStage
  public let witnessInput: Reallyme_Zk_V1_ZkStageWitnessInput

  public var description: String {
    "ZKStageRequest(bundleKind: \(bundleKind.rawValue), credentialHashAlgorithm: \(credentialHashAlgorithm.rawValue), stage: \(stage.rawValue), witnessInput: <redacted>)"
  }

  public var debugDescription: String {
    description
  }

  public init(
    bundleKind: ZKClaimProofBundleKind,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm = .sha256,
    stage: ZKClaimProofBundleStage,
    witnessInput: Reallyme_Zk_V1_ZkStageWitnessInput = Reallyme_Zk_V1_ZkStageWitnessInput()
  ) {
    self.bundleKind = bundleKind
    self.credentialHashAlgorithm = credentialHashAlgorithm
    self.stage = stage
    self.witnessInput = witnessInput
  }

  public func providerProveRequest() -> ReallyMeZKStageProveRequest {
    ReallyMeZKStageProveRequest(coordinate: coordinate)
  }

  public func providerWitnessRequest() -> ReallyMeZKWitnessRequest {
    ReallyMeZKWitnessRequest(coordinate: coordinate, input: witnessInput)
  }

  public func providerVerifyRequest(
    expectedSessionBinding: Reallyme_Zk_V1_ZkSessionBinding
  ) -> ReallyMeZKStageVerifyRequest {
    ReallyMeZKStageVerifyRequest(
      coordinate: coordinate,
      expectedSessionBinding: expectedSessionBinding
    )
  }

  private var coordinate: ReallyMeZKStageCoordinate {
    ReallyMeZKStageCoordinate(
      credentialHashAlgorithm: credentialHashAlgorithm.protoCredentialHashAlgorithm,
      family: bundleKind.circuitFamily,
      stage: stage.circuitStage,
      circuitRevision: 1,
      proofSuite: .barretenbergUltraHonkKeccakZkNoIpa
    )
  }
}

extension ZKClaimProofBundleKind {
  fileprivate var circuitFamily: Reallyme_Zk_V1_ZkCircuitFamily {
    switch protoBundleKind {
    case .credentialSubjectClaimV1:
      return .credentialSubjectClaimV1
    case .privatePersonaClaimV1:
      return .privatePersonaClaimV1
    case .unspecified, .UNRECOGNIZED:
      return .unspecified
    }
  }
}

extension ZKClaimProofBundleStage {
  fileprivate var circuitStage: Reallyme_Zk_V1_ZkCircuitStage {
    switch protoStage {
    case .session:
      return .session
    case .credentialEnvelope:
      return .credentialEnvelope
    case .credentialRoot:
      return .credentialRoot
    case .claim:
      return .claim
    case .unspecified, .UNRECOGNIZED:
      return .unspecified
    }
  }
}

public struct ZKWitnessByteCount: Equatable, Sendable {
  // Keep this aligned with the Rust API boundary. Current exact-source
  // claim_bundle_4 witnesses can exceed one MiB after Noir serialization.
  public static let maximum = 4 * 1_024 * 1_024

  public let value: Int

  public init(_ value: Int) throws(ReallyMeZKError) {
    self.value = try validateByteCount(value, maximum: Self.maximum)
  }
}

public struct ZKVerificationKeyByteCount: Equatable, Sendable {
  public static let maximum = 16_777_216

  public let value: Int

  public init(_ value: Int) throws(ReallyMeZKError) {
    self.value = try validateByteCount(value, maximum: Self.maximum)
  }
}

public struct ZKPublicInputByteCount: Equatable, Sendable {
  public static let maximum = 4 * 1_024

  public let value: Int

  public init(_ value: Int) throws(ReallyMeZKError) {
    self.value = try validateByteCount(value, maximum: Self.maximum)
  }
}

public struct ZKProofByteCount: Equatable, Sendable {
  public static let maximum = 256 * 1_024

  public let value: Int

  public init(_ value: Int) throws(ReallyMeZKError) {
    self.value = try validateByteCount(value, maximum: Self.maximum)
  }
}

public struct ZKBytecodeByteCount: Equatable, Sendable {
  public static let maximum = 67_108_864

  public let value: Int

  public init(_ value: Int) throws(ReallyMeZKError) {
    self.value = try validateByteCount(value, maximum: Self.maximum)
  }
}

private func validateByteCount(_ value: Int, maximum: Int) throws(ReallyMeZKError) -> Int {
  guard value > 0 else {
    throw ReallyMeZKError.invalidProviderResponse(.emptyBuffer)
  }
  guard value <= maximum else {
    throw ReallyMeZKError.invalidProviderResponse(.oversizedBuffer)
  }
  return value
}

public struct ZKWitnessMetrics: Equatable, Sendable {
  public let byteCount: ZKWitnessByteCount?

  public init(byteCount: ZKWitnessByteCount? = nil) {
    self.byteCount = byteCount
  }
}

public struct ZKProofMetrics: Equatable, Sendable {
  public let verificationKeyByteCount: ZKVerificationKeyByteCount?
  public let publicInputByteCount: ZKPublicInputByteCount
  public let proofByteCount: ZKProofByteCount

  public init(
    verificationKeyByteCount: ZKVerificationKeyByteCount? = nil,
    publicInputByteCount: ZKPublicInputByteCount,
    proofByteCount: ZKProofByteCount
  ) {
    self.verificationKeyByteCount = verificationKeyByteCount
    self.publicInputByteCount = publicInputByteCount
    self.proofByteCount = proofByteCount
  }
}

public struct ZKProviderWitnessResult<Handle: Sendable>: Sendable {
  public let handle: Handle
  public let metrics: ZKWitnessMetrics

  public init(handle: Handle, metrics: ZKWitnessMetrics) {
    self.handle = handle
    self.metrics = metrics
  }
}

public struct ZKProviderProofResult<Handle: Sendable>: Sendable {
  public let handle: Handle
  public let metrics: ZKProofMetrics

  public init(handle: Handle, metrics: ZKProofMetrics) {
    self.handle = handle
    self.metrics = metrics
  }
}

public struct ZKClaimProofBundleByteCount: Equatable, Sendable {
  public static let maximum = ZKProofByteCount.maximum * ZKClaimProofBundleStage.allCases.count

  public let value: Int

  public init(_ value: Int) throws(ReallyMeZKError) {
    self.value = try validateByteCount(value, maximum: Self.maximum)
  }
}

public struct ZKClaimProofBundleMetrics: Equatable, Sendable {
  public let stageCount: Int
  public let proofByteCount: ZKClaimProofBundleByteCount

  public init(
    stageCount: Int,
    proofByteCount: ZKClaimProofBundleByteCount
  ) {
    self.stageCount = stageCount
    self.proofByteCount = proofByteCount
  }
}

public struct ZKProviderClaimProofBundleResult<Handle: Sendable>: Sendable {
  public let handle: Handle
  public let metrics: ZKClaimProofBundleMetrics

  public init(handle: Handle, metrics: ZKClaimProofBundleMetrics) {
    self.handle = handle
    self.metrics = metrics
  }
}
