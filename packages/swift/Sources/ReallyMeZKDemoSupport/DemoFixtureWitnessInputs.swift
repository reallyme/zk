// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import ReallyMeZKKit
import ReallyMeZkProtoGenerated

/// Loads reviewed synthetic sample fixtures as canonical protobuf witness
/// inputs for demo apps. Production integrations should construct
/// `ZkStageWitnessInput` directly at their trusted boundary.
public enum ReallyMeZKDemoFixtureWitnessInputs {
  public static func fixtureResourceName(
    bundleKind: ZKClaimProofBundleKind,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm = .sha256,
    stage: ZKClaimProofBundleStage
  ) throws(ReallyMeZKError) -> String {
    "\(credentialHashAlgorithm.rawValue)_\(try bundleKindName(bundleKind))_\(try stageName(stage))_inputs"
  }

  public static func witnessInput(
    bundleKind: ZKClaimProofBundleKind,
    stage: ZKClaimProofBundleStage,
    protobufData: Data
  ) throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkStageWitnessInput {
    guard protobufData.isEmpty == false,
      protobufData.count <= maximumFixtureProtobufBytes
    else {
      throw malformedWitness()
    }
    let input: Reallyme_Zk_V1_ZkStageWitnessInput
    do {
      input = try Reallyme_Zk_V1_ZkStageWitnessInput(serializedBytes: protobufData)
    } catch {
      throw malformedWitness()
    }
    try validate(input: input, bundleKind: bundleKind, stage: stage)
    return input
  }

  public static func witnessInput(
    bundleKind: ZKClaimProofBundleKind,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm = .sha256,
    stage: ZKClaimProofBundleStage,
    bundle: Bundle
  ) throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkStageWitnessInput {
    let resourceName = try fixtureResourceName(
      bundleKind: bundleKind,
      credentialHashAlgorithm: credentialHashAlgorithm,
      stage: stage
    )
    // Xcode synchronized resources are copied into the app bundle root.
    guard let url = bundle.url(forResource: resourceName, withExtension: "pb") else {
      throw malformedWitness()
    }
    let data: Data
    do {
      data = try Data(contentsOf: url, options: [.mappedIfSafe])
    } catch {
      throw malformedWitness()
    }
    try validatePinnedFixture(resourceName: resourceName, data: data, bundle: bundle)
    return try witnessInput(bundleKind: bundleKind, stage: stage, protobufData: data)
  }

  public static func sessionBinding(
    input: Reallyme_Zk_V1_ZkStageWitnessInput
  ) throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkSessionBinding {
    let context = try sessionContext(input: input)
    try validateBytes32(context.challenge.value)
    try validateBytes32(context.audienceHash.value)
    try validateBytes32(context.transactionDataHash.value)
    var binding = Reallyme_Zk_V1_ZkSessionBinding()
    binding.nonceHash = context.challenge.value
    binding.audienceHash = context.audienceHash.value
    binding.transactionDataHash = context.transactionDataHash.value
    return binding
  }

  public static func issuer(
    input: Reallyme_Zk_V1_ZkStageWitnessInput
  ) throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkP256PublicKey {
    let context = try issuerContext(input: input)
    try validateBytes32(context.issuerPublicKey.x.value)
    try validateBytes32(context.issuerPublicKey.y.value)
    var issuer = Reallyme_Zk_V1_ZkP256PublicKey()
    issuer.x = context.issuerPublicKey.x.value
    issuer.y = context.issuerPublicKey.y.value
    return issuer
  }
}

private func validatePinnedFixture(
  resourceName: String,
  data: Data,
  bundle: Bundle
) throws(ReallyMeZKError) {
  guard let manifestURL = bundle.url(forResource: "SHA256SUMS", withExtension: nil) else {
    throw malformedWitness()
  }
  let manifest: String
  do {
    manifest = try String(contentsOf: manifestURL, encoding: .utf8)
  } catch {
    throw malformedWitness()
  }
  let fileName = "\(resourceName).pb"
  guard let pin = fixturePin(fileName: fileName, manifest: manifest),
    pin.byteCount == data.count,
    pin.sha256 == hexSHA256(data)
  else {
    throw malformedWitness()
  }
}

private func fixturePin(
  fileName: String,
  manifest: String
) -> (sha256: String, byteCount: Int)? {
  for line in manifest.split(separator: "\n", omittingEmptySubsequences: true) {
    let fields = line.split(separator: " ", omittingEmptySubsequences: true)
    guard fields.count == 3 else {
      return nil
    }
    if fields[0] == "sha256" && fields[1] == "bytes" && fields[2] == "file" {
      continue
    }
    guard fields[2] == fileName,
      fields[0].count == sha256HexLength,
      let byteCount = Int(fields[1])
    else {
      continue
    }
    return (String(fields[0]), byteCount)
  }
  return nil
}

private func hexSHA256(_ data: Data) -> String {
  SHA256.hash(data: data).reduce(into: String()) { output, byte in
    output.append(hexAlphabet[Int(byte >> 4)])
    output.append(hexAlphabet[Int(byte & 0x0f)])
  }
}

private func validate(
  input: Reallyme_Zk_V1_ZkStageWitnessInput,
  bundleKind: ZKClaimProofBundleKind,
  stage: ZKClaimProofBundleStage
) throws(ReallyMeZKError) {
  switch (bundleKind, stage, input.input) {
  case (.credentialSubjectClaim, .session, .credentialSubjectClaimSession?),
    (.privatePersona, .session, .privatePersonaSession?),
    (_, .credentialEnvelope, .credentialEnvelope?),
    (_, .credentialRoot, .credentialRoot?),
    (.credentialSubjectClaim, .claim, .credentialSubjectClaim?),
    (.privatePersona, .claim, .privatePersonaClaim?):
    return
  default:
    throw malformedWitness()
  }
}

private func sessionContext(
  input: Reallyme_Zk_V1_ZkStageWitnessInput
) throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkInputSessionContext {
  switch input.input {
  case .credentialSubjectClaimSession(let stageInput):
    return stageInput.sessionContext
  case .privatePersonaSession(let stageInput):
    return stageInput.sessionContext
  case .credentialEnvelope, .credentialRoot, .credentialSubjectClaim, .privatePersonaClaim, .none:
    throw malformedWitness()
  }
}

private func issuerContext(
  input: Reallyme_Zk_V1_ZkStageWitnessInput
) throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkInputIssuerContext {
  switch input.input {
  case .credentialEnvelope(let stageInput):
    return stageInput.issuerContext
  case .credentialRoot(let stageInput):
    return stageInput.issuerContext
  case .credentialSubjectClaim(let stageInput):
    return stageInput.issuerContext
  case .privatePersonaClaim(let stageInput):
    return stageInput.issuerContext
  case .credentialSubjectClaimSession, .privatePersonaSession, .none:
    throw malformedWitness()
  }
}

private func validateBytes32(_ data: Data) throws(ReallyMeZKError) {
  guard data.count == digestBytes else {
    throw malformedWitness()
  }
}

private func bundleKindName(_ bundleKind: ZKClaimProofBundleKind) throws(ReallyMeZKError) -> String {
  switch bundleKind {
  case .credentialSubjectClaim:
    return "flow_credential_subject_claim_v1"
  case .privatePersona:
    return "flow_private_persona_claim_v1"
  default:
    throw malformedWitness()
  }
}

private func stageName(_ stage: ZKClaimProofBundleStage) throws(ReallyMeZKError) -> String {
  switch stage {
  case .session:
    return "session"
  case .credentialEnvelope:
    return "credential_envelope"
  case .credentialRoot:
    return "credential_root"
  case .claim:
    return "claim"
  default:
    throw malformedWitness()
  }
}

private func malformedWitness() -> ReallyMeZKError {
  ReallyMeZKError.providerRejected(.malformedWitness)
}

private let maximumFixtureProtobufBytes = 16 * 1024
private let digestBytes = 32
private let sha256HexLength = 64
private let hexAlphabet = Array("0123456789abcdef")
