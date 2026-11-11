// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeZKKit

enum Subject: String, CaseIterable, Identifiable {
  case claim = "Claim"
  case persona = "Persona"
  case commonCredentialRoot = "Common credential root"

  var id: Self { self }
}

enum Timing: String, CaseIterable, Identifiable {
  case now = "For this request"
  case prepared = "Prepare ahead"

  var id: Self { self }
}

enum ProofFlowCopy {
  // One proving worker keeps the example's memory use predictable on phones.
  static let proofThreadCount = 1

  static func title(
    subject: Subject, personaMode: ZKCommonCredentialRootPersonaMode, timing: Timing
  ) -> String {
    switch subject {
    case .claim: return "Credential subject claim"
    case .commonCredentialRoot:
      return personaMode == .privatePersona
        ? "Common credential root · private persona" : "Common credential root · public persona"
    case .persona:
      let visibility = personaMode == .privatePersona ? "Private" : "Public"
      let timingLabel =
        personaMode == .publicPersona || timing == .prepared
        ? "prepared" : "request-bound"
      return "\(visibility) persona · \(timingLabel)"
    }
  }

  static func description(
    subject: Subject, personaMode: ZKCommonCredentialRootPersonaMode, timing: Timing
  ) -> String {
    switch subject {
    case .claim:
      return "Prove a claim for this request without presenting a persona."
    case .commonCredentialRoot:
      let visibility =
        personaMode == .privatePersona
        ? "The presenting persona stays hidden."
        : "The presenting persona is public and linkable."
      return
        "Prove that two issuer credentials share one assured root. \(visibility) This sample generates and verifies nine request-bound proofs."
    case .persona where timing == .now && personaMode == .privatePersona:
      return "Generate a fresh proof while keeping the persona hidden."
    case .persona:
      return personaMode == .privatePersona
        ? "Prepare a private proof sample, then check it once without new proving. The fixed sample key is not a one-time token stock."
        : "Prepare public proof stages once and recheck the same sample proofs. The sample does not fetch current issuer status or sign a live request."
    }
  }

  static func safeErrorDetail(for error: Error) -> String {
    guard let proofError = error as? ProofSampleError else {
      return "The proof request failed before provider admission."
    }
    switch proofError {
    case .providerUnavailable:
      return "The ZK provider is unavailable."
    case .artifactMismatch:
      return "The bundled ZK artifacts do not match this provider."
    case .operationCancelled:
      return "The proof job was cancelled."
    case .alreadyRunning:
      return "Another proof job is already running."
    case .proofRejected:
      return "The generated proof was rejected."
    case .malformedFixture:
      return "The demo fixture is malformed."
    case .invalidOptions:
      return "The proof options are not supported by this demo profile."
    case .internalFailure:
      return "The proof provider failed."
    }
  }

  static func safeErrorStatus(for error: Error) -> String {
    guard let proofError = error as? ProofSampleError else {
      return "request rejected."
    }
    switch proofError {
    case .providerUnavailable:
      return "provider unavailable."
    case .artifactMismatch:
      return "artifact mismatch."
    case .operationCancelled:
      return "cancelled."
    case .alreadyRunning:
      return "already running."
    case .proofRejected:
      return "proof rejected."
    case .malformedFixture:
      return "malformed fixture."
    case .invalidOptions:
      return "invalid options."
    case .internalFailure:
      return "provider failure."
    }
  }
}
