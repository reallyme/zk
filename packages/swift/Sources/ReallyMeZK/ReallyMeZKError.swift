// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

public enum ZKProviderFailureReason: Equatable, Sendable {
  case unsupportedSuite
  case unsupportedCircuit
  case unsupportedTransport
  case crsMissing
  case crsHashMismatch
  case artifactMismatch
  case malformedWitness
  case malformedProof
  case proofRejected
  case emptyBuffer
  case oversizedBuffer
  case invalidTiming
  case arithmeticOverflow
  case internalFailure
}

public enum ReallyMeZKError: Error, Equatable, Sendable {
  case providerUnavailable
  case alreadyRunning
  case operationCancelled
  case invalidProviderResponse(ZKProviderFailureReason)
  case providerRejected(ZKProviderFailureReason)
}

extension ReallyMeZKError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .providerUnavailable:
      return "ZK provider is unavailable."
    case .alreadyRunning:
      return "Another proof job is already running."
    case .operationCancelled:
      return "The proof job was cancelled."
    case .invalidProviderResponse:
      return "The ZK provider returned an invalid response."
    case .providerRejected:
      return "The ZK provider rejected the request."
    }
  }
}
