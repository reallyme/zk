// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZkProtoGenerated
import Synchronization

/// Owns one canonical, secret-bearing persona-credential-evidence request until native dispatch.
/// The caller must clear any source buffer after constructing this owner.
public final class ReallyMeZKPersonaCredentialEvidenceStageProveRequest: Sendable {
  private static let maximumRequestBytes = 1_024 * 1_024
  private let storage: Mutex<Data?>
  public let mode: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceMode
  public let circuitRef: Reallyme_Zk_V1_ZkCircuitRef

  public init(
    canonicalRequestBytes: Data,
    mode: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceMode,
    circuitRef: Reallyme_Zk_V1_ZkCircuitRef
  ) throws(ReallyMeZKError) {
    guard canonicalRequestBytes.isEmpty == false,
      canonicalRequestBytes.count <= Self.maximumRequestBytes
    else {
      throw ReallyMeZKError.providerRejected(
        canonicalRequestBytes.isEmpty ? .emptyBuffer : .oversizedBuffer)
    }
    guard mode == .publicPersonaV1 || mode == .privatePersonaOneTimeV1,
      circuitRef.family == .personaCredentialEvidenceV1,
      circuitRef.circuitRevision == 1,
      circuitRef.credentialHashAlgorithm == .sha256
        || circuitRef.credentialHashAlgorithm == .poseidon2,
      circuitRef.stage == .evidenceIssuerEnvelope
        || circuitRef.stage == .evidenceClaimRoot
        || circuitRef.stage == .evidenceSignedValidity
        || circuitRef.stage == .evidenceCurrentState
        || mode == .publicPersonaV1 && circuitRef.stage == .evidencePublicClaim
        || mode == .privatePersonaOneTimeV1 && circuitRef.stage == .evidencePrivateClaim
    else {
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
    self.mode = mode
    self.circuitRef = circuitRef
    self.storage = Mutex(canonicalRequestBytes)
  }

  public func close() {
    storage.withLock { stored in
      if var bytes = stored {
        stored = nil
        _ = bytes.withUnsafeMutableBytes { buffer in
          buffer.initializeMemory(as: UInt8.self, repeating: 0)
        }
        bytes.removeAll(keepingCapacity: false)
      }
    }
  }

  func takeCanonicalRequestBytes() throws(ReallyMeZKError) -> Data {
    let bytes = storage.withLock { stored -> Data? in
      defer { stored = nil }
      return stored
    }
    guard let bytes else {
      throw ReallyMeZKError.providerRejected(.unsupportedTransport)
    }
    return bytes
  }

  deinit {
    close()
  }
}
