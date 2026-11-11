// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKKit
import ReallyMeZKPlatformNative

struct DemoNativeContext: Sendable {
  let transport: ReallyMeZKPlatformTransport
  let contextHandle: UInt64

  private let context: ReallyMeZKPlatformContext

  init(bundle: Bundle) throws(ProofSampleError) {
    guard let resourceRoot = bundle.url(forResource: "zk_demo", withExtension: nil) else {
      throw ProofSampleError.providerUnavailable
    }
    let artifactRoot = resourceRoot.appendingPathComponent("artifacts", isDirectory: true)
    let indexURL = resourceRoot.appendingPathComponent("release-index.pb")
    let g1URL = resourceRoot.appendingPathComponent("crs/bn254_g1.prover")
    let g2URL = resourceRoot.appendingPathComponent("crs/bn254_g2")

    let approvedIndexDigest = try checkedHexDigest(approvedReleaseIndexSha256)
    do {
      let nativeContext = try ReallyMeZKPlatformContext(
        artifactRoot: artifactRoot,
        releaseIndexURL: indexURL,
        approvedReleaseIndexSHA256: approvedIndexDigest,
        crsG1URL: g1URL,
        crsG2URL: g2URL,
        crsMode: .fullProver
      )
      self.context = nativeContext
      self.contextHandle = nativeContext.contextHandle
      self.transport = nativeContext.transport
    } catch ReallyMeZKError.providerRejected(.artifactMismatch) {
      throw ProofSampleError.artifactMismatch
    } catch {
      throw ProofSampleError.providerUnavailable
    }
  }

  func close() async throws(ReallyMeZKError) {
    try await context.close()
  }
}

private func checkedHexDigest(_ value: String) throws(ProofSampleError) -> Data {
  guard value.count == 64 else {
    throw ProofSampleError.providerUnavailable
  }
  var bytes = Data()
  bytes.reserveCapacity(32)
  var index = value.startIndex
  while index < value.endIndex {
    let next = value.index(index, offsetBy: 2)
    guard let byte = UInt8(value[index..<next], radix: 16) else {
      throw ProofSampleError.providerUnavailable
    }
    bytes.append(byte)
    index = next
  }
  return bytes
}

private let approvedReleaseIndexSha256 =
  "9260afdb9a3a0133a679af141a310b6aacbf2e814724692ca964d2711ae49ce7"
