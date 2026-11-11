// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZkProtoGenerated
import Testing

@Suite
struct ReallyMeZKCanonicalFixtureTests {
  @Test
  func commonRootRequestsRetainTheNativeCanonicalEncoding() throws {
    let root = repositoryRoot()
    for directory in [
      "vectors/common-credential-root-mobile-fixtures-v1",
      "vectors/common-credential-root-stage-requests-v1",
    ] {
      let urls = try FileManager.default.contentsOfDirectory(
        at: root.appendingPathComponent(directory), includingPropertiesForKeys: nil
      ).filter { $0.pathExtension == "pb" }
      #expect(urls.isEmpty == false)
      for url in urls {
        var bytes = try Data(contentsOf: url)
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        let request = try Reallyme_Zk_V1_ZkProviderOperationRequest(serializedBytes: bytes)
        var encoded = try request.serializedData()
        defer { encoded.resetBytes(in: 0..<encoded.count) }
        #expect(encoded == bytes, "Canonical field order differs for \(url.lastPathComponent)")
      }
    }
  }

  private func repositoryRoot() -> URL {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<5 { root.deleteLastPathComponent() }
    return root
  }
}
