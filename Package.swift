// swift-tools-version: 6.4
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import PackageDescription

let ffiArtifactChecksum = "da09e0d12c29c9173867374a74af93edf7ce1c16037e34ca6efd43aa9a42471b"
let ffiArtifactVersion = "0.3.0"
let ffiArtifactLocalPathOverride = ""

let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let defaultPlatformFFIRelativePath =
  "release-artifacts/modern-v1-bb-6.0.0/apple-platform-ffi/ReallyMeZKPlatformFFI.xcframework"
let platformFFIRelativePath =
  ffiArtifactLocalPathOverride.isEmpty
  ? defaultPlatformFFIRelativePath : ffiArtifactLocalPathOverride
let platformFFILocalPath = "\(packageRoot)/\(platformFFIRelativePath)"
let platformFFITarget: Target =
  if FileManager.default.fileExists(atPath: platformFFILocalPath) {
    .binaryTarget(
      name: "ReallyMeZKPlatformFFI",
      path: platformFFIRelativePath
    )
  } else {
    .binaryTarget(
      name: "ReallyMeZKPlatformFFI",
      url:
        "https://static.reallyme.net/zk/swift/\(ffiArtifactChecksum)/ReallyMeZKPlatformFFI.xcframework.zip",
      checksum: ffiArtifactChecksum
    )
  }

let package = Package(
  name: "ReallyMeZKKit",
  platforms: [
    .iOS(.v18),
    .macOS(.v27),
  ],
  products: [
    .library(
      name: "ReallyMeZKKit",
      targets: ["ReallyMeZKKit"]
    ),
    .library(
      name: "ReallyMeZKPlatformNative",
      targets: ["ReallyMeZKPlatformNative"]
    ),
    .library(
      name: "ReallyMeZKDemoSupport",
      targets: ["ReallyMeZKDemoSupport"]
    ),
    .library(
      name: "ReallyMeZKDemoBundle",
      type: .dynamic,
      targets: ["ReallyMeZKKit", "ReallyMeZKPlatformNative", "ReallyMeZKDemoSupport"]
    ),
  ],
  dependencies: [
    .package(
      url: "https://github.com/apple/swift-protobuf.git",
      exact: "1.39.0"
    )
  ],
  targets: [
    .target(
      name: "ReallyMeZkProtoGenerated",
      dependencies: [
        .product(name: "SwiftProtobuf", package: "swift-protobuf")
      ],
      path: "packages/swift/Sources/Generated/ReallyMeZkProtoGenerated"
    ),
    .target(
      name: "ReallyMeZKProtoCodec",
      dependencies: ["ReallyMeZkProtoGenerated"],
      path: "packages/swift/Sources/ReallyMeZKProtoCodec",
      swiftSettings: [
        .enableUpcomingFeature("StrictConcurrency")
      ]
    ),
    .target(
      name: "ReallyMeZKKit",
      dependencies: ["ReallyMeZKProtoCodec", "ReallyMeZkProtoGenerated"],
      path: "packages/swift/Sources/ReallyMeZK",
      swiftSettings: [
        .enableUpcomingFeature("StrictConcurrency")
      ]
    ),
    .target(
      name: "ReallyMeZKPlatformNative",
      dependencies: ["ReallyMeZKKit", "ReallyMeZKPlatformFFI"],
      path: "packages/swift/Sources/ReallyMeZKPlatformNative",
      swiftSettings: [
        .enableUpcomingFeature("StrictConcurrency")
      ]
    ),
    .target(
      name: "ReallyMeZKDemoSupport",
      dependencies: ["ReallyMeZKKit", "ReallyMeZkProtoGenerated"],
      path: "packages/swift/Sources/ReallyMeZKDemoSupport",
      swiftSettings: [
        .enableUpcomingFeature("StrictConcurrency")
      ]
    ),
    .testTarget(
      name: "ReallyMeZKTests",
      dependencies: [
        "ReallyMeZKKit",
        "ReallyMeZKDemoSupport",
        "ReallyMeZKProtoCodec",
        "ReallyMeZkProtoGenerated",
      ],
      path: "packages/swift/Tests/ReallyMeZKTests",
      swiftSettings: [
        .enableUpcomingFeature("StrictConcurrency")
      ]
    ),
    platformFFITarget,
  ]
)
