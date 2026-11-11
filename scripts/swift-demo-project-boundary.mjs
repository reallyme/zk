// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

export const SWIFT_DEMO_PROJECT_PATH =
  "packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo.xcodeproj/project.pbxproj";

const SIGNING_SETTINGS = [
  "DEVELOPMENT_TEAM",
  "CODE_SIGN_IDENTITY",
  "PROVISIONING_PROFILE",
];

function firstMatch(source, expression) {
  return expression.exec(source);
}

export function validateSwiftDemoBundleProjectBoundarySource(
  source,
  projectPath = SWIFT_DEMO_PROJECT_PATH,
) {
  for (const forbidden of SIGNING_SETTINGS) {
    if (source.includes(forbidden)) {
      return `${projectPath} contains checked-in ${forbidden}`;
    }
  }

  const productDependency = firstMatch(
    source,
    /([0-9A-F]+) \/\* ReallyMeZKDemoBundle \*\/ = \{\s*isa = XCSwiftPackageProductDependency;\s*package = ([0-9A-F]+) \/\* XCLocalSwiftPackageReference "\.\.\/\.\.\/\.\.\/\.\." \*\/;\s*productName = ReallyMeZKDemoBundle;\s*\};/u,
  );
  if (productDependency === null) {
    return `${projectPath} does not declare ReallyMeZKDemoBundle product dependency`;
  }
  const bundleProductId = productDependency[1];
  const packageReference = firstMatch(
    source,
    /([0-9A-F]+) \/\* XCLocalSwiftPackageReference "\.\.\/\.\.\/\.\.\/\.\." \*\/ = \{\s*isa = XCLocalSwiftPackageReference;\s*relativePath = \.\.\/\.\.\/\.\.\/\.\.;\s*\};/u,
  );
  if (packageReference === null || packageReference[1] !== productDependency[2]) {
    return `${projectPath} does not link ReallyMeZKDemoBundle to the local package`;
  }

  const frameworkEntry = firstMatch(
    source,
    /([0-9A-F]+) \/\* ReallyMeZKDemoBundle in Frameworks \*\/ = \{[^\n]+\};/u,
  );
  if (
    frameworkEntry === null ||
    !frameworkEntry[0].includes(`productRef = ${bundleProductId} /* ReallyMeZKDemoBundle */;`)
  ) {
    return `${projectPath} does not link the ReallyMeZKDemoBundle product`;
  }

  const embedEntry = firstMatch(
    source,
    /([0-9A-F]+) \/\* ReallyMeZKDemoBundle in Embed Frameworks \*\/ = \{[^\n]+\};/u,
  );
  if (
    embedEntry === null ||
    !embedEntry[0].includes(`productRef = ${bundleProductId} /* ReallyMeZKDemoBundle */;`) ||
    !embedEntry[0].includes("CodeSignOnCopy")
  ) {
    return `${projectPath} does not embed and sign the ReallyMeZKDemoBundle product`;
  }
  const embedBuildFileId = embedEntry[1];

  const appTarget = firstMatch(
    source,
    /([0-9A-F]+) \/\* ReallyMeZKDemo \*\/ = \{[\s\S]*?isa = PBXNativeTarget;([\s\S]*?productType = "com\.apple\.product-type\.application";[\s\S]*?)\n\t\t\};/u,
  );
  if (appTarget === null) {
    return `${projectPath} does not declare the ReallyMeZKDemo app target`;
  }
  const appBuildPhases = firstMatch(appTarget[2], /buildPhases = \(([\s\S]*?)\);/u);
  if (appBuildPhases === null) {
    return `${projectPath} does not declare app target build phases`;
  }

  const copyPhasePattern =
    /([0-9A-F]+) \/\* Embed Frameworks \*\/ = \{[\s\S]*?isa = PBXCopyFilesBuildPhase;([\s\S]*?)\n\t\t\};/gu;
  for (const copyPhase of source.matchAll(copyPhasePattern)) {
    const copyPhaseId = copyPhase[1];
    const copyPhaseBody = copyPhase[2];
    if (
      appBuildPhases[1].includes(`${copyPhaseId} /* Embed Frameworks */`) &&
      copyPhaseBody.includes(`${embedBuildFileId} /* ReallyMeZKDemoBundle in Embed Frameworks */`)
    ) {
      return null;
    }
  }

  return `${projectPath} does not embed ReallyMeZKDemoBundle in the app target`;
}
