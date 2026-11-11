#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_dir="${root}/build/maven-central-upload"
version="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "${root}/packages/kotlin/build.gradle.kts")"
unsigned=false
if [[ "${1:-}" == "--unsigned" ]]; then
  unsigned=true
  shift
fi

fail() {
  printf 'Maven Central bundle failed: %s\n' "$1" >&2
  exit 1
}

[[ "$#" == 0 ]] || fail "usage: scripts/maven-central-bundle.local.sh [--unsigned]"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  fail "the Kotlin package must declare one release version"
command -v python3 >/dev/null || fail "python3 is required"

if [[ "$unsigned" == false ]]; then
  command -v gpg >/dev/null || fail "gpg is required for signing"
  [[ "${MAVEN_SIGNING_KEY_ID:-}" =~ ^([[:xdigit:]]{16}|[[:xdigit:]]{40}|[[:xdigit:]]{64})$ ]] ||
    fail "set MAVEN_SIGNING_KEY_ID to the GPG long key ID or fingerprint"
  [[ -n "${MAVEN_SIGNING_PASSWORD:-}" ]] || fail "load MAVEN_SIGNING_PASSWORD before signing"
fi

cd "$root"
mkdir -p "$work_dir"
stage="$(mktemp -d "${work_dir}/staging.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
bundle_root="${stage}/bundle-root"
prepared="${work_dir}/unsigned/${version}"

if [[ "$unsigned" == true ]]; then
  [[ ! -e "$prepared" && ! -L "$prepared" ]] || fail "move the previous unsigned staging directory before rebuilding"
  # Gradle can infer the pinned NDK from the installed SDK on macOS.
  if [[ -z "${ANDROID_HOME:-}" && -z "${ANDROID_SDK_ROOT:-}" && -d "${HOME}/Library/Android/sdk" ]]; then
    export ANDROID_HOME="${HOME}/Library/Android/sdk"
  fi
  scripts/check-android-platform-jni-freshness.sh
  env -u MAVEN_SIGNING_KEY_ID -u MAVEN_SIGNING_PASSWORD \
    packages/kotlin/gradlew --project-dir packages/kotlin --no-daemon \
    "-PreallymeZkCentralStaging=${stage}/repository" \
    publishKotlinProviderPublicationsToLocalReleaseArtifactsRepository
  python3 scripts/stage-maven-central-bundle.py "${stage}/repository" "$bundle_root" "$version"
  mkdir -p "$(dirname "$prepared")"
  mv "$bundle_root" "$prepared"
  printf 'Unsigned staging directory: %s\n' "$prepared"
  exit 0
fi

[[ -d "$prepared" && ! -L "$prepared" ]] || fail "prepare the unsigned bundle first with --unsigned"
python3 scripts/stage-maven-central-bundle.py --reuse "$prepared" "$bundle_root" "$version"

while IFS= read -r -d '' artifact; do
  gpg --batch --pinentry-mode loopback --passphrase-fd 0 --local-user "$MAVEN_SIGNING_KEY_ID" \
    --armor --detach-sign --output "${artifact}.asc" "$artifact" <<<"$MAVEN_SIGNING_PASSWORD"
  gpg --batch --verify "${artifact}.asc" "$artifact" >/dev/null 2>&1 ||
    fail "a detached signature failed verification"
done < <(find "$bundle_root/me" -type f ! -name '*.asc' -print0)

output_dir="${work_dir}/out"
bundle="${output_dir}/reallyme-maven-central-${version}.zip"
mkdir -p "$output_dir"
python3 scripts/stage-maven-central-bundle.py --archive "$bundle_root" "${stage}/bundle.zip" "$version"
ln "${stage}/bundle.zip" "$bundle" || fail "the output ZIP already exists or could not be created"
printf 'Upload this bundle in the Central Portal: %s\n' "$bundle"
