#!/usr/bin/env bash
set -euo pipefail

SIERE_AUTH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIERE_AUTH_DERIVED_DATA="$(mktemp -d "${TMPDIR:-/tmp}/siere-auth-ios-derived.XXXXXX")"
trap 'rm -rf "$SIERE_AUTH_DERIVED_DATA"' EXIT

cd "$SIERE_AUTH_ROOT"

if rg -i 'cocoapods|Pods_' sample/iosApp/iosApp.xcodeproj sample/iosApp/KotlinMultiplatformLinkedPackage; then
  echo "CocoaPods reference found in the SwiftPM sample" >&2
  exit 1
fi

xcodebuild \
  -resolvePackageDependencies \
  -onlyUsePackageVersionsFromResolvedFile \
  -project sample/iosApp/iosApp.xcodeproj \
  -scheme iOSApp

xcodebuild \
  -project sample/iosApp/iosApp.xcodeproj \
  -scheme iOSApp \
  -onlyUsePackageVersionsFromResolvedFile \
  -disableAutomaticPackageResolution \
  -configuration Debug \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$SIERE_AUTH_DERIVED_DATA" \
  CODE_SIGNING_ALLOWED=NO \
  ARCHS=arm64 \
  COMPILER_INDEX_STORE_ENABLE=NO \
  CLANG_ENABLE_EXPLICIT_MODULES=NO \
  SWIFT_ENABLE_EXPLICIT_MODULES=NO \
  build

if find "$SIERE_AUTH_DERIVED_DATA/Build" \
  \( -name 'Pods-*' -o -name 'Pods_*.framework' -o -name 'Pods_*.a' \) \
  -print -quit | grep -q .; then
  echo "CocoaPods artifact found in fresh DerivedData" >&2
  exit 1
fi
