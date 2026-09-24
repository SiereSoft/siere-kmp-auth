#!/usr/bin/env python3
"""Validate that Kotlin/JS OIDC live evidence matches the current candidate sources."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs" / "js-oidc-sample-evidence.md"
RUNTIME_FILES = (
    "build.gradle.kts",
    "settings.gradle.kts",
    "gradle/libs.versions.toml",
    "gradle/wrapper/gradle-wrapper.properties",
    "auth-oidc/build.gradle.kts",
    "sample/build.gradle.kts",
    "sample/src/commonMain/kotlin/dev/siere/auth/sample/SampleApp.kt",
    "sample/src/jsMain/kotlin/BrowserOidc.kt",
    "sample/src/jsMain/kotlin/main.kt",
    "sample/src/jsMain/resources/index.html",
    "sample/src/jsMain/resources/oidc-callback.html",
    "sample-jvm-oidc/keycloak/siere-realm.json",
)


def runtime_paths() -> list[Path]:
    paths = [ROOT / relative for relative in RUNTIME_FILES]
    paths.extend((ROOT / "auth-oidc" / "src").glob("**/*.kt"))
    distribution = ROOT / "sample" / "build" / "dist" / "js" / "productionExecutable"
    paths.extend(
        path
        for path in distribution.glob("**/*")
        if path.is_file() and path.suffix != ".map"
    )
    return sorted(set(paths), key=lambda path: path.relative_to(ROOT).as_posix())


def runtime_digest() -> str:
    digest = hashlib.sha256()
    paths = runtime_paths()
    missing = [path for path in paths if not path.is_file()]
    if missing:
        names = ", ".join(path.relative_to(ROOT).as_posix() for path in missing)
        raise FileNotFoundError(f"Missing runtime inputs: {names}")
    distribution = ROOT / "sample" / "build" / "dist" / "js" / "productionExecutable"
    if not distribution.is_dir():
        raise FileNotFoundError(
            "Missing production distribution; run :sample:jsBrowserDistribution first",
        )
    for path in paths:
        relative = path.relative_to(ROOT).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    expected = runtime_digest()
    if "--print-digest" in sys.argv:
        print(expected)
        return 0

    if not EVIDENCE.is_file():
        print(f"Missing live evidence: {EVIDENCE.relative_to(ROOT)}", file=sys.stderr)
        return 1
    callback = (ROOT / "sample/src/jsMain/resources/oidc-callback.html").read_text(encoding="utf-8")
    unsafe_callback_markers = [marker for marker in ("window.close()", '"*"') if marker in callback]
    if unsafe_callback_markers:
        print(
            "Callback page contains unsafe lifecycle or messaging markers: "
            + ", ".join(unsafe_callback_markers),
            file=sys.stderr,
        )
        return 1
    callback_requirements = (
        'const openerOrigin = "http://127.0.0.1:8081"',
        'type: "siere-oidc-callback"',
        "version: 1",
        "window.opener.postMessage(message, openerOrigin)",
    )
    missing_callback_requirements = [value for value in callback_requirements if value not in callback]
    if missing_callback_requirements:
        print(
            "Callback page is missing exact-origin protocol requirements: "
            + ", ".join(missing_callback_requirements),
            file=sys.stderr,
        )
        return 1
    built_callback = ROOT / "sample/build/dist/js/productionExecutable/oidc-callback.html"
    if not built_callback.is_file() or built_callback.read_bytes() != callback.encode("utf-8"):
        print("Built callback artifact does not match its source resource", file=sys.stderr)
        return 1
    text = EVIDENCE.read_text(encoding="utf-8")
    match = re.search(r"Runtime digest: `([0-9a-f]{64})`", text)
    recorded = match.group(1) if match else None
    required = (
        "Status: **passed**",
        "Google Chrome 153.0.8010.53",
        "Signed in as Siere Demo",
        "Fresh session ready",
        "Signed out",
        "No CORS error",
        "No mixed-content error",
        "No token-bearing log",
        "No uncaught exception",
    )
    missing = [value for value in required if value not in text]
    if recorded != expected:
        print(
            f"Live evidence digest is stale: recorded={recorded!r}, expected={expected}",
            file=sys.stderr,
        )
        return 1
    if missing:
        print("Live evidence is missing: " + ", ".join(missing), file=sys.stderr)
        return 1
    print(f"Kotlin/JS OIDC live evidence matches runtime digest {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
