#!/usr/bin/env python3
"""Fail when source-controlled files contain common private credential forms."""

from __future__ import annotations

import re
import subprocess
import base64
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_NAMES = {"google-services.json", "GoogleService-Info.plist"}
PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "Supabase secret key": re.compile(r"sb_secret_[0-9A-Za-z_-]{20,}"),
    "AWS access key": re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    "GitHub token": re.compile(r"gh[oprsu]_[0-9A-Za-z]{36,}"),
}
JWT_PATTERN = re.compile(r"eyJ[0-9A-Za-z_-]+\.([0-9A-Za-z_-]+)\.[0-9A-Za-z_-]+")


def candidate_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def main() -> int:
    findings: list[str] = []
    scanned = 0
    for path in candidate_paths():
        if not path.is_file():
            continue
        if path.name in FORBIDDEN_NAMES:
            findings.append(f"forbidden provider configuration file: {path.relative_to(ROOT)}")
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        for label, pattern in PATTERNS.items():
            if pattern.search(content):
                findings.append(f"{label}: {path.relative_to(ROOT)}")
        for match in JWT_PATTERN.finditer(content):
            payload = match.group(1)
            try:
                decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
                role = json.loads(decoded).get("role", "").lower().replace("-", "_")
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                continue
            if role in {"service_role", "servicerole", "supabase_admin"}:
                findings.append(f"Supabase privileged JWT: {path.relative_to(ROOT)}")

    if findings:
        print("Potential secrets detected:")
        for finding in findings:
            print(f"- {finding}")
        return 1

    print(f"Secret hygiene check passed ({scanned} text files scanned).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
