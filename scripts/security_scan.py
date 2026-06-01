#!/usr/bin/env python3
"""Lightweight repository guard for obvious secrets and directory PII exports."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {
    ".git",
    ".github",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
    "instance",
    "venv",
    ".venv",
}

TEXT_SUFFIXES = {
    ".bat",
    ".cfg",
    ".conf",
    ".css",
    ".env",
    ".example",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".sql",
    ".txt",
    ".yml",
    ".yaml",
}

PROHIBITED_FILE_PATTERNS = [
    re.compile(r"(^|/)migration_ready_by_department_.*\.(csv|xlsx)$", re.IGNORECASE),
    re.compile(r"(^|/).*_migration_ready.*\.(csv|xlsx)$", re.IGNORECASE),
]

PROHIBITED_CONTENT_PATTERNS = [
    (
        "Weak SECRET_KEY fallback",
        re.compile(r"SECRET_KEY\s*=\s*os\.environ\.get\(\s*['\"]SECRET_KEY['\"]\s*,"),
    ),
    (
        "Docker Compose weak secret fallback",
        re.compile(r"\$\{(?:SECRET_KEY|DB_PASSWORD|GRAFANA_PASSWORD):-[^}]+}"),
    ),
    (
        "Active Directory DN plus email export",
        re.compile(r"(?=.*\bDC=)(?=.*\bOU=)(?=.*@)", re.IGNORECASE),
    ),
    (
        "TLS certificate validation disabled",
        re.compile(r"\b(?:CERT_NONE|SkipCACheck|SkipCNCheck|ServerCertificateValidationCallback)\b"),
    ),
    (
        "PowerShell execution policy bypass",
        re.compile(r"-ExecutionPolicy\s+Bypass", re.IGNORECASE),
    ),
    (
        "Credential provider HTTP reset URL",
        re.compile(r"http://localhost:5000/reset-password", re.IGNORECASE),
    ),
    (
        "Native python-ldap dependency",
        re.compile(r"^python-ldap\b", re.IGNORECASE),
    ),
]


def iter_repo_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        rel_parts = path.relative_to(ROOT).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.is_file():
            files.append(path)
    return files


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        with path.open("rb") as handle:
            chunk = handle.read(1024)
        return b"\0" not in chunk
    except OSError:
        return False


def main() -> int:
    findings: list[str] = []
    for path in iter_repo_files():
        rel = path.relative_to(ROOT).as_posix()
        if any(pattern.search(rel) for pattern in PROHIBITED_FILE_PATTERNS):
            findings.append(f"{rel}: prohibited generated export artifact")
            continue
        if rel == "scripts/security_scan.py":
            continue

        if not is_text_file(path):
            continue

        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            findings.append(f"{rel}: unable to read file: {exc}")
            continue

        for line_no, line in enumerate(lines, start=1):
            for label, pattern in PROHIBITED_CONTENT_PATTERNS:
                if pattern.search(line):
                    findings.append(f"{rel}:{line_no}: {label}")

    if findings:
        print("Security scan failed:")
        for finding in findings:
            print(f"  - {finding}")
        return 1

    print("Security scan passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
