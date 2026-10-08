from __future__ import annotations

import re
from pathlib import Path
from typing import Callable
from scanners.traversal import iter_files

SKIP_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
MAX_FILE_SIZE = 1_000_000
SAFE_PLACEHOLDER_WORDS = {"fake", "example", "sample", "test", "placeholder", "dummy"}

RULES = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret access key", re.compile(r'''(?i)aws_secret_access_key\s*[:=]\s*["'][^"']{20,}["']''')),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("Google service-account private key", re.compile(r'"type"\s*:\s*"service_account"|"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----')),
    ("Azure client secret", re.compile(r'''(?i)\b(?:azure[_-]?client[_-]?secret|client[_-]?secret)\s*[:=]\s*["'][^"']{12,}["']''')),
    ("npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI API token", re.compile(r"\bpypi-[A-Za-z0-9_-]{16,}\b")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Heroku API key", re.compile(r'''(?i)\bheroku[_-]?api[_-]?key\s*[:=]\s*["'][0-9a-f-]{20,}["']''')),
    ("Discord bot token", re.compile(r"\b(?:[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,})\b")),
    ("Generic secret assignment", re.compile(r'''(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*["'][^"']{8,}["']''')),
)


def scan_file(file_path: Path, root: Path, max_file_size: int = MAX_FILE_SIZE) -> list[dict[str, object]]:
    """Scan one file; cache callers must handle read failures."""
    if file_path.stat().st_size > max_file_size:
        return []
    return scan_text(file_path.read_text(encoding="utf-8", errors="ignore"), str(file_path.relative_to(root)))


def scan_text(content: str, relative: str) -> list[dict[str, object]]:
    """Apply the same detection rules to already-read content without file I/O."""
    findings: list[dict[str, object]] = []
    for line_number, line in enumerate(content.splitlines(), 1):
        for rule_name, pattern in RULES:
            if pattern.search(line):
                findings.append({"severity": "CRITICAL", "rule": rule_name,
                    "confidence": "high" if rule_name != "Generic secret assignment" else "medium",
                    "file": relative, "line": line_number})
    return findings

def scan_directory(root: Path, ignored_directories: set[str] | None = None, max_file_size: int = MAX_FILE_SIZE, *, on_finding: Callable[[dict[str, object]], None] | None = None) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    root = root.resolve()
    for file_path in iter_files(root, SKIP_DIRECTORIES if ignored_directories is None else ignored_directories):
        try:
            file_findings = scan_file(file_path, root, max_file_size)
            findings.extend(file_findings)
            if on_finding is not None:
                for finding in file_findings:
                    on_finding(dict(finding))
        except OSError:
            continue
    return findings
