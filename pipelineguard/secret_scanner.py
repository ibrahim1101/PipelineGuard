from __future__ import annotations

import re
from pathlib import Path

SKIP_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
MAX_FILE_SIZE = 1_000_000

RULES = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic secret assignment", re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
)


def scan_directory(root: Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for file_path in root.rglob("*"):
        if not file_path.is_file() or any(part in SKIP_DIRECTORIES for part in file_path.parts):
            continue
        try:
            if file_path.stat().st_size > MAX_FILE_SIZE:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule_name, pattern in RULES:
                if pattern.search(line):
                    findings.append({
                        "severity": "CRITICAL",
                        "rule": rule_name,
                        "file": str(file_path.relative_to(root)),
                        "line": line_number,
                    })
    return findings
