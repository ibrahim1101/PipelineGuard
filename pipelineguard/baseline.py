"""Deterministic finding baselines with explicit, atomic snapshot updates."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

BASELINE_VERSION = 1
IDENTITY_FIELDS = ("rule", "file", "line", "id", "package", "version", "ecosystem", "manifest")
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "MODERATE": 2, "WARNING": 2, "HIGH": 3, "CRITICAL": 4}


def finding_key(finding: dict[str, Any]) -> str:
    """Stable identity independent of severity and dictionary insertion order."""
    identity = {key: finding[key] for key in IDENTITY_FIELDS if key in finding}
    payload = json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def snapshot(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Keep only identifying metadata, never raw evidence or secret values."""
    entries: dict[str, dict[str, Any]] = {}
    for finding in findings:
        key = finding_key(finding)
        entries[key] = {
            "severity": str(finding.get("severity", "INFO")).upper(),
            "identity": {field: finding[field] for field in IDENTITY_FIELDS if field in finding},
        }
    return {"version": BASELINE_VERSION, "findings": entries}


def read_baseline(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": BASELINE_VERSION, "findings": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read baseline {path}: {exc}") from exc
    if (not isinstance(data, dict) or data.get("version") != BASELINE_VERSION
            or not isinstance(data.get("findings"), dict)):
        raise ValueError(f"Unsupported or malformed PipelineGuard baseline: {path}")
    for key, entry in data["findings"].items():
        if not isinstance(key, str) or not isinstance(entry, dict) or not isinstance(entry.get("severity"), str):
            raise ValueError(f"Malformed PipelineGuard baseline entry: {path}")
    return data


def compare_baseline(findings: list[dict[str, Any]], previous: dict[str, Any]) -> dict[str, Any]:
    old = previous["findings"]
    current = snapshot(findings)["findings"]
    new_keys = sorted(set(current) - set(old))
    fixed_keys = sorted(set(old) - set(current))
    existing_keys = sorted(set(current) & set(old))
    regressed_keys = {key for key in existing_keys if SEVERITY_RANK.get(current[key]["severity"], 0)
                      > SEVERITY_RANK.get(old[key]["severity"], 0)}
    return {
        "new": len(new_keys),
        "existing": len(existing_keys),
        "fixed": len(fixed_keys),
        "regressed": len(regressed_keys),
        "fixed_findings": [old[key]["identity"] for key in fixed_keys],
        "finding_states": {key: ("regressed" if key in regressed_keys else "existing") for key in existing_keys}
                          | {key: "new" for key in new_keys},
    }


def write_baseline(path: Path, findings: list[dict[str, Any]]) -> None:
    """Write a versioned snapshot atomically; never silently repair corrupt input."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(snapshot(findings), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
