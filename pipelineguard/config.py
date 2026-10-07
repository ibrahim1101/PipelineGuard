from __future__ import annotations

import json
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PipelineGuardConfig:
    ignored_directories: set[str] = field(default_factory=lambda: {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"})
    max_file_size: int = 1_000_000
    fail_on_warning: bool = False
    allowlist: list[dict[str, object]] = field(default_factory=list)
    minimum_score: int = 0
    blocked_rules: set[str] = field(default_factory=set)
    block_advisory_severity: str | None = None


def load_config(path: Path | None) -> PipelineGuardConfig:
    config = PipelineGuardConfig()
    if path is None:
        return config
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Configuration must be a JSON object")
    allowed = {"ignored_directories", "max_file_size", "fail_on_warning", "allowlist", "minimum_score", "blocked_rules", "block_advisory_severity"}
    if "block_advisory_severity" in data and data["block_advisory_severity"] not in (None, "LOW", "MODERATE", "HIGH", "CRITICAL"):
        raise ValueError("block_advisory_severity must be LOW, MODERATE, HIGH, CRITICAL, or null")
    unknown = set(data) - allowed
    if unknown:
        raise ValueError("Unknown configuration keys: " + ", ".join(sorted(unknown)))
    for key in ("ignored_directories", "blocked_rules"):
        if key in data and (not isinstance(data[key], list) or any(not isinstance(item, str) or not item for item in data[key])):
            raise ValueError(f"{key} must be a list of nonempty strings")
    if "fail_on_warning" in data and type(data["fail_on_warning"]) is not bool:
        raise ValueError("fail_on_warning must be a boolean")
    for key in ("max_file_size", "minimum_score"):
        if key in data and type(data[key]) is not int:
            raise ValueError(f"{key} must be an integer")
    if data.get("max_file_size", 1) <= 0:
        raise ValueError("max_file_size must be positive")
    if not 0 <= data.get("minimum_score", 0) <= 100:
        raise ValueError("minimum_score must be between 0 and 100")
    if "allowlist" in data:
        if not isinstance(data["allowlist"], list):
            raise ValueError("allowlist must be a list")
        for item in data["allowlist"]:
            if not isinstance(item, dict) or any(not isinstance(item.get(key), str) or not item[key] for key in ("rule", "file")):
                raise ValueError("Each allowlist entry requires a nonempty rule and file")
            if set(item) - {"rule", "file", "line"}:
                raise ValueError("Unknown allowlist fields")
            if "line" in item and (type(item["line"]) is not int or item["line"] < 1):
                raise ValueError("Allowlist line must be a positive integer")
    if "ignored_directories" in data:
        config.ignored_directories = set(data["ignored_directories"])
    if "max_file_size" in data:
        config.max_file_size = int(data["max_file_size"])
    if "fail_on_warning" in data:
        config.fail_on_warning = bool(data["fail_on_warning"])
    if "allowlist" in data:
        config.allowlist = list(data["allowlist"])
    if "minimum_score" in data:
        config.minimum_score = max(0, min(100, int(data["minimum_score"])))
    if "blocked_rules" in data:
        config.blocked_rules = set(data["blocked_rules"])
    config.block_advisory_severity = data.get("block_advisory_severity")
    return config


def policy_blocks(report: dict[str, object], config: PipelineGuardConfig) -> bool:
    if int(report.get("score", 0)) < config.minimum_score:
        return True
    findings = report.get("findings", [])
    ranks = {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if config.block_advisory_severity:
        threshold = ranks[config.block_advisory_severity]
        if any(
            isinstance(item, dict) and item.get("rule") == "Known dependency vulnerability"
            and ranks.get(item.get("advisory_severity", "UNKNOWN"), 0) >= threshold
            for item in findings
        ):
            return True
    return any(item.get("rule") in config.blocked_rules for item in findings if isinstance(item, dict))


def apply_allowlist(findings: list[dict[str, object]], allowlist: list[dict[str, object]]) -> list[dict[str, object]]:
    """Remove only findings explicitly approved by rule, path pattern, and line."""
    filtered = []
    for finding in findings:
        approved = False
        for item in allowlist:
            if not isinstance(item, dict) or not item.get("rule") or not item.get("file"):
                continue
            if item.get("rule") and item["rule"] != finding.get("rule"):
                continue
            pattern = str(item["file"]).replace("\\", "/")
            finding_file = str(finding.get("file", "")).replace("\\", "/")
            if not fnmatch.fnmatchcase(finding_file, pattern):
                continue
            if "line" in item and item["line"] != finding.get("line"):
                continue
            approved = True
            break
        if not approved:
            filtered.append(finding)
    return filtered
