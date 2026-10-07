"""Scan profiles define cost/capability envelopes for PipelineGuard v2."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    workers: int
    online_intelligence: bool
    incremental: bool
    git_context: bool
    deep_analysis: bool
    history_secrets: bool


PROFILES = {
    "quick": ScanProfile("quick", 4, False, True, True, False, False),
    "standard": ScanProfile("standard", 4, True, True, True, False, False),
    "deep": ScanProfile("deep", 6, True, True, True, True, True),
    "release": ScanProfile("release", 4, True, True, True, True, True),
    "forensic": ScanProfile("forensic", 2, True, False, True, True, True),
}


def get_profile(name: str) -> ScanProfile:
    try:
        return PROFILES[name.lower()]
    except (AttributeError, KeyError) as exc:
        choices = ", ".join(PROFILES)
        raise ValueError(f"Unknown scan profile {name!r}; choose one of: {choices}") from exc
