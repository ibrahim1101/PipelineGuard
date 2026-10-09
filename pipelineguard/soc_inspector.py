"""Privacy-preserving presentation of scanner findings in the SOC desktop.

Only allowlisted metadata is displayed or copied. In particular, untrusted
finding fields and local source lines must never be pasted into the inspector.
"""
from __future__ import annotations

import re
from typing import Mapping, Any


def _metadata(value: Any, limit: int = 220) -> str:
    """Bound single-line metadata to avoid control characters and huge widgets."""
    if value is None:
        return "—"
    text = str(value)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text).strip()
    return text[:limit] + ("…" if len(text) > limit else "") if text else "—"


def finding_group(item: Mapping[str, Any]) -> str:
    """Categorize observed findings, without inferring scanner results."""
    if item.get("package") or item.get("ecosystem"):
        return "Dependencies"
    if item.get("file"):
        return "Secrets"
    return "Other"


def safe_finding_details(item: Mapping[str, Any]) -> str:
    """Render metadata only: never raw JSON, source, token, or arbitrary summary."""
    fields = [
        ("Severity", item.get("severity")),
        ("Rule", item.get("rule")),
        ("Location", item.get("file")),
        ("Line", item.get("line")),
        ("Package", item.get("package")),
        ("Version", item.get("version")),
        ("Advisory", item.get("id")),
    ]
    lines = [f"{label}: {_metadata(value)}" for label, value in fields if value is not None]
    lines.extend(("", "Recommended action",
                  "Review the reported location and apply the relevant security fix.",
                  "Sensitive values and raw finding payloads are intentionally hidden."))
    return "\n".join(lines)


def masked_code_preview(item: Mapping[str, Any]) -> str:
    """Never open source files: a secrets scanner must not reveal found values."""
    path = item.get("file")
    if not path:
        return "Source preview unavailable for dependency advisories."
    location = _metadata(path)
    line = item.get("line")
    line_number = line if type(line) is int and line > 0 else "?"
    return (f"{location}:{line_number}\n"
            f"{line_number:>5}  [source content hidden for privacy]\n\n"
            "Open this file in your editor to review the finding safely.")


def safe_finding_heading(item: Mapping[str, Any]) -> tuple[str, str]:
    """Compact inspector title from bounded, single-line allowlisted metadata."""
    severity = _metadata(item.get("severity"), 16).upper()
    rule = _metadata(item.get("rule"), 90)
    return severity, rule
